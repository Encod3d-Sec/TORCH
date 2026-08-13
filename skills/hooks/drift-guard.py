#!/usr/bin/env python3
"""PreToolUse(Bash) hook: make the campaign driver NON-OPTIONAL (anti-drift).

The proven failure: the deterministic driver (scripts/campaign.py) is advisory BY
INVOCATION - it only enforces its gates on turns the agent chooses to run it, so under
momentum the agent walked away from `campaign.py next` in 90 seconds and free-handed a whole
box via 85 raw `bash /root/vm.sh` exploit calls. This hook pulls the agent back: on an
exploit-shaped Bash command during an active campaign, if the agent is OFF-BOARD (running an
exploit/scan binary the driver never emitted, and the board is NOT empty), it ESCALATES a
counter and eventually DENIES until the agent consults the driver.

Policy (matches the harness rule that a hard Bash deny is risky, so escalate, don't snap-deny):
  - off_board_streak 1-2  -> INJECT an advisory warning ("run campaign.py next; N calls since")
  - off_board_streak >= 3 -> DENY (permissionDecision deny), telling them to run next/board/done
  - `campaign.py next|board|done|pass-done|init` seen in the command -> reset the streak to 0

ON-BOARD (allowed, never counted) when EITHER:
  - the command's exploit/scan binary is in .campaign.json emitted_bins (the driver told them to
    run it), OR
  - the board is empty/uncounted (generic tech -> playbook+behaviours yield 0 rows -> the driver
    has nothing to serve, so there is nothing to hold the agent to). Fail-open by design.

EXPLOIT-SHAPED = handroll.classify() fires (a substitutable hand-rolled request loop) OR the
command mentions a network/scan/exploit binary (NET_BINS). NET_BINS is word-searched over the
WHOLE command string, not just the leading token, so `bash /root/vm.sh 'nmap ...'` - the exact
wrapper the reference failure used - is caught by the inner binary.

SAFETY (this hook can block, so it must never trap the operator):
  - Fail-OPEN everywhere: no engagement / no .campaign.json / pass < 5 / unparseable / any
    exception -> exit 0, allow. A hook bug never blocks a command.
  - Escape hatch: create skills/hooks/.enforce-off (shared with scope-guard) to downgrade every
    deny to an advisory warning.
  - pass >= 5 gate: only fires once the board is actually driving (passes 0-4 are pre-board recon
    where free exploration is expected).
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))

# Network/scan/exploit binary set = the driver's own NET_BINS (drift pre-filter). Import it so the
# two never diverge; fall back to a literal mirror if campaign.py can't be imported.
try:
    from campaign import NET_BINS
except Exception:
    NET_BINS = {"curl", "wget", "nmap", "rustscan", "dnsx", "httpx", "nc", "ncat", "ffuf",
                "feroxbuster", "gobuster", "sqlmap", "nuclei", "nxc", "netexec", "katana",
                "gau", "subfinder", "amass", "nikto", "wpscan", "dig", "openssl", "hydra"}
try:
    from handroll import classify as _handroll_classify
except Exception:
    def _handroll_classify(_cmd):
        return False, None, ""

HEAVY_SCANNERS = {"ffuf", "feroxbuster", "gobuster", "wpscan", "nuclei", "dirb", "katana", "nikto"}
_SCAN_WINDOW = 180          # seconds: a 2nd heavy scanner launched within this is "concurrent"

_BIN_RE = re.compile(r"\b(" + "|".join(sorted(map(re.escape, NET_BINS), key=len, reverse=True)) + r")\b")
_DRIVER_RE = re.compile(r"campaign\.py\s+(?:next|board|done|pass-done|init)\b")
# A HAND-WRITTEN exploit run as a script/interpreter, or an interactive reverse-shell driver:
# exploit-shaped even though it touches no NET_BIN (the exact gap the post-mortem free-handed
# through - `bash /root/vm.sh 'python3 exp.py'`). Deliberately does NOT match the `bash /root/vm.sh`
# transport wrapper itself (that is how EVERY VM command runs); it matches the INNER interpreter.
_INTERP_RE = re.compile(
    r"\bpython3?\s+(?:-c\b|\S+\.py\b)|\bphp\s+(?:-r\b|\S+\.php\b)|\bruby\s+-e\b|\bperl\s+-e\b"
    r"|\bvm-rsh\.sh\b|\bwin-rsh\.sh\b|(?:^|\s)\./\S+\.(?:py|sh|elf)\b")


# Framework/dev commands are NOT engagement drift: running tests, the driver itself, or editing the
# vault's own trees while an engagement happens to be active must never fire the guard (observed:
# `pytest` misfiring during harness development). Mirrors recon-capture.py's framework-meta guard.
_META_RE = re.compile(
    r"\bpytest\b|\bpy_compile\b|-m\s+pytest|campaign\.py|campaign-doctor|check-hooks|"
    r"tool-phase-backfill|playbook-tools-backfill|\bgit\b|install-hooks|new-engagement|"
    r"scripts/(?:campaign|check|tool|playbook|wiki|gen_|build_|lint|eval_|status|next_move)|"
    r"tests/|skills/hooks|setup/", re.IGNORECASE)


def _enforcing():
    return not os.path.exists(os.path.join(HERE, ".enforce-off"))


def _post_foothold(d, _eng):
    """Deny-suppression: True once the target is a confirmed-primitive/foothold asset, where varied
    deepening is legitimate. Covers access>=foothold AND a `## CONFIRMED CHAIN`/breakthrough marker
    (a confirmed primitive pre-shell - the redeploy case that hard-blocked confirmed re-establishment)."""
    p = os.path.join(d, "state.md")
    try:
        for r in _eng._parse_table(p):
            acc = (r.get("access") or r.get("foothold") or "").strip().lower()
            if any(k in acc for k in ("foothold", "shell", "user", "root", "admin", "owned", "vuln")):
                return True
    except Exception:
        pass
    try:
        txt = open(p, encoding="utf-8").read()
        if re.search(r"^#{1,6}\s*(CONFIRMED CHAIN|BREAKTHROUGH|STATUS:\s*SOLVED)", txt, re.M | re.I):
            return True
    except Exception:
        pass
    return False


def _bins_in(cmd):
    """Exploit/scan binaries mentioned anywhere in the command string (whole-string search, so a
    binary inside a `bash vm.sh '<inner>'` wrapper is still seen)."""
    return set(_BIN_RE.findall(cmd or ""))


def _scanner_cap(d, st, cmd_bins):
    """Hard-deny a 2nd HEAVY scanner within _SCAN_WINDOW on a small box (ctf). The mistake that DoS'd
    the box. Records each heavy-scanner launch to .scan-launches.jsonl; denies (and does not record)
    if a prior launch is < _SCAN_WINDOW old. Returns a reason string to deny with, or None to allow."""
    import time
    heavy = cmd_bins & HEAVY_SCANNERS
    if not heavy:
        return None
    if (st.get("type") or "").lower() != "ctf":       # small-box policy: ctf only (extend later)
        return None
    p = os.path.join(d, ".scan-launches.jsonl")
    now = time.time()
    prior = None
    try:
        for ln in open(p, encoding="utf-8"):
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if now - float(e.get("ts", 0)) < _SCAN_WINDOW:
                prior = e
    except Exception:
        pass
    if prior and _enforcing():
        age = int(now - float(prior["ts"]))
        return ("a scan is already running (`%s` launched %ds ago) - serialize on this small/tunnel "
                "box (scope.md: curl-preferred), or drop threads to -t<=20. Wait for it or kill it "
                "first. (False block? create skills/hooks/.enforce-off.)" % (prior.get("tool", "?"), age))
    try:                                              # record this launch, then allow
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": now, "tool": sorted(heavy)[0]}) + "\n")
    except Exception:
        pass
    return None


def main():
    try:
        data = json.loads(sys.stdin.read())
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd:
        return

    import _engagement
    d = _engagement.active_dir()
    if not d:
        return
    sp = os.path.join(d, ".campaign.json")
    if not os.path.isfile(sp):
        return                                    # no campaign -> nothing to enforce
    try:
        st = json.load(open(sp, encoding="utf-8"))
    except Exception:
        return

    # A driver call resets the streak (the agent came back to the board).
    if _DRIVER_RE.search(cmd):
        if st.get("off_board_streak"):
            st["off_board_streak"] = 0
            try:
                json.dump(st, open(sp, "w", encoding="utf-8"), indent=1)
            except Exception:
                pass
        return

    if _META_RE.search(cmd):
        return                                    # framework/dev command, not engagement drift
    if st.get("pass", 0) < 5:
        return                                    # pre-board recon: free exploration expected

    cmd_bins = _bins_in(cmd)
    exploit_shaped = bool(cmd_bins) or _handroll_classify(cmd)[0] or bool(_INTERP_RE.search(cmd))
    if not exploit_shaped:
        return                                    # not an exploit/scan/interpreter call -> ignore

    _deny = _scanner_cap(d, st, cmd_bins)
    if _deny:
        try:
            import _telemetry; _telemetry.hook("drift-guard", action="deny-scanner")
        except Exception:
            pass
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
              "permissionDecision": "deny",
              "permissionDecisionReason": "BLOCKED by harness enforcement (scanner-cap): " + _deny}}))
        return

    since = _engagement.seconds_since_direction(d)
    if since is not None and since > 300:
        _engagement.touch_direction(d)                 # fire once per 5-min window; RTL call re-resets
        try:
            import _telemetry; _telemetry.hook("drift-guard", action="auto-rtl")
        except Exception:
            pass
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
              "additionalContext": (
                "DRIFT (%d min without a board advance or a finding): you are spinning. Load "
                "`Skill(redteamlead)` NOW for ranked direction, or say in ONE line why you are on a "
                "known-productive track. Do not keep hand-rolling the same vector." % int(since // 60))}}))
        return

    # ON-BOARD escape 1: no OPEN ([ ]/[~]) rows -> empty board (generic tech) OR end-of-board.
    # Either way the driver has nothing to hold the agent to, so allow (fail-open). Checking OPEN
    # status (not mere presence) stops end-of-board verification probes from being false-blocked.
    rows = _engagement._parse_table(os.path.join(d, "Approach.md"))
    open_rows = [r for r in rows if (r.get("status") or "[ ]").strip() in ("[ ]", "[~]", "")]
    if not open_rows:
        return
    # ON-BOARD escape 2: the binary is a tool of a currently-OPEN row, or one the driver emitted.
    # Deriving the whitelist from OPEN-row tools (not only the append-only emitted_bins) stops the
    # guard eroding as a long campaign appends every tool to emitted_bins.
    onboard = set(st.get("emitted_bins") or [])
    for r in open_rows:
        t = (r.get("tool") or "").strip().lower()
        if t:
            onboard.add(t)
    if cmd_bins & onboard:
        return

    # OFF-BOARD: escalate.
    streak = int(st.get("off_board_streak", 0) or 0) + 1
    st["off_board_streak"] = streak
    try:
        json.dump(st, open(sp, "w", encoding="utf-8"), indent=1)
    except Exception:
        pass

    off = ", ".join(sorted(cmd_bins)) or "hand-rolled request loop"
    try:
        import _telemetry
        _telemetry.drift("drift-guard", "off-board streak %d (%s)" % (streak, off))
        _telemetry.hook("drift-guard", action=("deny" if streak >= 3 and _enforcing()
                        and not _post_foothold(d, _engagement) else "advise"))
    except Exception:
        pass

    if streak >= 3 and _enforcing() and not _post_foothold(d, _engagement):
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "BLOCKED by harness enforcement (drift-guard): %d consecutive OFF-BOARD "
                "exploit calls without consulting the driver (last: %s, not in the board's "
                "emitted tools).\n\nThe campaign driver owns the plan - stop free-handing. Run "
                "`python3 scripts/campaign.py next` (or `board`), follow the action/tool it "
                "prints, and `campaign.py done <row>` when it lands.\n(False block? create "
                "skills/hooks/.enforce-off to downgrade to advisory.)" % (streak, off)),
        }}))
    else:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": (
                "DRIFT (off-board, %d/3): %d exploit-shaped call(s) since the last driver step "
                "(%s not emitted by the board). The campaign driver is authoritative - run "
                "`python3 scripts/campaign.py next` to get the required row + tool before "
                "continuing, and `done` each row as it lands." % (streak, streak, off)),
        }}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
