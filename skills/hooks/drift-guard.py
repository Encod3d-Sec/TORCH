#!/usr/bin/env python3
"""PreToolUse(Bash) hook: nudge the campaign driver back into view (anti-drift, advisory-only).

The proven failure: the deterministic driver (scripts/campaign.py) is advisory BY
INVOCATION - it only enforces its gates on turns the agent chooses to run it, so under
momentum the agent walked away from `campaign.py next` in 90 seconds and free-handed a whole
box via 85 raw `bash /root/vm.sh` exploit calls. This hook pulls the agent back: on an
exploit-shaped Bash command during an active campaign, if the agent is OFF-BOARD (running an
exploit/scan binary the driver never emitted, and the board is NOT empty), it ESCALATES a
counter and ADVISES the agent back to the driver. It never denies a command - the standing
operator complaint was that a hard deny throttles legit engagements, so this hook is advisory
only (the RTL reflex now lives in campaign.py's `_tells_stop` + recon-capture's vector-doubt
nudges).

Policy:
  - off_board_streak N -> INJECT an advisory warning ("run campaign.py next; N calls since"),
    for every N (the counter is kept and reported, but never escalates to a deny)
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

SAFETY (this hook only advises, but stays fail-open anyway - never let a hook bug break a turn):
  - Fail-OPEN everywhere: no engagement / no .campaign.json / pass < 5 / unparseable / any
    exception -> exit 0, allow. A hook bug never blocks a command.
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

# Network/scan/exploit binary set = the driver's own NET_BINS (drift pre-filter). Import the shared
# _netbins module (NOT campaign.py) so this PreToolUse hook never parses the ~90KB driver per call;
# fall back to a literal mirror if the module can't be imported.
try:
    from _netbins import NET_BINS
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
# Own regex, independent of NET_BINS: dirb (and any future HEAVY_SCANNERS entry not in NET_BINS)
# must still be caught even when it's the ONLY thing in the command (not otherwise exploit-shaped).
_HEAVY_RE = re.compile(r"\b(" + "|".join(sorted(map(re.escape, HEAVY_SCANNERS), key=len, reverse=True)) + r")\b")

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


def _bins_in(cmd):
    """Exploit/scan binaries mentioned anywhere in the command string (whole-string search, so a
    binary inside a `bash vm.sh '<inner>'` wrapper is still seen)."""
    return set(_BIN_RE.findall(cmd or ""))


def _scanner_cap(d, st, cmd):
    """Advise on a 2nd HEAVY scanner within _SCAN_WINDOW on a small box (ctf) - the mistake that DoS'd
    the box. Records each heavy-scanner launch to .scan-launches.jsonl; if a prior launch is <
    _SCAN_WINDOW old, returns a reason string (the caller always advises, never denies, on it).
    Records this launch and returns None (allow) only when there is no prior in-window launch."""
    import time
    heavy = set(_HEAVY_RE.findall(cmd or ""))
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
    if prior:
        age = int(now - float(prior["ts"]))
        return ("a scan is already running (`%s` launched %ds ago) - serialize on this small/tunnel "
                "box (scope.md: curl-preferred), or drop threads to -t<=20. Wait for it or kill it "
                "first." % (prior.get("tool", "?"), age))
    try:                                              # record this launch, then allow
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": now, "tool": sorted(heavy)[0]}) + "\n")
    except Exception:
        pass
    return None


# T5.2 self-kill footgun: `pkill -f bash` / `killall nc` / `pkill python` matches the operator's OWN
# reverse shell or session and kills it (a recurring shell-loss drift across several boxes). Advisory only
# (never deny - the operator may genuinely want it), fires on a shell/reverse-shell process name in a
# pkill/killall. The sibling footgun (Ctrl-C on an unstabilized shell) is a terminal signal no hook
# sees, so it stays CLAUDE.md prose. Word-list kept to actual shell/relay binaries -> low false-fire.
_SELFKILL_RE = re.compile(
    r"\b(pkill|killall)\b[^|;&\n]*\b(ba?sh|nc|ncat|netcat|socat|python\d?|perl|php|rlwrap|/dev/tcp)\b",
    re.IGNORECASE)


def _selfkill_advisory(cmd):
    """Advisory string when a pkill/killall could self-match the operator's own shell, else None."""
    if not _SELFKILL_RE.search(cmd or ""):
        return None
    return ("SELF-KILL RISK: `pkill`/`killall` on a shell/relay name (bash/sh/nc/python/socat...) "
            "will also match your OWN reverse shell or session and kill it (recurring footgun). Kill "
            "by PID (`kill <PID>`, get it from `ps`) or bracket the pattern to exclude your shell. If "
            "the next command hangs or drops to the attacker prompt, the shell died - re-pop it.")


# --- advisory throttle (A1/A2/A3): a legitimately off-board run (writeup-driven, or post-foothold
#     manual exploitation the driver can't plan) was getting the SAME nudge injected on every call
#     (observed: 184 identical fires in one box = pure token noise). The streak is still COUNTED
#     every time (telemetry/eval-metrics accuracy); only the context INJECTION is gated.
_STATUS_RE = re.compile(r"^##\s*status:\s*(solved|owned|rooted|complete)\b", re.I | re.M)
_FOOTHOLD = {"foothold", "user", "root", "owned", "system", "domain-admin", "da"}


def _state_text(d):
    try:
        return open(os.path.join(d, "state.md"), encoding="utf-8", errors="ignore").read()
    except Exception:
        return ""


def _post_foothold(d):
    """True once state.md's host table shows an access cell at foothold-or-better. The board is a
    PRE-foothold planning aid; post-foothold manual exploitation should not be nagged repeatedly."""
    try:
        import _engagement                       # imported here: main()'s import is local-scoped
        for r in _engagement._parse_table(os.path.join(d, "state.md")):
            if (r.get("access") or "").strip().lower() in _FOOTHOLD:
                return True
    except Exception:
        pass
    return False


def _should_advise(streak, post_foothold):
    """Gate the context injection (never the count). Post-foothold: one reminder then silent. Else:
    streak 1,2,3 then every 25th - keeps the early signal, kills the ~180x repeat that was noise."""
    if post_foothold:
        return streak == 1
    return streak in (1, 2, 3) or streak % 25 == 0


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

    # self-kill footgun advisory (any time, before the campaign gates) - skip framework-meta so a
    # grep/test string mentioning `pkill bash` during harness dev never fires it.
    if not _META_RE.search(cmd):
        _sk = _selfkill_advisory(cmd)
        if _sk:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                  "additionalContext": _sk}}))
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

    if _STATUS_RE.search(_state_text(d)):
        return                                    # A2: engagement SOLVED -> board is moot, stay silent

    cmd_bins = _bins_in(cmd)
    exploit_shaped = bool(cmd_bins) or _handroll_classify(cmd)[0] or bool(_INTERP_RE.search(cmd))

    # Scanner-cap runs on ANY heavy-scanner mention, independent of exploit_shaped/NET_BINS, so a
    # bare `dirb ...` (not in NET_BINS, and not otherwise exploit-shaped) still hits it.
    if _HEAVY_RE.search(cmd):
        _deny = _scanner_cap(d, st, cmd)
        if _deny:
            try:
                import _telemetry
                _telemetry.hook("drift-guard", action="advise-scanner")
            except Exception:
                pass
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                  "additionalContext": "SCANNER-CAP (advisory): " + _deny}}))
            return

    if not exploit_shaped:
        return                                    # not an exploit/scan/interpreter call -> ignore

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
    except Exception:
        pass

    # THROTTLE the context injection (the count above still fired for eval accuracy).
    if not _should_advise(streak, _post_foothold(d)):
        return

    try:
        import _telemetry
        _telemetry.hook("drift-guard", action="advise")
    except Exception:
        pass

    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "additionalContext": (
            "DRIFT (off-board, streak %d): %d exploit-shaped call(s) since the last driver step "
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
