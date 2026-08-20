#!/usr/bin/env python3
"""PreToolUse(Bash) hook: ENFORCING scope + RoE guard.

Before a shell command runs, DENY it (permissionDecision: deny -> the tool call is
blocked, the reason is shown) when it deterministically:
  - targets an out-of-scope host/IP (exact host/domain match or IP-in-CIDR against
    scope.md's out_of_scope list; IPv4 and IPv6), or
  - uses tooling forbidden by the engagement RoE flags
    (no_bruteforce / no_dos / passive_only in scope.md).

This is the harness's "enforce, don't nudge" boundary: these two are DETERMINISTIC
(no judgement), so blocking them costs no tokens/time and prevents the wrong action
outright. Semantic workflow steps (wiki-first, tools-not-manual, capture, intended-path)
stay advisory elsewhere -- hard-blocking a judgement call would false-fire and make us
MORE stuck, the opposite of the goal. (The anti-narration `echo "=== ... ==="` norm is
CLAUDE.md guidance, not a deny: it was evadable and only added a re-run tax.)

SAFETY (this hook can block, so it must never trap the operator):
  - Fail-OPEN: any exception -> exit 0, allow. A hook bug never blocks a command.
  - Narrow matches only: out-of-scope needs an explicit out_of_scope entry (empty on a
    typical single-target CTF -> never fires); RoE denies need the flag set. IPs/hosts that
    appear only in a URL query/fragment or a data/header-flag value (an SSRF/redirect
    payload) are exempt; the target is the host, not a param value. Option-assigned
    targets (`--url=<host>`) are NOT exempt.
  - Escape hatch: create `skills/hooks/.enforce-off` (== the hooks dir) to instantly
    downgrade every deny back to an advisory warning, for when a false-block gets in the way.
No active engagement -> nothing to deny. Any error exits 0 silent.
"""
import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# permissive IPv6 grab (>=2 colons); every candidate is validated with ipaddress.ip_address,
# so a hex-ish false grab (git sha, MAC, HH:MM:SS) is rejected. IP_RE is IPv4-only, so without
# this an out_of_scope IPv6 CIDR was never enforced (the under-block).
IP6_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}")
# Non-target noise stripped BEFORE extracting the target host/IP, so an out-of-scope host/IP
# that is only an SSRF/redirect PAYLOAD (not the target) is not mistaken for the target (the
# over-block). Two sources: a URL query string/fragment (?.../#...) - a value there is a
# parameter, never the authority; and the value of a data/header flag (-d/--data*/-F/--form/
# -H/--header) - SSRF/redirect payloads. We do NOT blanket-strip `=`: that hid `--url=<target>`
# / `-u=<target>` and let a real out-of-scope target escape the deny (the under-block).
_QUERY_FRAG = re.compile(r"[?#]\S*")
_DATA_FLAG = re.compile(
    r"(?<!\S)(?:--data(?:-raw|-binary|-urlencode)?|--form|--header|-d|-F|-H)\s+(?:'[^']*'|\"[^\"]*\"|\S+)",
    re.I)


def _strip_noise(cmd):
    """Remove URL query/fragment values and data/header-flag payloads so only genuine target
    host/IP tokens remain for scope matching. Keeps option-assigned targets (`--url=<host>`)."""
    return _QUERY_FRAG.sub("", _DATA_FLAG.sub(" ", cmd))
HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
# file extensions that HOST_RE would otherwise match as "hosts" (config.yml, app.py...)
FILE_EXT = {"json", "yml", "yaml", "md", "sh", "py", "txt", "js", "ts", "go", "rs",
            "conf", "cfg", "ini", "toml", "lock", "log", "csv", "xml", "html", "css",
            "png", "jpg", "jpeg", "gif", "svg", "pdf", "zip", "tar", "gz", "bak", "tmp",
            "c", "cpp", "h", "java", "rb", "php", "env", "example", "local", "sample"}

BRUTEFORCE = re.compile(r"\b(hydra|medusa|patator|ncrack|kerbrute)\b|--password-file|\bspray(ing|hound)?\b|-P\s+\S+\.txt", re.I)
DOS = re.compile(r"\b(slowloris|hping3|stress-ng|siege|t50)\b|--flood|--min-rate\s+[0-9]{5,}|nmap[^|;&]*-T5|\bab\b[^|;&]*-n\s+[0-9]{5,}", re.I)
ACTIVE = re.compile(r"\b(nmap|masscan|rustscan|nuclei|ffuf|gobuster|feroxbuster|nxc|netexec|crackmapexec|hydra|medusa|sqlmap|wpscan|nikto|dirb)\b", re.I)


def ip_out_of_scope(cmd, sc):
    """IPv4/IPv6 tokens in `cmd` that fall inside an out_of_scope CIDR/IP. URL query/fragment
    values and data/header-flag payloads are stripped first (see _strip_noise), so an OOS IP
    that only appears as an SSRF/redirect param against an in-scope host is NOT flagged; an
    option-assigned target (`--url=<oos>`) IS still seen."""
    cidrs = []
    for o in sc.get("out_of_scope", []):
        o = o.strip()
        try:
            cidrs.append(ipaddress.ip_network(o, strict=False))
        except ValueError:
            pass
    if not cidrs:
        return []
    scan = _strip_noise(cmd)
    hits = []
    for tok in IP_RE.findall(scan) + IP6_RE.findall(scan):
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if any(ip in c for c in cidrs):
            hits.append(tok)
    return hits


def _enforcing():
    """Enforcement is ON unless an escape-hatch marker sits in the hooks dir. Creating
    `skills/hooks/.enforce-off` (== HERE) downgrades every deny to an advisory warning.
    ENFORCE_OFF_MARKER overrides the marker path so parallel test workers point it at a tmp file
    instead of colliding on the shared hooks-dir marker (operator default path is unchanged)."""
    marker = os.environ.get("ENFORCE_OFF_MARKER") or os.path.join(HERE, ".enforce-off")
    return not os.path.exists(marker)


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd:
        return

    deny = []   # deterministic, block-worthy reasons (one line each)

    # scope / RoE (only when an engagement is active)
    try:
        import _engagement
        d = _engagement.active_dir()
        if d:
            sc = _engagement.scope(d)
            # out-of-scope targets: IP-in-CIDR (IPv4+IPv6) + exact/parent host match. URL
            # query/fragment values and data/header-flag payloads are exempt (see _strip_noise):
            # the target is the host, not an SSRF/redirect param value; `--url=<host>` is kept.
            flagged = set(ip_out_of_scope(cmd, sc))
            for host in HOST_RE.findall(_strip_noise(cmd)):
                if host.rsplit(".", 1)[-1].lower() in FILE_EXT:
                    continue   # config.yml / app.py are filenames, not hosts
                if _engagement.out_of_scope_match(host, sc):
                    flagged.add(host)
            if flagged:
                deny.append("out-of-scope: command targets " + ", ".join(sorted(flagged))
                            + " which match an OUT-OF-SCOPE entry in scope.md")
            # RoE tooling
            if sc.get("no_bruteforce") and BRUTEFORCE.search(cmd):
                deny.append("RoE no_bruteforce: command uses brute-force tooling")
            if sc.get("no_dos") and DOS.search(cmd):
                deny.append("RoE no_dos: command looks like high-volume/DoS tooling")
            if sc.get("passive_only") and ACTIVE.search(cmd):
                deny.append("RoE passive_only: command runs an active scanner")
    except Exception:
        pass

    if not deny:
        return
    body = "\n- ".join(deny)
    # telemetry: every block/advise is a recorded drift signal (a wrong action the guard caught)
    try:
        import _telemetry
        reason = ("blocked " if _enforcing() else "advised ") + " | ".join(x.split(":")[0] for x in deny)
        _telemetry.drift("scope-guard", reason)
        _telemetry.hook("scope-guard", action=("deny" if _enforcing() else "advise"))
    except Exception:
        pass
    if _enforcing():
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": ("BLOCKED by harness enforcement:\n- " + body
                + "\n\nFix the command and re-run. (False block? create skills/hooks/.enforce-off "
                  "to downgrade enforcement to advisory.)"),
        }}))
    else:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "SCOPE/RoE/HYGIENE (advisory; enforcement OFF via .enforce-off):\n- " + body,
        }}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
