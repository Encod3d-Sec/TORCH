#!/usr/bin/env python3
"""PostToolUse(Bash): append every meaningful command + its output to
targets/<eng>/poc/cmdlog/<tool>.md, grouped by the primary binary, so the operator has a readable,
per-tool record of exactly what ran and what came back - without any manual capture step.

Example: `bash /root/vm.sh 'nmap -sCV 10.1.1.5'` appends to poc/cmdlog/nmap.md:

    ## 2026-08-10 09:06:12

    ```
    nmap -sCV 10.1.1.5
    ```

    ```
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 ...
    ```

Grouped by the INNER binary (via tool-telemetry._binaries), so vm.sh-wrapped scans land under the
real tool. Skips framework/dev commands (pytest, campaign.py, git, editing the vault) and empty
output. Fail-open and silent; capped so one runaway scan can't bloat the file. Records into
`cmdlog/` (not poc/ root) so it never mixes with curated PoC screenshots.
"""
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

MAX_OUT = 40000        # per-entry output cap (chars); a huge scan is truncated, not dropped
_META_RE = re.compile(
    r"\bpytest\b|\bpy_compile\b|-m\s+pytest|campaign\.py|campaign-doctor|check-hooks|"
    r"tool-phase-backfill|playbook-tools-backfill|\bgit\b|install-hooks|new-engagement|"
    r"scripts/(?:campaign|check|tool|playbook|wiki|gen_|build_|lint|eval_|status|next_move)|"
    r"tests/|skills/hooks|setup/|capture\.sh|\beval_metrics\b", re.IGNORECASE)

try:
    from tool_telemetry import _binaries
except Exception:
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "tool_telemetry", os.path.join(HERE, "tool-telemetry.py"))
    _tt = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_tt)
    _binaries = _tt._binaries


def _response_text(data):
    r = data.get("tool_response")
    if r is None:
        return ""
    if isinstance(r, str):
        return r
    if isinstance(r, dict):
        for k in ("stdout", "output", "content", "stderr"):
            v = r.get(k)
            if isinstance(v, str) and v.strip():
                return v
    try:
        return json.dumps(r)
    except Exception:
        return str(r)


def _unwrap(cmd):
    """The INNER command of a `bash /root/vm.sh '<inner>'` (or vm-rsh/win-rsh) transport, so the
    entry is grouped by the real tool (nmap) not the wrapper (bash)."""
    m = re.search(r"(?:vm\.sh|vm-rsh\.sh|win-rsh\.sh)\b[^'\"]*['\"](.+)['\"]\s*$", cmd or "", re.S)
    return m.group(1) if m else (cmd or "")


def _slug(binary):
    s = re.sub(r"[^A-Za-z0-9_.-]", "-", binary or "misc").strip("-.") or "misc"
    return s[:40]


def main():
    try:
        data = json.loads(sys.stdin.read())
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd or _META_RE.search(cmd):
        return
    out = _response_text(data)
    if not out.strip():
        return

    import _engagement
    d = _engagement.active_dir()
    if not d:
        return

    bins = _binaries(_unwrap(cmd)) or []
    # first binary that is not a pure wrapper/transport is the meaningful tool
    tool = next((b for b in bins if b not in ("bash", "sh", "sudo", "env", "time")), None) \
        or (bins[0] if bins else "misc")

    pdir = os.path.join(d, "poc", "cmdlog")
    try:
        os.makedirs(pdir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = out if len(out) <= MAX_OUT else out[:MAX_OUT] + "\n...[truncated]"
        entry = "\n## %s\n\n```\n%s\n```\n\n```\n%s\n```\n" % (ts, cmd.strip(), body.rstrip())
        with open(os.path.join(pdir, _slug(tool) + ".md"), "a", encoding="utf-8") as fh:
            fh.write(entry)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
