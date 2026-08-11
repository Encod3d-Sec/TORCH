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
import base64
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


# Pure shell/navigation builtins that are never the point of a step -- stripped when they are a
# whole top-level segment (but NOT when they feed a pipeline, e.g. `echo <payload> | nc host port`,
# whose real command is the pipe SINK, not the echo).
_NOISE_BINS = {"cd", "ls", "pwd", "mkdir", "clear", "export", "true", ":", "echo", "printf"}
# a local read of vault/engagement state (not target loot) -> noise. A remote `cat /etc/shadow`
# has no targets//.md/ClaudeBrain marker and survives.
_LOCAL_READ_RE = re.compile(r"^(?:cat|head|tail|less|bat|wc)\b.*(?:targets/|\.md\b|/ClaudeBrain/)")
_B64_PIPE_RE = re.compile(r"^echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+-d\s*\|\s*(.+)$", re.S)
# a shell compound statement (loop/conditional) is ONE command -- its internal `;` must not be
# split into separate lines. A false positive only makes cleanup MORE conservative (show the whole
# command un-split), which is the safe direction.
_COMPOUND_RE = re.compile(r"\bdone\b|\bthen\b|\bfi\b|\besac\b|;\s*do\b|^\s*(?:for|while|until|if|case)\b")


def _split_top_level(cmd):
    """Split on top-level `;` `&&` `||` that are NOT inside single/double quotes. A `|` pipe is
    kept intact inside a segment. Fail-soft: on any confusion the worst case is one un-split
    segment, which is still logged (never dropped)."""
    segs, buf, quote, i, n = [], [], None, 0, len(cmd or "")
    while i < n:
        c = cmd[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
        elif c == ";":
            segs.append("".join(buf)); buf = []; i += 1
        elif c in "&|" and i + 1 < n and cmd[i + 1] == c:      # && or ||
            segs.append("".join(buf)); buf = []; i += 2
        else:
            buf.append(c); i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def _effective_bin(seg):
    """The leading word of a pipeline's SINK (last `|` stage) -- the command that actually does the
    work. `echo X | base64 -d | nc h p` -> `nc`. Naive `|` split is fine here: a mis-split only
    keeps a segment (the safe direction)."""
    stage = (seg.rsplit("|", 1)[-1]).strip()
    return (stage.split() or [""])[0].strip("(){}").lower()


def _decode_b64_pipe(seg):
    """`echo <literal-b64> | base64 -d | bash|sh` -> the decoded shell command (the common
    download/IEX cradle), so the real command shows instead of an opaque blob. A `$VAR`-based b64
    is not a literal -> left untouched (undecodable by design; the value isn't in the string)."""
    m = _B64_PIPE_RE.match(seg.strip())
    if not m:
        return seg
    b64, rest = m.group(1), m.group(2).strip()
    if (rest.split() or [""])[0] not in ("bash", "sh"):
        return seg
    try:
        dec = base64.b64decode(b64).decode("utf-8", "replace").strip()
    except Exception:
        return seg
    return dec or seg


def _clean_for_display(cmd):
    """Turn the raw issued command into the REAL command(s) for the cmdlog: strip the vm.sh/rsh
    transport, decode literal base64 cradles, and drop top-level noise segments (cd/echo banners,
    local state reads). Returns '' when nothing meaningful remains (all transport/noise) so the
    caller skips the entry entirely. Fail-soft: any parse trouble falls back to the unwrapped
    command rather than dropping it."""
    try:
        inner = _unwrap(cmd).strip()
        if _COMPOUND_RE.search(inner):        # a for/while/if/case block is one command -> keep whole
            return inner
        kept = []
        for s in _split_top_level(inner):
            s = _decode_b64_pipe(s)
            if _effective_bin(s) in _NOISE_BINS or _LOCAL_READ_RE.match(s):
                continue
            kept.append(s)
        return "\n".join(kept).strip()
    except Exception:
        return _unwrap(cmd).strip()


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

    # Show the REAL command, not the raw issued line: unwrap the vm.sh/rsh transport, decode
    # literal base64 cradles, drop cd/echo-banner/local-read noise. Empty -> the command was pure
    # transport/navigation, nothing worth a cmdlog entry.
    display = _clean_for_display(cmd)
    if not display.strip():
        return

    import _engagement
    d = _engagement.active_dir()
    if not d:
        return

    bins = _binaries(display.replace("\n", " ; ")) or []
    # first binary that is not a pure wrapper/transport is the meaningful tool
    tool = next((b for b in bins if b not in ("bash", "sh", "sudo", "env", "time")), None) \
        or (bins[0] if bins else "misc")

    pdir = os.path.join(d, "poc", "cmdlog")
    try:
        os.makedirs(pdir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = out if len(out) <= MAX_OUT else out[:MAX_OUT] + "\n...[truncated]"
        entry = "\n## %s\n\n```\n%s\n```\n\n```\n%s\n```\n" % (ts, display, body.rstrip())
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
