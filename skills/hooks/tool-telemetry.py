#!/usr/bin/env python3
"""PostToolUse(*) hook: per-box telemetry capture.

For every tool call, appends one event to the active engagement's `.events.jsonl` (the tool
name, plus the skill name for `Skill` calls so skill invocations are countable by name), stamps
`started_at` on the very first event, and records the session `transcript_path` (so token usage
can be attributed to this box later, even across several sessions).

Fail-open and silent: emits nothing, never blocks (PostToolUse can't block a completed call
anyway), no active engagement -> no-op. All aggregation is done offline by scripts/eval_metrics.py.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Shell separators that start a new command.
_BIN_SPLIT = re.compile(r"[|;\n]|&&|\|\|")
# Compound-header keywords: `for p in a b c` names no binary at all -- skip the whole segment,
# or the loop VARIABLE gets logged as a tool (the loop body is a separate segment and is kept).
_SKIP_SEGMENT = {"for", "while", "until", "if", "elif", "case", "select"}
# Tokens that merely precede the real binary: body keywords and wrappers.
_SKIP_TOKEN = {"do", "then", "else", "done", "fi", "esac", "{", "}", "!",
               "sudo", "env", "time", "nohup", "xargs", "doas", "command", "exec"}


def _binaries(cmd):
    """Program names invoked by a shell command.

    Without this every shell call logs as `tool: Bash`, so nothing can tell `sqlmap` from a
    hand-rolled `curl` loop -- which is why tool-use was unmeasurable across a whole campaign.

    Leak-safe by construction: only program NAMES are kept, never arguments, which are what
    carry target hosts, paths and tokens.
    """
    out = []
    for seg in _BIN_SPLIT.split(cmd or ""):
        for tok in seg.split():
            if "=" in tok and not tok.startswith("-"):
                continue                      # env-var prefix: FOO=bar cmd
            b = os.path.basename(tok.strip("()`$'\"&"))
            if (not b or b.startswith("-") or b in _SKIP_SEGMENT
                    or "<" in b or ">" in b):     # a flag or a redirect: no binary follows
                break
            if b in _SKIP_TOKEN:
                continue                      # do/then/sudo/env <real-binary>
            if b not in out:
                out.append(b)
            break
    return out[:8]


def main():
    try:
        data = json.loads(sys.stdin.read())
    except Exception:
        return
    tool = data.get("tool_name")
    if not tool:
        return
    try:
        import _telemetry
        import _engagement
    except Exception:
        return
    d = _engagement.active_dir()
    if not d:
        return
    ti = data.get("tool_input") or {}
    skill = ti.get("skill") if tool == "Skill" else None
    # Record a wiki-page READ (path relative to wiki/, e.g. "techniques/web/ssrf.md"). This is
    # the only way a hook can tell "the mapped page was actually opened" from "worked from
    # memory" -- Skill calls are already countable by name, reads were not. Leak-safe by
    # construction: only paths INSIDE the vault's own wiki/ are recorded, never a target path.
    wiki = None
    if tool in ("Read", "Grep"):
        try:
            p = os.path.abspath(str(ti.get("file_path") or ti.get("path") or ""))
            root = os.path.join(_engagement.VAULT, "wiki") + os.sep
            if p.startswith(root):
                wiki = p[len(root):]
        except Exception:
            wiki = None
    bins = _binaries(ti.get("command")) if tool == "Bash" else None
    _telemetry.log_event("tool", d=d, tool=tool, skill=skill, wiki=wiki, bins=bins or None)
    _telemetry.stamp_once("started_at", _telemetry.now_iso(), d=d)
    _telemetry.add_transcript(data.get("transcript_path"), d=d)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
