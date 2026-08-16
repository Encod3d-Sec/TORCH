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
_SKIP_SEGMENT = {"for", "case", "select"}
# Tokens that merely precede the real binary: body keywords and wrappers. `while`/`until`/
# `if`/`elif` are here (not _SKIP_SEGMENT) because, unlike `for`, their header IS a real
# invoked command (`until grep ...; do`, `if grep ...; then`) -- skipping the keyword must fall
# through to it, not skip the segment.
_SKIP_TOKEN = {"do", "then", "else", "done", "fi", "esac", "{", "}", "!", "while", "until",
               "if", "elif",
               "sudo", "env", "time", "nohup", "xargs", "doas", "command", "exec"}
# Quoted spans, e.g. a grep pattern's `'a|b|kerbrute'` -- blanked (not stripped) before
# splitting/tokenizing so neither an inner `|` nor an inner word is read as real shell syntax.
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
# A shell function DEFINITION header, e.g. `q(){`, `try()`, or `q () {` (space before the
# parens is common) -- the function's own name is never a real tool; checked on the RAW token,
# before the `()` gets stripped below.
_FUNC_DEF = re.compile(r"^[A-Za-z_]\w*\(\)\{?$")
# Same, but findall'd across the whole (blanked) command to also catch a LATER bare call of a
# function defined earlier in the same command, e.g. `q(){ curl ...; }; q "x"` -- `q` must not
# be logged from either the def or the call. Optional whitespace before `()` covers `q ()`.
_FUNC_DEF_ANY = re.compile(r"\b([A-Za-z_]\w*)\s*\(\)")


def _blank_quotes(s):
    """Blank single/double-quoted spans (length-preserving) so shell operators and words
    INSIDE quotes are inert -- e.g. a `grep -qiE 'a|b|kerbrute'` pattern must not be split
    on its `|` alternation, nor have `kerbrute` read as an invoked command."""
    return _QUOTED.sub(lambda m: " " * len(m.group(0)), s)


def _binaries(cmd):
    """Program names invoked by a shell command.

    Without this every shell call logs as `tool: Bash`, so nothing can tell `sqlmap` from a
    hand-rolled `curl` loop -- which is why tool-use was unmeasurable across a whole campaign.

    Leak-safe by construction: only program NAMES are kept, never arguments, which are what
    carry target hosts, paths and tokens.
    """
    blanked = _blank_quotes(cmd or "")
    funcs = set(_FUNC_DEF_ANY.findall(blanked))   # names defined anywhere in this command
    out = []
    for seg in _BIN_SPLIT.split(blanked):
        for tok in seg.split():
            if "=" in tok and not tok.startswith("-"):
                continue                      # env-var prefix: FOO=bar cmd
            if _FUNC_DEF.match(tok):
                continue                      # q(){ ... -- function's own name, not a tool
            b = os.path.basename(tok.strip("()`$'\"&"))
            if (not b or b.startswith("-") or b in _SKIP_SEGMENT
                    or "<" in b or ">" in b):     # a flag or a redirect: no binary follows
                break
            if b in funcs:
                break                          # a bare call of a locally-defined function,
                                                 # e.g. `q "x"` -- what follows is its ARG, not
                                                 # a command, so stop (don't log the arg either)
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
