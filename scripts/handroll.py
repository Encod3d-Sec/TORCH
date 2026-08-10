#!/usr/bin/env python3
"""handroll.py - detect a hand-rolled request loop that should have been a tool.

The reference campaign hand-rolled 341 curl calls against 22 Skill invocations and ran sqlmap
twice. A detector that fired on every curl would be noise (46% of Bash calls touch no network,
and a single authed confirmation fetch is legitimate). So this is two-stage, with thresholds
measured against that corpus:

  1. pre-filter: only a command that touches the network is considered
  2. breadth:    fire only on a loop with >= 4 items, OR >= 3 calls to a locally-defined
                 curl-wrapping shell function, OR >= 5 curl occurrences in one command

Measured on the real corpus this fires on 106/306 network calls (38%) and spares 175 (62%)
legitimate one-offs. classify() returns (fires, tool, reason); the caller withholds and emits the
mapped tool. Shared by campaign.py (Task 16) and the grep-as-read detector (Task 19c).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "skills", "hooks"))
try:
    from tool_telemetry import _binaries  # reuse the exact binary parser telemetry uses
except Exception:                          # hook module name has a hyphen on disk; load by path
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "tool_telemetry", os.path.join(os.path.dirname(HERE), "skills", "hooks", "tool-telemetry.py"))
    _tt = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_tt)
    _binaries = _tt._binaries

NET = re.compile(r"\b(curl|wget|openssl\s+s_client|nc|ncat|/dev/tcp|http|https)\b")

# hand-roll pattern -> the tool that should have run, ordered by measured payoff.
_SIGNATURES = [
    (re.compile(r"\bsqlmap\b"), None),                                    # already the tool
    (re.compile(r"(sleep\(|--data|'\s*or\s*'|union\s+select|%27|benchmark\()", re.I), "sqlmap"),
    (re.compile(r"/(FUZZ|\{\}|\$[a-z]|%s)", re.I), "ffuf"),               # path templating in a loop
    (re.compile(r"\.js(\?|\b)", re.I), "jsluice"),
    (re.compile(r"(subdomain|crt\.sh|wayback|web\.archive)", re.I), "gau"),
    (re.compile(r"(Origin:|Access-Control)", re.I), "ffuf"),
]


def _touches_network(cmd):
    return bool(NET.search(cmd or ""))


def _breadth(cmd):
    """(fires, reason) - the measured breadth thresholds."""
    c = cmd or ""
    # a for/while loop with >= 4 literal items
    m = re.search(r"\bfor\s+\w+\s+in\s+([^\n;]+?);\s*do\b", c)
    if m and len(m.group(1).split()) >= 4:
        return True, "for-loop >= 4 items"
    if re.search(r"\bwhile\s+read\b", c) and "curl" in c:
        return True, "while-read curl loop"
    # >= 5 curl occurrences in one command
    if len(re.findall(r"\bcurl\b", c)) >= 5:
        return True, ">= 5 curl in one command"
    # >= 3 calls to a locally-defined curl-wrapping function: `f(){ ...curl...;}` then f a; f b; f c
    fn = re.search(r"(\w+)\s*\(\)\s*\{[^}]*curl", c)
    if fn:
        name = fn.group(1)
        if len(re.findall(r"\b" + re.escape(name) + r"\b", c)) >= 4:  # def + >=3 calls
            return True, "curl-wrapping function >= 3 calls"
    return False, ""


def classify(cmd):
    """(fires, tool, reason). fires=True means this is a substitutable hand-roll; `tool` is the
    binary that should have run (best-effort, may be None if unknown)."""
    if not _touches_network(cmd):
        return False, None, ""
    fires, reason = _breadth(cmd)
    if not fires:
        return False, None, ""
    tool = None
    for pat, t in _SIGNATURES:
        if pat.search(cmd or ""):
            tool = t
            break
    if tool is None:
        tool = "ffuf"                      # a breadth-y network loop with no other signal = discovery
    return True, tool, reason


def is_grep_as_read(cmd, read_artifacts):
    """Task 19c: True when `cmd` greps an artifact NOT in read_artifacts (grep before reading).
    Grep against an already-read artifact is legitimate (locate inside a large file)."""
    m = re.search(r"\b(grep|rg|Select-String|egrep| grep)\b.*?([\w./-]+\.(?:js|php|py|json|html?|map))",
                  cmd or "", re.I)
    if not m:
        return False, None
    artifact = os.path.basename(m.group(2))
    read = {os.path.basename(a) for a in (read_artifacts or [])}
    return (artifact not in read), artifact


if __name__ == "__main__":
    for c in sys.argv[1:]:
        f, t, r = classify(c)
        print("%s  tool=%s  reason=%s  :: %s" % ("FIRE" if f else "ok  ", t, r, c[:60]))
