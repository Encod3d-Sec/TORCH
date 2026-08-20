"""In-process runner for the PreToolUse/PostToolUse hooks.

The hooks are stdin->stdout filters (`main()` reads a JSON tool payload from stdin and prints a
JSON `hookSpecificOutput` block, or nothing). Historically every hook test shelled out via
`subprocess.run(["python3", HOOK], ...)` -- correct but slow: ~1300 cold Python starts made the
suite a 7-minute run. This runner imports each hook ONCE and calls `main()` in-process with stdin
patched, cutting the per-call cost to a function call.

Vault redirection is handled by the `vault` fixture (it monkeypatches `_engagement.VAULT/TARGETS`),
so a hook called here while that fixture is active resolves to the tmp vault with no env needed.

Fidelity: the only thing the `if __name__ == "__main__"` wrapper adds over `main()` is `sys.exit(0)`
and a top-level try/except -- both irrelevant to the assertion (a hook that raised would fail the
test loudly, which is what we want). So calling `main()` is behaviourally equivalent for testing.
"""
import importlib.util
import io
import json
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS = os.path.join(_REPO, "skills", "hooks")
_cache = {}


def load_hook(name):
    """Import a hyphen-named hook module once (e.g. 'drift-guard'); cached across calls."""
    if name not in _cache:
        path = os.path.join(_HOOKS, name + ".py")
        spec = importlib.util.spec_from_file_location("hook_" + name.replace("-", "_"), path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _cache[name] = mod
    return _cache[name]


def run_hook(name, tool_name="Bash", command="", tool_response=None, extra=None):
    """Call <name>'s main() in-process with a synthetic tool payload; return the parsed
    hookSpecificOutput dict (or {} when the hook prints nothing). `command` fills
    tool_input.command; `tool_response` fills tool_response; `extra` merges top-level keys."""
    payload = {"tool_name": tool_name, "tool_input": {"command": command}}
    if tool_response is not None:
        payload["tool_response"] = tool_response
    if extra:
        payload.update(extra)
    mod = load_hook(name)
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(json.dumps(payload)), io.StringIO()
    try:
        mod.main()
        txt = sys.stdout.getvalue().strip()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    if not txt:
        return {}
    try:
        return json.loads(txt).get("hookSpecificOutput") or {}
    except Exception:
        return {}


class _Result:
    """CompletedProcess-like shim so `.stdout` call sites convert with no other change."""
    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def run_payload(name, payload):
    """Feed a FULL payload dict to <name>'s main() in-process; return a CompletedProcess-like object
    whose .stdout is the raw printed text. Drop-in for `subprocess.run([...], input=json.dumps(
    payload)).stdout` call sites (e.g. test_hooks.py's central run_hook helper). `name` may include
    a trailing '.py'."""
    mod = load_hook(name[:-3] if name.endswith(".py") else name)
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(json.dumps(payload)), io.StringIO()
    try:
        mod.main()
        txt = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    return _Result(txt)
