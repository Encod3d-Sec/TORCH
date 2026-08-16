"""tool-telemetry.py `_binaries`: the shell-command binary-name extractor that feeds both
capture-poc.py's cmdlog/<tool>.md grouping and scripts/eval_metrics.py's tool-call counts. Must be
quote-aware -- a `|` inside a quoted grep/regex pattern must not split the command, and a word
inside quotes must never be read as an invoked binary. Must also not log a shell function's own
NAME (`q(){ ...; }`) as a binary. Pure-function tests, no I/O."""
import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "tool-telemetry.py")


def _load():
    spec = importlib.util.spec_from_file_location("tool_telemetry", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_binaries = _load()._binaries


def test_quoted_grep_alternation_not_split():
    out = _binaries('grep -qiE "user_pass|Auxiliary module|user_login" f')
    assert out == ["grep"]
    assert "Auxiliary" not in out
    assert "module" not in out
    assert "user_login" not in out


def test_quoted_alternation_in_until_loop():
    out = _binaries(
        'until grep -qiE "a|session .* opened" /tmp/x; do sleep 5; done; sed -i s/a/b/ f')
    assert "grep" in out
    assert "sleep" in out
    assert "sed" in out
    assert "session" not in out
    assert "opened" not in out
    assert "a" not in out


def test_shell_function_name_not_logged():
    out = _binaries('q(){ curl -s http://t; }; q "x"')
    assert "q" not in out


def test_shell_function_name_not_logged_with_loop_call():
    out = _binaries('try(){ curl http://t; }; for p in a b; do try admin "$p"; done')
    assert "try" not in out


def test_space_separated_func_def_not_logged():
    out = _binaries('q () { curl -s http://t; }; q "x"')
    assert "q" not in out


def test_if_header_command_captured_not_keyword():
    out = _binaries('if grep -q x f; then echo yes; fi')
    assert "grep" in out
    assert "echo" in out
    assert "if" not in out


def test_elif_header_command_captured_not_keyword():
    out = _binaries('elif grep -q x f; then echo yes; fi')
    assert "grep" in out
    assert "elif" not in out


def test_pipeline_sink_still_kept():
    assert "nc" in _binaries("echo X | base64 -d | nc h p")


def test_env_var_prefix_stripped():
    assert _binaries("FOO=bar sqlmap -u http://t") == ["sqlmap"]


def test_plain_command_unchanged():
    assert _binaries("nmap -sCV 10.0.0.1") == ["nmap"]


def test_none_fails_open():
    assert _binaries(None) == []


def test_empty_fails_open():
    assert _binaries("") == []
