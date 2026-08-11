"""vm-stabilize.sh emits a clean, bridge-safe PTY-upgrade sequence.

Guards the two ceilings that matter: the default `script` upgrade must contain no
shell-quoting hazards, and the --python fallback must be base64-wrapped (its quotes would
otherwise not survive the vm.sh -> tmux send-keys bridge).
"""
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SH = os.path.join(ROOT, "scripts", "vm-stabilize.sh")


def _run(*args):
    return subprocess.run(["bash", SH, "--dry-run", *args, "myeng"],
                          capture_output=True, text=True, timeout=20).stdout


def test_default_script_upgrade_and_size():
    out = _run("--win", "shell")
    assert "script -qc /bin/bash /dev/null" in out
    assert "TERM=xterm-256color" in out
    assert "stty rows 50 cols 220" in out
    # the default upgrade must carry no quote chars that would break the bridge send
    assert '"' not in out and "\\" not in out


def test_python_fallback_is_base64_wrapped():
    out = _run("--python")
    assert "base64 -d | python3" in out
    # the raw pty.spawn string must NOT appear un-encoded (that is the quoting hazard we avoid)
    assert 'pty.spawn("/bin/bash")' not in out
