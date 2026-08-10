"""vm-rsh.sh: runs a command in the reverse-shell tmux tab and returns clean output.
Mocks the VM_SH bridge with a fake vm.sh so no live VM is touched."""
import os
import subprocess
import textwrap

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RSH = os.path.join(REPO, "scripts", "vm-rsh.sh")


def _fake_vm(tmp_path, pane_lines):
    """A fake /root/vm.sh: no-op on send-keys; prints a canned pane on capture-pane."""
    body = "\n".join(pane_lines)
    fake = tmp_path / "vm.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        "  *capture-pane*) cat <<'PANE'\n" + body + "\nPANE\n"
        "  ;;\n"
        "  *) : ;;\n"
        "esac\n")
    fake.chmod(0o755)
    return str(fake)


def test_vm_rsh_returns_output_between_markers(tmp_path):
    # real ordering: typed line (has both markers) THEN the echo-output markers around the output
    pane = [
        "SH> echo __RSH_START_9f3a__; echo QQ==|base64 -d|bash 2>&1; echo __RSH_END_9f3a__",
        "__RSH_START_9f3a__",
        "uid=0(root) gid=0(root)",
        "flag{winner}",
        "__RSH_END_9f3a__",
        "SH> ",
    ]
    env = dict(os.environ, VM_SH=_fake_vm(tmp_path, pane))
    r = subprocess.run(["bash", RSH, "--timeout", "3", "acme", "id; cat /root/root.txt"],
                       capture_output=True, text=True, env=env, timeout=20)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip("\n") == "uid=0(root) gid=0(root)\nflag{winner}"


def test_vm_rsh_fails_soft_without_end_marker(tmp_path):
    env = dict(os.environ, VM_SH=_fake_vm(tmp_path, ["SH> ", "no markers here"]))
    r = subprocess.run(["bash", RSH, "--timeout", "1", "acme", "id"],
                       capture_output=True, text=True, env=env, timeout=20)
    assert r.returncode != 0
    assert r.stdout.strip() == ""


def _logging_vm(tmp_path, pane_lines, logfile):
    """Like _fake_vm but also appends every invocation's args to logfile, so a test can assert
    WHICH tmux window the send/capture targeted."""
    body = "\n".join(pane_lines)
    fake = tmp_path / "vm.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'printf "%s\\n" "$*" >> ' + logfile + "\n"
        'case "$*" in\n'
        "  *capture-pane*) cat <<'PANE'\n" + body + "\nPANE\n"
        "  ;;\n"
        "  *) : ;;\n"
        "esac\n")
    fake.chmod(0o755)
    return str(fake)


def test_vm_rsh_targets_the_named_window(tmp_path):
    # --win msf routes both send-keys and capture-pane at <session>:msf (the msfconsole window),
    # not the default :shell. This proves the generic window-targeting the interactive-session
    # design relies on; it does NOT assert the base64|bash wrapper runs inside a real msf REPL
    # (msf driving is launch+attach / drop-to-shell by design).
    pane = [
        "msf6 > echo __RSH_START_9f3a__; echo c2Vzc2lvbnMK|base64 -d|bash 2>&1; echo __RSH_END_9f3a__",
        "__RSH_START_9f3a__",
        "meterpreter session 1 opened",
        "__RSH_END_9f3a__",
        "msf6 > ",
    ]
    log = tmp_path / "calls.log"
    env = dict(os.environ, VM_SH=_logging_vm(tmp_path, pane, str(log)))
    r = subprocess.run(["bash", RSH, "--win", "msf", "--timeout", "3", "acme", "sessions -l"],
                       capture_output=True, text=True, env=env, timeout=20)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "meterpreter session 1 opened"
    calls = log.read_text()
    assert "acme:msf" in calls          # window targeting used the --win name
    assert "acme:shell" not in calls    # not the default window
