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


def _staged_vm(tmp_path, early_pane, full_pane):
    """A fake vm.sh reproducing an UNSTABILIZED (echo-on, 80-col) reverse-shell PTY.

    The first two capture-pane calls return early_pane: the shell has echoed the whole
    `echo START; ...; echo END` command line back (markers EMBEDDED, and visually wrapped),
    but the command has not run yet, so there is no output. Later captures return full_pane
    with the executed markers alone on their own lines around the real output. A poll that
    breaks on the embedded END, or an extractor that grabs the embedded markers, gets it wrong.
    """
    counter = tmp_path / "capn"
    counter.write_text("0")
    early = "\n".join(early_pane)
    full = "\n".join(full_pane)
    fake = tmp_path / "vm.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        "  *capture-pane*)\n"
        "    n=$(cat '" + str(counter) + "'); echo $((n+1)) > '" + str(counter) + "'\n"
        "    if [ \"$n\" -lt 2 ]; then cat <<'EARLY'\n" + early + "\nEARLY\n"
        "    else cat <<'FULL'\n" + full + "\nFULL\n"
        "    fi ;;\n"
        "  *) : ;;\n"
        "esac\n")
    fake.chmod(0o755)
    return str(fake)


def test_vm_rsh_unstabilized_pty_echo_and_wrap(tmp_path):
    # echo-on PTY: the echoed command line carries the START/END markers EMBEDDED, and a
    # narrow terminal wraps it across two physical lines. The embedded END must NOT end the
    # poll early, and the embedded markers must NOT be mistaken for the output boundaries.
    echoed = [
        "SH> echo __RSH_START_9f3a__; echo aWQ7IGNhdCAvcm9vdC9yb290LnR4dA==| base",
        "64 -d | bash 2>&1; echo __RSH_END_9f3a__",
    ]
    full = echoed + [
        "__RSH_START_9f3a__",
        "uid=0(root) gid=0(root)",
        "flag{root}",
        "__RSH_END_9f3a__",
        "SH> ",
    ]
    env = dict(os.environ, VM_SH=_staged_vm(tmp_path, echoed, full))
    r = subprocess.run(["bash", RSH, "--timeout", "5", "acme", "id; cat /root/root.txt"],
                       capture_output=True, text=True, env=env, timeout=25)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip("\n") == "uid=0(root) gid=0(root)\nflag{root}"


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
