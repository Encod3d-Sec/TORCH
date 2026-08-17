"""RCE-landing detector for the reverse-shell/stabilize reflex.

`_is_rce_landing` gates a fire-once nudge that pushes the operator from hand-poked one-liner
web-RCE to a proper stabilized reverse shell (the recurring drift: RCE achieved, but no rshell
and no shell stabilization until the operator asks). It must fire on a service-account `id`
and NOT on a reflected attacker-root `id` (the false-RCE trap).

The stabilize nudge should NOT fire when the command is an existing interactive session
(SSH/sshpass/evil-winrm) -- only for raw web-RCE/unstabilized nc shells.
"""
import importlib.util
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    os.environ.setdefault("CLAUDEBRAIN_VAULT", ROOT)
    spec = importlib.util.spec_from_file_location(
        "rc", os.path.join(ROOT, "skills", "hooks", "recon-capture.py"))
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


FIRES = [
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)",
    "www-data@box:/var/www$ id\nuid=33(www-data) gid=33(www-data)",
]

NO_FIRE = [
    "",
    "some normal recon output with no id",
    "uid=0(root) gid=0(root) groups=0(root)",          # reflected attacker-root = false-RCE trap
    "PID   USER   %CPU  COMMAND",                        # pspy-style, no id line
]


def test_service_account_id_fires():
    rc = _load()
    for txt in FIRES:
        assert rc._is_rce_landing(txt), f"should detect RCE landing: {txt!r}"


def test_no_id_or_attacker_root_does_not_fire():
    rc = _load()
    for txt in NO_FIRE:
        assert not rc._is_rce_landing(txt), f"should NOT fire: {txt!r}"


def _run_hook(cmd, output, engagement_dir, vault_path):
    """Run the hook with a PostToolUse payload and return the blocks output."""
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": cmd},
        "tool_response": output,
    }
    old_stdin = sys.stdin
    old_cwd = os.getcwd()
    old_vault = os.environ.get("CLAUDEBRAIN_VAULT")
    try:
        # Set the vault path BEFORE loading
        os.environ["CLAUDEBRAIN_VAULT"] = vault_path

        # Ensure the engagement dir is "active" (most recent)
        os.utime(engagement_dir, None)
        os.chdir(os.path.dirname(engagement_dir))
        sys.stdin = _MockStdin(json.dumps(payload))

        # Load the hook with the correct vault
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "rc_hook", os.path.join(ROOT, "skills", "hooks", "recon-capture.py"))
        rc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rc)

        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = _MockStdout()
        try:
            rc.main()
            output_text = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        # Parse the JSON output to extract additionalContext
        if output_text:
            try:
                result = json.loads(output_text)
                return result.get("hookSpecificOutput", {}).get("additionalContext", "")
            except json.JSONDecodeError:
                return ""
        return ""
    finally:
        sys.stdin = old_stdin
        os.chdir(old_cwd)
        if old_vault is not None:
            os.environ["CLAUDEBRAIN_VAULT"] = old_vault
        elif "CLAUDEBRAIN_VAULT" in os.environ:
            del os.environ["CLAUDEBRAIN_VAULT"]


class _MockStdin:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self):
        return self.data

    def readline(self):
        lines = self.data.split('\n')
        if self.pos < len(lines):
            line = lines[self.pos]
            self.pos += 1
            return line + '\n'
        return ''


class _MockStdout:
    def __init__(self):
        self.buf = []

    def write(self, s):
        self.buf.append(s)

    def getvalue(self):
        return ''.join(self.buf)


def test_raw_web_rce_fires_stabilize_nudge():
    """A curl/webshell command with id output SHOULD fire the stabilize nudge."""
    with tempfile.TemporaryDirectory() as tmpdir:
        eng_dir = os.path.join(tmpdir, "test_eng")
        os.makedirs(eng_dir)

        # Create minimal state.md so the engagement is recognized
        state_file = os.path.join(eng_dir, "state.md")
        with open(state_file, "w") as f:
            f.write("# Test engagement\n")

        # Create targets dir structure
        targets_dir = os.path.join(tmpdir, "targets")
        os.makedirs(targets_dir)

        # Move engagement under targets
        os.rename(eng_dir, os.path.join(targets_dir, "test_eng"))
        eng_dir = os.path.join(targets_dir, "test_eng")

        cmd = "curl -s http://target/shell.php?cmd=id"
        output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

        result = _run_hook(cmd, output, eng_dir, tmpdir)

        assert "RCE / code-exec confirmed" in result, f"Stabilize nudge should fire for web-RCE, got: {result!r}"
        assert "PREFER msfconsole" in result, f"Should mention msfconsole handler, got: {result!r}"


def test_ssh_command_does_not_fire_stabilize_nudge():
    """An SSH command with id output should NOT fire the stabilize nudge (false-fire fix)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        eng_dir = os.path.join(tmpdir, "test_eng2")
        os.makedirs(eng_dir)

        # Create minimal state.md
        state_file = os.path.join(eng_dir, "state.md")
        with open(state_file, "w") as f:
            f.write("# Test engagement\n")

        # Create targets dir structure
        targets_dir = os.path.join(tmpdir, "targets")
        os.makedirs(targets_dir)

        # Move engagement under targets
        os.rename(eng_dir, os.path.join(targets_dir, "test_eng2"))
        eng_dir = os.path.join(targets_dir, "test_eng2")

        cmd = "ssh user@target id"
        output = "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)"

        result = _run_hook(cmd, output, eng_dir, tmpdir)

        assert "RCE / code-exec confirmed" not in result, f"Stabilize nudge should NOT fire for SSH sessions, got: {result!r}"


def test_sshpass_command_does_not_fire_stabilize_nudge():
    """A sshpass command with id output should NOT fire the stabilize nudge."""
    with tempfile.TemporaryDirectory() as tmpdir:
        eng_dir = os.path.join(tmpdir, "test_eng3")
        os.makedirs(eng_dir)

        state_file = os.path.join(eng_dir, "state.md")
        with open(state_file, "w") as f:
            f.write("# Test engagement\n")

        targets_dir = os.path.join(tmpdir, "targets")
        os.makedirs(targets_dir)

        os.rename(eng_dir, os.path.join(targets_dir, "test_eng3"))
        eng_dir = os.path.join(targets_dir, "test_eng3")

        cmd = "sshpass -p password ssh user@target id"
        output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

        result = _run_hook(cmd, output, eng_dir, tmpdir)

        assert "RCE / code-exec confirmed" not in result, f"Stabilize nudge should NOT fire for sshpass, got: {result!r}"


def test_stabilize_nudge_contains_no_pwncat():
    """The stabilize nudge should not mention pwncat."""
    with tempfile.TemporaryDirectory() as tmpdir:
        eng_dir = os.path.join(tmpdir, "test_eng4")
        os.makedirs(eng_dir)

        state_file = os.path.join(eng_dir, "state.md")
        with open(state_file, "w") as f:
            f.write("# Test engagement\n")

        targets_dir = os.path.join(tmpdir, "targets")
        os.makedirs(targets_dir)

        os.rename(eng_dir, os.path.join(targets_dir, "test_eng4"))
        eng_dir = os.path.join(targets_dir, "test_eng4")

        cmd = "curl -s http://target/shell.php?cmd=id"
        output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

        result = _run_hook(cmd, output, eng_dir, tmpdir)

        assert "pwncat" not in result.lower(), f"Nudge should NOT contain pwncat, got: {result!r}"
