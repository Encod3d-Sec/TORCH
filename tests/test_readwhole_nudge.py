import json, os, subprocess
import _engagement  # noqa: F401
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "recon-capture.py")

def _run(cmd, env, tool_out=""):
    p = subprocess.run(["python3", HOOK], input=json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": cmd}, "tool_response": {"stdout": tool_out}}),
        capture_output=True, text=True, env=env, timeout=20)
    return (json.loads(p.stdout) if p.stdout.strip() else {}).get("hookSpecificOutput") or {}

def _foothold(eng):
    (eng / "state.md").write_text("| asset | access |\n|--|--|\n| 10.0.0.5 | foothold |\n")

def test_grep_on_pam_sudo_nudges_once(vault):
    eng = vault / "targets" / "acme"; _foothold(eng)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    o1 = _run("bash /root/vm.sh 'grep pam_ssh /etc/pam.d/sudo'", env)
    assert "read" in o1.get("additionalContext", "").lower() and "whole" in o1["additionalContext"].lower()
    o2 = _run("bash /root/vm.sh 'grep foo /etc/pam.d/sudo'", env)   # once per path
    assert o2 == {} or "whole" not in o2.get("additionalContext", "").lower()

def test_no_nudge_pre_foothold_or_plain_read(vault):
    eng = vault / "targets" / "acme"                 # no foothold recorded
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    assert _run("bash /root/vm.sh 'grep x /etc/pam.d/sudo'", env) == {}
    _foothold(eng)
    assert "whole" not in _run("bash /root/vm.sh 'cat /etc/pam.d/sudo'", env).get("additionalContext", "").lower()
