import json, os, time, subprocess
import _engagement  # noqa: F401
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "drift-guard.py")

def _run(cmd, env):
    p = subprocess.run(["python3", HOOK], input=json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": cmd}}),
        capture_output=True, text=True, env=env, timeout=20)
    return (json.loads(p.stdout) if p.stdout.strip() else {}).get("hookSpecificOutput") or {}

def _ctf(eng):
    json.dump({"type": "ctf", "pass": 5, "emitted_bins": ["ffuf", "feroxbuster"]},
              open(eng / ".campaign.json", "w"))
    (eng / "Approach.md").write_text(
        "### 4a\n| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n"
        "| r1 | 10.0.0.5 | content-discovery | ffuf | [ ] |\n")

def test_second_scanner_denied_on_ctf(vault):
    eng = vault / "targets" / "acme"; _ctf(eng)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    assert _run("bash scripts/vm-scan.sh --win a thm t 'ffuf -w x -u http://10.0.0.5/FUZZ'", env).get("permissionDecision") != "deny"
    o2 = _run("bash scripts/vm-scan.sh --win b thm t 'feroxbuster -u http://10.0.0.5/'", env)
    assert o2.get("permissionDecision") == "deny" and "already running" in o2["permissionDecisionReason"]

def test_second_scanner_allowed_after_window(vault):
    eng = vault / "targets" / "acme"; _ctf(eng)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    _run("bash /root/vm.sh 'ffuf -u http://10.0.0.5/FUZZ'", env)
    # backdate the recorded launch to >3 min ago
    p = eng / ".scan-launches.jsonl"
    lines = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    lines[-1]["ts"] = time.time() - 200
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    assert _run("bash /root/vm.sh 'feroxbuster -u http://10.0.0.5/'", env).get("permissionDecision") != "deny"

def test_scanner_cap_not_on_non_ctf(vault):
    eng = vault / "targets" / "acme"
    json.dump({"type": "pentest", "pass": 5, "emitted_bins": ["ffuf"]}, open(eng / ".campaign.json", "w"))
    (eng / "Approach.md").write_text("### 4a\n| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n| r1 | 10.0.0.5 | content-discovery | ffuf | [ ] |\n")
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    _run("bash /root/vm.sh 'ffuf -u http://10.0.0.5/FUZZ'", env)
    assert _run("bash /root/vm.sh 'feroxbuster -u http://10.0.0.5/'", env).get("permissionDecision") != "deny"
