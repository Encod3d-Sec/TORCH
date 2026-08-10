"""drift-guard.py: OFF-BOARD exploit calls escalate warn->warn->deny; driver calls reset;
on-board / empty-board / pass<5 / no-campaign all fail open (allow)."""
import json
import os
import subprocess

import _engagement  # noqa: F401  (self-locate VAULT before any vault fixture, see test_hooks.py)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "drift-guard.py")


def _run(cmd, env):
    p = subprocess.run(["python3", HOOK], input=json.dumps({
        "tool_name": "Bash", "tool_input": {"command": cmd}}),
        capture_output=True, text=True, env=env, timeout=20)
    out = json.loads(p.stdout) if p.stdout.strip() else {}
    return (out.get("hookSpecificOutput") or {})


def _campaign(eng, pass_=5, emitted=None, board=True):
    json.dump({"type": "ctf", "pass": pass_, "emitted_bins": emitted or []},
              open(eng / ".campaign.json", "w"))
    kc = ("---\ntype: engagement-killchain\n---\n\n### 4a\n\n"
          "| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n")
    if board:
        kc += "| r1 | 10.0.0.5 | sqli | sqlmap | [ ] |\n"
    (eng / "killchain.md").write_text(kc)


def test_off_board_escalates_then_denies(vault):
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=["ffuf"])           # board wants ffuf; agent free-hands nmap
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    o1 = _run("bash /root/vm.sh 'nmap -sV 10.0.0.5'", env)
    assert "additionalContext" in o1 and "off-board, 1/3" in o1["additionalContext"]
    o2 = _run("nmap -p- 10.0.0.5", env)
    assert "additionalContext" in o2 and "2/3" in o2["additionalContext"]
    o3 = _run("curl http://10.0.0.5/", env)     # 3rd off-board -> DENY
    assert o3.get("permissionDecision") == "deny"
    assert json.load(open(eng / ".campaign.json"))["off_board_streak"] == 3


def test_driver_call_resets_streak(vault):
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=[])
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    _run("nmap 10.0.0.5", env)
    _run("nmap 10.0.0.5", env)
    assert json.load(open(eng / ".campaign.json"))["off_board_streak"] == 2
    _run("python3 scripts/campaign.py next", env)
    assert json.load(open(eng / ".campaign.json"))["off_board_streak"] == 0


def test_framework_meta_not_drift(vault):
    """Dev/framework commands (pytest, editing scripts) must NOT fire even while an engagement is
    active at pass>=5 - observed misfiring on pytest during harness development."""
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=[])
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    for c in ["python3 -m pytest tests/test_campaign.py -q",
              "python3 scripts/campaign-doctor.py",
              "git add scripts/ && git commit -m x",
              "python3 scripts/playbook-tools-backfill.py --write"]:
        assert _run(c, env) == {}, "framework-meta fired: " + c


def test_scripted_exploit_over_vmsh_fires(vault):
    """THE post-mortem hole: a hand-written python exploit run over the vm.sh wrapper touches no
    NET_BIN, so the original guard missed it and the agent free-handed the box. Must fire now."""
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=["sqlmap"])
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    o = _run("bash /root/vm.sh 'python3 /tmp/typo3_rce.py --target 10.0.0.5'", env)
    assert "additionalContext" in o and "off-board, 1/3" in o["additionalContext"]
    # a reverse-shell driver is the interactive free-hand zone -> also fires
    o2 = _run("bash scripts/vm-rsh.sh 'id'", env)
    assert "2/3" in o2.get("additionalContext", "")


def test_vmsh_transport_not_falsely_matched(vault):
    """The `bash /root/vm.sh '...'` transport is how EVERY VM command runs; a benign inner command
    must NOT be read as an interpreter exploit (no `bash \\S+\\.sh` collision with vm.sh)."""
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=[])
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    assert _run("bash /root/vm.sh 'ls -la /var/www'", env) == {}
    assert _run("bash /root/vm.sh 'cat /etc/passwd'", env) == {}


def test_open_row_tool_is_on_board(vault):
    """A binary that is the tool of a currently-OPEN row is on-board even if not in emitted_bins
    (so the whitelist is board-derived, not the eroding global emitted set)."""
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=[])                      # board's open row wants sqlmap; emitted empty
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    assert _run("bash /root/vm.sh 'sqlmap -u http://10.0.0.5/?id=1 --batch'", env) == {}


def test_end_of_board_allows(vault):
    """All rows [x] -> no OPEN rows -> nothing to serve -> allow (was falsely denying verification
    probes)."""
    eng = vault / "targets" / "acme"
    json.dump({"type": "ctf", "pass": 5, "emitted_bins": []}, open(eng / ".campaign.json", "w"))
    (eng / "killchain.md").write_text(
        "### 4a\n| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n"
        "| r1 | 10.0.0.5 | sqli | sqlmap | [x] |\n| r2 | 10.0.0.5 | rce | nuclei | [!] |\n")
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    assert _run("nmap 10.0.0.5", env) == {}


def test_on_board_and_failopen_allow(vault):
    eng = vault / "targets" / "acme"
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    # emitted binary -> on-board -> allow (no output)
    _campaign(eng, emitted=["nmap"])
    assert _run("nmap -sV 10.0.0.5", env) == {}
    # empty board -> nothing to serve -> allow
    _campaign(eng, emitted=[], board=False)
    assert _run("nmap 10.0.0.5", env) == {}
    # pass < 5 (pre-board) -> allow
    _campaign(eng, pass_=2, emitted=[])
    assert _run("nmap 10.0.0.5", env) == {}
    # non-exploit command -> ignore
    _campaign(eng, emitted=[])
    assert _run("cat /etc/passwd", env) == {}
    # no .campaign.json -> allow
    os.remove(eng / ".campaign.json")
    assert _run("nmap 10.0.0.5", env) == {}
