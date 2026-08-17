"""drift-guard.py: OFF-BOARD exploit calls escalate an advisory streak counter (never deny -
declawed, advisory-only); driver calls reset; on-board / empty-board / pass<5 / no-campaign
all fail open (allow)."""
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
    kc = ("---\ntype: engagement-approach\n---\n\n### 4a\n\n"
          "| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n")
    if board:
        kc += "| r1 | 10.0.0.5 | sqli | sqlmap | [ ] |\n"
    (eng / "Approach.md").write_text(kc)


def test_off_board_escalates_but_never_denies(vault):
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=["ffuf"])           # board wants ffuf; agent free-hands nmap
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    o1 = _run("bash /root/vm.sh 'nmap -sV 10.0.0.5'", env)
    assert "additionalContext" in o1 and "off-board, streak 1" in o1["additionalContext"]
    assert "permissionDecision" not in o1
    o2 = _run("nmap -p- 10.0.0.5", env)
    assert "additionalContext" in o2 and "streak 2" in o2["additionalContext"]
    assert "permissionDecision" not in o2
    o3 = _run("curl http://10.0.0.5/", env)     # 3rd off-board -> still advisory, never deny
    assert "additionalContext" in o3 and "streak 3" in o3["additionalContext"]
    assert "permissionDecision" not in o3
    # the streak counter itself is kept (only the escalation-to-deny is removed)
    assert json.load(open(eng / ".campaign.json"))["off_board_streak"] == 3


def test_selfkill_advisory_on_pkill_shell(vault):
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    for cmd in ("bash /root/vm.sh 'pkill -f bash'", "killall nc", "pkill python3", "pkill -f socat"):
        o = _run(cmd, env)
        assert "SELF-KILL" in (o.get("additionalContext") or ""), cmd


def test_selfkill_advisory_not_on_safe_kill(vault):
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    assert "SELF-KILL" not in (_run("kill 1234", env).get("additionalContext") or "")
    assert "SELF-KILL" not in (_run("killall -9 chrome", env).get("additionalContext") or "")
    assert "SELF-KILL" not in (_run("pkill -f myserviced", env).get("additionalContext") or "")


def test_selfkill_advisory_skips_framework_meta(vault):
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    # grepping the hook's own source during harness dev must not fire it (framework-meta path)
    o = _run("grep -n 'pkill bash' skills/hooks/drift-guard.py", env)
    assert "SELF-KILL" not in (o.get("additionalContext") or "")


def test_driver_call_resets_streak(vault):
    eng = vault / "targets" / "acme"
    _campaign(eng, emitted=[])
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    _run("nmap 10.0.0.5", env)
    _run("nmap 10.0.0.5", env)
    assert json.load(open(eng / ".campaign.json"))["off_board_streak"] == 2
    _run("python3 scripts/campaign.py next", env)
    assert json.load(open(eng / ".campaign.json"))["off_board_streak"] == 0


def test_post_foothold_never_denies(vault):
    """Post-foothold, privesc enum is legit and varied -> the guard ADVISES but never hard-denies
    (blocking privesc enum is the over-fire the review warned about). Now true unconditionally
    (the hook is advisory-only everywhere), but kept as a regression guard on this specific case."""
    eng = vault / "targets" / "acme"
    json.dump({"type": "ctf", "pass": 5, "emitted_bins": []}, open(eng / ".campaign.json", "w"))
    (eng / "Approach.md").write_text(
        "### 4a\n| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n"
        "| r1 | 10.0.0.5 | privesc | linpeas | [ ] |\n")
    (eng / "state.md").write_text("| asset | access |\n|--|--|\n| 10.0.0.5 | foothold |\n")
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    o1 = _run("bash /root/vm.sh 'python3 /tmp/x.py'", env)
    o2 = _run("nmap 10.0.0.5", env)
    o3 = _run("curl http://10.0.0.5/", env)         # 3rd - advisory only, never deny
    assert o3.get("permissionDecision") != "deny"
    assert "additionalContext" in o3


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
    assert "additionalContext" in o and "off-board, streak 1" in o["additionalContext"]
    # a reverse-shell driver is the interactive free-hand zone -> also fires
    o2 = _run("bash scripts/vm-rsh.sh 'id'", env)
    assert "streak 2" in o2.get("additionalContext", "")


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
    (eng / "Approach.md").write_text(
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


def test_confirmed_chain_never_denies(vault):
    """A confirmed primitive (## CONFIRMED CHAIN in state.md) is on-board even before a shell -
    the redeploy case that used to hard-block re-establishing a confirmed LFI. Now true
    unconditionally (the hook is advisory-only everywhere), kept as a regression guard."""
    eng = vault / "targets" / "acme"
    json.dump({"type": "ctf", "pass": 5, "emitted_bins": []}, open(eng / ".campaign.json", "w"))
    (eng / "Approach.md").write_text(
        "### 4a\n| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n"
        "| r1 | 10.0.0.5 | ssrf | sqlmap | [ ] |\n")
    (eng / "state.md").write_text(
        "| asset | access |\n|--|--|\n| 10.0.0.5 | port-open |\n\n## CONFIRMED CHAIN\n1. LFI via redirect\n")
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    _run("bash /root/vm.sh 'python3 /tmp/lfi.py'", env)
    _run("bash /root/vm.sh 'python3 /tmp/lfi.py'", env)
    o3 = _run("nmap 10.0.0.5", env)              # 3rd off-board -> advisory only, never deny
    assert o3.get("permissionDecision") != "deny"
