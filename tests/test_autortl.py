"""The time-based 5-min auto-rtl is REMOVED from drift-guard.py (declawed to advisory-only, no
time-based nagging). RTL reflex now lives in campaign.py `_tells_stop` (tests/test_tells.py) +
recon-capture vector-doubt nudges."""
import json, os, time
import _engagement  # noqa: F401
from hookrunner import run_hook
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "drift-guard.py")

def _run(cmd, env=None):
    return run_hook("drift-guard", command=cmd)

def _ctf(eng):
    json.dump({"type": "ctf", "pass": 5, "emitted_bins": ["sqlmap"]}, open(eng / ".campaign.json", "w"))
    (eng / "Approach.md").write_text("### 4a\n| id | asset | vuln class | tool | status |\n|--|--|--|--|--|\n| r1 | 10.0.0.5 | sqli | sqlmap | [ ] |\n")

def test_no_time_based_autortl_even_after_long_drift(vault):
    eng = vault / "targets" / "acme"; _ctf(eng)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    dp = eng / ".last-direction"; dp.write_text("")
    old = time.time() - 360; os.utime(dp, (old, old))      # 6 min since direction
    o1 = _run("bash /root/vm.sh 'curl http://10.0.0.5/'", env)
    assert "spinning" not in o1.get("additionalContext", "").lower()
    assert "redteamlead" not in o1.get("additionalContext", "").lower()
    o2 = _run("bash /root/vm.sh 'curl http://10.0.0.5/'", env)
    assert "spinning" not in o2.get("additionalContext", "").lower()
    assert "redteamlead" not in o2.get("additionalContext", "").lower()

def test_autortl_silent_when_recent_direction(vault):
    eng = vault / "targets" / "acme"; _ctf(eng)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    (eng / ".last-direction").write_text("")               # just now
    o = _run("bash /root/vm.sh 'curl http://10.0.0.5/'", env)
    assert "redteamlead" not in o.get("additionalContext", "").lower()
