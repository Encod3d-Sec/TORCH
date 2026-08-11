"""The drift reminder fires when exploit calls pile up with no wiki/skill touch, and re-arms."""
import datetime
import importlib.util
import json
import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    os.environ.setdefault("CLAUDEBRAIN_VAULT", ROOT)
    spec = importlib.util.spec_from_file_location(
        "rc", os.path.join(ROOT, "skills", "hooks", "recon-capture.py"))
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


def _iso(min_ago):
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=min_ago)).isoformat()


def _events(tmp, evs):
    open(os.path.join(tmp, ".events.jsonl"), "w").write(
        "\n".join(json.dumps(e) for e in evs) + "\n")


def _state(tmp):
    open(os.path.join(tmp, "state.md"), "w").write(
        "---\ntype: engagement-state\n---\n\n# State\n\nno STATUS here\n")


EXPLOIT = "curl -s 'http://t/login.php' --data \"u=admin' OR SLEEP(5)-- -\""


def test_fires_past_volume_threshold(tmp_path):
    rc = _load()
    _state(str(tmp_path))
    _events(str(tmp_path), [{"kind": "tool", "tool": "Bash", "bins": ["curl"], "ts": _iso(i)}
                            for i in range(8, 0, -1)])   # 8 curl calls, no wiki/skill
    msg = rc._drift_reminder(str(tmp_path), EXPLOIT)
    assert msg and "REMINDER" in msg


def test_silent_when_recent_skill_touch(tmp_path):
    rc = _load()
    _state(str(tmp_path))
    _events(str(tmp_path), [{"kind": "tool", "tool": "Skill", "skill": "hunt-sqli", "ts": _iso(1)},
                            {"kind": "tool", "tool": "Bash", "bins": ["curl"], "ts": _iso(0)}])
    assert rc._drift_reminder(str(tmp_path), EXPLOIT) is None


def test_silent_below_threshold(tmp_path):
    rc = _load()
    _state(str(tmp_path))
    _events(str(tmp_path), [{"kind": "tool", "tool": "Bash", "bins": ["curl"], "ts": _iso(1)},
                            {"kind": "tool", "tool": "Bash", "bins": ["curl"], "ts": _iso(0)}])
    assert rc._drift_reminder(str(tmp_path), EXPLOIT) is None


def test_arm_fires_once_then_rearms_on_discipline(tmp_path):
    rc = _load()
    _state(str(tmp_path))
    evs = [{"kind": "tool", "tool": "Bash", "bins": ["curl"], "ts": _iso(i)}
           for i in range(8, 0, -1)]
    _events(str(tmp_path), evs)
    assert rc._drift_reminder(str(tmp_path), EXPLOIT)          # fires
    assert rc._drift_reminder(str(tmp_path), EXPLOIT) is None  # same window -> silent
    # a Skill touch advances the discipline ts -> re-arm; then drift again
    evs.append({"kind": "tool", "tool": "Skill", "skill": "hunt-sqli", "ts": _iso(0)})
    evs += [{"kind": "tool", "tool": "Bash", "bins": ["curl"], "ts": _iso(0)} for _ in range(8)]
    _events(str(tmp_path), evs)
    assert rc._drift_reminder(str(tmp_path), EXPLOIT)          # fires again after re-arm


def test_framework_meta_never_fires(tmp_path):
    rc = _load()
    _state(str(tmp_path))
    _events(str(tmp_path), [{"kind": "tool", "tool": "Bash", "bins": ["curl"], "ts": _iso(i)}
                            for i in range(8, 0, -1)])
    assert rc._drift_reminder(str(tmp_path), "python3 scripts/campaign.py next") is None
