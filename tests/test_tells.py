import datetime, json, os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
CAMPAIGN = os.path.join(VAULT, "scripts", "campaign.py")
FIX = os.path.join(HERE, "fixtures", "campaign")

def _mk(tmp_path):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    open(d / "state.md", "w").write(
        "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n\n"
        "| asset | ip | os | services | access | owned | notes |\n"
        "|-------|----|----|----------|--------|-------|-------|\n"
        "| 10.10.1.1 | 10.10.1.1 | Linux | http | port-open | no | web |\n")
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "init", "--type", "ctf"],
                   capture_output=True, text=True)
    return d

def _next(d):
    return subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "next"],
                          capture_output=True, text=True).stdout

def test_crack_miss_two_prints_stop(tmp_path):
    d = _mk(tmp_path)
    (d / ".crack-miss-count").write_text("2")
    out = _next(d)
    assert "STOP" in out and "redteamlead" in out and "wordlist" in out

def test_crack_miss_one_no_stop(tmp_path):
    d = _mk(tmp_path)
    (d / ".crack-miss-count").write_text("1")
    out = _next(d)
    assert "STOP:" not in out

def test_starve_marker_prints_stop(tmp_path):
    d = _mk(tmp_path)
    (d / ".vector-doubt-starve").write_text("")
    out = _next(d)
    assert "STOP" in out and "redteamlead" in out and "starv" in out.lower()

def test_redteamlead_after_tell_clears_stop(tmp_path):
    d = _mk(tmp_path)
    (d / ".crack-miss-count").write_text("2")
    # a redteamlead Skill event dated AFTER the marker mtime clears the STOP
    mtime = os.path.getmtime(d / ".crack-miss-count")
    after = datetime.datetime.fromtimestamp(mtime + 5, tz=datetime.timezone.utc).isoformat()
    with open(d / ".events.jsonl", "a") as f:
        f.write(json.dumps({"kind": "tool", "tool": "Skill", "skill": "redteamlead",
                            "ts": after}) + "\n")
    out = _next(d)
    assert "STOP:" not in out

def test_redteamlead_before_tell_keeps_stop(tmp_path):
    d = _mk(tmp_path)
    (d / ".crack-miss-count").write_text("2")
    # an OLD redteamlead event (before the marker) does not clear the STOP
    mtime = os.path.getmtime(d / ".crack-miss-count")
    before = datetime.datetime.fromtimestamp(mtime - 5, tz=datetime.timezone.utc).isoformat()
    with open(d / ".events.jsonl", "a") as f:
        f.write(json.dumps({"kind": "tool", "tool": "Skill", "skill": "redteamlead",
                            "ts": before}) + "\n")
    out = _next(d)
    assert "STOP" in out and "redteamlead" in out and "wordlist" in out
