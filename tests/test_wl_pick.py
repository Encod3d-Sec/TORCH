# tests/test_wl_pick.py
"""wl-pick.sh deterministic selector. Runs an ISOLATED COPY from tmp_path (like
test_wl_add.py) with a stub seclists base + stub map, so the contract is exercised
without depending on the host's real seclists tree."""
import json
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "wl-pick.sh")


@pytest.fixture
def pick(tmp_path):
    """Isolated wl-pick.sh + a stub map pointing at a fake seclists base whose
    referenced files all exist. Returns run(*args) -> CompletedProcess."""
    shutil.copy(SCRIPT, tmp_path / "wl-pick.sh")
    base = tmp_path / "seclists"
    (base / "Discovery" / "Web-Content" / "CMS").mkdir(parents=True)
    for rel in ("Discovery/Web-Content/common.txt",
                "Discovery/Web-Content/raft-large-directories.txt",
                "Discovery/Web-Content/CMS/wordpress.fuzz.txt"):
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text("x\n")
    wl = tmp_path / "wordlists"
    wl.mkdir()
    (wl / "harness-paths.txt").write_text("internal\n")
    mp = {
        "seclists_bases": [str(base)],
        "surfaces": {"content": ["Discovery/Web-Content/common.txt",
                                  "Discovery/Web-Content/raft-large-directories.txt"]},
        "fingerprints": {"wordpress": ["Discovery/Web-Content/CMS/wordpress.fuzz.txt"]},
        "harness_first": {"content": "wordlists/harness-paths.txt"},
        "profiles": {"ctf": {"threads": 60, "rate": 0, "recursion": 2, "jitter": "off"},
                     "bb": {"threads": 15, "rate": 10, "recursion": 1, "jitter": "on"}},
    }
    (tmp_path / "wordlist-map.json").write_text(json.dumps(mp))

    def run(*args):
        return subprocess.run(["bash", str(tmp_path / "wl-pick.sh"), *args],
                              capture_output=True, text=True)
    return run, str(base)


def test_usage_on_no_surface(pick):
    run, _ = pick
    p = run()
    assert p.returncode != 0
    assert "usage" in p.stderr.lower()


def test_emits_base_and_flags(pick):
    run, base = pick
    p = run("content", "", "bb")
    assert p.returncode == 0, p.stderr
    assert ("# seclists: " + base) in p.stdout
    assert "threads=15" in p.stdout and "rate=10" in p.stdout and "jitter=on" in p.stdout
    assert "profile=bb" in p.stdout


def test_harness_first_then_size_order(pick):
    run, _ = pick
    p = run("content", "", "ctf")
    paths = [l for l in p.stdout.splitlines() if not l.startswith("#")]
    assert paths[0].endswith("harness-paths.txt")
    assert "common.txt" in "\n".join(paths)
    assert paths.index([x for x in paths if x.endswith("common.txt")][0]) < \
           paths.index([x for x in paths if x.endswith("raft-large-directories.txt")][0])


def test_unknown_surface_shows_usage(pick):
    run, _ = pick
    p = run("bogus")
    assert p.returncode != 0
    assert "usage" in p.stderr.lower()


def test_fingerprint_jumps_to_t3(pick):
    run, _ = pick
    p = run("content", "wordpress", "ctf")
    paths = [l for l in p.stdout.splitlines() if not l.startswith("#")]
    # the wordpress list appears before the generic content lists (T3 jump)
    wp = [i for i, x in enumerate(paths) if x.endswith("wordpress.fuzz.txt")][0]
    common = [i for i, x in enumerate(paths) if x.endswith("common.txt")][0]
    assert wp < common
