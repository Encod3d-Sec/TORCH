"""wordlist-map.json is the data behind wl-pick.sh: valid JSON, required keys,
size-ordered surface lists, and every referenced seclists path must exist under
a resolved base (so the selector never emits a dead path)."""
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAP = os.path.join(REPO, "scripts", "wordlist-map.json")


def _map():
    with open(MAP, encoding="utf-8") as fh:
        return json.load(fh)


def _base():
    for b in _map()["seclists_bases"]:
        if os.path.isdir(b):
            return b
    return None


def test_valid_json_and_keys():
    m = _map()
    for k in ("seclists_bases", "surfaces", "fingerprints", "harness_first", "profiles"):
        assert k in m, "missing key: " + k


def test_required_surfaces_present():
    s = _map()["surfaces"]
    for surf in ("content", "files", "vhost", "api", "params", "artifacts"):
        assert surf in s and s[surf], "surface missing/empty: " + surf


def test_content_is_size_ordered():
    # common.txt (4.7k) must precede raft-large (62k) which must precede 2.3-medium (220k)
    content = " ".join(_map()["surfaces"]["content"])
    assert content.index("common.txt") < content.index("raft-large-directories.txt")
    assert content.index("raft-large-directories.txt") < content.index("2.3-medium")


def test_profiles_have_flag_keys():
    for prof in ("ctf", "pt", "bb"):
        p = _map()["profiles"][prof]
        for k in ("threads", "rate", "recursion", "jitter"):
            assert k in p, "profile %s missing %s" % (prof, k)


def test_harness_first_paths_exist():
    # every harness_first pointer must resolve to a real file under scripts/
    m = _map()
    scripts_dir = os.path.join(REPO, "scripts")
    for surface, rel in m["harness_first"].items():
        p = os.path.join(scripts_dir, rel)
        assert os.path.isfile(p), "harness_first[%s] -> missing file: %s" % (surface, rel)


def test_every_seclists_path_exists():
    base = _base()
    if base is None:
        import pytest
        pytest.skip("no seclists base installed on this host")
    m = _map()
    for group in ("surfaces", "fingerprints"):
        for name, paths in m[group].items():
            for rel in paths:
                assert os.path.exists(os.path.join(base, rel)), \
                    "%s/%s -> missing path: %s" % (group, name, rel)
