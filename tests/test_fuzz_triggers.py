"""triggers.json routes the content/vhost/param discovery vocabulary to Skill(fuzz)."""
import json
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRIG = os.path.join(REPO, "skills", "hunt", "triggers.json")


def _surface():
    return json.load(open(TRIG, encoding="utf-8"))["surface_triggers"]


def test_valid_json_still_loads():
    json.load(open(TRIG, encoding="utf-8"))


def test_fuzz_vocabulary_routes_to_fuzz():
    st = _surface()
    fuzz_patterns = [rx for rx, skill in st.items() if skill == "fuzz"]
    assert fuzz_patterns, "no surface_trigger routes to fuzz"
    for phrase in ("fuzz the", "content discovery", "vhost", "hidden parameters", "directory brute"):
        assert any(re.search(rx, phrase, re.I) for rx in fuzz_patterns), \
            "no fuzz pattern matches: %r" % phrase


def test_credential_bruteforce_does_not_route_to_fuzz():
    st = _surface()
    fuzz_patterns = [rx for rx, skill in st.items() if skill == "fuzz"]
    for phrase in ("brute force the ssh login", "brute-force the password", "password brute force"):
        assert not any(re.search(rx, phrase, re.I) for rx in fuzz_patterns), \
            "credential brute-force phrase must not route to fuzz: %r" % phrase
