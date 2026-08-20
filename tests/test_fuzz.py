"""Skill(fuzz) is wired end to end: the campaign crawl-pass guidance, campaign-doctor's file list,
the recon-capture content-discovery nudges, the playbook discoverable-surface fingerprint, and the
triggers.json vocabulary all route content/vhost/param discovery to Skill(fuzz) (and credential
brute-force / benign pages do NOT). Consolidated from the former test_fuzz_* family."""
import json
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_CAMPAIGN = open(os.path.join(REPO, "scripts", "campaign.py"), encoding="utf-8").read()
SRC_RECON = open(os.path.join(REPO, "skills", "hooks", "recon-capture.py"), encoding="utf-8").read()
PB = json.load(open(os.path.join(REPO, "scripts", "playbook.json"), encoding="utf-8"))["fingerprints"]
TRIG = os.path.join(REPO, "skills", "hunt", "triggers.json")


# --- campaign crawl-pass guidance (was test_fuzz_crawl_guidance) ---
def test_crawl_guidance_names_fuzz():
    i = SRC_CAMPAIGN.index("Crawl every in-scope host")
    assert "Skill(fuzz)" in SRC_CAMPAIGN[i:i + 500]


# --- campaign-doctor + wordlists cheatsheet (was test_fuzz_map_doctor) ---
def test_doctor_lists_new_files():
    src = open(os.path.join(REPO, "scripts", "campaign-doctor.py"), encoding="utf-8").read()
    assert "wl-pick.sh" in src and "wordlist-map.json" in src


def test_cheatsheet_has_size_correction():
    md = open(os.path.join(REPO, "wiki", "cheatsheets", "wordlists.md"), encoding="utf-8").read()
    assert "wl-pick.sh" in md
    assert "87" in md and "raft-large" in md


# --- recon-capture content-discovery nudges (was test_fuzz_nudge_route) ---
def test_recon_completeness_nudge_names_fuzz():
    i = SRC_RECON.index("RECON COMPLETENESS")
    assert "Skill(fuzz)" in SRC_RECON[i:i + 600]


def test_widen_nudge_names_fuzz():
    i = SRC_RECON.index("WIDEN THE SURFACE")
    assert "Skill(fuzz)" in SRC_RECON[i:i + 900]


# --- playbook discoverable-surface fingerprint (was test_fuzz_playbook_route) ---
def _skills(text):
    out = []
    for rx, entry in PB.items():
        if re.search(rx, text, re.I):
            out += entry.get("skills", [])
    return out


def test_directory_listing_routes_to_fuzz():
    assert "fuzz" in _skills("<title>Index of /uploads</title>")


def test_robots_disallow_routes_to_fuzz():
    assert "fuzz" in _skills("User-agent: *\nDisallow: /admin/\nDisallow: /backup/")


def test_swagger_routes_to_fuzz():
    assert "fuzz" in _skills("GET /swagger/index.html  ... /api-docs")


def test_benign_page_does_not_route_to_fuzz():
    assert "fuzz" not in _skills("<html><body><h1>Welcome to our homepage</h1></body></html>")


def test_bare_robots_mention_does_not_route_to_fuzz():
    assert "fuzz" not in _skills("For SEO best practices, add a robots.txt file to your site.")


# --- triggers.json vocabulary (was test_fuzz_triggers) ---
def _surface():
    return json.load(open(TRIG, encoding="utf-8"))["surface_triggers"]


def test_valid_json_still_loads():
    json.load(open(TRIG, encoding="utf-8"))


def test_fuzz_vocabulary_routes_to_fuzz():
    fuzz_patterns = [rx for rx, skill in _surface().items() if skill == "fuzz"]
    assert fuzz_patterns, "no surface_trigger routes to fuzz"
    for phrase in ("fuzz the", "content discovery", "vhost", "hidden parameters", "directory brute"):
        assert any(re.search(rx, phrase, re.I) for rx in fuzz_patterns), phrase


def test_credential_bruteforce_does_not_route_to_fuzz():
    fuzz_patterns = [rx for rx, skill in _surface().items() if skill == "fuzz"]
    for phrase in ("brute force the ssh login", "brute-force the password", "password brute force"):
        assert not any(re.search(rx, phrase, re.I) for rx in fuzz_patterns), phrase
