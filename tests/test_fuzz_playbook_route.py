"""A precise discoverable-surface fingerprint routes to fuzz; a benign page does not."""
import json
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PB = json.load(open(os.path.join(REPO, "scripts", "playbook.json"), encoding="utf-8"))["fingerprints"]


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
