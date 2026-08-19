"""The campaign crawl-pass (pass 1) guidance names Skill(fuzz) for content/vhost/api discovery."""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(REPO, "scripts", "campaign.py"), encoding="utf-8").read()


def test_crawl_guidance_names_fuzz():
    # the guidance dict entry keyed 1 (crawl) should reference Skill(fuzz)
    i = SRC.index("Crawl every in-scope host")
    block = SRC[i:i + 500]
    assert "Skill(fuzz)" in block, "crawl-pass guidance should name Skill(fuzz)"
