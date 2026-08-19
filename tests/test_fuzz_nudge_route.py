"""The recon-capture content-discovery nudges name Skill(fuzz) as the destination."""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(REPO, "skills", "hooks", "recon-capture.py"), encoding="utf-8").read()


def test_recon_completeness_nudge_names_fuzz():
    i = SRC.index("RECON COMPLETENESS")
    block = SRC[i:i + 600]
    assert "Skill(fuzz)" in block, "recon-completeness nudge should route to Skill(fuzz)"


def test_widen_nudge_names_fuzz():
    i = SRC.index("WIDEN THE SURFACE")
    block = SRC[i:i + 900]
    assert "Skill(fuzz)" in block, "widen nudge should route to Skill(fuzz)"
