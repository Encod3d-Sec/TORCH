"""ctf-box is slimmed (box-specific war stories gone, phase spine intact); ctf-workflow is corrected."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOX = os.path.join(ROOT, "skills", "workflow", "ctf-box", "SKILL.md")
WF = os.path.join(ROOT, "skills", "workflow", "ctf-workflow", "SKILL.md")


def test_ctfbox_has_no_box_specific_lessons():
    txt = open(BOX, encoding="utf-8").read()
    # the box-specific war-story headers ("## Lesson: ... (THM X)") are migrated to wiki
    assert "## Lesson:" not in txt
    # phase spine and the standing mandate remain
    for anchor in ("## Phase 1 Recon", "## Phase 4 Exploit", "Wiki-first"):
        assert anchor in txt


def test_ctfbox_is_substantially_slimmer():
    assert len(open(BOX, encoding="utf-8").read().splitlines()) < 260  # was 428


def test_ctfworkflow_documents_approach_and_fixes_4b_claim():
    txt = open(WF, encoding="utf-8").read()
    assert "APPROACH" in txt                       # new per-row output documented
    assert "REMINDER" in txt or "reminder" in txt  # the drift reminder documented
    # the old false claim ("writes 4a foothold rows plus 4b pspy/linpeas ... rows") must be corrected
    assert "4b pspy/linpeas/sudo/docker privesc rows" not in txt
