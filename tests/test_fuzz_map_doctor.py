"""campaign-doctor lists the new fuzz-selection files, and the wordlists cheatsheet
carries the size-correction note so the human reference matches wordlist-map.json."""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_doctor_lists_new_files():
    src = open(os.path.join(REPO, "scripts", "campaign-doctor.py"), encoding="utf-8").read()
    assert "wl-pick.sh" in src and "wordlist-map.json" in src


def test_cheatsheet_has_size_correction():
    md = open(os.path.join(REPO, "wiki", "cheatsheets", "wordlists.md"), encoding="utf-8").read()
    assert "wl-pick.sh" in md, "cheatsheet should point to the deterministic selector"
    # the size-correction fact: 2.3-small is bigger than raft-large
    assert "87" in md and "raft-large" in md, "cheatsheet should carry the size-order correction"
