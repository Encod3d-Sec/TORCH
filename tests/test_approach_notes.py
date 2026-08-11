"""approach-notes.json loads, keys are real board class tokens, and cmd_next prints the note."""
import json
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "scripts"))
CAMPAIGN = os.path.join(VAULT, "scripts", "campaign.py")
FIX = os.path.join(HERE, "fixtures", "campaign")


def test_loader_parses_and_has_privesc_keys():
    import campaign
    notes = campaign._approach_notes()
    assert "content-discovery" in notes and "sqli" in notes
    assert "privesc-auto" in notes and "privesc-manual" in notes
    for v in notes.values():
        assert v.get("do") and v.get("refs")


@pytest.fixture
def eng(tmp_path):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    return str(d)


def test_next_prints_approach_for_content_discovery(eng):
    # a bare web asset -> surface-seeds emits a `content-discovery` row (deterministic)
    state = os.path.join(eng, "state.md")
    open(state, "w").write(
        "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n\n"
        "| asset | ip | os | services | access | owned | notes |\n"
        "|-------|----|----|----------|--------|-------|-------|\n"
        "| 10.0.0.9 | 10.0.0.9 | Linux | http nginx | port-open | no | web |\n")
    subprocess.run([sys.executable, CAMPAIGN, "--eng", eng, "init", "--type", "ctf"],
                   capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", eng, "board"], capture_output=True, text=True)
    # fill the arsenal cell of the content-discovery row so `next` serves past the G1 gate
    import campaign
    rows = campaign.read_board(eng)
    cd = next(r for r in rows if (r.get("vuln class") or "") == "content-discovery")
    # minimal arsenal file so `note` accepts it
    ars = os.path.join(eng, "arsenal")
    os.makedirs(ars, exist_ok=True)
    open(os.path.join(ars, "content-discovery.md"), "w").write(
        "## Techniques\nx\n## Payloads\nx\n## Tools\nx\n## Cheatsheets\nx\n")
    subprocess.run([sys.executable, CAMPAIGN, "--eng", eng, "note", cd["id"],
                    "--arsenal", "content-discovery"], capture_output=True, text=True)
    out = subprocess.run([sys.executable, CAMPAIGN, "--eng", eng, "next"],
                         capture_output=True, text=True).stdout
    assert "APPROACH" in out and "userdir" in out
