"""cmd_board seeds pspy/linpeas privesc rows for a FOOTHOLD asset (ctf/pentest), not for bb."""
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


def _mk(tmp_path, access, etype):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    open(d / "state.md", "w").write(
        "---\ntype: engagement-state\nengagement_type: %s\n---\n\n# State\n\n"
        "| asset | ip | os | services | access | owned | notes |\n"
        "|-------|----|----|----------|--------|-------|-------|\n"
        "| 10.0.0.9 | 10.0.0.9 | Linux | http | %s | no | x |\n" % (etype, access))
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "init", "--type",
                    {"ctf": "ctf", "pentest": "pt", "bugbounty": "bb"}[etype]],
                   capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "board"], capture_output=True, text=True)
    import campaign
    campaign._APPROACH_NOTES = None  # reset cache across parametrized runs
    return [r.get("vuln class") for r in campaign.read_board(str(d))]


def test_foothold_seeds_privesc_rows_ctf(tmp_path):
    classes = _mk(tmp_path, "foothold", "ctf")
    assert "privesc-auto" in classes and "privesc-manual" in classes


def test_port_open_asset_has_no_privesc_rows(tmp_path):
    classes = _mk(tmp_path, "port-open", "ctf")
    assert "privesc-auto" not in classes


def test_bugbounty_never_seeds_privesc(tmp_path):
    classes = _mk(tmp_path, "foothold", "bugbounty")
    assert "privesc-auto" not in classes and "privesc-manual" not in classes
