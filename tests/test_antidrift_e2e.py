"""End-to-end: a web-asset recon state produces a board whose web row prints the userdir
APPROACH."""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "scripts"))
CAMPAIGN = os.path.join(VAULT, "scripts", "campaign.py")
FIX = os.path.join(HERE, "fixtures", "campaign")


def test_web_box_board_prints_userdir_approach(tmp_path):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    open(d / "state.md", "w").write(
        "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n\n"
        "| asset | ip | os | services | access | owned | notes |\n"
        "|-------|----|----|----------|--------|-------|-------|\n"
        "| 10.10.1.1 | 10.10.1.1 | Linux | http apache | port-open | no | web |\n")
    open(d / "state.md", "a").write("")  # no STATUS -> not solved
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "init", "--type", "ctf"],
                   capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "board"], capture_output=True, text=True)
    import campaign
    campaign._APPROACH_NOTES = None
    rows = campaign.read_board(str(d))
    cd = next(r for r in rows if (r.get("vuln class") or "") == "content-discovery")
    ars = d / "arsenal"; ars.mkdir(exist_ok=True)
    (ars / "content-discovery.md").write_text(
        "## Techniques\nx\n## Payloads\nx\n## Tools\nx\n## Cheatsheets\nx\n")
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "note", cd["id"],
                    "--arsenal", "content-discovery"], capture_output=True, text=True)
    out = subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "next"],
                         capture_output=True, text=True).stdout
    assert "APPROACH" in out and "userdir" in out
