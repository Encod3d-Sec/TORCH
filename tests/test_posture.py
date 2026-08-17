import os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "scripts"))
CAMPAIGN = os.path.join(VAULT, "scripts", "campaign.py")
FIX = os.path.join(HERE, "fixtures", "campaign")
import campaign

def test_msf_posture_fires_on_codeexec_no_foothold():
    assert campaign._msf_shell_posture("rce", False)
    assert "multi/handler" in campaign._msf_shell_posture("upload", False)

def test_msf_posture_suppressed_with_foothold():
    assert campaign._msf_shell_posture("rce", True) is None

def test_msf_posture_suppressed_non_codeexec():
    assert campaign._msf_shell_posture("xss", False) is None

def test_preboard_fingerprint_prints_searchsploit(tmp_path):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    open(d / "state.md", "w").write("---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n")
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "init", "--type", "ctf"],
                   capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "pass-done"], capture_output=True, text=True)
    subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "pass-done"], capture_output=True, text=True)  # -> pass 2
    out = subprocess.run([sys.executable, CAMPAIGN, "--eng", str(d), "next"],
                         capture_output=True, text=True).stdout
    assert "searchsploit" in out.lower()
