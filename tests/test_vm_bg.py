import os, subprocess
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SH = os.path.join(REPO, "scripts", "vm-bg.sh")

def test_dry_run_prints_devshm_plan():
    p = subprocess.run(["bash", SH, "--dry-run", "eng1", "pspy", "/opt/pspy/pspy64 -pf"],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode == 0
    out = p.stdout
    assert "/dev/shm/pspy.log" in out and "tmux" in out and "stdbuf" in out
