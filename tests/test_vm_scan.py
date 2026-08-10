"""vm-scan.sh --dry-run tests (no VM; asserts the remote tmux script it would run)."""
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "vm-scan.sh")


def dry(*args):
    p = subprocess.run(["bash", SCRIPT, "--dry-run", *args],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout


def test_sanitizes_dots_colons_spaces_in_name():
    out = dry("eng1", "demo-web-10.0.0.5", "nmap", "-sV", "10.0.0.5")
    assert "demo-web-10-0-0-5" in out          # dots -> dashes in the tab name
    assert "10.0.0.5" not in out.split("send-keys", 1)[0]   # name portion has no dots
    assert "new-window" in out and "#{window_id}" in out    # id-based targeting
    assert "send-keys" in out and "nmap -sV 10.0.0.5" in out


def test_session_and_multiweb_name():
    out = dry("eng1", "acme-web-app.example.com", "nuclei", "-u", "https://app.example.com")
    assert "acme-web-app-example-com" in out
    assert "has-session -t eng1" in out or "new-session -d -s eng1" in out


def test_win_flag_decouples_window_from_target():
    # parallel scans on ONE host get their own window via --win (same session, no session churn).
    out = dry("--win", "nuclei", "eng1", "10.0.0.5", "nuclei", "-u", "http://10.0.0.5")
    assert '$2=="nuclei"' in out                            # window lookup keys on the --win name
    assert "-n 'nuclei'" in out                             # new-window is named nuclei
    assert "10-0-0-5" not in out.split("send-keys", 1)[0]   # the target IP is NOT the window name
    assert "has-session -t eng1" in out                     # still one session per engagement


def test_remote_script_reports_reused_vs_new_window():
    # the remote tmux script must track create-vs-reuse so the local side can warn on
    # collision (two scans sent to the SAME target name land in the SAME tab and can
    # corrupt each other's stdin -- reproduced live when a nuclei command was sent into
    # a still-running feroxbuster tab). Regression guard for that fix.
    out = dry("eng1", "10.0.0.5", "nmap", "-sV", "10.0.0.5")
    assert "REUSED=1" in out and "REUSED=0" in out
    assert "reused=$REUSED" in out


# (Area 2 .pending-tmux marker removed: loop-driver + recon-capture tmux staging that
# consumed it are deleted, so vm-scan.sh no longer writes the marker.)


def test_win_msf_lands_msfconsole_in_a_named_msf_window():
    # interactive-session design: msfconsole is launched into its own persistent tmux window via
    # the existing generic --win, no launcher change. Mirrors the shell-window pattern.
    out = dry("--win", "msf", "eng1", "10.0.0.5",
              "msfconsole", "-q", "-x", "use exploit/multi/handler; run")
    assert "-n 'msf'" in out                                 # window is named msf
    assert '$2=="msf"' in out                                # lookup keys on the msf window name
    assert "msfconsole -q -x use exploit/multi/handler; run" in out   # the msf launch cmd is sent
    assert "10-0-0-5" not in out.split("send-keys", 1)[0]    # the target is NOT the window name
    assert "has-session -t eng1" in out                      # still one session per engagement
