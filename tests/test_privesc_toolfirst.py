"""T3.2: the privesc-tool-first advisory. Manual SUID/cron/getcap enum post-foothold with no
linpeas/pspy launched -> nudge ONCE. Gated on foothold, suppressed once the tools ran, fires once.
Low false-fire by construction (that's why it's shippable given the operator's hook-aversion)."""
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    os.environ.setdefault("CLAUDEBRAIN_VAULT", ROOT)
    spec = importlib.util.spec_from_file_location(
        "rc", os.path.join(ROOT, "skills", "hooks", "recon-capture.py"))
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


def _eng():
    import _engagement
    return _engagement


_STATE_FOOTHOLD = (
    "---\ntype: engagement-state\nengagement_type: ctf\n---\n\n# State\n\n"
    "| target | service | port | foothold | access | flag | notes |\n"
    "|--------|---------|------|----------|--------|------|-------|\n"
    "| 10.0.0.5 | http | 80 | web-rce | foothold | - | apache shell |\n")
_STATE_NONE = _STATE_FOOTHOLD.replace("| foothold |", "| none |")

MANUAL = "bash /root/vm.sh 'find / -perm -4000 -type f 2>/dev/null'"


def _write(d, state):
    open(os.path.join(d, "state.md"), "w").write(state)


def test_nudges_on_manual_suid_post_foothold(tmp_path):
    rc = _load()
    d = str(tmp_path)
    _write(d, _STATE_FOOTHOLD)
    out = rc._privesc_toolfirst_nudge(d, MANUAL, _eng())
    assert out and "TOOL-FIRST" in out


def test_no_nudge_without_foothold(tmp_path):
    rc = _load()
    d = str(tmp_path)
    _write(d, _STATE_NONE)
    assert rc._privesc_toolfirst_nudge(d, MANUAL, _eng()) is None


def test_suppressed_after_linpeas_launched(tmp_path):
    rc = _load()
    d = str(tmp_path)
    _write(d, _STATE_FOOTHOLD)
    # a linpeas launch records the marker and returns None
    assert rc._privesc_toolfirst_nudge(d, "bash /root/vm.sh 'linpeas.sh'", _eng()) is None
    # subsequent manual enum is now suppressed
    assert rc._privesc_toolfirst_nudge(d, MANUAL, _eng()) is None


def test_fires_once_per_engagement(tmp_path):
    rc = _load()
    d = str(tmp_path)
    _write(d, _STATE_FOOTHOLD)
    assert rc._privesc_toolfirst_nudge(d, MANUAL, _eng()) is not None
    assert rc._privesc_toolfirst_nudge(d, "bash /root/vm.sh 'cat /etc/crontab'", _eng()) is None


def test_ignores_unrelated_command(tmp_path):
    rc = _load()
    d = str(tmp_path)
    _write(d, _STATE_FOOTHOLD)
    assert rc._privesc_toolfirst_nudge(d, "bash /root/vm.sh 'whoami'", _eng()) is None
