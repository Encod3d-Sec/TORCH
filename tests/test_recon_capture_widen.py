"""Widen-the-surface drift reflex predicate.

`_is_web_probe` gates a fire-once nudge that fires after WIDEN_AT web probes with no foothold,
pushing the operator to enumerate a NEW surface class (userdir /~, vhost-by-redirect-location,
another port, source-read) instead of grinding a dead obvious surface -- the recurring ~40-min
drift on a box whose real entry was an Apache userdir.
"""
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


WEB_PROBES = [
    "feroxbuster -u http://olympus.thm -w list.txt",
    "ffuf -u http://10.1.1.1/ -H 'Host: FUZZ.t' -w list -mc all",
    "bash /root/vm.sh 'curl -s http://chat.t/login.php'",
    "gobuster dir -u http://t -w w.txt",
    "nuclei -u http://t",
]

NOT_WEB_PROBES = [
    "nmap -p- 10.1.1.1",                 # port scan, not a web probe
    "cat /etc/passwd",                   # not a probe
    "curl file:///etc/passwd",           # curl but not http(s)
    "sqlmap -u 'http://t/?id=1'",        # exploitation tool, not a discovery-grind signal
    "ssh zeus@t",                        # not web
]


def test_web_probes_detected():
    rc = _load()
    for c in WEB_PROBES:
        assert rc._is_web_probe(c), f"should be a web probe: {c!r}"


def test_non_web_probes_ignored():
    rc = _load()
    for c in NOT_WEB_PROBES:
        assert not rc._is_web_probe(c), f"should NOT be a web probe: {c!r}"


def test_widen_threshold_sane():
    rc = _load()
    assert 10 <= rc.WIDEN_AT <= 40, "widen threshold should be a realistic grind count"
