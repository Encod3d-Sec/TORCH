"""Vector-doubt reflex: two mechanical tells that the CURRENT exploit vector is wrong, so the
operator reconsiders the VECTOR instead of tuning the tooling.

(a) target starved -- an exploit-shaped loop draws repeated 000 / connection-timeout / empty-reply
    responses = the box is being DoS'd by our own load (almost never the intended vector on a lab
    box); (b) uncrackable hashes -- >=2 '0 password hashes cracked' results in one engagement =
    the passwords are not wordlist material (delivered out-of-band: email/notes/KeePass), so stop
    cracking and re-enumerate. Recurring drift: a fragile-box SQLi hash-dump-and-crack grind that
    was a rabbit hole while the real foothold was an unenumerated file-read/LFI class.
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


STARVED_OUTPUTS = [
    "try1: code=000 time=10.0\ntry2: code=000 time=10.0",   # curl loop, box dropping
    "curl: (28) Connection timed out\ncurl: (28) Connection timed out after 25000 ms",
    "* Empty reply from server\n* Empty reply from server",
]

NOT_STARVED_OUTPUTS = [
    "try1: code=200 time=0.1\ntry2: code=000 time=10.0",    # a SINGLE 000 = transient, not starved
    "code=200 time=0.2\ncode=200 time=0.2",                  # healthy
    "",                                                       # no output
]

UNCRACKED_OUTPUTS = [
    "0 password hashes cracked, 1 left",
    "Loaded 1 password hash\n...\n0 password hashes cracked, 1 left\nSession completed.",
    "No password hashes left to crack (see status)",
]

NOT_UNCRACKED_OUTPUTS = [
    "1 password hash cracked, 0 left",
    "Backup:Lhotse56185\n1 password hash cracked",
    "Will run 4 OpenMP threads",     # a run in progress, no verdict yet
]

# commands that ARE an exploit-shaped loop (so a starved output is meaningful, not a bare scan)
EXPLOIT_LOOP_CMDS = [
    "bash /root/vm.sh 'for i in 1 2 3; do curl -s http://t/wp-admin/admin-ajax.php --data time=...; done'",
    "sqlmap -u 'http://t/?id=1' --dump",
    "bash /root/vm.sh 'bash /tmp/ext.sh'",
    "john /tmp/kdbx.hash --wordlist=/tmp/mount.txt",
    "hashcat -m 0 hash.txt rockyou.txt",
]

NOT_EXPLOIT_LOOP_CMDS = [
    "nmap -p- 10.1.1.1",
    "cat /etc/passwd",
    "ls -la",
]


def test_starved_output_detected():
    rc = _load()
    for t in STARVED_OUTPUTS:
        assert rc._output_starved(t), f"should read as starved: {t!r}"


def test_healthy_output_not_starved():
    rc = _load()
    for t in NOT_STARVED_OUTPUTS:
        assert not rc._output_starved(t), f"should NOT read as starved: {t!r}"


def test_uncracked_detected():
    rc = _load()
    for t in UNCRACKED_OUTPUTS:
        assert rc._output_uncracked(t), f"should read as an uncracked-hash verdict: {t!r}"


def test_cracked_or_running_not_uncracked():
    rc = _load()
    for t in NOT_UNCRACKED_OUTPUTS:
        assert not rc._output_uncracked(t), f"should NOT read as uncracked: {t!r}"


def test_exploit_loop_detected():
    rc = _load()
    for c in EXPLOIT_LOOP_CMDS:
        assert rc._is_exploit_loop(c), f"should be an exploit loop: {c!r}"


def test_non_exploit_not_a_loop():
    rc = _load()
    for c in NOT_EXPLOIT_LOOP_CMDS:
        assert not rc._is_exploit_loop(c), f"should NOT be an exploit loop: {c!r}"


def test_crack_miss_threshold_sane():
    rc = _load()
    assert rc.VECTOR_DOUBT_CRACK_AT == 2, "two uncrackable-hash results should trip the doubt reflex"


def test_predicates_fail_open_on_none():
    rc = _load()
    # never raise on None / non-str -- the hook must fail open
    assert rc._output_starved(None) is False
    assert rc._output_uncracked(None) is False
    assert rc._is_exploit_loop(None) is False


def test_widen_rearms_up_to_a_cap():
    rc = _load()
    assert getattr(rc, "_WIDEN_CAP", 0) >= 2, "widen nudge should re-arm up to a cap, not fire once"
