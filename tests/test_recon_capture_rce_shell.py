"""RCE-landing detector for the reverse-shell/stabilize reflex.

`_is_rce_landing` gates a fire-once nudge that pushes the operator from hand-poked one-liner
web-RCE to a proper stabilized reverse shell (the recurring drift: RCE achieved, but no rshell
and no shell stabilization until the operator asks). It must fire on a service-account `id`
and NOT on a reflected attacker-root `id` (the false-RCE trap).
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


FIRES = [
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)",
    "www-data@box:/var/www$ id\nuid=33(www-data) gid=33(www-data)",
]

NO_FIRE = [
    "",
    "some normal recon output with no id",
    "uid=0(root) gid=0(root) groups=0(root)",          # reflected attacker-root = false-RCE trap
    "PID   USER   %CPU  COMMAND",                        # pspy-style, no id line
]


def test_service_account_id_fires():
    rc = _load()
    for txt in FIRES:
        assert rc._is_rce_landing(txt), f"should detect RCE landing: {txt!r}"


def test_no_id_or_attacker_root_does_not_fire():
    rc = _load()
    for txt in NO_FIRE:
        assert not rc._is_rce_landing(txt), f"should NOT fire: {txt!r}"
