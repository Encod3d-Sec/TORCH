"""A4: fingerprint-router per-tech cap + clean label extraction.

Each playbook fingerprint should route ONCE per engagement (a `skip` set of already-fired labels
drops repeats -- the fix for hunt-rce re-firing on every `id`), and the display/dedup label should
be a clean leading token, not the raw regex (so `uid=\\d+...` -> 'uid')."""
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


_ID = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"


def test_label_is_clean_leading_token():
    rc = _load()
    labels = [lbl for lbl, _ in rc.fingerprint_records(_ID)]
    assert "uid" in labels                                   # clean token, not the raw regex
    assert not any(("\\" in lbl) or ("(" in lbl) for lbl in labels)


def test_skip_caps_repeat_routing():
    rc = _load()
    first = [lbl for lbl, _ in rc.fingerprint_records(_ID)]
    assert first                                             # fires at least one tech
    again = [lbl for lbl, _ in rc.fingerprint_records(_ID, skip=set(first))]
    assert all(lbl not in first for lbl in again)            # already-fired techs suppressed


def test_hits_respects_skip():
    rc = _load()
    lbl = rc.fingerprint_records(_ID)[0][0]
    assert any((lbl + " detected") in ln for ln in rc.fingerprint_hits(_ID))
    assert not any((lbl + " detected") in ln for ln in rc.fingerprint_hits(_ID, skip={lbl}))


def test_bare_changelog_filename_does_not_route_nday():
    """A4b: a bare CHANGELOG.md in grep output (no version) must NOT route nday; a real version
    disclosure still does."""
    rc = _load()
    noise = "modules/pm2/node/node_modules/axios/CHANGELOG.md"
    labels_noise = [lbl for lbl, _ in rc.fingerprint_records(noise)]
    assert "changelog" not in labels_noise
    real = "Changelog for v2.4.1 - security fixes"
    assert any(spec.get("skills") == ["nday", "metasploit"]
               for _lbl, spec in rc.fingerprint_records(real))
