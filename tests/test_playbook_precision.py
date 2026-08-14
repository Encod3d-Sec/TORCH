"""T2.1: playbook.json fingerprint precision - the router must not fire hunt-* on signals that
every modern web page carries (a bare <script> tag, an Age/x-cache header, a JSON "type":"password"
string). These bare-presence patterns were the recurring false-fire class (3 retro entries): they
routed hunt-xss/hunt-cache/hunt-sqli on nearly every page, training the operator to ignore the router.
Real signals (a login-form input element, a DOM sink, a cache HIT/MISS status) must still fire.
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


def _skills(blob):
    rc = _load()
    out = set()
    for _label, spec in rc.fingerprint_records(blob):
        for s in (spec.get("skills") or []):
            out.add(s)
    return out


def test_benign_page_does_not_false_fire():
    """A normal page: a <script> include, an Age response header, a CloudFront x-cache header (no
    hit/miss status), and a JSON type:password field - none of these is a real hunt signal."""
    benign = ('<html><head><script src="/static/app.js"></script></head>'
              '<body>HTTP Age: 42  x-cache: cloudfront  {"type":"password"}</body></html>')
    fired = _skills(benign)
    assert "hunt-xss" not in fired, fired
    assert "hunt-cache" not in fired, fired
    assert "hunt-sqli" not in fired, fired


def test_real_login_form_still_fires_auth():
    fired = _skills('<form><input name="user"><input name="password" type="password"></form>')
    assert "hunt-sqli" in fired and "hunt-auth" in fired, fired


def test_real_dom_sink_still_fires_xss():
    fired = _skills("var h = location.hash; el.innerHTML = h;")
    assert "hunt-xss" in fired, fired


def test_real_cache_status_still_fires_cache():
    fired = _skills("HTTP/1.1 200 OK\nX-Cache: cache-hit\nVia: 1.1 varnish")
    assert "hunt-cache" in fired, fired
