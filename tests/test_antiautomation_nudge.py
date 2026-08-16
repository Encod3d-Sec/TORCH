"""Anti-automation / WAF reflex: target OUTPUT shows a request-limiter/ban/taunt (defeats sqlmap
by burst rate) or a WAF/CDN block page -> nudge once per class per engagement. Fail-open by
construction (mirrors the privesc-tool-first advisory's test shape)."""
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


def test_antiauto_marker_fires(tmp_path):
    rc = _load()
    d = str(tmp_path)
    out = rc._antiautomation_nudge(d, "...Try SqlMap.. I dare you...", _eng())
    assert out and "MANUAL" in out


def test_429_fires_antiauto(tmp_path):
    rc = _load()
    d = str(tmp_path)
    out = rc._antiautomation_nudge(d, "HTTP 429 Too Many Requests", _eng())
    assert out is not None
    assert "MANUAL" in out


def test_waf_marker_fires(tmp_path):
    rc = _load()
    d = str(tmp_path)
    out = rc._antiautomation_nudge(d, "Attention Required! | Cloudflare ... cf-ray", _eng())
    assert out and "WAF" in out


def test_clean_output_silent(tmp_path):
    rc = _load()
    d = str(tmp_path)
    assert rc._antiautomation_nudge(d, "<h3>Price: $500000</h3>", _eng()) is None


def test_fires_once_per_class(tmp_path):
    rc = _load()
    d = str(tmp_path)
    assert rc._antiautomation_nudge(d, "...Try SqlMap.. I dare you...", _eng()) is not None
    # 2nd anti-automation blob: same class already fired -> silent
    assert rc._antiautomation_nudge(d, "HTTP 429 Too Many Requests", _eng()) is None
    # different class (waf) -> still fires
    out = rc._antiautomation_nudge(d, "Attention Required! | Cloudflare ... cf-ray", _eng())
    assert out is not None
