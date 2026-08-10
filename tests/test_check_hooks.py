"""Tests for scripts/check-hooks.py drift detection.

check-hooks.py has a hyphen in its filename, so load it via importlib (mirrors
the _load helper pattern in tests/test_scripts.py).
"""
import importlib.util
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _settings_with(basenames):
    """Build a minimal settings.json dict registering the given hook basenames."""
    hooks = {"SessionStart": []}
    for b in basenames:
        hooks["SessionStart"].append(
            {"hooks": [{"type": "command",
                        "command": "python3 ~/.claude/vault-hooks/" + b}]})
    return {"hooks": hooks}


def _all_basenames(ch):
    return [basename for _event, basename in ch.EXPECTED_HOOKS]


def test_missing_hook_detected(tmp_path):
    ch = _load("scripts/check-hooks.py", "check_hooks_missing")
    present = [b for b in _all_basenames(ch) if b != "scope-guard.py"]
    p = tmp_path / "settings.json"
    p.write_text(json.dumps(_settings_with(present)))
    miss = ch.missing_hooks(str(p))
    assert "scope-guard.py" in miss
    assert "engagement-init.py" not in miss


def test_complete_settings_no_drift(tmp_path):
    ch = _load("scripts/check-hooks.py", "check_hooks_complete")
    p = tmp_path / "settings.json"
    p.write_text(json.dumps(_settings_with(_all_basenames(ch))))
    assert ch.missing_hooks(str(p)) == []


def test_expected_hooks_trimmed():
    ch = _load("scripts/check-hooks.py", "check_hooks_trimmed")
    names = _all_basenames(ch)
    assert "no-echo-banner.py" not in names        # deleted (cosmetic deny hook)
    assert "loop-driver.py" not in names           # deleted (488-line render drain)
    assert len(ch.EXPECTED_HOOKS) == 11            # -web-recon (auto-launched recon on discovery); +drift-guard
    assert "web-recon.py" not in names             # deleted (fired on tool OUTPUT, re-scanned retired hosts)
    assert ("PostToolUse", "wiki-reindex.py") in ch.EXPECTED_HOOKS
    # the only Stop hook is the minimal close-out reflex, not the old render drain
    assert [b for e, b in ch.EXPECTED_HOOKS if e == "Stop"] == ["close-out.py"]


def test_unreadable_path_fails_open(tmp_path):
    ch = _load("scripts/check-hooks.py", "check_hooks_unreadable")
    missing_path = str(tmp_path / "does-not-exist.json")
    assert ch.missing_hooks(missing_path) == []


# --- missing_skills (install drift) ---

def _make_skill(skills_root, *parts):
    """Create skills_root/<parts...>/SKILL.md (parts[-1] is the skill name)."""
    d = skills_root.joinpath(*parts)
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("x")


def test_missing_skill_detected(tmp_path):
    ch = _load("scripts/check-hooks.py", "check_hooks_skill_missing")
    sroot = tmp_path / "skills"
    _make_skill(sroot, "hunt", "alpha")   # nested like skills/hunt/<name>
    _make_skill(sroot, "beta")            # top-level like skills/<name>
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "alpha").mkdir()              # only alpha registered
    assert ch.missing_skills(str(sroot), str(dest)) == ["beta"]


def test_all_skills_registered_no_drift(tmp_path):
    ch = _load("scripts/check-hooks.py", "check_hooks_skill_ok")
    sroot = tmp_path / "skills"
    _make_skill(sroot, "hunt", "alpha")
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(str(sroot / "hunt" / "alpha"), str(dest / "alpha"))
    assert ch.missing_skills(str(sroot), str(dest)) == []


def test_broken_symlink_counts_as_registered(tmp_path):
    """lexists semantics: a present-but-dangling link is a different drift."""
    ch = _load("scripts/check-hooks.py", "check_hooks_skill_broken")
    sroot = tmp_path / "skills"
    _make_skill(sroot, "alpha")
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(str(tmp_path / "gone"), str(dest / "alpha"))  # dangling
    assert ch.missing_skills(str(sroot), str(dest)) == []


def test_unreadable_skills_root_fails_open(tmp_path):
    ch = _load("scripts/check-hooks.py", "check_hooks_skill_open")
    assert ch.missing_skills(str(tmp_path / "nope"), str(tmp_path)) == []


def test_tool_lean_removed():
    import importlib.util, os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("ch", os.path.join(root, "scripts", "check-hooks.py"))
    ch = importlib.util.module_from_spec(spec); spec.loader.exec_module(ch)
    assert not any("tool-lean" in b for _e, b in ch.EXPECTED_HOOKS)
    assert not os.path.exists(os.path.join(root, "skills", "hooks", "tool-lean.py"))


def test_wiki_log_removed_and_count_is_11():
    import importlib.util, os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("ch", os.path.join(root, "scripts", "check-hooks.py"))
    ch = importlib.util.module_from_spec(spec); spec.loader.exec_module(ch)
    assert not any("wiki-log" in b for _e, b in ch.EXPECTED_HOOKS)
    assert not os.path.exists(os.path.join(root, "skills", "hooks", "wiki-log.py"))
    assert len(ch.EXPECTED_HOOKS) == 11   # ... +tool-telemetry +wiki-reindex, -web-recon, +drift-guard


def test_docs_hook_count_matches_expected():
    import importlib.util, os, re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("ch", os.path.join(root, "scripts", "check-hooks.py"))
    ch = importlib.util.module_from_spec(spec); spec.loader.exec_module(ch)
    setup = open(os.path.join(root, "docs", "setup.md"), encoding="utf-8").read()
    m = re.search(r"(\d+)\s+hook commands", setup)
    assert m and int(m.group(1)) == len(ch.EXPECTED_HOOKS) == 11


def test_stale_hook_detected(tmp_path):
    """A hook deleted upstream but still registered must be flagged.

    The mirror of test_missing_hook_detected: install-hooks.sh only ever added,
    so a removed hook (web-recon.py, 2026-08-04) stayed registered on every
    already-provisioned device and errored on every matching tool call.
    """
    ch = _load("scripts/check-hooks.py", "check_hooks_stale")
    hooks_dir = tmp_path / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / "scope-guard.py").write_text("")
    p = tmp_path / "settings.json"
    p.write_text(json.dumps(_settings_with(["scope-guard.py", "web-recon.py"])))
    stale = ch.stale_hooks(str(p), str(hooks_dir))
    assert stale == ["web-recon.py"]


def test_stale_hooks_fails_open(tmp_path):
    ch = _load("scripts/check-hooks.py", "check_hooks_stale_open")
    assert ch.stale_hooks(str(tmp_path / "nope.json"), str(tmp_path)) == []
