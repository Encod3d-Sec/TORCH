"""Area 3: CTF-aware template redesign - type-aware heal set, opt-in files,
new-engagement.sh scaffold, and finding-template reconciliation."""
import importlib.util
import os
import re
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "hooks"))
sys.path.insert(0, os.path.join(REPO, "scripts"))
import _engagement  # noqa: E402


def _mk(eng, etype):
    """Bare engagement dir with only a typed state.md; returns the Path."""
    os.makedirs(eng)
    (eng / "state.md").write_text(
        f"---\ntype: engagement-state\nengagement_type: {etype}\n---\n", encoding="utf-8")
    return eng


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ensure_ctf_heals_lean_set(vault, monkeypatch):
    eng = _mk(vault / "targets" / "room", "ctf")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    created = _engagement.ensure_state_files()
    for f in ("loot.md", "Approach.md", "scope.md", "Deadends.md"):
        assert f in created and (eng / f).exists()
    assert "Kill-Chain Board" in (eng / "Approach.md").read_text()
    for f in ("Killchain.md", "log.md", "walkthrough.md", "eval.md", "hot.md"):
        assert f not in created and not (eng / f).exists()
    for dsub in ("ingest/", "poc/"):
        assert dsub in created
    assert "recon/" not in created and not (eng / "recon").exists()   # auto firehose retired
    assert (eng / "poc").is_dir()
    for f in ("oob.md", "coverage.md", "Vuln-index.md"):
        assert f not in created and not (eng / f).exists()


def test_ensure_pentest_heals_full_set(vault, monkeypatch):
    eng = _mk(vault / "targets" / "pt", "pentest")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    created = _engagement.ensure_state_files()
    for f in ("oob.md", "Vuln-index.md",
              "loot.md", "Killchain.md", "Approach.md", "walkthrough.md"):
        assert f in created and (eng / f).exists()
    assert (eng / "poc").is_dir()


def test_ensure_ctf_idempotent(vault, monkeypatch):
    eng = _mk(vault / "targets" / "room2", "ctf")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    _engagement.ensure_state_files()
    assert _engagement.ensure_state_files() == []


def test_ensure_optional_backfills_oob(vault, monkeypatch):
    eng = _mk(vault / "targets" / "room3", "ctf")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    _engagement.ensure_state_files()          # lean: no oob
    assert not (eng / "oob.md").exists()
    assert _engagement.ensure_optional_file("oob") == "oob.md"
    assert (eng / "oob.md").exists() and "room3" in (eng / "oob.md").read_text()
    assert _engagement.ensure_optional_file("oob") == ""       # already exists -> ''
    assert _engagement.ensure_optional_file("coverage") == ""  # coverage retired -> unknown kind
    assert _engagement.ensure_optional_file("bogus") == ""     # unknown kind -> ''


def test_ensure_optional_vuln_index_slim_for_ctf(vault, monkeypatch):
    eng = _mk(vault / "targets" / "room4", "ctf")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    assert _engagement.ensure_optional_file("vuln-index") == "Vuln-index.md"
    txt = (eng / "Vuln-index.md").read_text()
    assert "room4" in txt and "<ENGAGEMENT>" not in txt
    assert "Key Attack Chains" not in txt      # slim: no chain narrative (lives in paths/walkthrough)
    assert "Severity Count" not in txt         # slim: no severity machinery


def test_ensure_optional_vuln_index_full_for_pentest(vault, monkeypatch):
    eng = _mk(vault / "targets" / "pt2", "pentest")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    assert _engagement.ensure_optional_file("vuln-index") == "Vuln-index.md"
    assert "Severity Count" in (eng / "Vuln-index.md").read_text()   # full template


@pytest.fixture
def eng_vault(tmp_path):
    """A vault with real templates + a copy of new-engagement.sh, so the script's
    readlink-based self-locate resolves VAULT to this tmp dir (isolated)."""
    root = tmp_path / "v"
    shutil.copytree(os.path.join(REPO, "setup", "templates"), root / "setup" / "templates")
    shutil.copy(os.path.join(REPO, "setup", "new-engagement.sh"),
                root / "setup" / "new-engagement.sh")
    (root / "targets").mkdir(parents=True)
    return root


def _run_new(root, *args):
    return subprocess.run(["bash", str(root / "setup" / "new-engagement.sh"), *args],
                          capture_output=True, text=True)


def test_new_engagement_ctf_lean(eng_vault):
    r = _run_new(eng_vault, "room", "ctf")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "room"
    for f in ("state.md", "loot.md", "Approach.md", "scope.md", "Deadends.md"):
        assert (d / f).exists()
    assert "Kill-Chain Board" in (d / "Approach.md").read_text()
    for f in ("Killchain.md", "log.md", "walkthrough.md", "eval.md", "hot.md"):
        assert not (d / f).exists()
    for sub in ("ingest", "poc"):
        assert (d / sub).is_dir()
    assert not (d / "recon").exists()   # auto firehose retired
    for f in ("oob.md", "coverage.md", "Vuln-index.md"):
        assert not (d / f).exists()
    assert (eng_vault / "targets" / "active.md").read_text().strip() == "room"


def test_new_engagement_pentest_full(eng_vault):
    r = _run_new(eng_vault, "pt", "pentest")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "pt"
    for f in ("oob.md", "Vuln-index.md", "Killchain.md", "log.md", "walkthrough.md", "eval.md"):
        assert (d / f).exists()          # full set (backward compat, unaffected by the ctf trim)
    assert not (d / "coverage.md").exists()   # coverage retired -> board 4a table
    assert (d / "poc").is_dir()          # poc/ now scaffolded at init


def test_new_engagement_campaign_files_pentest_bb_only(eng_vault):
    r = _run_new(eng_vault, "pt2", "pentest")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "pt2"
    for f in ("identities.md", "source-ledger.md", "write-ledger.md"):
        assert (d / f).exists()
    assert not (d / "decisions.md").exists()   # decisions.md is on-demand for every type


def test_new_engagement_ctf_omits_campaign_driver_files(eng_vault):
    r = _run_new(eng_vault, "room7", "ctf")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "room7"
    for f in ("identities.md", "source-ledger.md", "write-ledger.md", "decisions.md"):
        assert not (d / f).exists()


def test_new_engagement_ctf_with_flags(eng_vault):
    r = _run_new(eng_vault, "room2", "ctf", "--with-oob")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "room2"
    assert (d / "oob.md").exists()
    assert not (d / "coverage.md").exists()     # coverage retired
    assert not (d / "Vuln-index.md").exists()   # ctf still omits the severity index


def test_new_engagement_scope_seeds_in_scope_bullet(eng_vault):
    r = _run_new(eng_vault, "room3", "ctf", "--scope", "10.10.10.5")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "room3"
    scope_text = (d / "scope.md").read_text()
    assert "- 10.10.10.5" in scope_text
    parsed = _engagement.scope(str(d))
    assert parsed["in_scope"] == ["10.10.10.5"]


def test_new_engagement_scope_repeatable_flag_preserves_order(eng_vault):
    r = _run_new(eng_vault, "room4", "ctf", "--scope", "10.10.10.5", "--scope", "example.com")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "room4"
    scope_text = (d / "scope.md").read_text()
    assert "- 10.10.10.5" in scope_text
    assert "- example.com" in scope_text
    parsed = _engagement.scope(str(d))
    assert parsed["in_scope"] == ["10.10.10.5", "example.com"]


def test_new_engagement_no_scope_flag_unchanged(eng_vault):
    r = _run_new(eng_vault, "room5", "ctf")
    assert r.returncode == 0, r.stderr
    d = eng_vault / "targets" / "room5"
    parsed = _engagement.scope(str(d))
    assert parsed["in_scope"] == []


def test_targets_md_documents_ctf_chain_split():
    p = os.path.join(REPO, "targets", "TARGETS.md")
    if not os.path.exists(p):
        pytest.skip("targets/TARGETS.md is gitignored; local-only check")
    t = open(p, encoding="utf-8").read()
    assert "## Chain" in t and "## Status" in t   # ctf's Killchain/log split documented


def test_new_engagement_scope_rejects_malformed_value(eng_vault):
    r = _run_new(eng_vault, "room6", "ctf", "--scope", "bad host;rm")
    assert r.returncode == 0, r.stderr    # creation still succeeds
    d = eng_vault / "targets" / "room6"
    scope_text = (d / "scope.md").read_text()
    in_scope_section = scope_text.split("## In scope")[1].split("## Out of scope")[0]
    assert "bad host" not in in_scope_section
    assert ";" not in in_scope_section
    assert "rm" not in in_scope_section
    parsed = _engagement.scope(str(d))
    assert "bad host;rm" not in parsed["in_scope"]
    assert parsed["in_scope"] == []


def test_new_engagement_rename_resubs_title(eng_vault):
    _run_new(eng_vault, "old-room", "ctf")
    assert "Scope - old-room" in (eng_vault / "targets" / "old-room" / "scope.md").read_text()
    r = _run_new(eng_vault, "--rename", "old-room", "new-room")
    assert r.returncode == 0, r.stderr
    assert not (eng_vault / "targets" / "old-room").exists()
    new_scope = (eng_vault / "targets" / "new-room" / "scope.md").read_text()
    assert "Scope - new-room" in new_scope   # title + H1 re-substituted
    assert "old-room" not in new_scope       # stale name gone from this file
    assert (eng_vault / "targets" / "active.md").read_text().strip() == "new-room"


def test_new_engagement_rename_rejects_path_traversal(eng_vault):
    """FIND: --rename used OLD raw in SRC="$VAULT/targets/$OLD", so an OLD of
    "../setup/templates" resolved outside targets/ entirely and got mv'd. Runs
    against the eng_vault's OWN copied templates dir (never the real repo's),
    so even an unpatched script can only damage the disposable tmp fixture."""
    templates_dir = eng_vault / "setup" / "templates"
    before = sorted(str(p.relative_to(templates_dir)) for p in templates_dir.rglob("*"))
    assert before, "fixture template tree must be non-empty for this test to mean anything"

    r = _run_new(eng_vault, "--rename", "../setup/templates", "whatever")

    assert r.returncode != 0, r.stdout + r.stderr
    assert templates_dir.is_dir()
    after = sorted(str(p.relative_to(templates_dir)) for p in templates_dir.rglob("*"))
    assert after == before                                   # untouched, nothing moved out
    assert not (eng_vault / "targets" / "whatever").exists()  # nothing moved in either


def test_new_engagement_rename_rejects_dotdot(eng_vault):
    """OLD=".." resolves SRC to the vault root ($VAULT/targets/.. == $VAULT).
    Must be rejected before any mv is attempted."""
    r = _run_new(eng_vault, "--rename", "..", "whatever")

    assert r.returncode != 0, r.stdout + r.stderr
    assert not (eng_vault / "targets" / "whatever").exists()
    assert (eng_vault / "setup").is_dir()   # vault root untouched


def test_new_engagement_rename_rejects_sanitized_dotdot(eng_vault):
    """Validate-then-mutate: OLD_RAW=".!." is not literally "."/".."/empty and
    has no "/", so it passes the raw-input case reject above. But the sanitizer
    (tr ' /' '--' | tr -cd 'A-Za-z0-9._-') strips the "!" and collapses it to
    "..", and the SANITIZED value is what SRC is actually built from
    ("$VAULT/targets/.." == the vault root) - the checked variable (raw) is not
    the used variable (sanitized). Today this only fails because `mv` happens
    to refuse to move a dir into its own subtree/cwd; that is an accident, not
    a guard, so this asserts an EXPLICIT reject message, not just a nonzero
    exit."""
    _run_new(eng_vault, "existing-room", "ctf")   # a real engagement must survive untouched

    templates_dir = eng_vault / "setup" / "templates"
    templates_before = sorted(str(p.relative_to(templates_dir)) for p in templates_dir.rglob("*"))
    targets_before = sorted(p.name for p in (eng_vault / "targets").iterdir())

    r = _run_new(eng_vault, "--rename", ".!.", "whatever")

    assert r.returncode != 0, r.stdout + r.stderr
    combined = (r.stdout + r.stderr).lower()
    assert "error" in combined and "sanitiz" in combined, (
        "must be an explicit reject naming the sanitized-value collapse, "
        f"not an incidental mv failure: {r.stdout + r.stderr}")
    assert templates_dir.is_dir()
    templates_after = sorted(str(p.relative_to(templates_dir)) for p in templates_dir.rglob("*"))
    assert templates_after == templates_before                # nothing moved out of templates/
    targets_after = sorted(p.name for p in (eng_vault / "targets").iterdir())
    assert targets_after == targets_before                     # engagement dirs untouched
    assert not (eng_vault / "targets" / "whatever").exists()   # nothing moved in either


def test_find_md_headings_lock_to_find_lint():
    """_find.md is the single source of truth: each required heading must satisfy
    exactly one find-lint REQUIRED regex, and References stays optional."""
    fl = _load("scripts/find-lint.py", "fl_lock")
    text = open(os.path.join(REPO, "setup", "templates", "_find.md"), encoding="utf-8").read()
    heads = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("## ")]
    assert heads == ["## Description", "## Proof of Concept", "## Impact",
                     "## Remediation", "## References"]
    for label, rx in fl.REQUIRED.items():
        matched = [h for h in heads if re.match(rx, h, re.I)]
        assert len(matched) == 1, f"{label} matched {matched}"
    assert not any(re.match(rx, "## References", re.I) for rx in fl.REQUIRED.values())


def test_find_lint_accepts_find_md_shaped_finding(tmp_path):
    fl = _load("scripts/find-lint.py", "fl_shape")
    body = ("---\nseverity: MEDIUM\ncvss: \"\"\naffected: api.x\n---\n"
            "# t\n## Description\nBroken access control on the report endpoint here.\n"
            "## Proof of Concept\nGET /report/2 returns another user's data verbatim.\n"
            "## Impact\nAny authenticated user reads every other user's report data.\n"
            "## Remediation\nEnforce an object-level ownership check on the endpoint.\n"
            "## References\nOWASP API1:2023.\n")
    f = tmp_path / "FIND-003-MEDIUM-idor.md"
    f.write_text(body)
    issues, warnings = fl.lint_file(str(f))
    assert issues == []      # MEDIUM: no cvss/vector required; affected non-empty; all sections present


def test_targets_md_finding_template_is_pointer():
    p = os.path.join(REPO, "targets", "TARGETS.md")
    if not os.path.exists(p):
        pytest.skip("targets/TARGETS.md is gitignored; local-only check")
    t = open(p, encoding="utf-8").read()
    assert "setup/templates/_find.md" in t          # points at the single source
    for stale in ("## Summary", "## Reproduction", "## Evidence", "## Retest Notes"):
        assert stale not in t                        # divergent inline template removed


def test_targets_md_tree_matches_scaffold():
    p = os.path.join(REPO, "targets", "TARGETS.md")
    if not os.path.exists(p):
        pytest.skip("targets/TARGETS.md is gitignored; local-only check")
    t = open(p, encoding="utf-8").read()
    assert "poc/" in t                                  # scaffolded for all types
    assert "first FIND" in t                            # Vulns/ documented as lazy
    assert "Killchain.md" in t and "walkthrough.md" in t    # one live + one final attack-chain home
    assert "ctf" in t.lower()                           # ctf-specific omissions noted
    for phantom in ("├── scope/", "└── reports/"):      # never auto-scaffolded -> not promised as auto
        assert phantom not in t


def test_ctf_state_template_has_chain_and_status_sections():
    p = os.path.join(REPO, "setup", "templates", "ctf", "state.md")
    text = open(p, encoding="utf-8").read()
    assert "## Chain" in text
    assert "## Status" in text
    # both live AFTER the host table, so a mid-box SOLVED edit can never split it again
    assert text.index("## Chain") > text.index("| target | service")
    assert text.index("## Status") > text.index("## Chain")


def test_scope_template_comments_moved_to_frontmatter():
    p = os.path.join(REPO, "setup", "templates", "_scope.md")
    text = open(p, encoding="utf-8").read()
    _, fm, body = text.split("---", 2)
    assert "<!--" not in body
    for hint in ("In scope", "Out of scope", "Allowed tooling", "Rules of engagement"):
        assert hint in fm


def test_ensure_optional_backfills_decisions(vault, monkeypatch):
    eng = _mk(vault / "targets" / "room8", "ctf")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    assert not (eng / "decisions.md").exists()
    assert _engagement.ensure_optional_file("decisions") == "decisions.md"
    txt = (eng / "decisions.md").read_text()
    assert "## Decision log" in txt and "room8" in txt
    assert _engagement.ensure_optional_file("decisions") == ""   # already exists -> ''
