"""Schema/docs wiring: page-types + layout + CLAUDE.md document the Approach/Killchain rename and the
ctf-lean file set; the templates carry the expected headers; and _engagement._migrate_schema_names
renames pre-swap killchain.md/paths.md. Consolidated from the former test_schema_* family."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
import _engagement as E  # noqa: E402


# --- docs / CLAUDE.md name + lean-set documentation (was test_schema_docs) ---
def test_page_types_defines_new_names():
    txt = open(os.path.join(VAULT, "docs", "page-types.md")).read()
    assert "Approach.md" in txt and "Killchain.md" in txt
    assert "| `paths.md` |" not in txt and "| `killchain.md` |" not in txt


def test_claudemd_file_set_updated():
    txt = open(os.path.join(VAULT, "CLAUDE.md")).read()
    assert "Approach.md" in txt and "Killchain.md" in txt


def test_page_types_documents_ctf_lean_set():
    txt = open(os.path.join(VAULT, "docs", "page-types.md")).read()
    assert "lean" in txt.lower() and "eval.md" in txt
    assert "Killchain.md" in txt and "pentest/bugbounty" in txt


def test_layout_md_documents_ctf_lean_set():
    txt = open(os.path.join(VAULT, "docs", "layout.md")).read()
    assert "ctf: lean" in txt.lower()


def test_claudemd_documents_ctf_lean_set():
    txt = open(os.path.join(VAULT, "CLAUDE.md")).read()
    assert "ctf files (lean" in txt.lower()


# --- template headers (was test_schema_enrichment) ---
def test_killchain_templates_have_confirmed_chain_header():
    # ctf has no Killchain.md template (pentest/bugbounty-only per the ctf scaffold trim; a ctf's
    # live chain lives in state.md's ## Chain/## Status sections instead).
    for t in ("pentest", "bugbounty"):
        txt = open(os.path.join(VAULT, "setup", "templates", t, "Killchain.md")).read()
        assert "## Confirmed chain so far" in txt
    assert not os.path.exists(os.path.join(VAULT, "setup", "templates", "ctf", "Killchain.md"))


def test_decisions_template_has_decision_log():
    txt = open(os.path.join(VAULT, "setup", "templates", "_decisions.md")).read()
    assert "## Decision log" in txt


# --- _migrate_schema_names (was test_schema_migration) ---
def test_migration_renames_and_rewrites_type(tmp_path, monkeypatch):
    d = tmp_path / "eng"; d.mkdir()
    (d / "killchain.md").write_text("---\ntype: engagement-killchain\n---\n\n### 4a\n| id |\n")
    (d / "paths.md").write_text("---\ntype: engagement-paths\n---\n\n# Paths\n")
    E._migrate_schema_names(str(d))
    assert (d / "Approach.md").exists() and not (d / "killchain.md").exists()
    assert (d / "Killchain.md").exists() and not (d / "paths.md").exists()
    assert "type: engagement-approach" in (d / "Approach.md").read_text()
    assert "type: engagement-killchain" in (d / "Killchain.md").read_text()


def test_migration_idempotent_and_nondestructive(tmp_path):
    d = tmp_path / "eng"; d.mkdir()
    (d / "Approach.md").write_text("keep-me")
    (d / "killchain.md").write_text("do-not-clobber")
    E._migrate_schema_names(str(d))              # Approach.md exists -> skip, do not overwrite
    assert (d / "Approach.md").read_text() == "keep-me"
    E._migrate_schema_names(str(d))              # second run is a no-op
    assert (d / "Approach.md").read_text() == "keep-me"
