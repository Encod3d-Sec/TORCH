"""ensure_state_files migrates pre-swap killchain.md/paths.md to Approach.md/Killchain.md."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
import _engagement as E


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
