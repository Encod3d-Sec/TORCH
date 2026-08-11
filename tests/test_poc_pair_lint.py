import importlib.util
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("ppl", REPO / "scripts" / "poc-pair-lint.py")
ppl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ppl)


def test_paired_files_are_clean(tmp_path):
    (tmp_path / "01-thing.png").write_bytes(b"\x89PNG")
    (tmp_path / "01-thing-source.md").write_text("# card\n")
    assert ppl.lint_dir(tmp_path) == []


def test_image_without_card_is_reported(tmp_path):
    (tmp_path / "02-lonely.png").write_bytes(b"\x89PNG")
    issues = ppl.lint_dir(tmp_path)
    assert [f for f, _ in issues] == ["02-lonely.png"]
    assert "source card" in issues[0][1]


def test_card_without_image_is_reported(tmp_path):
    (tmp_path / "03-orphan-source.md").write_text("# card\n")
    issues = ppl.lint_dir(tmp_path)
    assert [f for f, _ in issues] == ["03-orphan-source.md"]
    assert "image" in issues[0][1]


def test_jpg_counts_as_an_image(tmp_path):
    (tmp_path / "04-shot.jpg").write_bytes(b"\xff\xd8")
    (tmp_path / "04-shot-source.md").write_text("# card\n")
    assert ppl.lint_dir(tmp_path) == []


def test_missing_dir_is_clean_not_an_error(tmp_path):
    assert ppl.lint_dir(tmp_path / "nope") == []


def test_main_returns_1_on_issues_and_0_when_clean(tmp_path, capsys):
    (tmp_path / "05-lonely.png").write_bytes(b"\x89PNG")
    assert ppl.main([str(tmp_path)]) == 1
    (tmp_path / "05-lonely-source.md").write_text("# card\n")
    assert ppl.main([str(tmp_path)]) == 0


def test_foreign_md_files_are_ignored(tmp_path):
    (tmp_path / "06-thing.png").write_bytes(b"\x89PNG")
    (tmp_path / "06-thing-source.md").write_text("# card\n")
    (tmp_path / "06-thing-snippet.md").write_text("# other\n")
    assert ppl.lint_dir(tmp_path) == []


def test_main_with_empty_argv_returns_2(capsys):
    assert ppl.main([]) == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err
