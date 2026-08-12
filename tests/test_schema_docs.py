import os
HERE = os.path.dirname(os.path.abspath(__file__)); VAULT = os.path.dirname(HERE)


def test_page_types_defines_new_names():
    txt = open(os.path.join(VAULT, "docs", "page-types.md")).read()
    assert "Approach.md" in txt and "Killchain.md" in txt
    assert "| `paths.md` |" not in txt and "| `killchain.md` |" not in txt


def test_claudemd_file_set_updated():
    txt = open(os.path.join(VAULT, "CLAUDE.md")).read()
    assert "Approach.md" in txt and "Killchain.md" in txt
