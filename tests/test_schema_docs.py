import os
HERE = os.path.dirname(os.path.abspath(__file__)); VAULT = os.path.dirname(HERE)


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
