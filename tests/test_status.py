"""Tests for scripts/status.py (on-demand engagement dashboard).

Hyphen-free filename, but load via importlib to match the suite pattern and keep
the sys.path shim isolated.
"""
import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    spec = importlib.util.spec_from_file_location(
        "status_mod", os.path.join(REPO, "scripts", "status.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_evidence_counts_recursive(tmp_path):
    st = _load()
    (tmp_path / "poc").mkdir()
    (tmp_path / "poc" / "sub").mkdir()
    (tmp_path / "recon").mkdir()
    (tmp_path / "poc" / "a.png").write_bytes(b"x")
    (tmp_path / "poc" / "sub" / "b.png").write_bytes(b"x")   # nested counts
    (tmp_path / "recon" / "c.png").write_bytes(b"x")
    (tmp_path / "poc" / "notes.txt").write_text("x")          # non-png ignored
    assert st.evidence_counts(str(tmp_path)) == (2, 1)


def test_deadend_lines_skips_template_placeholder(tmp_path):
    st = _load()
    (tmp_path / "Deadends.md").write_text(
        "# Deadends\n\n- [ ]\n- rockyou brute on SSH: 0 hits, ~40h ETA\n-\n",
        encoding="utf-8")
    lines = st.deadend_lines(str(tmp_path))
    assert lines == ["rockyou brute on SSH: 0 hits, ~40h ETA"]


def test_board_phase_picks_highest_open(tmp_path):
    st = _load()
    (tmp_path / "Approach.md").write_text(
        "## 1. Recon\n- [x] nmap\n## 2. Weaponize\n- [ ] pick payload\n"
        "## 4. Exploit\n- [~] foothold\n- [!] dead vector\n", encoding="utf-8")
    where, open_n, dead_n = st.board_phase(str(tmp_path))
    assert where == "Phase 4 Exploit"
    assert open_n == 2 and dead_n == 1


def test_board_phase_prefers_explicit_current_phase_over_heuristic(tmp_path):
    st = _load()
    (tmp_path / "scope.md").write_text(
        "## In Scope\n- host1.internal\n## Out of Scope\n- other.internal\n",
        encoding="utf-8")
    (tmp_path / "Approach.md").write_text(
        "---\n"
        "current_phase: Phase 2 Weaponize (explicit)\n"
        "entered_because: pivot via host1.internal\n"
        "---\n"
        "## 1. Recon\n- [x] nmap\n"
        "## 4. Exploit\n- [ ] foothold\n- [!] dead vector\n",
        encoding="utf-8")
    where, open_n, dead_n = st.board_phase(str(tmp_path))
    # explicit frontmatter field wins over the heuristic, which would otherwise
    # report "Phase 4 Exploit" from the highest-numbered phase with an open item
    assert where == "Phase 2 Weaponize (explicit)"
    assert open_n == 1 and dead_n == 1


def test_render_composes_dashboard():
    st = _load()
    summ = {"hosts": 5, "owned": 1, "creds": 3, "open_paths": 0}
    out = st.render("acme", "ctf", True, summ, ("Phase 4 Exploit", 2, 1),
                    2, 0, ["foo failed"], "Next moves (acme):\n 1. do x")
    assert "acme (ctf)  STATUS: SOLVED" in out
    assert "hosts 5 (owned 1) | creds 3 | open paths 0" in out
    assert "board: Phase 4 Exploit | 2 open | 1 deadends" in out
    assert "evidence: 2 poc shot(s), 0 recon card(s)" in out
    assert "- foo failed" in out
    assert "Next moves (acme)" in out


def test_board_phase_none_when_no_board(tmp_path):
    st = _load()
    assert st.board_phase(str(tmp_path)) is None


def test_render_coverage_marks_tested_and_untested():
    st = _load()
    out = st.render_coverage(["rce", "sqli", "ssrf"], ["a.x", "b.x"], {"a.x": {"rce"}})
    assert "coverage matrix" in out
    lines = out.splitlines()
    a_line = next(l for l in lines if l.strip().startswith("a.x"))
    b_line = next(l for l in lines if l.strip().startswith("b.x"))
    # per-asset grid cells follow the base-class order (rce, sqli, ssrf)
    assert a_line.split()[1:4] == ["x", ".", "."] and "(1/3)" in a_line
    assert b_line.split()[1:4] == [".", ".", "."] and "(0/3)" in b_line
    assert "class order: rce sqli ssrf" in out


def test_render_coverage_empty_when_no_assets():
    st = _load()
    assert "no in-scope assets" in st.render_coverage(["rce"], [], {})
