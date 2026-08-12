"""Tests for chains.json + its _engagement readers + phase_explicit."""
import json
import os

import _engagement


def _mkfind(eng, name, fm, body="x"):
    d = eng / "Vulns"
    d.mkdir(parents=True, exist_ok=True)
    fmtxt = "\n".join(f"{k}: {v}" for k, v in fm.items())
    (d / name).write_text(f"---\n{fmtxt}\n---\n\n# {fm.get('title', name)}\n\n{body}\n",
                          encoding="utf-8")


VULN_INDEX = """---
type: engagement-vuln-index
---

# Vuln Index

## CRITICAL

| ID | Title | Host | Status |
|----|-------|------|--------|
| FIND-001 | SSRF in fetch | web01 | CONFIRMED |

## HIGH

| ID | Title | Host | Status |
|----|-------|------|--------|
| FIND-002 | IDOR on profile | web02 | PARTIAL (needs victim id) |
| FIND-003 | XSS reflected | web03 | VERSION CONFIRMED / PoC pending |
| FIND-004 | Old bug | web04 | CLOSED |

## Severity Count

| Severity | Count | Confirmed | Notes |
|----------|-------|-----------|-------|
| Critical | 1 | 1 | CONFIRMED |
"""


def test_vuln_index_confirmed_ids(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Vuln-index.md").write_text(VULN_INDEX, encoding="utf-8")
    ids = _engagement._vuln_index_confirmed_ids(str(eng))
    # CONFIRMED + PARTIAL kept; VERSION CONFIRMED / CLOSED / Severity-Count excluded
    assert ids == {"FIND-001": "web01", "FIND-002": "web02"}


def test_confirmed_findings_gated_and_classed(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Vuln-index.md").write_text(VULN_INDEX, encoding="utf-8")
    # FIND-001 has explicit class; FIND-002 relies on fuzzy title; FIND-003 is not confirmed
    _mkfind(eng, "FIND-001-CRITICAL-ssrf-fetch.md",
            {"title": "SSRF in fetch", "class": "ssrf", "affected": "web01", "status": "Research"})
    _mkfind(eng, "FIND-002-HIGH-idor-profile.md",
            {"title": "IDOR on profile", "affected": "web02", "status": "Research"})
    _mkfind(eng, "FIND-003-MEDIUM-xss.md",
            {"title": "XSS reflected", "affected": "web03", "status": "Research"})
    got = {(f["class"], f["asset"], f["severity"]) for f in _engagement.confirmed_findings(str(eng))}
    assert ("ssrf", "web01", "CRITICAL") in got     # explicit class + severity from filename
    assert ("idor", "web02", "HIGH") in got         # fuzzy class from title
    assert not any(a == "web03" for _, a, _ in got)  # not confirmed -> excluded


def test_confirmed_findings_missing_files(tmp_path):
    assert _engagement.confirmed_findings(str(tmp_path / "nope")) == []


# Synthetic-only: markdown-linked IDs and decorated statuses, as seen in real
# Vuln-index.md files but never copying real client rows.
VULN_INDEX_DECORATED = """---
type: engagement-vuln-index
---

# Vuln Index

## CRITICAL

| ID | Title | Host | Status |
|----|-------|------|--------|
| [FIND-005](FIND-005-HIGH-x.md) | Linked finding | web05 | CONFIRMED |
| FIND-006 | Emoji confirmed | web06 | ✅ CONFIRMED (Flag 1) |
| FIND-007 | Bold confirmed | web07 | **CONFIRMED HIGH** (x) |
| FIND-008 | Version confirmed | web08 | VERSION CONFIRMED / PoC pending |
| FIND-009 | Closed | web09 | CLOSED |
"""


def test_vuln_index_confirmed_ids_linked_and_decorated(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Vuln-index.md").write_text(VULN_INDEX_DECORATED, encoding="utf-8")
    ids = _engagement._vuln_index_confirmed_ids(str(eng))
    # markdown-linked ID cell + emoji/bold-decorated status all still count as CONFIRMED;
    # VERSION CONFIRMED / PoC pending and CLOSED still excluded
    assert ids == {"FIND-005": "web05", "FIND-006": "web06", "FIND-007": "web07"}


def test_confirmed_findings_comma_split_affected(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Vuln-index.md").write_text(VULN_INDEX, encoding="utf-8")
    _mkfind(eng, "FIND-001-CRITICAL-ssrf-fetch.md",
            {"title": "SSRF in fetch", "class": "ssrf", "affected": "web08a, web08b",
             "status": "Research"})
    got = _engagement.confirmed_findings(str(eng))
    assert sorted(f["asset"] for f in got) == ["web08a", "web08b"]


def test_chains_json_schema_valid():
    vocab = _engagement._class_vocab()
    chains = json.load(open(os.path.join(_engagement.VAULT, "scripts", "chains.json"), encoding="utf-8"))
    edges = chains["edges"]
    assert edges, "chains.json must define at least one edge"
    for src, spec in edges.items():
        assert src.lower() in vocab, f"edge source class {src} not in vocab"
        assert spec["then"], f"edge {src} has no candidates"
        for c in spec["then"]:
            assert c["to_class"].lower() in vocab, f"{src}->{c['to_class']} to_class not in vocab"
            assert isinstance(c["to_phase"], int)
            assert isinstance(c["gain"], int) and 0 <= c["gain"] <= 3
            assert c["cost"] in ("cheap", "medium", "expensive")
            assert isinstance(c["likelihood"], (int, float)) and 0.0 <= c["likelihood"] <= 1.0
            assert c["gate"] in (None, "oob")
            assert c["skill"] is None or isinstance(c["skill"], str)
            assert isinstance(c["move"], str) and c["move"]


KILLCHAIN = """---
type: engagement-approach
current_phase: "Phase 5 Post-Ex"
entered_because: "FIND-001 RCE on web01 (CONFIRMED) -> post-ex edge"
---

## 1. Recon
- [ ] rustscan
"""


def test_phase_explicit_prefers_field(tmp_path, monkeypatch):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Approach.md").write_text(KILLCHAIN, encoding="utf-8")
    monkeypatch.setattr(_engagement, "scope",
                        lambda d=None: {"in_scope": [], "out_of_scope": []})
    assert _engagement.phase_explicit(str(eng)) == "Phase 5 Post-Ex"


def test_phase_explicit_ignores_out_of_scope_citation(tmp_path, monkeypatch):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Approach.md").write_text(KILLCHAIN, encoding="utf-8")
    monkeypatch.setattr(_engagement, "scope",
                        lambda d=None: {"in_scope": [], "out_of_scope": ["web01"]})
    assert _engagement.phase_explicit(str(eng)) is None   # citation names an out-of-scope host


def test_phase_explicit_absent_field(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Approach.md").write_text("---\ntype: engagement-approach\n---\n\n## 1. Recon\n",
                                      encoding="utf-8")
    assert _engagement.phase_explicit(str(eng)) is None


def test_tested_classes_honors_explicit_class(tmp_path):
    eng = tmp_path / "eng"
    (eng / "Vulns").mkdir(parents=True)
    # title says nothing matchable; explicit class: ssrf must still credit ssrf
    (eng / "Vulns" / "FIND-009-HIGH-weird-name.md").write_text(
        "---\ntitle: weird name\nclass: ssrf\naffected: web09\nstatus: Research\n---\n\nx\n",
        encoding="utf-8")
    per_asset, _glob = _engagement.tested_classes(str(eng), "bugbounty",
                                                  ["ssrf", "rce", "idor"])
    assert "ssrf" in per_asset.get("web09", set())


def test_approach_templates_document_phase_keys():
    for etype in ("pentest", "bugbounty", "ctf"):
        # use _engagement.VAULT (repo-root self-location); _engagement.py is in skills/hooks/,
        # so dirname(dirname(__file__)) would wrongly land in skills/.
        txt = open(os.path.join(_engagement.VAULT, "setup", "templates", etype, "Approach.md"),
                   encoding="utf-8").read()
        assert "current_phase" in txt, f"{etype} Approach.md missing current_phase key"
        assert "entered_because" in txt, f"{etype} Approach.md missing entered_because key"
