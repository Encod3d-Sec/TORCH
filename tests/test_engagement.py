"""Tests for _engagement.py: parser, type detection, summary, log, self-heal."""
import os

import _engagement


def test_parse_table_padded_and_separator(vault):
    rows = _engagement._parse_table(str(vault / "targets" / "acme" / "state.md"))
    assert len(rows) == 2
    assert rows[0]["host"] == "WS1"
    assert rows[0]["signing"] == "False"
    assert rows[1]["access"] == "none"


def test_parse_table_missing_file(tmp_path):
    assert _engagement._parse_table(str(tmp_path / "nope.md")) == []


def test_active_dir_from_pointer(vault):
    assert os.path.basename(_engagement.active_dir()) == "acme"


def test_engagement_type_reads_frontmatter(vault):
    assert _engagement.engagement_type() == "pentest"


def test_engagement_type_defaults_pentest(tmp_path, monkeypatch):
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(tmp_path))
    assert _engagement.engagement_type() == "pentest"


def test_summary_counts(vault):
    s = _engagement.summary()
    assert s["name"] == "acme"
    assert s["hosts"] == 2
    assert s["open_paths"] == 1  # dead path excluded


def test_recent_log_returns_newest_block(vault):
    rl = _engagement.recent_log()
    assert "entry one" in rl
    assert "intro" not in rl  # header intro skipped


def test_ensure_state_files_creates_missing(vault, monkeypatch):
    eng = vault / "targets" / "fresh"
    os.makedirs(eng)
    (eng / "state.md").write_text(
        "---\ntype: engagement-state\nengagement_type: bugbounty\n---\n", encoding="utf-8")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    created = _engagement.ensure_state_files()
    assert "loot.md" in created and "paths.md" in created
    assert "log.md" in created and "ingest/" in created
    # bugbounty template used -> bugbounty column present
    assert "asset" in (eng / "state.md").read_text() or (eng / "loot.md").exists()
    assert (eng / "ingest").is_dir()


def test_state_files_includes_killchain():
    assert "killchain.md" in _engagement.STATE_FILES


def test_recon_dir_not_scaffolded():
    assert "recon" not in _engagement.STATE_DIRS
    assert "ingest" in _engagement.STATE_DIRS and "poc" in _engagement.STATE_DIRS


def _load_engagement_init():
    import importlib.util
    p = os.path.join(os.path.dirname(_engagement.__file__), "engagement-init.py")
    spec = importlib.util.spec_from_file_location("engagement_init", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_board_status_surfaces_phase_and_counts(vault, monkeypatch):
    ei = _load_engagement_init()
    eng = vault / "targets" / "acme"
    (eng / "killchain.md").write_text(
        "# Kill-Chain Board\n\n"
        "## 1. Recon\n- [x] rustscan\n- [ ] nmap\n\n"
        "## 4. Exploit\n### 4a. Foothold\n- [~] sqli\n- [!] xxe deadend\n",
        encoding="utf-8")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    s = ei.board_status()
    assert s is not None
    assert "Phase 4 Exploit" in s   # highest-numbered phase with an open item
    assert "2 open" in s            # [ ] nmap + [~] sqli
    assert "1 deadends" in s        # [!] xxe


def test_board_status_none_without_board(vault, monkeypatch):
    eng = vault / "targets" / "noboard"
    os.makedirs(eng)
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    assert _load_engagement_init().board_status() is None


def test_harness_maintenance_returns_list(vault, monkeypatch):
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(vault / "targets" / "acme"))
    assert isinstance(_load_engagement_init().harness_maintenance(), list)


def test_killchain_healed_for_every_type(vault, monkeypatch):
    for etype in ("ctf", "pentest", "bugbounty"):
        eng = vault / "targets" / ("kc_" + etype)
        os.makedirs(eng)
        (eng / "state.md").write_text(
            "---\ntype: engagement-state\nengagement_type: %s\n---\n" % etype, encoding="utf-8")
        monkeypatch.setattr(_engagement, "active_dir", lambda e=eng: str(e))
        _engagement.ensure_state_files()
        board = eng / "killchain.md"
        assert board.exists()
        text = board.read_text()
        assert "Kill-Chain Board" in text
        assert "engagement_type: %s" % etype in text
        assert "<ENGAGEMENT>" not in text and "<DATE>" not in text
        assert "{{ENGAGEMENT}}" not in text and "{{DATE}}" not in text  # heal substituted the {{ }} tokens
        assert "GATE 1 (wiki)" in text


def test_scope_parse(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\ntype: engagement-scope\nno_bruteforce: true\npassive_only: false\n---\n\n"
        "# Scope\n\n## In scope\n- 10.0.0.0/24\n- app.example.com\n\n"
        "## Out of scope\n- prod-db.example.com\n\n"
        "## Allowed tooling\n- nmap, manual\n\n## Rules of engagement\n- 9-5 only\n",
        encoding="utf-8")
    s = _engagement.scope()
    assert s["no_bruteforce"] is True and s["passive_only"] is False
    assert "10.0.0.0/24" in s["in_scope"] and "app.example.com" in s["in_scope"]
    assert s["out_of_scope"] == ["prod-db.example.com"]
    assert s["roe"] == ["9-5 only"]


def test_out_of_scope_match():
    sc = {"out_of_scope": ["prod-db", "10.9.9.0/24"]}
    assert _engagement.out_of_scope_match("prod-db.example.com", sc) is True   # label prefix
    assert _engagement.out_of_scope_match("prod-db", sc) is True               # exact
    assert _engagement.out_of_scope_match("10.9.9.42", sc) is True             # in CIDR
    assert _engagement.out_of_scope_match("ws1", sc) is False
    assert _engagement.out_of_scope_match("", sc) is False


def test_out_of_scope_no_substring_overmatch():
    # the old bidirectional-substring bug flagged these; boundary match must not
    sc = {"out_of_scope": ["db", "corp.com"]}
    assert _engagement.out_of_scope_match("db-staging", sc) is False   # not 'db.' prefix
    assert _engagement.out_of_scope_match("mydbserver", sc) is False
    assert _engagement.out_of_scope_match("notcorp.com", sc) is False  # not '.corp.com' suffix
    assert _engagement.out_of_scope_match("api.corp.com", sc) is True  # real subdomain


def test_scope_entry_match_no_dotted_label_confusion():
    # BUG (pre-fix): a dotted/IP scope entry's label-prefix arm wrongly matched an
    # attacker-controlled host that merely starts with the scope entry as a string
    # prefix (10.0.0.9 -> 10.0.0.9.evil.com). This let <scope>.evil.com be judged
    # in-scope, which the poc/pages capture gate then treats as safe to write to disk.
    assert _engagement._scope_entry_match("10.0.0.9.evil.com", "10.0.0.9") is False
    assert _engagement._scope_entry_match("example.com.evil.com", "example.com") is False


def test_scope_entry_match_preserved_cases():
    # bare-label prefix (no dot in the scope entry) still matches (advisory default)
    assert _engagement._scope_entry_match("prod-db.corp.com", "prod-db") is True
    # parent-domain suffix match (endswith arm) is untouched
    assert _engagement._scope_entry_match("api.example.com", "example.com") is True
    # exact match
    assert _engagement._scope_entry_match("10.0.0.9", "10.0.0.9") is True
    # CIDR match
    assert _engagement._scope_entry_match("10.0.0.9", "10.0.0.0/24") is True


def test_scope_entry_match_url_and_wildcard():
    # 1.2: a URL-form entity reduces to its bare host, and a *.dom wildcard entry
    # matches the apex + any subdomain. One function serves scope-guard (out-of-scope)
    # and next_move's in-scope allowlist gate, so both gain URL/wildcard handling.
    m = _engagement._scope_entry_match
    # URL-form entity vs a bare-host scope entry (scheme/port/path/query stripped)
    assert m("https://api.example.com/admin", "api.example.com") is True
    assert m("http://api.example.com:8443/x?u=1", "api.example.com") is True
    # bare-host entity vs a URL-form scope entry (path present, not a CIDR)
    assert m("api.example.com", "https://api.example.com/admin") is True
    # wildcard entry: apex + subdomain in, lookalike out
    assert m("api.example.com", "*.example.com") is True
    assert m("example.com", "*.example.com") is True
    assert m("api.evil.com", "*.example.com") is False
    assert m("notexample.com", "*.example.com") is False
    # a URL entity still resolves into a CIDR scope entry
    assert m("http://10.9.9.42:8080/", "10.9.9.0/24") is True


def test_scope_entry_match_strict_drops_spoofable_label_prefix():
    # The label-prefix arm is attacker-spoofable (anyone can register
    # <label>.attacker.tld), so under strict=True -- used by the poc/pages disk-write
    # gate -- it is dropped entirely. A bare-label entry like `prod-db` must NOT match
    # `prod-db.evil.com`, closing the leak the dotted-only guard from 9c858c0 missed.
    m = _engagement._scope_entry_match
    assert m("prod-db.evil.com", "prod-db", strict=True) is False
    assert m("localhost.evil.com", "localhost", strict=True) is False
    assert m("10.0.0.9.evil.com", "10.0.0.9", strict=True) is False
    assert m("example.com.evil.com", "example.com", strict=True) is False


def test_scope_entry_match_strict_preserves_safe_arms():
    # strict=True keeps the safe arms: exact host, exact FQDN, genuine subdomain of an
    # in-scope domain (parent-suffix), deep subdomain, and CIDR containment.
    m = _engagement._scope_entry_match
    assert m("10.0.0.9", "10.0.0.9", strict=True) is True
    assert m("prod-db.corp.local", "prod-db.corp.local", strict=True) is True
    assert m("api.example.com", "example.com", strict=True) is True
    assert m("a.b.example.com", "example.com", strict=True) is True
    assert m("10.0.0.9", "10.0.0.0/24", strict=True) is True


def test_scope_entry_match_advisory_default_keeps_label_prefix():
    # the advisory (default non-strict) label-prefix convenience is unchanged, so
    # scope-guard / next_move keep matching a bare-label entry against its FQDN forms.
    assert _engagement._scope_entry_match("prod-db.corp.com", "prod-db") is True


def test_scope_text(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\nno_dos: true\n---\n# Scope\n## In scope\n- a\n- b\n## Out of scope\n- c\n",
        encoding="utf-8")
    t = _engagement.scope_text()
    assert "in-scope 2" in t and "out-of-scope 1" in t and "no_dos" in t


def test_scope_empty_when_absent(vault):
    s = _engagement.scope()  # acme has no scope.md by default
    assert s["in_scope"] == [] and s["no_bruteforce"] is False
    assert _engagement.scope_text() == ""


def test_scope_parses_tunnel_safe(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: true\nno_dos: false\n---\n\n"
        "# Scope\n\n## In scope\n- 10.0.0.5\n", encoding="utf-8")
    s = _engagement.scope()
    assert s["tunnel_safe"] is True
    assert s["no_dos"] is False


def test_scope_tunnel_safe_defaults_false_when_absent(vault):
    # acme ships no scope.md by default -> every flag, tunnel_safe included, is False
    s = _engagement.scope()
    assert s["tunnel_safe"] is False


def test_scope_template_ships_tunnel_safe_false():
    # the shipped template must carry the flag so every new engagement gets it
    import os
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tpl = open(os.path.join(repo, "setup", "templates", "_scope.md"),
               encoding="utf-8").read()
    assert "tunnel_safe: false" in tpl


def test_ensure_is_idempotent(vault, monkeypatch):
    # acme already complete -> only log/ingest may be created once, second run none.
    # monkeypatch (not raw assignment) so active_dir reverts and does not poison later tests.
    import _engagement as e
    monkeypatch.setattr(e, "active_dir", lambda: str(vault / "targets" / "acme"))
    first = e.ensure_state_files()
    second = e.ensure_state_files()
    assert second == []


def test_ensure_creates_vuln_index_and_deadends(vault, monkeypatch):
    # both files are referenced by triage + ~30 hunt skills but had no template;
    # self-heal must create them with the engagement name substituted in.
    eng = vault / "targets" / "fjord"
    os.makedirs(eng)
    (eng / "state.md").write_text(
        "---\ntype: engagement-state\nengagement_type: pentest\n---\n", encoding="utf-8")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))

    created = _engagement.ensure_state_files()
    assert "Vuln-index.md" in created and "Deadends.md" in created

    vuln_index = eng / "Vuln-index.md"
    deadends = eng / "Deadends.md"
    assert vuln_index.exists() and deadends.exists()
    # placeholder substituted -> engagement name present, no raw <ENGAGEMENT> left
    assert "fjord" in vuln_index.read_text() and "<ENGAGEMENT>" not in vuln_index.read_text()
    assert "fjord" in deadends.read_text() and "<ENGAGEMENT>" not in deadends.read_text()

    # idempotent: a second run must not overwrite an edited file
    deadends.write_text("SENTINEL custom dead-end\n", encoding="utf-8")
    again = _engagement.ensure_state_files()
    assert "Vuln-index.md" not in again and "Deadends.md" not in again
    assert deadends.read_text() == "SENTINEL custom dead-end\n"


def test_ensure_does_not_create_engagement_hot_cache(vault, monkeypatch):
    # per-engagement hot.md was removed; log.md is the continuity cache now.
    eng = vault / "targets" / "hotfix"
    os.makedirs(eng)
    (eng / "state.md").write_text(
        "---\ntype: engagement-state\nengagement_type: pentest\n---\n", encoding="utf-8")
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(eng))
    created = _engagement.ensure_state_files()
    assert "hot.md" not in created
    assert not (eng / "hot.md").exists()
    assert "log.md" in created and (eng / "log.md").exists()   # continuity lives here now
    assert not hasattr(_engagement, "recent_hot")              # helper removed


# ---- is_solved / walkthrough_stale (walkthrough auto-assembly gate) --------------

def test_is_solved_true_on_status_heading(tmp_path):
    (tmp_path / "state.md").write_text(
        "---\ntype: engagement-state\n---\n\n# State\n\n## STATUS: SOLVED\n\nrooted.\n",
        encoding="utf-8")
    assert _engagement.is_solved(str(tmp_path)) is True


def test_is_solved_true_case_insensitive_and_owned_rooted_complete(tmp_path):
    for word in ("owned", "ROOTED", "Complete"):
        p = tmp_path / word
        p.mkdir()
        (p / "state.md").write_text("## status: %s\n" % word, encoding="utf-8")
        assert _engagement.is_solved(str(p)) is True, word


def test_is_solved_false_without_status_heading(tmp_path):
    (tmp_path / "state.md").write_text(
        "---\ntype: engagement-state\n---\n\n# State\n\n| host |\n|---|\n", encoding="utf-8")
    assert _engagement.is_solved(str(tmp_path)) is False


def test_is_solved_false_missing_file(tmp_path):
    assert _engagement.is_solved(str(tmp_path)) is False


def test_is_solved_false_none_dir():
    assert _engagement.is_solved(None) is False


def test_walkthrough_stale_true_when_missing(tmp_path):
    assert _engagement.walkthrough_stale(str(tmp_path)) is True


def test_walkthrough_stale_true_when_empty(tmp_path):
    (tmp_path / "walkthrough.md").write_text("   \n\n", encoding="utf-8")
    assert _engagement.walkthrough_stale(str(tmp_path)) is True


def test_walkthrough_stale_true_on_unfilled_template(tmp_path):
    (tmp_path / "walkthrough.md").write_text(
        "# Walkthrough\n\n**TL;DR chain:** `<entrypoint>` -> `<foothold / user>` -> root\n\n"
        "## 0. Access / connectivity\n- target:\n- reach:\n\n## Evidence\n| shot | caption |\n|---|---|\n",
        encoding="utf-8")
    assert _engagement.walkthrough_stale(str(tmp_path)) is True


def test_walkthrough_stale_true_on_bare_target_reach_stub_lines(tmp_path):
    (tmp_path / "walkthrough.md").write_text(
        "# Walkthrough\n\n**TL;DR chain:** entry -> user -> root\n\n"
        "## 0. Access\n- target:\n- reach:\n\n"
        "## Evidence\n| ![](poc/01.png) | login |\n",
        encoding="utf-8")
    assert _engagement.walkthrough_stale(str(tmp_path)) is True


def test_walkthrough_stale_true_when_evidence_gallery_empty(tmp_path):
    (tmp_path / "walkthrough.md").write_text(
        "# Walkthrough\n\n**TL;DR chain:** real -> path -> done\n\n"
        "## 0. Access\n- target: 10.0.0.5\n- reach: vpn\n\n"
        "## Evidence\n| shot | caption |\n|------|---------|\n",
        encoding="utf-8")
    assert _engagement.walkthrough_stale(str(tmp_path)) is True


def test_walkthrough_stale_false_when_filled_and_gallery_populated(tmp_path):
    (tmp_path / "walkthrough.md").write_text(
        "# Walkthrough\n\n**TL;DR chain:** 10.0.0.5 -> www-data -> root\n\n"
        "## 0. Access\n- target: 10.0.0.5\n- reach: openvpn\n\n"
        "## Evidence\n| shot | caption |\n|------|---------|\n"
        "| ![](poc/01-login.png) | login page |\n",
        encoding="utf-8")
    assert _engagement.walkthrough_stale(str(tmp_path)) is False


def test_walkthrough_stale_false_missing_dir_fails_open():
    assert _engagement.walkthrough_stale(None) is False


# ---- learn_pending (post-engagement harvest gate) --------------------------------

_ASSEMBLED_WT = (
    "# Walkthrough\n\n**TL;DR chain:** 10.0.0.5 -> www-data -> root\n\n"
    "## 0. Access\n- target: 10.0.0.5\n- reach: openvpn\n\n"
    "## Evidence\n| shot | caption |\n|------|---------|\n"
    "| ![](poc/01-login.png) | login page |\n")


def _solved_assembled(d):
    """A closed-out engagement dir: SOLVED state.md + an assembled walkthrough.md."""
    (d / "state.md").write_text(
        "---\ntype: engagement-state\n---\n\n# State\n\n## STATUS: SOLVED\n", encoding="utf-8")
    (d / "walkthrough.md").write_text(_ASSEMBLED_WT, encoding="utf-8")


def test_learn_pending_true_when_solved_assembled_no_marker(tmp_path):
    _solved_assembled(tmp_path)
    assert _engagement.learn_pending(str(tmp_path)) is True


def test_learn_pending_false_when_not_solved(tmp_path):
    (tmp_path / "state.md").write_text(
        "---\ntype: engagement-state\n---\n\n# State\n\n| host |\n|---|\n", encoding="utf-8")
    (tmp_path / "walkthrough.md").write_text(_ASSEMBLED_WT, encoding="utf-8")
    assert _engagement.learn_pending(str(tmp_path)) is False


def test_learn_pending_false_when_walkthrough_stale(tmp_path):
    # solved but the walkthrough is not assembled yet -> the walkthrough gate owns this
    # Stop; learn must stay silent so it never pre-empts walkthrough.
    (tmp_path / "state.md").write_text("## STATUS: SOLVED\n", encoding="utf-8")
    assert _engagement.learn_pending(str(tmp_path)) is False


def test_learn_pending_false_when_marker_fresh(tmp_path):
    _solved_assembled(tmp_path)
    (tmp_path / ".learn-done").write_text("", encoding="utf-8")   # written after -> newer
    assert _engagement.learn_pending(str(tmp_path)) is False


def test_learn_pending_true_when_marker_older_than_state(tmp_path):
    _solved_assembled(tmp_path)
    marker = tmp_path / ".learn-done"
    marker.write_text("", encoding="utf-8")
    # operator touched state.md after the last learn pass -> re-arm the gate
    old = os.path.getmtime(tmp_path / "state.md") - 100
    os.utime(marker, (old, old))
    assert _engagement.learn_pending(str(tmp_path)) is True


def test_learn_pending_false_none_dir_fails_open():
    assert _engagement.learn_pending(None) is False


# ---- flag_accounting_gap / captured_flags (ctf close-out flag sweep) --------------

def _solved_ctf(tmp_path, flags_expected="3", flags=(), etype="ctf"):
    fe = "" if flags_expected is None else str(flags_expected)
    (tmp_path / "state.md").write_text(
        '---\ntype: engagement-state\nengagement_type: %s\nflags_expected: "%s"\n---\n\n'
        "# State\n\n## STATUS: SOLVED\n" % (etype, fe), encoding="utf-8")
    rows = "".join("| %s | flag | src | where | captured |\n" % f for f in flags)
    (tmp_path / "loot.md").write_text(
        "---\ntype: engagement-loot\n---\n\n# Loot\n\n| item | type | source | where | status |\n"
        "|---|---|---|---|---|\n" + rows, encoding="utf-8")


def test_flag_gap_fires_on_shortfall(tmp_path):
    _solved_ctf(tmp_path, "3", ("THM{aaa}", "THM{bbb}"))
    g = _engagement.flag_accounting_gap(str(tmp_path))
    assert g and "2/3" in g and "THM{" in g


def test_flag_gap_silent_when_complete(tmp_path):
    _solved_ctf(tmp_path, "3", ("THM{aaa}", "THM{bbb}", "THM{ccc}"))
    assert _engagement.flag_accounting_gap(str(tmp_path)) == ""


def test_flag_gap_fires_when_expected_unset(tmp_path):
    _solved_ctf(tmp_path, "", ("THM{aaa}",))
    g = _engagement.flag_accounting_gap(str(tmp_path))
    assert g and "unset" in g.lower()


def test_flag_gap_silent_when_not_solved(tmp_path):
    (tmp_path / "state.md").write_text(
        '---\nengagement_type: ctf\nflags_expected: "3"\n---\n\n# State\n\n| host |\n|---|\n',
        encoding="utf-8")
    (tmp_path / "loot.md").write_text("# Loot\n", encoding="utf-8")
    assert _engagement.flag_accounting_gap(str(tmp_path)) == ""


def test_flag_gap_silent_for_non_ctf(tmp_path):
    _solved_ctf(tmp_path, "3", (), etype="pentest")
    assert _engagement.flag_accounting_gap(str(tmp_path)) == ""


def test_flag_gap_fails_open_missing_state(tmp_path):
    assert _engagement.flag_accounting_gap(str(tmp_path)) == ""
    assert _engagement.flag_accounting_gap(None) == ""


def test_flag_gap_infers_platform_prefix(tmp_path):
    _solved_ctf(tmp_path, "2", ("HTB{only}",))
    g = _engagement.flag_accounting_gap(str(tmp_path))
    assert g and "HTB{" in g


def test_captured_flags_dedups_duplicate_value(tmp_path):
    # a copied flag file (/tmp/rootflag.txt == /root/root.txt) must count once
    _solved_ctf(tmp_path, "3", ("THM{root}", "THM{root}", "THM{user}"))
    assert _engagement.captured_flags(str(tmp_path)) == {"THM{root}", "THM{user}"}


def test_captured_flags_ignores_prose_placeholder_row(tmp_path):
    # a 'Base Flag' placeholder row (no PREFIX{...} token) is not a captured flag
    _solved_ctf(tmp_path, "3", ("THM{user}",))
    with open(tmp_path / "loot.md", "a", encoding="utf-8") as fh:
        fh.write("| Base Flag | flag | room page | off-box | not on target |\n")
    assert _engagement.captured_flags(str(tmp_path)) == {"THM{user}"}


def test_captured_flags_skips_decoy_labeled_row(tmp_path):
    # a decoy flag file must NOT count as a scored flag (else it masks a missing scored flag)
    _solved_ctf(tmp_path, "3", ("THM{user}", "THM{root}"))
    with open(tmp_path / "loot.md", "a", encoding="utf-8") as fh:
        fh.write("| THM{decoyval} | flag | /home/x/flag1.txt | DECOY troll marker | captured |\n")
    assert _engagement.captured_flags(str(tmp_path)) == {"THM{user}", "THM{root}"}
    # and the gap now correctly fires 2/3 despite the decoy string being present
    g = _engagement.flag_accounting_gap(str(tmp_path))
    assert g and "2/3" in g


def test_eval_in_shared_core_for_every_type():
    for etype in ("ctf", "bugbounty", "pentest"):
        assert ("eval.md", "_eval.md") in _engagement._heal_shared_set(etype), etype


def test_poc_md_file_no_longer_healed():
    # poc.md (the FILE) was vestigial: evidence lives in the poc/ DIR, nothing read the file.
    for etype in ("ctf", "bugbounty", "pentest"):
        names = [d for d, _ in _engagement._heal_shared_set(etype)]
        assert "poc.md" not in names, etype
    assert not os.path.isfile(os.path.join(_engagement.TEMPLATES, "_poc.md"))


def test_eval_template_exists():
    p = os.path.join(_engagement.TEMPLATES, "_eval.md")
    assert os.path.isfile(p)
    body = open(p, encoding="utf-8").read()
    assert "{{ENGAGEMENT}}" in body and "Drift moments" in body
