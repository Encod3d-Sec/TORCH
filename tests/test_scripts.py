"""Tests for wiki-gaps, build_moc, find-lint, gen_index, lint-wiki."""
import importlib.util
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_capture_sh_exists_and_executable():
    p = os.path.join(REPO, "scripts", "capture.sh")
    assert os.path.exists(p) and os.access(p, os.X_OK)


def test_capture_sh_usage_lists_all_modes():
    import subprocess
    r = subprocess.run(["bash", os.path.join(REPO, "scripts", "capture.sh")],
                       capture_output=True, text=True)
    combined = r.stdout + r.stderr
    for mode in ("ev", "req", "tmux", "burp"):
        assert mode in combined
    assert r.returncode != 0   # no mode -> usage + nonzero


def test_capture_sh_rejects_unknown_mode():
    import subprocess
    r = subprocess.run(["bash", os.path.join(REPO, "scripts", "capture.sh"), "bogus", "e", "s"],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "unknown mode" in (r.stdout + r.stderr)


def test_wiki_gaps_normalize_filters_junk():
    wg = _load("scripts/wiki-gaps.py", "wiki_gaps")
    assert wg.normalize("Sql-Injection") == "sql-injection"
    assert wg.normalize('exploit.jar"') == ""   # not a kebab slug
    assert wg.normalize("path/to/ssrf") == "ssrf"


def test_wiki_gaps_detects_missing(tmp_path, monkeypatch):
    wg = _load("scripts/wiki-gaps.py", "wiki_gaps2")
    wiki = tmp_path / "wiki" / "techniques" / "web"
    hunt = tmp_path / "skills" / "hunt" / "h"
    os.makedirs(wiki); os.makedirs(hunt)
    (wiki / "sql-injection.md").write_text("x")
    (hunt / "SKILL.md").write_text(
        "update wiki/techniques/web/sql-injection.md and wiki/techniques/web/missing-page.md")
    monkeypatch.setattr(wg, "WIKI", str(tmp_path / "wiki"))
    monkeypatch.setattr(wg, "HUNT", str(tmp_path / "skills" / "hunt"))
    monkeypatch.setattr(wg, "TARGETS", str(tmp_path / "targets"))
    os.makedirs(tmp_path / "targets")
    have = wg.existing_slugs()
    assert "sql-injection" in have and "missing-page" not in have


def _bb_classes():
    return json.load(open(os.path.join(REPO, "scripts", "coverage-classes.json")))["bugbounty"]


def test_tested_classes_autocredit(tmp_path):
    """coverage self-maintains from the files the discipline already writes:
    the Approach.md 4a table + written findings + Deadends.md."""
    import _engagement
    d = tmp_path / "eng"
    (d / "Vulns").mkdir(parents=True)
    (d / "Approach.md").write_text(
        "| asset | vuln class | wiki | payload/tool | status | poc |\n"
        "|---|---|---|---|---|---|\n"
        "| api.x | csrf | [[csrf]] | - | [x] | poc/1.png |\n")
    (d / "state.md").write_text("| asset | access |\n|---|---|\n| api.x | tested |\n")
    (d / "Vulns" / "FIND-001-HIGH-sqli-login.md").write_text(
        '---\ntitle: "SQL Injection in login form"\ntype: finding\naffected: api.x\n---\n# x\n')
    (d / "Deadends.md").write_text(
        "---\ntype: deadends\n---\n# Dead-ends\n\n"
        "- SSRF on api.x via ?url=: all schemes blocked, 40 payloads 0 callbacks\n")
    per_asset, glob = _engagement.tested_classes(str(d), "bugbounty", _bb_classes())
    got = per_asset.get("api.x", set())
    assert "csrf" in got     # explicit Approach.md 4a row (status [x])
    assert "sqli" in got     # finding title/slug -> tested-and-found
    assert "ssrf" in got     # dead-end attributed to api.x -> tested-and-cleared
    assert "xss" not in got  # never touched -> still a gap


def test_tested_classes_no_false_credit(tmp_path):
    """word-boundary + specific aliases: 'source'/'author' must not credit rce/auth."""
    import _engagement
    d = tmp_path / "eng"
    (d / "Vulns").mkdir(parents=True)
    (d / "Vulns" / "FIND-001-LOW-info-leak.md").write_text(
        '---\ntitle: "Verbose error exposes source path and author name"\naffected: api.x\n---\n')
    per_asset, glob = _engagement.tested_classes(str(d), "bugbounty", _bb_classes())
    got = per_asset.get("api.x", set())
    assert "rce" not in got and "auth" not in got


def test_normalize_tags_skips_generated(tmp_path, monkeypatch):
    nt = _load("scripts/normalize-tags.py", "normalize_tags")
    wiki = tmp_path / "wiki"
    (wiki / "techniques" / "web").mkdir(parents=True)
    (wiki / "CTF").mkdir()
    for name in ("index.md", "moc.md", "overview.md", "active-directory-moc.md"):
        (wiki / name).write_text("---\ntags: [x]\n---\n")
    (wiki / "techniques" / "web" / "xss.md").write_text("---\ntags: [x]\n---\n")
    (wiki / "CTF" / "box.md").write_text("---\ntags: [x]\n---\n")
    monkeypatch.setattr(nt, "WIKI", str(wiki))
    got = {os.path.basename(p) for p in nt.pages()}
    assert "xss.md" in got                          # normal page: eligible
    assert got.isdisjoint({"index.md", "moc.md", "overview.md", "active-directory-moc.md"})  # generated: skipped
    assert "box.md" not in got                       # CTF: excluded


def test_gen_index_frontmatter_crlf(tmp_path):
    gi = _load("scripts/gen_index.py", "gen_index_crlf")
    p = tmp_path / "page.md"
    p.write_bytes(b'---\r\ntitle: "CRLF Page"\r\ntags: [alpha, beta]\r\n---\r\n\r\nbody\r\n')
    fm = gi.frontmatter(str(p))
    assert "CRLF" in fm["title"] and "alpha" in fm["tags"]   # CRLF frontmatter still parses


def test_trigger_stats(tmp_path, monkeypatch, capsys):
    ts = _load("scripts/trigger-stats.py", "trigger_stats")
    assert ts._pct(1, 4) == 25.0
    log = tmp_path / ".trigger-fire.jsonl"
    log.write_text('{"ts": 1, "hard": ["hunt-sqli"], "soft": [], "n": 1}\n'
                   '{"ts": 2, "hard": [], "soft": ["hunt-xss"], "n": 2}\n'
                   '{"ts": 3, "hard": [], "soft": [], "n": 3}\n')
    monkeypatch.setattr(ts, "LOG", str(log))
    ts.main()
    out = capsys.readouterr().out
    assert "%" in out and "hunt-sqli" in out          # runs on a valid log, reports skills


def test_find_lint(tmp_path):
    fl = _load("scripts/find-lint.py", "find_lint")
    complete = ("---\nseverity: HIGH\ncvss: CVSS:3.1/AV:N\naffected: api.x\n---\n"
                "# t\n## Description\nA real description with enough text here.\n"
                "## Proof of Concept\nstep 1 do the thing exactly like so.\n"
                "## Impact\nAttacker reads all the data, full account takeover.\n"
                "## Remediation\nValidate input and patch the library now.\n")
    incomplete = ("---\nseverity: HIGH\n---\n# t\n## Description\nshort\n"
                  "## Impact\nbad stuff happens to the system here\n")
    cf = tmp_path / "FIND-001-HIGH-good.md"
    cf.write_text(complete)
    inc = tmp_path / "FIND-002-HIGH-bad.md"
    inc.write_text(incomplete)
    issues, warnings = fl.lint_file(str(cf))
    assert issues == []
    issues, warnings = fl.lint_file(str(inc))
    assert any("Proof of Concept" in i for i in issues)
    assert any("Remediation" in i for i in issues)
    assert any("CVSS" in i for i in issues)  # HIGH without vector


def test_cvss_score_extracts_score_not_version():
    fl = _load("scripts/find-lint.py", "find_lint_score")
    fmt = 'cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1"'
    assert fl.cvss_score(fmt) == 9.1


def test_cvss_score_accepts_bare_number_not_version():
    fl = _load("scripts/find-lint.py", "find_lint_bare")
    assert fl.cvss_score("cvss: 9.8") == 9.8                        # bare number accepted
    assert fl.cvss_score("cvss: CVSS:3.1/AV:N/AC:L - 7.0") == 7.0   # vector + dash score
    assert fl.cvss_score("cvss: CVSS:3.1/AV:N/AC:L") is None        # vector w/o score: not the 3.1


def test_cvss_band_thresholds():
    fl = _load("scripts/find-lint.py", "find_lint_band")
    assert fl.cvss_band(9.1) == "CRITICAL"
    assert fl.cvss_band(5.3) == "MEDIUM"
    assert fl.cvss_band(7.5) == "HIGH"
    assert fl.cvss_band(3.0) == "LOW"
    assert fl.cvss_band(0) == "INFO"


def test_find_lint_warns_on_cvss_severity_mismatch(tmp_path):
    fl = _load("scripts/find-lint.py", "find_lint_mismatch")
    mismatched = ('---\nseverity: HIGH\ncvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1"\n'
                  "affected: api.x\n---\n# t\n## Description\nA real description with enough text here.\n"
                  "## Proof of Concept\nstep 1 do the thing exactly like so.\n"
                  "## Impact\nAttacker reads all the data, full account takeover.\n"
                  "## Remediation\nValidate input and patch the library now.\n")
    mf = tmp_path / "FIND-001-HIGH-mismatch.md"
    mf.write_text(mismatched)
    issues, warnings = fl.lint_file(str(mf))
    assert issues == []  # not a hard failure
    assert any("CRITICAL" in w and "HIGH" in w for w in warnings)


def test_find_lint_no_warning_when_score_matches_label(tmp_path):
    fl = _load("scripts/find-lint.py", "find_lint_match")
    matched = ('---\nseverity: HIGH\ncvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 7.5"\n'
               "class: ssrf\n"
               "affected: api.x\n---\n# t\n## Description\nA real description with enough text here.\n"
               "## Proof of Concept\nstep 1 do the thing exactly like so.\n"
               "## Impact\nAttacker reads all the data, full account takeover.\n"
               "## Remediation\nValidate input and patch the library now.\n")
    mf = tmp_path / "FIND-001-HIGH-match.md"
    mf.write_text(matched)
    issues, warnings = fl.lint_file(str(mf))
    assert issues == []
    assert warnings == []


def test_find_lint_class_advisory_blank_vs_set(tmp_path):
    fl = _load("scripts/find-lint.py", "find_lint_class_advisory")
    body = ("affected: api.x\n---\n# t\n## Description\nA real description with enough text here.\n"
            "## Proof of Concept\nstep 1 do the thing exactly like so.\n"
            "## Impact\nAttacker reads all the data, full account takeover.\n"
            "## Remediation\nValidate input and patch the library now.\n")
    blank = ('---\nseverity: MEDIUM\ncvss: ""\n'
             'class: ""            # optional: canonical vuln class\n' + body)
    bf = tmp_path / "FIND-001-MEDIUM-blank.md"
    bf.write_text(blank)
    _issues, warnings = fl.lint_file(str(bf))
    assert any("no `class:` set" in w for w in warnings)

    setcls = ('---\nseverity: MEDIUM\ncvss: ""\nclass: ssrf\n' + body)
    sf = tmp_path / "FIND-002-MEDIUM-set.md"
    sf.write_text(setcls)
    _issues, warnings = fl.lint_file(str(sf))
    assert not any("no `class:` set" in w for w in warnings)


def test_build_moc_group_key_and_labels():
    bm = _load("scripts/build_moc.py", "build_moc")
    assert bm.group_key("active-directory-certificate-esc1") == "active-directory-certificate"
    assert bm.humanize("active-directory-certificate") == "ADCS (Certificate Services)"
    assert bm.group_key("aws-service-s3-buckets") == "aws-service"


def test_build_moc_generates_hub(tmp_path, monkeypatch):
    bm = _load("scripts/build_moc.py", "build_moc2")
    tech = tmp_path / "techniques" / "web"
    os.makedirs(tech)
    for p in ("sql-injection", "xss", "ssrf"):
        (tech / f"{p}.md").write_text("x")
    monkeypatch.setattr(bm, "TECH", str(tmp_path / "techniques"))
    monkeypatch.setattr(bm, "WIKI", str(tmp_path))
    bm.build_domain_moc("web")
    moc = (tech / "web-moc.md").read_text()
    assert "[[sql-injection]]" in moc and "[[xss]]" in moc
    assert "Map of Content" in moc


def test_gen_index_frontmatter_parse(tmp_path):
    gi = _load("scripts/gen_index.py", "gen_index")
    p = tmp_path / "x.md"
    p.write_text('---\ntitle: "Foo"\ntype: technique\n'
                 "tags: [a, b, c]\nphase: exploitation\n---\nbody")
    fm = gi.frontmatter(str(p))
    assert fm["tags"] == "a, b, c"
    assert fm["phase"] == "exploitation"
    assert fm["title"] == "Foo"


def test_gen_index_block_form_tags(tmp_path):
    gi = _load("scripts/gen_index.py", "gen_index_block")
    p = tmp_path / "y.md"
    p.write_text("---\ntitle: Bar\ntags:\n  - alpha\n  - beta\nphase: recon\n---\nbody")
    fm = gi.frontmatter(str(p))
    assert fm["tags"] == "alpha, beta"        # block-form list joined
    assert fm["title"] == "Bar" and fm["phase"] == "recon"


def test_gen_index_excludes_meta_and_moc(tmp_path, monkeypatch):
    gi = _load("scripts/gen_index.py", "gen_index2")
    web = tmp_path / "techniques" / "web"
    os.makedirs(web)
    (web / "xss.md").write_text("---\ntags: [xss]\n---\n")
    (web / "web-moc.md").write_text("---\ntags: [moc]\n---\n")
    (web / "index.md").write_text("---\ntags: [meta]\n---\n")
    monkeypatch.setattr(gi, "WIKI", str(tmp_path))
    slugs = [s for s, _ in gi.md_pages(str(web))]
    assert "xss" in slugs
    assert "web-moc" not in slugs and "index" not in slugs


def test_lint_ignores_code_blocks(tmp_path, monkeypatch):
    lw = _load("scripts/lint-wiki.py", "lint_wiki")
    wiki = tmp_path / "wiki"
    os.makedirs(wiki)
    (wiki / "good.md").write_text("x")
    (wiki / "page.md").write_text(
        'see [[good]] and [[missing-page]]\n'
        '```bash\nif [[ -z "$x" ]]; then :; fi\n```\n')
    monkeypatch.setattr(lw, "WIKI", str(wiki))
    bad = lw.check_broken_links(lw.existing_basenames())
    targets = {t for t, _ in bad}
    assert "missing-page" in targets        # real broken link caught
    assert "good" not in targets            # resolvable link not flagged
    assert all("-z" not in t for t in targets)  # bash [[ ]] in code ignored


def test_lint_dead_scriptrefs(tmp_path, monkeypatch):
    lw = _load("scripts/lint-wiki.py", "lint_wiki2")
    os.makedirs(tmp_path / "scripts")
    (tmp_path / "scripts" / "exists.py").write_text("x")
    os.makedirs(tmp_path / "docs")
    (tmp_path / "docs" / "w.md").write_text(
        "run scripts/exists.py then scripts/missing.py")
    monkeypatch.setattr(lw, "VAULT", str(tmp_path))
    names = {n for n, _ in lw.check_dead_scriptrefs()}
    assert "missing.py" in names and "exists.py" not in names


def test_lint_frontmatter_hard_vs_soft(tmp_path, monkeypatch):
    lw = _load("scripts/lint-wiki.py", "lint_wiki3")
    wiki = tmp_path / "wiki"
    os.makedirs(wiki)
    (wiki / "notags.md").write_text("---\ndate_created: 2026-01-01\n---\nx")
    (wiki / "nodate.md").write_text("---\ntags: [a]\n---\nx")
    monkeypatch.setattr(lw, "WIKI", str(wiki))
    hard, soft = lw.check_frontmatter()
    assert "notags.md" in {os.path.basename(p) for p, _ in hard}
    assert "nodate.md" in {os.path.basename(p) for p, _ in soft}


def test_fingerprint_router_matches_playbook():
    rc = _load("skills/hooks/recon-capture.py", "recon_capture")
    hits = " ".join(rc.fingerprint_hits("Server: Jenkins; X-Powered-By: spring; /graphql live"))
    assert "jenkins" in hits and "graphql" in hits and "spring" in hits
    assert "load Skill(" in hits                  # emits the hunt skill to load
    assert rc.fingerprint_hits("nothing interesting here") == []


def test_fingerprint_smb_workgroup_routes_windows_not_ad():
    # a STANDALONE/workgroup Windows box (single-label domain == hostname) must NOT route hunt-ad;
    # the Windows OS banner routes LOCAL privesc (hunt-windows) instead.
    rc = _load("skills/hooks/recon-capture.py", "recon_capture")
    blob = ("SMB 10.0.0.5 445 PRIVESC [*] Windows 10 / Server 2019 Build 17763 x64 "
            "(name:PRIVESC) (domain:privesc) (signing:False)")
    hits = " ".join(rc.fingerprint_hits(blob))
    assert "Skill(hunt-windows)" in hits
    assert "hunt-ad" not in hits


def test_fingerprint_smb_domain_fqdn_routes_ad():
    # a dotted FQDN realm (a DC / domain-joined host) DOES route hunt-ad
    rc = _load("skills/hooks/recon-capture.py", "recon_capture")
    blob = ("SMB 10.0.0.5 445 DC01 [*] Windows Server 2019 Build 17763 "
            "(name:DC01) (domain:corp.local) (signing:True)")
    hits = " ".join(rc.fingerprint_hits(blob))
    assert "Skill(hunt-ad)" in hits


def test_freshness_flags_old_pages(tmp_path, monkeypatch):
    from datetime import date
    fr = _load("scripts/freshness.py", "freshness")
    pay = tmp_path / "payloads"
    ch = tmp_path / "cheatsheets"
    os.makedirs(pay)
    os.makedirs(ch)
    (pay / "graphql.md").write_text("---\ndate_updated: 2026-06-01\n---\n")            # fresh
    (pay / "llm-prompt-injection.md").write_text("---\ndate_updated: 2026-01-01\n---\n")  # >90d fast
    (pay / "xss.md").write_text("---\ndate_updated: 2024-01-01\n---\n")                # >365d slow
    (ch / "default-credentials.md").write_text("---\ndate_updated: 2026-06-20\n---\n")  # fresh
    (ch / "unrelated.md").write_text("---\ndate_updated: 2000-01-01\n---\n")           # not designated
    monkeypatch.setattr(fr, "WIKI", str(tmp_path))
    slugs = {r[0] for r in fr.stale(today=date(2026, 6, 28))}
    assert "llm-prompt-injection" in slugs   # 178d > 90d fast window
    assert "xss" in slugs                      # > 365d slow window
    assert "graphql" not in slugs              # 27d, fresh
    assert "default-credentials" not in slugs  # 8d, fresh
    assert "unrelated" not in slugs            # not in the designated cheatsheet set


def test_freshness_scans_fast_technique_pages(tmp_path, monkeypatch):
    from datetime import date
    fr = _load("scripts/freshness.py", "freshness2")
    tech = tmp_path / "techniques" / "web"
    os.makedirs(tech)
    (tech / "mcp-server-attacks.md").write_text("---\ndate_updated: 2026-01-01\n---\n")  # fast, >90d
    (tech / "clickjacking.md").write_text("---\ndate_updated: 2024-01-01\n---\n")         # stable -> unscanned
    (tech / "html-smuggling.md").write_text("---\ndate_updated: 2024-01-01\n---\n")       # 'ml-' must not match
    monkeypatch.setattr(fr, "WIKI", str(tmp_path))
    slugs = {r[0] for r in fr.stale(today=date(2026, 6, 28))}
    assert "mcp-server-attacks" in slugs        # fast technique page now gated on the 90d window
    assert "clickjacking" not in slugs           # not a fast class -> not flooded onto the report
    assert "html-smuggling" not in slugs         # the specific 'ml-model' token must not false-match 'ml-'


def test_recon_capture_invokes_command_position():
    rc = _load("skills/hooks/recon-capture.py", "recon_capture_inv")
    # tool merely named as a path/arg -> NOT an invocation (the false-fire class)
    for c in ["ls /root/nuclei-templates", "find . -name nmap.txt",
              "python3 scripts/cve_feed.py", "wc -l out/nuclei.json"]:
        assert rc.invokes(c, rc.RECON_TOOLS) is None, c
    # tool actually invoked, incl. behind sudo/timeout or in a && chain -> matched
    for c, tool in [("nuclei -u https://x", "nuclei"),
                    ("sudo nmap -sV 10.0.0.0/24", "nmap"),
                    ("cd /x && nxc smb 10.0.0.1", "nxc"),
                    ("timeout 60 ffuf -u http://x/FUZZ", "ffuf")]:
        m = rc.invokes(c, rc.RECON_TOOLS)
        assert m and m.group(1) == tool, c


def test_scope_guard_logic():
    sg = _load("skills/hooks/scope-guard.py", "scope_guard")
    sc = {"out_of_scope": ["10.0.3.0/24", "prod.example.com"]}
    assert sg.ip_out_of_scope("nmap 10.0.3.129 -p445", sc) == ["10.0.3.129"]
    assert sg.ip_out_of_scope("nmap 10.199.1.5", sc) == []      # in scope -> not flagged
    assert sg.BRUTEFORCE.search("hydra -l a -P pw.txt ssh://x")
    assert sg.DOS.search("nmap -T5 --min-rate 9000 x")
    assert sg.ACTIVE.search("nuclei -u x")
    assert not sg.ACTIVE.search("cat notes.txt")


def test_tested_classes_list_affected_and_dash(tmp_path):
    import _engagement
    d = tmp_path / "eng"
    (d / "Vulns").mkdir(parents=True)
    (d / "Vulns" / "FIND-001-HIGH-xss.md").write_text(   # block-list affected
        '---\ntitle: "Stored XSS"\ntype: finding\naffected:\n  - host-a\n  - host-b\n---\n')
    # Approach.md 4a row with a dash in the 'vuln class' cell (done status): the dash
    # placeholder must NOT be credited as a tested class (the re.fullmatch('-+') guard).
    (d / "Approach.md").write_text(
        "| asset | vuln class | wiki | payload/tool | status | poc |\n"
        "|---|---|---|---|---|---|\n"
        "| host-a | - | - | - | [x] | - |\n")
    per_asset, glob = _engagement.tested_classes(str(d), "bugbounty", _bb_classes())
    assert "xss" in per_asset.get("host-a", set())      # credited to each list item...
    assert "xss" in per_asset.get("host-b", set())
    assert "xss" not in glob                             # ...not dumped to the global bucket
    assert "-" not in per_asset.get("host-a", set())     # '-' placeholder is not a tested class


def test_research_status_parsing(tmp_path, monkeypatch):
    rs = _load("scripts/research_status.py", "research_status")
    base = tmp_path / "raw" / "research"
    proj = base / "p1"
    os.makedirs(proj)
    (base / "active.md").write_text("p1\n")
    (proj / "loop.md").write_text(
        "## Hypotheses (ranked, current)\n| # | Approach | Priority | Status |\n|--|--|--|--|\n"
        "| 1 | parse_header overflow | high | open |\n| 2 | other | low | dead |\n\n"
        "## Status\n- **Phase:** investigate\n- **Next move:** fuzz it\n")
    (proj / "findings.md").write_text(
        "<!-- ## FIND-1: x [candidate | confirmed] -->\n## FIND-2: real [confirmed]\n")
    (proj / "deadends.md").write_text("<!-- - [ ] <approach> -->\n- [ ] tried X -- nothing\n")
    monkeypatch.setattr(rs, "RESEARCH", str(base))
    assert rs.parse_phase("- **Phase:** investigate") == "investigate"
    assert rs.parse_phase("- **Phase:** setup | surface-map | x") == "setup"   # unfilled template
    s = rs.collect(rs.active_project())
    assert s["phase"] == "investigate"
    assert s["hyps"] == ["parse_header overflow"]      # only the 'open' row
    assert s["conf"] == 1 and s["cand"] == 0           # commented example ignored
    assert s["dead"] == 1                              # comment placeholder ignored
    assert "fuzz it" in s["moves"][0]


def test_lint_check_playbook_flags_issues(tmp_path):
    lw = _load("scripts/lint-wiki.py", "lint_wiki_pb")
    repo = tmp_path
    os.makedirs(repo / "scripts")
    os.makedirs(repo / "skills" / "hunt" / "hunt-real")   # a skill that exists
    pb = {
        "fingerprints": {
            "good-key": {"skills": ["hunt-real"], "refs": ["payloads/graphql"]},
            "bad[regex": {"skills": ["hunt-real"], "refs": ["graphql"]},   # bad regex
            "missingref": {"skills": ["hunt-real"], "refs": ["nope-page"]},  # unresolved ref
            "missingskill": {"skills": ["hunt-ghost"], "refs": ["graphql"]},  # missing skill
        }
    }
    (repo / "scripts" / "playbook.json").write_text(json.dumps(pb))
    have = {"graphql"}                                   # only 'graphql' is a real page
    found = lw.check_playbook(have, str(repo))
    blob = " ".join(f"{loc} {why}" for loc, why in found)
    assert "bad regex" in blob and "bad[regex" in blob   # bad-regex key reported
    assert "unresolved ref: nope-page" in blob           # unresolved ref reported
    assert "missing skill: hunt-ghost" in blob           # missing skill reported
    # the all-valid fingerprint produces no finding
    assert "good-key" not in blob


def test_lint_check_playbook_failopen(tmp_path):
    lw = _load("scripts/lint-wiki.py", "lint_wiki_pb_fo")
    os.makedirs(tmp_path / "scripts")
    (tmp_path / "scripts" / "playbook.json").write_text("{ not valid json")
    found = lw.check_playbook(set(), str(tmp_path))      # must not raise
    assert len(found) == 1 and "unreadable" in found[0][1]


def test_lint_real_playbook_no_dangling():
    lw = _load("scripts/lint-wiki.py", "lint_wiki_pb_real")
    have = lw.existing_basenames()                       # real wiki basenames
    found = lw.check_playbook(have, lw.VAULT)            # real playbook + real repo
    assert found == [], f"real playbook.json has dangling refs/skills: {found}"


def test_lint_real_triggers_no_missing_skills():
    lw = _load("scripts/lint-wiki.py", "lint_wiki_trig_real")
    found = lw.check_triggers(lw.VAULT)                  # real triggers.json + real repo
    assert found == [], f"triggers.json has missing skills: {found}"


def test_lint_emdash_ignores_code(tmp_path, monkeypatch):
    lw = _load("scripts/lint-wiki.py", "lint_wiki_em")
    wiki = tmp_path / "wiki"
    os.makedirs(wiki)
    (wiki / "bad.md").write_text("prose -- dash\n```\ncode -- ignored\n```\n")
    (wiki / "good.md").write_text("prose - hyphen only\n")
    monkeypatch.setattr(lw, "WIKI", str(wiki))
    em = dict((os.path.basename(p), n) for p, n in lw.check_emdash())
    assert em.get("bad.md") == 1          # fenced em-dash not counted
    assert "good.md" not in em


def test_lint_emdash_ignores_anchors_comments_flags(tmp_path, monkeypatch):
    lw = _load("scripts/lint-wiki.py", "lint_wiki_em2")
    wiki = tmp_path / "wiki"
    os.makedirs(wiki)
    (wiki / "noise.md").write_text(
        "* [EoP - X](#eop---x)\n"        # TOC anchor slug (word--word)
        "<!-- a comment -->\n"           # html comment
        "run `tool --flag` now\n"        # inline-code CLI flag
        "| a | b |\n|---|---|\n"         # table separator row
        "see http://x/a--b for more\n")  # url slug (word--word)
    (wiki / "real.md").write_text("Shodan -- scan results here\n")
    monkeypatch.setattr(lw, "WIKI", str(wiki))
    em = dict((os.path.basename(p), n) for p, n in lw.check_emdash())
    assert "noise.md" not in em          # anchors/comments/flags/tables/urls all ignored
    assert em.get("real.md") == 1        # genuine prose em-dash still counted


def test_lint_placeholder_and_image_checks(tmp_path, monkeypatch):
    lw = _load("scripts/lint-wiki.py", "lint_wiki_soft")
    wiki = tmp_path / "wiki"
    os.makedirs(wiki)
    (wiki / "stub.md").write_text("## Tools\ncorrelate with wiki `[[tool]]` pages later\n")
    (wiki / "img.md").write_text("intro\n![diagram](https://x/y.png)\n")
    (wiki / "clean.md").write_text("real page with a [[nmap]] link, no image\n")
    monkeypatch.setattr(lw, "WIKI", str(wiki))
    ph = {os.path.basename(p) for p in lw.check_placeholder_tools()}
    assert ph == {"stub.md"}                                  # only the [[tool]] stub page
    imgs = {os.path.basename(p): n for p, n in lw.check_image_embeds()}
    assert imgs == {"img.md": 1}                              # image caught, [[nmap]] link is not one
