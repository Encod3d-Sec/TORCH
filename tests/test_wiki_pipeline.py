"""Live-wiki pipeline: wiki-stage.py scaffolding + wiki-promote.py list/review/promote.

Runs the REAL repo scripts with CLAUDEBRAIN_VAULT pointed at an isolated tmp vault, so
they resolve targets/ + wiki/ + check-leaks.sh + gen_index.py inside the fixture and
never touch the real vault."""
import glob
import os
import shutil
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGE = os.path.join(REPO, "scripts", "wiki-stage.py")
PROMOTE = os.path.join(REPO, "scripts", "wiki-promote.py")


def _vault(tmp_path):
    """Isolated vault: copied check-leaks.sh + gen_index.py + _engagement.py, minimal
    wiki target pages, one engagement 'clientx' (its dir name is the client marker)."""
    v = tmp_path / "v"
    (v / "scripts").mkdir(parents=True)
    (v / "skills" / "hooks").mkdir(parents=True)
    (v / "wiki" / "cheatsheets").mkdir(parents=True)
    (v / "wiki" / "techniques" / "web").mkdir(parents=True)
    for s in ("check-leaks.sh", "gen_index.py"):
        shutil.copy(os.path.join(REPO, "scripts", s), v / "scripts" / s)
    shutil.copy(os.path.join(REPO, "skills", "hooks", "_engagement.py"),
                v / "skills" / "hooks" / "_engagement.py")
    (v / "wiki" / "cheatsheets" / "default-credentials.md").write_text(
        "---\ntitle: x\n---\n# Default Credentials\n\n"
        "| product | version | username | password | source | notes |\n"
        "|---------|---------|----------|----------|--------|-------|\n"
        "| MSSQL | any | sa | sa | vendor | x |\n\n"
        "## How to extend\n- foo\n", encoding="utf-8")
    (v / "wiki" / "cheatsheets" / "api-request-findings.md").write_text(
        "---\ntitle: x\n---\n# API Request Findings\n\n"
        "| product/tech | endpoint | method | request / payload | auth | reveals / impact |\n"
        "|---|---|---|---|---|---|\n"
        "| Supabase | /rest/v1/<t> | GET | apikey | anon | rows |\n\n"
        "## How to extend\n- foo\n", encoding="utf-8")
    (v / "wiki" / "techniques" / "web" / "jwt-attacks.md").write_text(
        "---\ntitle: JWT\n---\n# JWT Attacks\n\nbody\n", encoding="utf-8")
    (v / "wiki" / "techniques" / "web" / "dummy.md").write_text(
        "---\ntitle: d\n---\n# d\n", encoding="utf-8")   # gives gen_index a page to catalog
    eng = v / "targets" / "clientx"
    eng.mkdir(parents=True)
    (v / "targets" / "active.md").write_text("clientx\n", encoding="utf-8")
    (eng / "scope.md").write_text("## In scope\n- clientx.example.com\n", encoding="utf-8")
    return v, eng, dict(os.environ, CLAUDEBRAIN_VAULT=str(v))


def _run(script, args, env):
    return subprocess.run(["python3", script, *args], capture_output=True, text=True, env=env)


def test_wiki_stage_scaffolds_candidate(tmp_path):
    v, eng, env = _vault(tmp_path)
    r = _run(STAGE, ["--kind", "default-cred", "--slug", "acmerouter-default",
                     "--body", "| AcmeRouter | any | admin | admin | vendor | web UI |"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    cand = eng / "wiki-candidates" / "acmerouter-default.md"
    assert cand.is_file()
    text = cand.read_text()
    assert "target_page: cheatsheets/default-credentials.md" in text
    assert "kind: default-cred" in text
    assert "slug: acmerouter-default" in text
    assert "source_eng: clientx" in text
    assert "status: pending" in text
    assert "| AcmeRouter | any | admin | admin | vendor | web UI |" in text


def test_wiki_stage_technique_requires_target_page(tmp_path):
    v, eng, env = _vault(tmp_path)
    r = _run(STAGE, ["--kind", "technique", "--slug", "jwt-null-sig"], env)
    assert r.returncode == 2 and "target-page" in (r.stdout + r.stderr)


def test_wiki_stage_technique_scaffold_body(tmp_path):
    v, eng, env = _vault(tmp_path)
    r = _run(STAGE, ["--kind", "technique", "--slug", "jwt-null-sig",
                     "--target-page", "techniques/web/jwt-attacks.md"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (eng / "wiki-candidates" / "jwt-null-sig.md").read_text()
    assert "target_page: techniques/web/jwt-attacks.md" in text
    assert "## <Heading>" in text


def test_wiki_stage_rejects_bad_slug(tmp_path):
    v, eng, env = _vault(tmp_path)
    r = _run(STAGE, ["--kind", "default-cred", "--slug", "Bad Slug!"], env)
    assert r.returncode == 2 and "slug" in (r.stdout + r.stderr).lower()


def _stage(eng, slug, kind, target_page, body, status="pending", source="clientx"):
    """Write a candidate file directly (isolated from wiki-stage.py)."""
    inbox = eng / "wiki-candidates"
    inbox.mkdir(exist_ok=True)
    (inbox / (slug + ".md")).write_text(
        "---\ntarget_page: %s\nkind: %s\nslug: %s\nsource_eng: %s\n"
        "date: 2026-07-06\nstatus: %s\n---\n\n%s\n"
        % (target_page, kind, slug, source, status, body), encoding="utf-8")
    return inbox / (slug + ".md")


def test_wiki_promote_list(tmp_path):
    v, eng, env = _vault(tmp_path)
    _stage(eng, "foovendor-default", "default-cred", "cheatsheets/default-credentials.md",
           "| FooVendor | any | admin | admin | vendor | web UI |")
    r = _run(PROMOTE, ["--list"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "foovendor-default" in r.stdout
    assert "cheatsheets/default-credentials.md" in r.stdout


def test_wiki_promote_list_extra_status_spacing(tmp_path):
    # FIX 1 consistency check: 'status:  pending' (two spaces) must still be
    # detected as pending by wiki-promote.py --list, the same as a normal
    # single-space candidate (engagement-init's wiki_candidate_count must agree).
    v, eng, env = _vault(tmp_path)
    inbox = eng / "wiki-candidates"
    inbox.mkdir(exist_ok=True)
    (inbox / "foovendor-default.md").write_text(
        "---\ntarget_page: cheatsheets/default-credentials.md\nkind: default-cred\n"
        "slug: foovendor-default\nsource_eng: clientx\ndate: 2026-07-06\nstatus:  pending\n---\n\n"
        "| FooVendor | any | admin | admin | vendor | web UI |\n", encoding="utf-8")
    r = _run(PROMOTE, ["--list"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "foovendor-default" in r.stdout
    assert "cheatsheets/default-credentials.md" in r.stdout


def test_wiki_promote_list_empty(tmp_path):
    v, eng, env = _vault(tmp_path)
    (eng / "wiki-candidates").mkdir()
    r = _run(PROMOTE, ["--list"], env)
    assert r.returncode == 0 and "no pending" in r.stdout


def test_wiki_promote_review(tmp_path):
    v, eng, env = _vault(tmp_path)
    _stage(eng, "foovendor-default", "default-cred", "cheatsheets/default-credentials.md",
           "| FooVendor | any | admin | admin | vendor | web UI |")
    r = _run(PROMOTE, ["--review", "foovendor-default"], env)
    assert r.returncode == 0 and "FooVendor" in r.stdout and "status: pending" in r.stdout


def test_wiki_promote_review_unknown(tmp_path):
    v, eng, env = _vault(tmp_path)
    (eng / "wiki-candidates").mkdir()
    r = _run(PROMOTE, ["--review", "nope"], env)
    assert r.returncode == 1


def test_wiki_promote_merges_dedups_archives_reindexes(tmp_path):
    v, eng, env = _vault(tmp_path)
    _stage(eng, "foovendor-default", "default-cred", "cheatsheets/default-credentials.md",
           "| FooVendor | any | admin | admin | vendor | web UI |")
    r = _run(PROMOTE, ["--promote", "foovendor-default"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    page = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    assert "| FooVendor | any | admin | admin | vendor | web UI |" in page   # merged into the table
    assert "promoted-slug: foovendor-default" in page                        # dedup marker
    assert page.index("FooVendor") < page.index("## How to extend")          # row stayed in the table
    arch = eng / "wiki-candidates" / "_promoted" / "foovendor-default.md"
    assert arch.is_file() and "status: promoted" in arch.read_text()
    assert not (eng / "wiki-candidates" / "foovendor-default.md").exists()    # moved out of pending
    assert (v / "wiki" / "index.md").is_file()                               # reindex ran
    # dedup: re-staging the same slug and re-promoting adds no second row
    _stage(eng, "foovendor-default", "default-cred", "cheatsheets/default-credentials.md",
           "| FooVendor | any | admin | admin | vendor | web UI |")
    _run(PROMOTE, ["--promote", "foovendor-default"], env)
    page2 = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    assert page2.count("| FooVendor | any | admin | admin | vendor | web UI |") == 1


def test_wiki_promote_leak_gate_refuses(tmp_path):
    v, eng, env = _vault(tmp_path)
    # body carries the client marker 'clientx' (the engagement dir name) -> must refuse
    _stage(eng, "leaky-cred", "default-cred", "cheatsheets/default-credentials.md",
           "| Router | any | admin | admin | observed | seen on clientx-prod-01 |")
    before = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    r = _run(PROMOTE, ["--promote", "leaky-cred"], env)
    assert r.returncode == 1
    assert "REFUSED" in r.stdout and "clientx" in r.stdout
    after = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    assert after == before                                              # wiki untouched
    assert (eng / "wiki-candidates" / "leaky-cred.md").exists()         # still pending
    assert not (eng / "wiki-candidates" / "_promoted" / "leaky-cred.md").exists()


def test_wiki_promote_leak_gate_uses_source_eng_scope(tmp_path):
    """FIX 2: the leak gate must derive scope-host markers from the CANDIDATE'S
    OWN source_eng, not just whichever engagement is currently active. The
    candidate physically sits in the active engagement's inbox (that is the
    only inbox wiki-promote.py ever reads), but its source_eng frontmatter
    names a DIFFERENT engagement, 'sidecorp', built here with its own
    scope.md. sidecorp's scope lists a host that appears nowhere else - not a
    dir-name marker, not in the active engagement's own scope - so it can only
    be caught if the gate is told to also check sidecorp specifically."""
    v, eng, env = _vault(tmp_path)   # active engagement = clientx (scope: clientx.example.com)
    sidecorp = v / "targets" / "sidecorp"
    sidecorp.mkdir(parents=True)
    (sidecorp / "scope.md").write_text(
        "## In scope\n- vpn-gw-7.internal-net.io\n", encoding="utf-8")
    _stage(eng, "leaky-scope-host", "default-cred", "cheatsheets/default-credentials.md",
           "| Router | any | admin | admin | observed | "
           "reachable via vpn-gw-7.internal-net.io |",
           source="sidecorp")
    before = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    r = _run(PROMOTE, ["--promote", "leaky-scope-host"], env)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "REFUSED" in r.stdout and "vpn-gw-7.internal-net.io" in r.stdout
    after = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    assert after == before                                                     # wiki untouched
    assert (eng / "wiki-candidates" / "leaky-scope-host.md").exists()          # still pending
    assert not (eng / "wiki-candidates" / "_promoted" / "leaky-scope-host.md").exists()


def test_wiki_promote_technique_section(tmp_path):
    v, eng, env = _vault(tmp_path)
    _stage(eng, "jwt-null-sig", "technique", "techniques/web/jwt-attacks.md",
           "## JWT null-signature bypass\n\nStrip the signature and set alg to none.")
    r = _run(PROMOTE, ["--promote", "jwt-null-sig"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    page = (v / "wiki" / "techniques" / "web" / "jwt-attacks.md").read_text()
    assert "## JWT null-signature bypass" in page
    assert "promoted-slug: jwt-null-sig" in page


def test_wiki_promote_all(tmp_path):
    v, eng, env = _vault(tmp_path)
    _stage(eng, "a-default", "default-cred", "cheatsheets/default-credentials.md",
           "| VendorA | any | admin | admin | vendor | x |")
    _stage(eng, "b-pattern", "api-pattern", "cheatsheets/api-request-findings.md",
           "| VendorB | /api/x | GET | - | none | data |")
    r = _run(PROMOTE, ["--promote", "all"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "promoted 2" in r.stdout
    assert "| VendorA | any | admin | admin | vendor | x |" in \
        (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    assert "| VendorB | /api/x | GET | - | none | data |" in \
        (v / "wiki" / "cheatsheets" / "api-request-findings.md").read_text()


def test_wiki_promote_refuses_target_escaping_wiki(tmp_path):
    v, eng, env = _vault(tmp_path)
    # target_page traversal resolves to <tmp_path>/scripts/wiki-promote.py, i.e.
    # OUTSIDE the vault's wiki/ entirely. Plant a sentinel there and confirm it
    # survives the promote attempt untouched.
    outside_dir = tmp_path / "scripts"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outside = outside_dir / "wiki-promote.py"
    sentinel = "#!/usr/bin/env python3\n# sentinel - must not be touched\n"
    outside.write_text(sentinel, encoding="utf-8")
    _stage(eng, "escape-attempt", "technique", "../../scripts/wiki-promote.py",
           "## Escape\n\nshould never merge here.")
    r = _run(PROMOTE, ["--promote", "escape-attempt"], env)
    assert r.returncode != 0
    assert "REFUSED" in r.stdout
    assert outside.read_text(encoding="utf-8") == sentinel                 # untouched
    assert (eng / "wiki-candidates" / "escape-attempt.md").exists()        # still pending
    assert not (eng / "wiki-candidates" / "_promoted" / "escape-attempt.md").exists()


def test_wiki_promote_leak_check_fails_closed_without_script(tmp_path):
    v, eng, env = _vault(tmp_path)
    (v / "scripts" / "check-leaks.sh").unlink()   # simulate a vault missing the gate script
    _stage(eng, "foovendor-default", "default-cred", "cheatsheets/default-credentials.md",
           "| FooVendor | any | admin | admin | vendor | web UI |")
    before = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    r = _run(PROMOTE, ["--promote", "foovendor-default"], env)
    assert r.returncode == 1
    assert "REFUSED" in r.stdout
    after = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    assert after == before                                                # wiki untouched
    assert (eng / "wiki-candidates" / "foovendor-default.md").exists()    # still pending
    assert not (eng / "wiki-candidates" / "_promoted" / "foovendor-default.md").exists()


def test_wiki_promote_refuses_bad_kind(tmp_path):
    v, eng, env = _vault(tmp_path)
    _stage(eng, "weird-thing", "not-a-real-kind", "cheatsheets/default-credentials.md",
           "| Weird | any | admin | admin | vendor | x |")
    before = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    r = _run(PROMOTE, ["--promote", "weird-thing"], env)
    assert r.returncode == 1
    assert "REFUSED" in r.stdout
    after = (v / "wiki" / "cheatsheets" / "default-credentials.md").read_text()
    assert after == before                                                # wiki untouched
    assert (eng / "wiki-candidates" / "weird-thing.md").exists()          # still pending
    assert not (eng / "wiki-candidates" / "_promoted" / "weird-thing.md").exists()


def test_skill_and_doc_wiring():
    def read(rel):
        return open(os.path.join(REPO, rel), encoding="utf-8").read()
    wiki = read("skills/wiki/SKILL.md")
    assert "## Promote candidates" in wiki
    assert "wiki-promote.py --list" in wiki
    for skill in ("skills/hunt/hunt-sqli/SKILL.md", "skills/hunt/hunt-api/SKILL.md"):
        text = read(skill)
        assert "## Wiki Feedback" not in text          # footer converted
        assert "wiki-stage.py" in text                  # now a numbered mid-workflow step


def test_all_hunt_skills_footer_converted():
    """Lock-in for the hunt-wiki-footer-consistency migration, now GLOB-DRIVEN so a
    newly-added hunt skill is auto-covered (the old hardcoded 25-name list let new
    skills escape the contract; per-kind enforcement moved to test_skill_contract.py).
    The old ad-hoc '## Wiki Feedback' footer must be gone from every
    skills/hunt/*/SKILL.md, and every vuln-class hunt skill (every skills/hunt/hunt-*
    plus wiki-recon) must carry the staged wiki-stage.py distill step. New lines must
    not carry a U+2014 em-dash."""
    skill_files = sorted(glob.glob(os.path.join(REPO, "skills", "hunt", "*", "SKILL.md")))
    assert skill_files, "no hunt skill files found under skills/hunt/*/SKILL.md"

    for path in skill_files:
        text = open(path, encoding="utf-8").read()
        assert "## Wiki Feedback" not in text, "%s still has the old footer header" % path

    vuln_class_skills = sorted(
        os.path.dirname(p) for p in glob.glob(os.path.join(REPO, "skills", "hunt", "hunt-*", "SKILL.md"))
    ) + [os.path.join(REPO, "skills", "workflow", "wiki-recon")]

    for skill_dir in vuln_class_skills:
        skill = os.path.basename(skill_dir)
        text = open(os.path.join(skill_dir, "SKILL.md"), encoding="utf-8").read()
        assert "wiki-stage.py" in text, "%s missing the wiki-stage.py distill step" % skill

        for line in text.splitlines():
            if "Distill to wiki" in line or "wiki-stage.py" in line:
                assert "—" not in line, "em-dash found in %s: %r" % (skill, line)


def test_exploit_script_preservation_step_present():
    """Lock-in for the exploit-script preservation standard: an exploit script
    (payload HTML, escape/forge script, webshell) or a read target source must be
    copied into targets/<eng>/poc/scripts/, not just screenshotted. Both ctf-box
    (Capture section) and screenshot (its capture-live lesson) must carry the
    poc/scripts step. New lines must not carry a U+2014 em-dash."""
    skills = (
        os.path.join(REPO, "skills", "workflow", "ctf-box", "SKILL.md"),
        os.path.join(REPO, "skills", "workflow", "screenshot", "SKILL.md"),
    )
    for path in skills:
        text = open(path, encoding="utf-8").read()
        assert "poc/scripts" in text, "%s missing the poc/scripts preservation step" % path

        for line in text.splitlines():
            if "poc/scripts" in line:
                assert "—" not in line, "em-dash found in %s: %r" % (path, line)


def test_ctfbox_reframed_on_kill_chain_phases():
    """The ctf-box spine is the four cyber-kill-chain phases; it anchors on the
    Approach.md board, checks /opt/arsenal first, and captures evidence via capture.sh.
    The privesc discipline (pspy + linpeas) and exploit-script preservation are kept."""
    text = open(os.path.join(REPO, "skills", "workflow", "ctf-box", "SKILL.md"), encoding="utf-8").read()
    for phase in ("Recon", "Weaponize", "Deliver", "Exploit"):
        assert phase in text, "ctf-box missing kill-chain phase: %s" % phase
    assert "Approach.md" in text
    assert "/opt/arsenal" in text
    assert "capture.sh" in text
    assert "pspy" in text and "linpeas" in text
    assert "poc/scripts" in text


def test_walkthrough_skill_exists_and_carries_required_steps():
    """Lock-in for the walkthrough auto-assembly skill: it must exist, name itself in
    frontmatter, carry the '## STATUS: SOLVED' close-out convention, the
    scripts/build-walkthrough.py scaffold+gallery step, and the live capture.sh
    evidence reference (evidence is captured into poc/ during the engagement, not
    rendered from a staged drain). ASCII only, no em-dash, and image-free (no markdown
    image embeds -- vault skill docs never carry images)."""
    path = os.path.join(REPO, "skills", "workflow", "walkthrough", "SKILL.md")
    assert os.path.isfile(path), "skills/workflow/walkthrough/SKILL.md is missing"
    text = open(path, encoding="utf-8").read()

    assert "name: walkthrough" in text
    assert "STATUS: SOLVED" in text
    assert "build-walkthrough.py" in text
    assert "capture.sh" in text                    # live evidence capture into poc/ (no staged drain)
    assert "poc/scripts" in text                   # exploit-script preservation step

    assert "![" not in text, "skill doc must stay image-free"
    text.encode("ascii")                           # raises UnicodeEncodeError on any non-ASCII char
    for line in text.splitlines():
        assert "—" not in line, "em-dash found in skills/workflow/walkthrough/SKILL.md: %r" % line


def test_delta_yield_logged_generic(tmp_path):
    """wiki-promote records a per-harvest delta-yield line (date, engagement_type, count) to a
    tracked, GENERIC docs/wiki-delta-log.md - never a client codename. A zero-yield promote still
    logs, so a sustained zero is visible."""
    import datetime
    v, eng, env = _vault(tmp_path)
    (eng / "state.md").write_text("---\nengagement_type: ctf\n---\n", encoding="utf-8")
    r = _run(PROMOTE, ["--promote", "all"], env)   # no candidates staged -> yields 0
    assert r.returncode == 0, r.stdout + r.stderr
    log = v / "docs" / "wiki-delta-log.md"
    assert log.exists(), "delta-yield log not created"
    content = log.read_text(encoding="utf-8")
    assert f"{datetime.date.today().isoformat()}  ctf  0" in content, content
    assert "clientx" not in content, "client codename leaked into a tracked file"
    assert "engagement_type" in content            # header present
