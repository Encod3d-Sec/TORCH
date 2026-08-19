"""Tests for scripts/campaign.py (the bb/pt/ctf workflow driver).

Each test copies tests/fixtures/campaign/ into a tmp dir and runs the driver against it, so the
fixture is never mutated. Covers the accept criteria of plan Tasks 6-12.
"""
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures", "campaign")
CAMPAIGN = os.path.join(VAULT, "scripts", "campaign.py")


def run(eng, *args, expect=None):
    r = subprocess.run([sys.executable, CAMPAIGN, "--eng", eng, *args],
                       capture_output=True, text=True)
    if expect is not None:
        assert r.returncode == expect, f"rc={r.returncode}\nout={r.stdout}\nerr={r.stderr}"
    return r


@pytest.fixture
def eng(tmp_path):
    d = tmp_path / "eng"
    shutil.copytree(FIX, d)
    return str(d)


def _init(eng, t="bb"):
    return run(eng, "init", "--type", t)


# --------------------------------------------------------------------------- Task 6 init

def test_init_ok(eng):
    r = _init(eng)
    assert r.returncode == 0, r.stderr
    st = json.load(open(os.path.join(eng, ".campaign.json")))
    assert st["type"] == "bb" and st["approach"] == "bugbounty" and st["pass"] == 0


def test_init_missing_envelope_key_exits_2(eng):
    p = os.path.join(eng, "scope.md")
    txt = open(p).read().replace("enum_cap: 5\n", "")
    open(p, "w").write(txt)
    r = _init(eng)
    assert r.returncode == 2
    assert "enum_cap" in r.stderr


def test_init_empty_inscope_exits_2(eng):
    p = os.path.join(eng, "scope.md")
    txt = re.sub(r"(## In scope\n)- \*\.example\.lt", r"\1-", open(p).read())
    open(p, "w").write(txt)
    r = _init(eng)
    assert r.returncode == 2
    assert "In scope" in r.stderr


def _make_ctf(eng):
    """Convert the bb fixture to a ctf engagement in place (state.md engagement_type)."""
    sp = os.path.join(eng, "state.md")
    txt = open(sp).read().replace("engagement_type: bugbounty", "engagement_type: ctf")
    open(sp, "w").write(txt)


def test_init_ctf_autoheals_missing_envelope(eng):
    """T1.1: a ctf box auto-heals missing/blank envelope keys instead of dying (the friction that
    made the agent skip the board). pt/bb keep hard-failing (test above)."""
    _make_ctf(eng)
    p = os.path.join(eng, "scope.md")
    txt = (open(p).read().replace("enum_cap: 5\n", "").replace("write_policy: none\n", "")
           .replace("rate_per_host: 2\n", ""))
    open(p, "w").write(txt)
    r = _init(eng, t="ctf")
    assert r.returncode == 0, r.stderr
    healed = open(p).read()
    assert re.search(r"^enum_cap:\s*50\s*$", healed, re.M)
    assert re.search(r"^write_policy:\s*full\s*$", healed, re.M)
    assert re.search(r"^rate_per_host:\s*50\s*$", healed, re.M)
    assert "auto-healed" in r.stderr


def test_init_ctf_autoheal_no_dup_on_blank_key(eng):
    """A present-but-blank envelope key is replaced in place, not duplicated."""
    _make_ctf(eng)
    p = os.path.join(eng, "scope.md")
    blanked = open(p).read().replace("enum_cap: 5", "enum_cap:")
    open(p, "w").write(blanked)
    r = _init(eng, t="ctf")
    assert r.returncode == 0, r.stderr
    assert len(re.findall(r"^enum_cap:", open(p).read(), re.M)) == 1


# --------------------------------------------------------------------------- Task 9 board

def test_board_generates_rows_with_skill(eng):
    _init(eng)
    r = run(eng, "board", expect=0)
    import _engagement as E
    sys_path = os.path.join(VAULT, "skills", "hooks")
    if sys_path not in sys.path:
        sys.path.insert(0, sys_path)
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    assert rows, "board produced no rows"
    # every row has an asset + class + a skill populated
    assert all(row.get("asset") and row.get("vuln class") for row in rows)
    assert any(row.get("skill") for row in rows)


def test_board_suppresses_deadend_pair(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    pairs = {(r["asset"].lower(), r["vuln class"].lower()) for r in rows}
    assert ("asset-2", "sqli") not in pairs, "G4: dead-end pair must be suppressed"


def test_board_empty_state_exits_2(eng):
    _init(eng)
    # strip all data rows from state.md
    p = os.path.join(eng, "state.md")
    lines = [ln for ln in open(p) if not ln.startswith("| asset-")]
    open(p, "w").write("".join(lines))
    # board now auto-seeds assets from scope.md's In scope block, so empty the scope too - the
    # exit-2 die path only fires when there is GENUINELY nothing to build a board from.
    sp = os.path.join(eng, "scope.md")
    open(sp, "w").write(re.sub(r"(## In scope\n)- \*\.example\.lt", r"\1-", open(sp).read()))
    r = run(eng, "board")
    assert r.returncode == 2
    assert "no assets" in r.stderr.lower() or "state.md" in r.stderr


def test_board_idempotent(eng):
    _init(eng)
    run(eng, "board", expect=0)
    b1 = open(os.path.join(eng, "Approach.md")).read()
    run(eng, "board", expect=0)
    b2 = open(os.path.join(eng, "Approach.md")).read()
    assert b1 == b2, "board must be idempotent"


# --------------------------------------------------------------------------- Task 10 next / G1

def test_next_withholds_exploit_while_arsenal_empty(eng):
    _init(eng)
    run(eng, "board", expect=0)
    r = run(eng, "next", expect=0)
    assert "Skill(wiki-arsenal)" in r.stdout
    assert "G1" in r.stdout
    # no tool/exploit action emitted yet
    assert "run:" not in r.stdout


def test_next_closeout_on_solved_marker(eng):
    # A box solved off-board never advances the pass cursor, so the exhaustion path never fires.
    # An explicit `## STATUS: SOLVED` in state.md must short-circuit `next` to the close-out chain.
    _init(eng)
    p = os.path.join(eng, "state.md")
    open(p, "a").write("\n## STATUS: SOLVED\n")
    r = run(eng, "next", expect=0)
    assert "CAMPAIGN COMPLETE" in r.stdout
    assert "SOLVED" in r.stdout
    # OWNED/ROOTED/COMPLETE are accepted synonyms
    txt = open(p).read().replace("## STATUS: SOLVED", "## STATUS: ROOTED")
    open(p, "w").write(txt)
    assert "CAMPAIGN COMPLETE" in run(eng, "next", expect=0).stdout


def test_next_never_asks_a_question(eng):
    _init(eng)
    run(eng, "board", expect=0)
    for _ in range(3):
        r = run(eng, "next", expect=0)
        for line in r.stdout.splitlines():
            assert not line.rstrip().endswith("?"), f"question emitted: {line}"
            assert not re.search(r"\b(Should I|Which|Approve|Do you want)\b", line)


# --------------------------------------------------------------------------- Task 11 note / done

def _first_row_id(eng):
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    return rows, rows[0]["id"]


def _write_arsenal(eng, slug):
    os.makedirs(os.path.join(eng, "arsenal"), exist_ok=True)
    open(os.path.join(eng, "arsenal", slug + ".md"), "w").write(
        "## Techniques\nt\n## Payloads\np\n## Tools\ntool\n## Cheatsheets\nc\n")


def test_class_skill_map_auth_tokens():
    """T1.2: access/auth class tokens map to the right hunt skill instead of falling through to an
    unrelated playbook skills[0] (the road session->hunt-xss mis-map)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("campaign", CAMPAIGN)
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    trig = {}
    assert c._skill_for_class("session", trig) == "hunt-auth"
    assert c._skill_for_class("account-takeover", trig) == "hunt-auth"
    assert c._skill_for_class("access-control", trig) == "hunt-idor"
    assert c._skill_for_class("business-logic", trig) == "hunt-bizlogic"
    # a real vuln-type token still resolves via the triggers.json fallback
    trig2 = {r"\bsqli\b|sql injection": "hunt-sqli"}
    assert c._skill_for_class("sqli", trig2) == "hunt-sqli"


def test_tool_for_class_manual_classes_get_curl():
    """T1.3: manual request-crafting classes default to curl (on-board for the drift-guard), not a
    scanner - so a curl ATO/session probe is not hard-blocked. sqli/rce keep their real tools."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("campaign", CAMPAIGN)
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    cfg = {}
    assert c._tool_for_class("session", cfg) == "curl"
    assert c._tool_for_class("account-takeover", cfg) == "curl"
    assert c._tool_for_class("business-logic", cfg) == "curl"
    assert c._tool_for_class("sqli", cfg) == "sqlmap"          # unchanged
    assert c._tool_for_class("rce", cfg) == "msfconsole"       # unchanged


def test_done_skill_override_satisfies_g2(eng):
    """T1.4: --skill lets a correctly-fired hunt skill close a row the board mapped to another skill,
    and writes the corrected skill back to the board."""
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    target = next(r for r in rows if r.get("skill") and r["skill"] != "hunt-auth")
    # fire a DIFFERENT skill than the board mapped
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": "hunt-auth"}) + "\n")
    _write_arsenal(eng, "ov")
    run(eng, "note", target["id"], "--arsenal", "ov", expect=0)
    run(eng, "done", target["id"], "--skill", "hunt-auth", "--poc", "poc/x.png", "--kind", "req",
        expect=0)
    rows2 = E._parse_table(os.path.join(eng, "Approach.md"))
    closed = next(r for r in rows2 if r["id"] == target["id"])
    assert closed["status"] == "[x]"
    assert closed["skill"] == "hunt-auth"   # board corrected to the skill that landed


def test_done_g2_message_points_at_skill_override(eng):
    """When the mapped skill never fired, the G2 refusal advertises the --skill escape hatch."""
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    target = next(r for r in rows if r.get("skill"))
    open(os.path.join(eng, ".events.jsonl"), "a").write(
        json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool", "tool": "Bash"}) + "\n")
    _write_arsenal(eng, "ov2")
    run(eng, "note", target["id"], "--arsenal", "ov2", expect=0)
    r = run(eng, "done", target["id"], "--poc", "poc/x.png", "--kind", "req")
    assert r.returncode == 2
    assert "--skill" in r.stderr and "G2" in r.stderr


def test_done_without_evidence_refused(eng):
    _init(eng)
    run(eng, "board", expect=0)
    _rows, rid = _first_row_id(eng)
    r = run(eng, "done", rid)
    assert r.returncode == 2
    assert "G3" in r.stderr


def test_note_requires_four_sections(eng):
    _init(eng)
    run(eng, "board", expect=0)
    _rows, rid = _first_row_id(eng)
    os.makedirs(os.path.join(eng, "arsenal"), exist_ok=True)
    open(os.path.join(eng, "arsenal", "minio.md"), "w").write("## Techniques\nt\n## Payloads\n\n## Tools\nx\n## Cheatsheets\nc\n")
    r = run(eng, "note", rid, "--arsenal", "minio")
    assert r.returncode == 2
    assert "Payloads" in r.stderr


def test_web_render_refused_on_nonvisual_class(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    # pick a non-visual row (secrets/idor/etc)
    target = next((r for r in rows if r["vuln class"] not in
                   ("xss", "ssti", "upload-preview", "ui-authz", "flag-onscreen")), rows[0])
    r = run(eng, "done", target["id"], "--poc", "p.png", "--kind", "web")
    assert r.returncode == 2
    assert "capture.sh req" in r.stderr


def test_g2_refuses_close_when_skill_never_fired(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    # a row whose skill is NOT hunt-secrets (the only fired skill in the fixture events)
    target = next((r for r in rows if r.get("skill") and r["skill"] != "hunt-secrets"), None)
    if not target:
        pytest.skip("no row with a non-fired skill")
    r = run(eng, "done", target["id"], "--poc", "p.png", "--kind", "req")
    assert r.returncode == 2
    assert "G2" in r.stderr


def test_g2_fails_open_when_events_absent(eng):
    _init(eng)
    run(eng, "board", expect=0)
    os.remove(os.path.join(eng, ".events.jsonl"))
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    target = next((r for r in rows if r.get("skill")), rows[0])
    r = run(eng, "done", target["id"], "--poc", "p.png", "--kind", "req")
    assert r.returncode == 0, r.stderr
    assert "fail-open" in r.stderr or "closed" in r.stdout


def test_done_dead_appends_deadend_and_bumps_streak(eng):
    _init(eng)
    run(eng, "board", expect=0)
    _rows, rid = _first_row_id(eng)
    before = open(os.path.join(eng, "Deadends.md")).read()
    r = run(eng, "done", rid, "--dead", "no oracle after 40 reqs", expect=0)
    after = open(os.path.join(eng, "Deadends.md")).read()
    assert len(after) > len(before)
    st = json.load(open(os.path.join(eng, ".campaign.json")))
    assert st["dry_streak"] == 1


def test_done_dead_streak_nudges_redteamlead(eng):
    _init(eng)
    run(eng, "board", expect=0)
    rows, _ = _first_row_id(eng)
    ids = [r["id"] for r in rows][:2]
    assert len(ids) == 2, "fixture board should have >=2 rows for a dead-end streak"
    r1 = run(eng, "done", ids[0], "--dead", "vector 1 exhausted", expect=0)
    assert "redteamlead" not in r1.stdout          # 1st dead-end (dry_streak=1): routine, no nudge
    r2 = run(eng, "done", ids[1], "--dead", "vector 2 exhausted", expect=0)
    assert "Skill(redteamlead)" in r2.stdout        # 2nd consecutive dead-end: nudge fires


# --------------------------------------------------------------------------- Task 12 pass-done

def test_pass_done_pass4_refuses_empty_board(eng):
    _init(eng)
    # jump to pass 4 without a board
    stp = os.path.join(eng, ".campaign.json")
    st = json.load(open(stp)); st["pass"] = 4; json.dump(st, open(stp, "w"))
    r = run(eng, "pass-done")
    assert r.returncode == 2
    assert "empty board" in r.stderr


# --------------------------------------------------------------------------- Task 31 behavioural

def test_behavioural_rows_from_endpoint_semantics(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    classes = {r["vuln class"] for r in rows}
    # asset-4 /coupon/redeem -> race-condition + business-logic; asset-2 ?id -> idor.
    # None of these have a tech fingerprint; they come from endpoint/param semantics.
    assert "race-condition" in classes
    assert "idor" in classes


def test_race_row_parks_under_write_policy_none(eng):
    _init(eng)  # fixture envelope is write_policy: none
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    race = next(r for r in rows if r["vuln class"] == "race-condition")
    assert race["status"] == "[?]", "a write-class row must park when write_policy forbids writes"
    assert os.path.isfile(os.path.join(eng, "decisions.md"))
    assert "## Decision log" in open(os.path.join(eng, "decisions.md")).read()


def test_race_row_runs_under_write_policy_full(eng):
    p = os.path.join(eng, "scope.md")
    txt = open(p).read().replace("write_policy: none", "write_policy: full")
    open(p, "w").write(txt)
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    race = next(r for r in rows if r["vuln class"] == "race-condition")
    assert race["status"] == "[ ]", "write_policy: full should let the race row run"


# --------------------------------------------------------------------------- audit-2 fixes

def test_init_resumes_not_clobbers(eng):
    _init(eng)
    run(eng, "board", expect=0)
    stp = os.path.join(eng, ".campaign.json")
    st = json.load(open(stp)); st["pass"] = 7; st["lenses_used"] = ["off-playbook"]
    json.dump(st, open(stp, "w"))
    r = run(eng, "init", "--type", "bb", expect=0)
    assert "resumed" in r.stdout
    st2 = json.load(open(stp))
    assert st2["pass"] == 7 and st2["lenses_used"] == ["off-playbook"]


def test_all_paused_does_not_close_out(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    for a in {r["asset"] for r in rows if r["status"] in ("[ ]", "[~]")}:
        run(eng, "pause-host", a, expect=0)
    r = run(eng, "next", expect=0)
    assert "PAUSED" in r.stdout and "resume" in r.stdout
    assert "CAMPAIGN COMPLETE" not in r.stdout


def test_empty_old_board_needs_migration(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Approach.md").write_text(
        "---\ntitle: t\n---\n### 4a\n\n| host | vuln class | wiki | payload/tool | status | poc |\n"
        "|------|-----------|------|--------------|--------|-----|\n")   # EMPTY old-schema table
    json.dump({"type": "bb", "approach": "bugbounty", "pass": 5}, open(eng / ".campaign.json", "w"))
    r = run(str(eng), "next")
    assert r.returncode == 2 and "migrate" in r.stderr
    run(str(eng), "migrate", expect=0)
    # after migrate, exactly one table, new header
    txt = open(eng / "Approach.md").read()
    assert txt.count("vuln class") == 1 and "| id |" in txt


# --------------------------------------------------------------------------- Task 20b two-account

def test_idor_row_needs_second_account(eng):
    # remove the second account -> the idor row must be gated on registering one
    p = os.path.join(eng, "identities.md")
    lines = [l for l in open(p) if "tester-b" not in l]
    open(p, "w").write("".join(lines))
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    idor = next(r for r in rows if r["vuln class"] == "idor")
    _write_arsenal(eng, "idor")
    run(eng, "note", idor["id"], "--arsenal", "idor", expect=0)
    for r in rows:
        if r["id"] != idor["id"] and r["status"] in ("[ ]", "[~]"):
            run(eng, "done", r["id"], "--dead", "x")
    r = run(eng, "next", expect=0)
    assert "second test account" in r.stdout.lower() and "20b" in r.stdout


# --------------------------------------------------------------------------- Task 20d ban / pause-host

def test_pause_host_skips_banned_asset(eng):
    _init(eng)
    run(eng, "board", expect=0)
    first = run(eng, "next", expect=0)
    asset = next(l.split()[1] for l in first.stdout.splitlines() if l.startswith("ASSET"))
    run(eng, "pause-host", asset, expect=0)
    r = run(eng, "next", expect=0)
    assert "PAUSED" in r.stdout and asset in r.stdout
    served = next((l.split()[1] for l in r.stdout.splitlines() if l.startswith("ASSET")), None)
    assert served != asset, "a paused host must not be served"
    run(eng, "pause-host", asset, "--resume", expect=0)
    st = json.load(open(os.path.join(eng, ".campaign.json")))
    assert asset.lower() not in [h.lower() for h in st.get("paused_hosts", [])]


# --------------------------------------------------------------------------- budget / effort from telemetry

def test_budget_fires_from_telemetry(eng):
    """req_count is derived from network events in .events.jsonl (the driver can't self-count), so
    the budget/report-only mechanism actually triggers."""
    p = os.path.join(eng, "scope.md")
    txt = open(p).read().replace("budget_requests: 5000", "budget_requests: 2")
    open(p, "w").write(txt)
    _init(eng)
    run(eng, "board", expect=0)
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        for i in range(3):
            fh.write(json.dumps({"ts": "2026-08-10T10:0%d:00Z" % i, "kind": "tool",
                                 "tool": "Bash", "bins": ["curl"]}) + "\n")
    r = run(eng, "next", expect=0)
    assert "report-only" in r.stdout
    assert "req 4/2" in r.stdout


def test_row_effort_ceiling_from_telemetry(eng):
    """Past the effort ceiling, next serves only close actions (anti-grind, Task 12c)."""
    p = os.path.join(eng, "scope.md")
    _init(eng)
    run(eng, "board", expect=0)
    r = run(eng, "next", expect=0)  # serves a row, stamps row_started
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rid = next(x for x in E._parse_table(os.path.join(eng, "Approach.md"))
               if x["status"] in ("[ ]", "[~]"))["id"]
    # flood telemetry past the ceiling (bb ceiling = 25)
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        for i in range(30):
            fh.write(json.dumps({"ts": "2026-12-01T10:%02d:00Z" % i, "kind": "tool",
                                 "tool": "Bash", "bins": ["curl"]}) + "\n")
    r = run(eng, "next", expect=0)
    assert "effort ceiling reached" in r.stdout


# --------------------------------------------------------------------------- Task 19 read gate

def test_pass1_refuses_unread_source_artifact(eng):
    _init(eng)
    p = os.path.join(eng, "source-ledger.md")            # mark the artifact unread
    txt = open(p).read().replace("| yes |", "| no |")
    open(p, "w").write(txt)
    stp = os.path.join(eng, ".campaign.json")
    st = json.load(open(stp)); st["pass"] = 1; json.dump(st, open(stp, "w"))
    r = run(eng, "pass-done")
    assert r.returncode == 2
    assert "read: no" in r.stderr and "app.min.js" in r.stderr


def test_pass1_advances_when_all_read(eng):
    _init(eng)                                            # fixture ships the artifact as read
    stp = os.path.join(eng, ".campaign.json")
    st = json.load(open(stp)); st["pass"] = 1; json.dump(st, open(stp, "w"))
    r = run(eng, "pass-done", expect=0)
    st2 = json.load(open(stp))
    assert st2["pass"] == 2


# --------------------------------------------------------------------------- pre-board recon

def test_next_before_board_guides_recon_not_reframe(eng):
    """A fresh init (pass 0, empty board) must guide recon, NOT treat the empty board as exhausted
    and dump reframe rows."""
    _init(eng)
    r = run(eng, "next", expect=0)
    assert "PRE-BOARD pass 0" in r.stdout
    assert "OSINT" in r.stdout
    assert "REFRAME" not in r.stdout
    # and no board rows were created
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    assert E._parse_table(os.path.join(eng, "Approach.md")) == []


def test_board_advances_to_driving(eng):
    _init(eng)
    run(eng, "board", expect=0)
    st = json.load(open(os.path.join(eng, ".campaign.json")))
    assert st["pass"] >= 5, "board should hand off to driving (pass 5)"
    r = run(eng, "next", expect=0)
    assert "ASSET" in r.stdout       # drives the board, not pre-board guidance


# --------------------------------------------------------------------------- audit fixes

def test_find_requires_evidence(eng):
    """G3: `done --find` without --poc must be refused (was a HIGH bypass: closed [x] + recorded
    CONFIRMED + tripped premature close-out with zero evidence)."""
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    rid = rows[0]["id"]
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:  # satisfy G2 honestly
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": rows[0]["skill"]}) + "\n")
    r = run(eng, "done", rid, "--find", "FIND-001-HIGH-x")
    assert r.returncode == 2 and "G3" in r.stderr
    rows2 = E._parse_table(os.path.join(eng, "Approach.md"))
    assert next(x for x in rows2 if x["id"] == rid)["status"] != "[x]"
    assert "CONFIRMED" not in open(os.path.join(eng, "Vuln-index.md")).read()


def test_done_ctf_gates_off_killchain_append(eng):
    _init(eng, t="ctf")
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    row = next(r for r in rows if r.get("vuln class") == "ssrf")
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": row["skill"]}) + "\n")
    r = run(eng, "done", row["id"], "--find", "FIND-001-HIGH-ssrf",
            "--poc", "poc/01.png", "--kind", "req", expect=0)
    assert "Killchain.md" not in r.stdout
    killchain = open(os.path.join(eng, "Killchain.md")).read()
    assert E._table_data_rows(killchain) == 0


def test_done_bb_still_appends_killchain(eng):
    _init(eng, t="bb")
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    row = next(r for r in rows if r.get("vuln class") == "ssrf")
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": row["skill"]}) + "\n")
    _write_verdict(eng, "FIND-001-HIGH-ssrf", refuted=False, evidence=["poc/01.png"])
    r = run(eng, "done", row["id"], "--find", "FIND-001-HIGH-ssrf",
            "--poc", "poc/01.png", "--kind", "req", expect=0)
    assert "Killchain.md" in r.stdout
    killchain = open(os.path.join(eng, "Killchain.md")).read()
    assert E._table_data_rows(killchain) == 1


def test_depth_first_cursor_is_sticky(eng):
    """G5: after closing one of an asset's rows, the cursor stays on that asset while it has open
    rows, instead of jumping to a different asset with an interleaved earlier row."""
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    # find an asset with >= 2 open rows
    from collections import Counter
    cnt = Counter(r["asset"] for r in rows if r["status"] == "[ ]")
    multi = [a for a, n in cnt.items() if n >= 2]
    if not multi:
        pytest.skip("no asset has two open rows in the fixture board")
    asset = multi[0]
    first = next(r for r in rows if r["asset"] == asset and r["status"] == "[ ]")
    # dead-end every OTHER asset's rows so only `asset` remains, then close one of its rows
    for r in rows:
        if r["asset"] != asset and r["status"] in ("[ ]", "[~]"):
            run(eng, "done", r["id"], "--dead", "x")
    run(eng, "done", first["id"], "--dead", "x")
    r = run(eng, "next", expect=0)
    assert "ASSET     %s" % asset in r.stdout, "cursor must stay on the in-progress asset"


# --------------------------------------------------------------------------- Task 20c OOB gate

def _prep_ssrf_row(eng):
    """Board, fill the ssrf arsenal, dead-end every other open row so the cursor lands on ssrf."""
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    ssrf = next(r for r in rows if r["vuln class"] == "ssrf")
    _write_arsenal(eng, "ssrf")
    run(eng, "note", ssrf["id"], "--arsenal", "ssrf", expect=0)
    for r in rows:
        if r["id"] != ssrf["id"] and r["status"] in ("[ ]", "[~]"):
            run(eng, "done", r["id"], "--dead", "x")
    return ssrf["id"]


def test_oob_row_withheld_without_listener(eng):
    _init(eng)
    _prep_ssrf_row(eng)
    r = run(eng, "next", expect=0)
    assert "OOB listener" in r.stdout and "20c" in r.stdout
    assert "run:" not in r.stdout          # exploit withheld


def test_oob_row_released_with_live_listener(eng):
    _init(eng)
    rid = _prep_ssrf_row(eng)
    with open(os.path.join(eng, "oob.md"), "a") as fh:
        fh.write("| abc123 | oast.live | /fetch | ssrf | 2026-12-01 | waiting | test |\n")
    r = run(eng, "next", expect=0)
    assert "OOB listener" not in r.stdout   # gate released
    assert "run:" in r.stdout or "Skill(" in r.stdout


def test_oob_row_parks_when_oob_forbidden(eng):
    p = os.path.join(eng, "scope.md")
    txt = open(p).read().replace("oob_allowed: true", "oob_allowed: false")
    open(p, "w").write(txt)
    _init(eng)
    _prep_ssrf_row(eng)
    r = run(eng, "next", expect=0)
    assert "cannot be proven" in r.stdout and "--park" in r.stdout


# --------------------------------------------------------------------------- Task 28 migrate

OLD_BOARD = """---
title: t
---
# board

### 4a. Foothold

| host | vuln class | wiki | payload/tool | status | poc |
|------|-----------|------|--------------|--------|-----|
| web1 | sqli | [[sqli]] | sqlmap | [x] | poc/a.png |
| web1 | xss | [[xss]] | dalfox | [!] | |

## keep
preserve me
"""


def test_migrate_roundtrip_preserves_findings(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Approach.md").write_text(OLD_BOARD)
    json.dump({"type": "bb", "approach": "bugbounty", "pass": 5},
              open(eng / ".campaign.json", "w"))
    eng = str(eng)
    run(eng, "migrate", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    assert len(rows) == 2 and all("id" in r for r in rows)
    assert rows[0]["status"] == "[x]" and rows[0]["poc"] == "poc/a.png"
    assert "preserve me" in open(os.path.join(eng, "Approach.md")).read()
    # exactly one table
    assert open(os.path.join(eng, "Approach.md")).read().count("vuln class") == 1
    run(eng, "migrate", "--unmigrate", expect=0)
    rows2 = E._parse_table(os.path.join(eng, "Approach.md"))
    assert all("id" not in r for r in rows2) and len(rows2) == 2


def test_next_refuses_unmigrated_board(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Approach.md").write_text(OLD_BOARD)
    json.dump({"type": "bb", "approach": "bugbounty", "pass": 5},
              open(eng / ".campaign.json", "w"))
    r = run(str(eng), "next")
    assert r.returncode == 2
    assert "migrate" in r.stderr


# --------------------------------------------------------------------------- campaign-doctor

def test_doctor_all_green():
    r = subprocess.run([sys.executable, os.path.join(VAULT, "scripts", "campaign-doctor.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALL GREEN" in r.stdout and "0 FAIL" in r.stdout


# --------------------------------------------------------------------------- Task 21 reframe

def _deadend_all_open(eng):
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    for r in E._parse_table(os.path.join(eng, "Approach.md")):
        if r["status"] in ("[ ]", "[~]"):
            run(eng, "done", r["id"], "--dead", "x")


def test_reframe_offplaybook_adds_coverage_rows(eng):
    _init(eng)
    run(eng, "board", expect=0)
    _deadend_all_open(eng)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    before = len(E._parse_table(os.path.join(eng, "Approach.md")))
    r = run(eng, "next", expect=0)          # board exhausted -> reframe lens 1 (off-playbook)
    assert "REFRAME lens 'off-playbook'" in r.stdout
    after = len(E._parse_table(os.path.join(eng, "Approach.md")))
    assert after > before, "off-playbook must seed coverage-class rows"


def test_two_dry_rounds_close_out(eng):
    _init(eng)
    run(eng, "board", expect=0)
    saw_complete = False
    for _ in range(12):
        _deadend_all_open(eng)
        out = run(eng, "next", expect=0).stdout
        if "CAMPAIGN COMPLETE" in out:
            saw_complete = True
            assert "Skill(triage)" in out  # bb close-out chain
            break
    assert saw_complete, "campaign must terminate at 2 dry reframe rounds"


def test_found_target_closes_out_not_reframe(eng):
    _init(eng)
    run(eng, "board", expect=0)
    stp = os.path.join(eng, ".campaign.json")
    st = json.load(open(stp)); st["max_sev_rank"] = 3; json.dump(st, open(stp, "w"))  # HIGH == target
    _deadend_all_open(eng)
    r = run(eng, "next", expect=0)
    assert "CAMPAIGN COMPLETE" in r.stdout
    assert "target-severity" in r.stdout


# --------------------------------------------------------------------------- Task 14 tool index

def test_tool_index_resolves_invocations():
    r = subprocess.run([sys.executable, CAMPAIGN, "tools"], capture_output=True, text=True)
    assert r.returncode == 0
    # sqlmap/ffuf/nuclei must resolve to their usage command, not their install line
    assert re.search(r"^sqlmap\s+exploit\s+sqlmap ", r.stdout, re.M), r.stdout
    assert re.search(r"^ffuf\s+fuzz\s+ffuf ", r.stdout, re.M)
    assert "missing: none" in r.stdout


# --------------------------------------------------------------------------- Task 16 detector

def test_handroll_detector():
    sys.path.insert(0, os.path.join(VAULT, "scripts"))
    import handroll as H
    fires = [
        "for p in admin api login backup config; do curl -s https://h/$p; done",
        "while read u; do curl -s $u; done < urls.txt",
        "curl a; curl b; curl c; curl d; curl e",
        "f(){ curl -s https://h/$1;}; f a; f b; f c",
    ]
    spares = [
        "curl -s https://x.lt/api/user/1",          # single authed fetch
        "curl 'https://h/x?id=1 union select 1,2'",  # single sqli probe
        "for p in a b; do curl https://h/$p; done",  # only 2 items
        "nmap -sCV 10.0.0.1",                        # a tool
        "ls -la",                                    # no network
    ]
    for c in fires:
        assert H.classify(c)[0], f"should fire: {c}"
    for c in spares:
        assert not H.classify(c)[0], f"should spare: {c}"


def test_grep_as_read_needs_ledger():
    sys.path.insert(0, os.path.join(VAULT, "scripts"))
    import handroll as H
    assert H.is_grep_as_read("grep -i secret app.min.js", [])[0] is True
    assert H.is_grep_as_read("grep -i secret app.min.js", ["app.min.js"])[0] is False


def test_full_happy_path_close_a_row(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    target = next((r for r in rows if r.get("skill")), rows[0])
    # the test controls its own G2 precondition: fire the target row's own skill
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": target["skill"]}) + "\n")
    _write_arsenal(eng, "card1")
    run(eng, "note", target["id"], "--arsenal", "card1", expect=0)
    run(eng, "done", target["id"], "--poc", "poc/x.png", "--kind", "req", expect=0)
    rows2 = E._parse_table(os.path.join(eng, "Approach.md"))
    closed = next(r for r in rows2 if r["id"] == target["id"])
    assert closed["status"] == "[x]" and closed["poc"] == "poc/x.png"


# ------------------------------------- tmux interactive-session / foothold wiring (design 2026-08-10)

def test_foothold_records_window_and_next_routes_post_ex_through_vm_rsh(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    rid = next(r["id"] for r in rows if r["asset"] == "asset-1")   # default-creds / trufflehog
    _write_arsenal(eng, "mc")
    run(eng, "note", rid, "--arsenal", "mc", expect=0)             # arms G1 + makes asset-1 sticky
    # a shell lands for asset-1 in tmux window 'shell'
    r = run(eng, "foothold", "asset-1", "--win", "shell", expect=0)
    assert "tmux attach" in r.stdout
    # state.md row flips to access=foothold and notes the window
    srow = next(x for x in E._parse_table(os.path.join(eng, "state.md")) if x["asset"] == "asset-1")
    assert srow["access"] == "foothold"
    assert "tmux:shell" in srow["notes"]
    # state.json records it
    st = json.load(open(os.path.join(eng, ".campaign.json")))
    assert st["footholds"]["asset-1"] == "shell"
    # next serves asset-1 (sticky) and routes its tool through vm-rsh --win shell + shows the attach hint
    r = run(eng, "next", expect=0)
    assert "FOOTHOLD" in r.stdout and "tmux attach" in r.stdout
    assert "vm-rsh.sh --win shell" in r.stdout
    assert "trufflehog" in r.stdout


def test_next_without_foothold_emits_bare_tool(eng):
    # regression: a non-foothold asset must NOT get the vm-rsh wrapper (only footholded assets do).
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    rid = next(r["id"] for r in rows if r["asset"] == "asset-1")
    _write_arsenal(eng, "mc")
    run(eng, "note", rid, "--arsenal", "mc", expect=0)
    r = run(eng, "next", expect=0)
    assert "vm-rsh.sh" not in r.stdout
    assert "FOOTHOLD" not in r.stdout


def test_done_win_records_foothold_on_close(eng):
    _init(eng)
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    target = next(r for r in rows if r["asset"] == "asset-1")
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:      # satisfy G2 like the happy-path test
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": target["skill"]}) + "\n")
    _write_arsenal(eng, "mc")
    run(eng, "note", target["id"], "--arsenal", "mc", expect=0)
    r = run(eng, "done", target["id"], "--poc", "poc/shell.png", "--kind", "req", "--win", "shell", expect=0)
    assert "foothold recorded" in r.stdout
    srow = next(x for x in E._parse_table(os.path.join(eng, "state.md")) if x["asset"] == "asset-1")
    assert srow["access"] == "foothold" and "tmux:shell" in srow["notes"]


# --------------------------------------------------------------------------- Task 5 code-exec ranking

def test_code_exec_classes_rank_first():
    # All 5 classes are in HIGH_VALUE_CLASSES (so they'd tie at v=2 without the +1000 boost) -
    # only rce/sqli are ALSO in CODE_EXEC_CLASSES, so only the boost can separate them out front.
    import campaign as C
    rows = [
        {"id": "4a:1", "asset": "h", "vuln class": "auth", "status": "[ ]", "tool": "hydra"},
        {"id": "4a:2", "asset": "h", "vuln class": "rce", "status": "[ ]", "tool": "nuclei"},
        {"id": "4a:3", "asset": "h", "vuln class": "ssrf", "status": "[ ]", "tool": "interactsh"},
        {"id": "4a:4", "asset": "h", "vuln class": "sqli", "status": "[ ]", "tool": "sqlmap"},
        {"id": "4a:5", "asset": "h", "vuln class": "idor", "status": "[ ]", "tool": "burp"},
    ]
    ordered = sorted(rows, key=lambda r: -C._row_value(r))
    assert {ordered[0]["vuln class"], ordered[1]["vuln class"]} == {"rce", "sqli"}
    assert {r["vuln class"] for r in ordered[2:]} == {"auth", "ssrf", "idor"}


# --------------------------------------------------------------------------- Task 8 enforce

def test_enforce_subcommand(tmp_path, monkeypatch):
    import campaign as C
    hooks = tmp_path / "skills" / "hooks"; hooks.mkdir(parents=True)
    monkeypatch.setattr(C, "HOOKS_DIR", str(hooks), raising=False)
    C.cmd_enforce(type("A", (), {"state": "off"})())
    assert (hooks / ".enforce-off").exists()
    C.cmd_enforce(type("A", (), {"state": "on"})())
    assert not (hooks / ".enforce-off").exists()


# --------------------------------------------------------------------------- verifier gate (2026-08-19)

def _bb_ssrf(eng):
    """Init bb, board, return (E, ssrf-row) with its hunt skill fired (G2 satisfied)."""
    _init(eng, t="bb")
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    row = next(r for r in rows if r.get("vuln class") == "ssrf")
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": row["skill"]}) + "\n")
    return E, row


def _write_verdict(eng, fid, refuted, evidence):
    os.makedirs(os.path.join(eng, "verdicts"), exist_ok=True)
    json.dump({"refuted": refuted, "confidence": "high", "evidence_checked": evidence,
               "reasons": ["disproven" if refuted else "confirmed differential"], "missing": []},
              open(os.path.join(eng, "verdicts", fid + ".json"), "w"))


def test_verify_prints_opus_prompt(eng):
    _init(eng, t="bb")
    r = run(eng, "verify", "FIND-001-HIGH-ssrf", expect=0)
    out = r.stdout.lower()
    assert "opus" in out                      # model pinned
    assert "verdicts" in out                   # where the verdict goes
    assert "refuted" in out and "evidence_checked" in out   # schema surfaced


def test_find_refused_without_verdict(eng):
    E, row = _bb_ssrf(eng)
    r = run(eng, "done", row["id"], "--find", "FIND-001-HIGH-ssrf", "--poc", "poc/01.png", "--kind", "req")
    assert r.returncode == 2, r.stdout
    assert "VERIFIER GATE" in r.stderr
    # gate fires BEFORE the row closes / CONFIRMED is recorded
    rows2 = E._parse_table(os.path.join(eng, "Approach.md"))
    assert next(x for x in rows2 if x["id"] == row["id"])["status"] != "[x]"
    assert "CONFIRMED" not in open(os.path.join(eng, "Vuln-index.md")).read()


def test_find_refused_when_refuted(eng):
    E, row = _bb_ssrf(eng)
    _write_verdict(eng, "FIND-001-HIGH-ssrf", refuted=True, evidence=["poc/01.png"])
    r = run(eng, "done", row["id"], "--find", "FIND-001-HIGH-ssrf", "--poc", "poc/01.png", "--kind", "req")
    assert r.returncode == 2
    assert "REFUTED" in r.stderr.upper()
    assert "CONFIRMED" not in open(os.path.join(eng, "Vuln-index.md")).read()


def test_find_refused_on_rubber_stamp(eng):
    E, row = _bb_ssrf(eng)
    # verdict says not-refuted but never cites the finding's real PoC -> rubber-stamp
    _write_verdict(eng, "FIND-001-HIGH-ssrf", refuted=False, evidence=["something-else.png"])
    r = run(eng, "done", row["id"], "--find", "FIND-001-HIGH-ssrf", "--poc", "poc/01.png", "--kind", "req")
    assert r.returncode == 2
    assert "CONFIRMED" not in open(os.path.join(eng, "Vuln-index.md")).read()


def test_find_allowed_with_valid_verdict(eng):
    E, row = _bb_ssrf(eng)
    _write_verdict(eng, "FIND-001-HIGH-ssrf", refuted=False, evidence=["poc/01.png"])
    r = run(eng, "done", row["id"], "--find", "FIND-001-HIGH-ssrf", "--poc", "poc/01.png", "--kind", "req",
            expect=0)
    assert "CONFIRMED" in open(os.path.join(eng, "Vuln-index.md")).read()


def test_ctf_find_skips_verifier_gate(eng):
    """ctf flags self-verify -> the gate must not require a verdict for ctf."""
    _init(eng, t="ctf")
    run(eng, "board", expect=0)
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    import _engagement as E
    rows = E._parse_table(os.path.join(eng, "Approach.md"))
    row = next(r for r in rows if r.get("vuln class") == "ssrf")
    with open(os.path.join(eng, ".events.jsonl"), "a") as fh:
        fh.write(json.dumps({"ts": "2026-12-01T00:00:00Z", "kind": "tool",
                             "tool": "Skill", "skill": row["skill"]}) + "\n")
    run(eng, "done", row["id"], "--find", "FIND-001-HIGH-ssrf", "--poc", "poc/01.png", "--kind", "req",
        expect=0)
