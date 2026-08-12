"""End-to-end hook tests via subprocess with an isolated fixture vault."""
import json
import os
import subprocess
import time

import pytest

# Import _engagement at module (collection) level, before any `vault` fixture runs,
# so its VAULT global self-locates to the REAL vault while CLAUDEBRAIN_VAULT is still
# unset. Without this, if this file is run in isolation, the first import happens
# lazily inside the first vault-fixture test (env var already monkeypatched at that
# point), which poisons the "original value" monkeypatch reverts to for the rest of
# the session. Mirrors the same pattern already relied on in test_engagement.py.
import _engagement  # noqa: E402,F401

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(REPO, "skills", "hooks")


def run_hook(name, payload, env):
    p = subprocess.run(
        ["python3", os.path.join(HOOKS, name)],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=20)
    return p


def _env(vault):
    return dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))


def test_hunt_trigger_routes_without_mandating(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py", {"prompt": "lets test ssrf here"}, env).stdout
    assert "Skill(hunt-ssrf)" in out                # still routes/surfaces the skill
    assert "Relevant skill" in out
    assert "MANDATORY" not in out                   # routing, not a hard mandate
    assert "before any other tool call" not in out.lower()


def test_hunt_trigger_surface_tier_is_softer(vault):
    # natural attack-surface term -> heuristic "consider" line, not MANDATORY
    out = run_hook("hunt-trigger.py", {"prompt": "look at this login form"}, _env(vault)).stdout
    assert "Skill(hunt-auth)" in out
    assert "consider" in out and "MANDATORY" not in out


def test_hunt_trigger_coloads_hunt_core(vault):
    out = run_hook("hunt-trigger.py", {"prompt": "test ssrf here"}, _env(vault)).stdout
    assert "Skill(hunt-ssrf)" in out
    assert "Skill(hunt-core)" in out            # spine co-loaded on a hard hunt fire


def test_hunt_trigger_coloads_core_on_soft_hunt(vault):
    out = run_hook("hunt-trigger.py", {"prompt": "look at this login form"}, _env(vault)).stdout
    assert "Skill(hunt-auth)" in out
    assert "Skill(hunt-core)" in out            # spine co-loaded on a soft hunt fire too


def test_hunt_trigger_no_core_for_non_hunt(vault):
    out = run_hook("hunt-trigger.py", {"prompt": "ingest the recon dump"}, _env(vault)).stdout
    assert "Skill(ingest)" in out
    assert "Skill(hunt-core)" not in out        # non-hunt skill -> no spine


def test_hunt_trigger_logs_fire_telemetry(vault):
    env = _env(vault)
    run_hook("hunt-trigger.py", {"prompt": "test ssrf"}, env)
    run_hook("hunt-trigger.py", {"prompt": "what time is it"}, env)  # miss
    log = os.path.join(str(vault), ".trigger-fire.jsonl")
    assert os.path.isfile(log)
    rows = [json.loads(l) for l in open(log) if l.strip()]
    assert any(r["hard"] == ["hunt-ssrf"] for r in rows)
    assert any(r["hard"] == [] and r["soft"] == [] for r in rows)  # miss logged too
    for r in rows:  # leak-safe: no prompt text in the record
        assert set(r) == {"ts", "hard", "soft", "n"}


def test_hunt_trigger_silent_on_unrelated(vault):
    out = run_hook("hunt-trigger.py", {"prompt": "what time is it"}, _env(vault)).stdout
    assert out.strip() == ""


def test_hunt_trigger_skips_injected_content(vault):
    # task-notifications / system-reminders reach UserPromptSubmit but are NOT typed
    # prompts; firing MANDATORY on their vuln-keyword text erodes trust in MANDATORY.
    injected = ("<task-notification>subagent found ssrf and idor; "
                "test the api and exploit it</task-notification>")
    out = run_hook("hunt-trigger.py", {"prompt": injected}, _env(vault)).stdout
    assert out.strip() == ""                                                    # no directive
    assert not os.path.isfile(os.path.join(str(vault), ".trigger-fire.jsonl"))  # not even logged


def test_session_guard_flags_client_marker(vault):
    # active engagement is 'acme' -> writing that marker into session/hot.md is a leak
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": str(vault / "session" / "hot.md"),
                              "content": "today on acme we filed findings"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert "CLIENT-DATA BOUNDARY" in out and "acme" in out


def test_session_guard_silent_for_targets_dest(vault):
    # writing the same into targets/<eng>/log.md is the CORRECT destination -> silent
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": str(vault / "targets" / "acme" / "log.md"),
                              "content": "today on acme we filed findings"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert out.strip() == ""


def test_session_guard_silent_for_generic_content(vault):
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": str(vault / "session" / "hot.md"),
                              "content": "refactored the lint-wiki playbook check"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert out.strip() == ""


def test_session_guard_flags_marker_in_tracked_framework_file(vault):
    # the recurring leak: the active codename baked into a tracked comment (skills/scripts/docs/wiki)
    payload = {"tool_name": "Edit",
               "tool_input": {"file_path": str(vault / "skills" / "hooks" / "recon-capture.py"),
                              "new_string": "# lesson observed on the acme box"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert "CLIENT-DATA BOUNDARY" in out and "acme" in out and "git-TRACKED" in out


def test_session_guard_silent_for_superpowers_retro(vault):
    # docs/superpowers/ is gitignored planning+retro -> may name the engagement -> silent
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": str(vault / "docs" / "superpowers" / "harness-retro.md"),
                              "content": "on the acme box the reflex mis-fired"}}
    out = run_hook("session-guard.py", payload, _env(vault)).stdout
    assert out.strip() == ""


def test_hunt_trigger_secrets_keyword(vault):
    # "found" is past-tense (excluded from the intent-verb gate), so hunt-secrets now
    # DOWNGRADES to the soft "consider" tier -- the assertion still holds via that line.
    out = run_hook("hunt-trigger.py", {"prompt": "found a hardcoded api key in the JS bundle"},
                   _env(vault)).stdout
    assert "Skill(hunt-secrets)" in out


def test_hunt_trigger_list_valued_routes_both(vault):
    # "broken access control" -> ["hunt-idor", "hunt-api"] (list-valued trigger)
    out = run_hook("hunt-trigger.py", {"prompt": "test for broken access control"}, _env(vault)).stdout
    assert "Skill(hunt-idor)" in out and "Skill(hunt-api)" in out


def test_hunt_trigger_multi_match(vault):
    # intent-laden prompt (was "sql injection and oauth", which has no intent verb) so
    # both hunt-* keywords stay in the hard tier -> MANDATORY multi-skill directive.
    out = run_hook("hunt-trigger.py",
                   {"prompt": "test for sql injection and attack the oauth flow"}, _env(vault)).stdout
    assert "hunt-sqli" in out and "hunt-federation" in out
    assert "Relevant skill" in out


def test_hunt_trigger_intent_verb_fires_hard(vault):
    # offensive/imperative verb ("exploit") near the hunt-* keyword -> stays MANDATORY
    out = run_hook("hunt-trigger.py",
                   {"prompt": "exploit the sqli in the login form"}, _env(vault)).stdout
    assert "Skill(hunt-sqli)" in out
    assert "Relevant skill" in out


def test_hunt_trigger_prose_mention_downgrades_to_soft(vault):
    # no intent verb near the keyword (ordinary descriptive prose) -> downgraded to
    # the soft "consider" tier, not dropped, and NOT a MANDATORY hard fire.
    out = run_hook("hunt-trigger.py",
                   {"prompt": "the SSRF router forwards requests to the backend"}, _env(vault)).stdout
    assert "MANDATORY" not in out
    assert "consider" in out and "Skill(hunt-ssrf)" in out


def test_hunt_trigger_review_prose_does_not_force_mandatory(vault):
    # discussing/reviewing a tool by name, not attacking it -> no intent verb nearby
    # -> hunt-mcp downgrades to soft, no imperative load-first directive.
    # (NOTE: the brief's original example prompt for this case, "using the Burp MCP
    # as a tool, not attacking one", was verified to still fire hard -- "attacking"
    # falls inside the 64-char window around the "mcp" match and the gate does not
    # do negation-detection ("not attacking"). Swapped in this prompt, which has no
    # intent-verb token anywhere in it, to actually exercise the intended behavior.)
    out = run_hook("hunt-trigger.py",
                   {"prompt": "using the Burp MCP as a tool during code review"}, _env(vault)).stdout
    assert "Your FIRST action MUST be to load Skill(hunt-mcp)" not in out
    assert "MANDATORY" not in out


def test_hunt_trigger_verbless_multi_downgrades_to_soft(vault):
    # two hunt-* keywords, no intent verb anywhere -> both downgrade to soft, no MANDATORY.
    # (NOTE: the brief's original example prompt for this case, "sql injection and oauth",
    # was verified to still fire hard -- "injection" itself matches the `inject\w*` intent
    # token baked into the vuln name, so the trigger keyword self-satisfies the gate
    # regardless of user intent. Swapped in this prompt, which has no intent-verb
    # substring in either keyword, to actually exercise the intended behavior.)
    out = run_hook("hunt-trigger.py", {"prompt": "idor and oauth"}, _env(vault)).stdout
    assert "hunt-idor" in out and "hunt-federation" in out
    assert "MANDATORY" not in out


def test_hunt_trigger_non_hunt_hard_trigger_unaffected_by_gate(vault):
    # non-hunt hard triggers (ingest, coverage, next-move, research, disclosure, nday,
    # ctf-*, screenshot) are not gated -- they keep firing MANDATORY unconditionally.
    out = run_hook("hunt-trigger.py", {"prompt": "ingest the recon dump"}, _env(vault)).stdout
    assert "Skill(ingest)" in out
    assert "Relevant skill" in out


def test_hunt_trigger_self_satisfying_keyword_still_gated(vault):
    # keywords that CONTAIN an intent verb (injection/bypass/smuggling/forgery/takeover/
    # poisoning) must not self-satisfy the gate: the intent verb must be in surrounding
    # prose, not the keyword span itself.
    env = _env(vault)
    for prose in ("the sql injection section of the report",
                  "the auth bypass finding is a dup",
                  "account takeover writeup for q2"):
        out = run_hook("hunt-trigger.py", {"prompt": prose}, env).stdout
        assert "MANDATORY" not in out, prose
    # with a real external intent verb, it fires hard
    out = run_hook("hunt-trigger.py", {"prompt": "test for sql injection on the login"}, env).stdout
    assert "Skill(hunt-sqli)" in out and "Relevant skill" in out


def test_hunt_trigger_cross_keyword_prose_does_not_fire(vault):
    # two vuln keywords in descriptive prose: one keyword's text must NOT satisfy the
    # OTHER's intent gate (both are masked before the intent search).
    env = _env(vault)
    for prose in ("cache poisoning and request smuggling are both discussed in this report",
                  "sql injection and oauth"):
        out = run_hook("hunt-trigger.py", {"prompt": prose}, env).stdout
        assert "MANDATORY" not in out, prose


def test_hunt_trigger_meta_prose_verbs_do_not_fire(vault):
    # narrowed intent set: common review/meta verbs (check/trigger/reach) near a keyword
    # must not force a MANDATORY load.
    env = _env(vault)
    for prose in ("can you check whether the ssrf section of the wiki is up to date",
                  "the trigger regex for ssrf looks fine to me",
                  "can we reach consensus on how the idor keyword should be phrased"):
        out = run_hook("hunt-trigger.py", {"prompt": prose}, env).stdout
        assert "MANDATORY" not in out, prose


def test_hunt_trigger_added_offensive_verbs_fire(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py",
                   {"prompt": "spoof the saml response to get into the oauth flow"}, env).stdout
    assert "Skill(hunt-federation)" in out and "Relevant skill" in out


def test_hunt_trigger_screenshot_no_overfire(vault):
    env = _env(vault)
    # bare 'screenshot' in ordinary prose must NOT force the MANDATORY load
    miss = run_hook("hunt-trigger.py", {"prompt": "add a screenshot to the README"}, env).stdout
    assert "Skill(screenshot)" not in miss
    # explicit capture intent still fires
    hit = run_hook("hunt-trigger.py", {"prompt": "grab a screenshot of the dashboard"}, env).stdout
    assert "Skill(screenshot)" in hit


def test_hunt_trigger_walkthrough_close_out_keyword(vault):
    env = _env(vault)
    for prompt in ("write the walkthrough for this box",
                   "close out the box now",
                   "assemble the walkthrough"):
        out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
        assert "Skill(walkthrough)" in out, prompt


def test_hunt_trigger_ics_no_overfire_on_company_suffix(vault):
    env = _env(vault)
    # 'Plc' (UK company suffix) and '.ics' must NOT fire the MANDATORY hunt-ics load
    miss = run_hook("hunt-trigger.py",
                    {"prompt": "Acme Plc is in scope per the .ics invite"}, env).stdout
    assert "Skill(hunt-ics)" not in miss
    # an unambiguous OT term still fires
    hit = run_hook("hunt-trigger.py",
                   {"prompt": "enumerate the modbus holding register"}, env).stdout
    assert "Skill(hunt-ics)" in hit


def test_hunt_trigger_ignores_keyword_in_fenced_code(vault):
    env = _env(vault)
    prompt = ("review this output\n```\ncurl 'http://x?url=http://169.254.169.254' # ssrf test\n"
              "```\nlooks fine")
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-ssrf)" not in out


def test_hunt_trigger_fires_on_prose_keyword(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py", {"prompt": "check the api for ssrf via the redirect param"},
                   env).stdout
    assert "Skill(hunt-ssrf)" in out


def test_hunt_trigger_ignores_keyword_in_inline_code(vault):
    env = _env(vault)
    out = run_hook("hunt-trigger.py",
                   {"prompt": "does the string `ssrf` appear in this log line?"}, env).stdout
    assert "Skill(hunt-ssrf)" not in out


def test_hunt_trigger_mixed_prose_and_code_still_fires(vault):
    env = _env(vault)
    prompt = "hunt for ssrf here\n```\ngrep -i xss file\n```"
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-ssrf)" in out


def test_hunt_trigger_ignores_keyword_in_unclosed_fence(vault):
    env = _env(vault)
    prompt = "logs below\n```\nsome mcp tool poisoning output"
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-mcp)" not in out


def test_hunt_trigger_stray_midline_backticks_do_not_swallow_prose(vault):
    # a stray ``` mid-sentence is NOT a code block: the prose keyword after it must still fire
    env = _env(vault)
    prompt = "oops I typed ``` earlier, anyway check the api for ssrf via the redirect param"
    out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
    assert "Skill(hunt-ssrf)" in out


def test_serial_enum_loop_nudges(vault):
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command":
                    "for i in $(seq 0 999); do curl -s http://10.0.0.5/datacubes/$i; done"}},
                   _env(vault)).stdout
    assert "SERIAL ENUMERATION" in out
    assert (vault / "targets" / "acme" / ".serial-enum-nudged").exists()


def test_serial_enum_silent_when_threaded(vault):
    # a threaded xargs -P sweep is the CORRECT pattern -> no nudge
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command":
                    "seq 1 65535 | xargs -P50 -I{} curl -s http://10.0.0.5:{}/"}}, _env(vault)).stdout
    assert "SERIAL ENUMERATION" not in out


def test_serial_enum_fires_once(vault):
    env = _env(vault)
    cmd = {"tool_name": "Bash", "tool_input":
           {"command": "for i in $(seq 1 50); do curl -s http://10.0.0.5/$i; done"}}
    first = run_hook("recon-capture.py", cmd, env).stdout
    second = run_hook("recon-capture.py", cmd, env).stdout
    assert "SERIAL ENUMERATION" in first and "SERIAL ENUMERATION" not in second


def test_recon_capture_silent_on_non_recon(vault):
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}, _env(vault)).stdout
    assert out.strip() == ""


def test_recon_capture_ignores_non_bash(vault):
    out = run_hook("recon-capture.py",
                   {"tool_name": "Read", "tool_input": {"file_path": "x"}}, _env(vault)).stdout
    assert out.strip() == ""


def test_recon_capture_malformed_exits_zero(vault):
    p = subprocess.run(["python3", os.path.join(HOOKS, "recon-capture.py")],
                       input="garbage", capture_output=True, text=True,
                       env=_env(vault), timeout=20)
    assert p.returncode == 0


def test_recon_capture_ignores_quoted_tool_alternation(vault):
    # a grep alternation like 'certipy|kerbrute' must NOT be read as invoking those tools:
    # invokes() split on the quoted '|' and matched each name -> phantom .pending-capture
    # markers that made the loop-driver nag "kerbrute ran" (the recurring false-fire).
    cmd = "for f in a b; do grep -oiE '\\b(certipy|kerbrute|secretsdump)\\b' \"$f\"; done"
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": cmd}}, _env(vault)).stdout
    assert "kerbrute" not in out and "certipy" not in out          # no capture nudge fired
    assert not os.path.isfile(str(vault / "targets" / "acme" / ".pending-capture"))  # no marker


def test_recon_completeness_fires_on_web_activity_without_discovery(vault):
    # restored+hardened reflex: web activity (curl) while ffuf/nuclei never ran -> nudge, and
    # the message names BOTH missing axes (one box left nuclei launched-but-unread; another never ran it)
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash",
                    "tool_input": {"command": "curl -s http://10.0.0.5/login"}}, _env(vault)).stdout
    assert "RECON COMPLETENESS" in out
    assert "missing: content, nuclei" in out
    assert (vault / "targets" / "acme" / ".recon-gap-fires").read_text().strip() == "1"


def test_recon_completeness_silent_once_both_axes_ran(vault):
    env = _env(vault)
    run_hook("recon-capture.py",
             {"tool_name": "Bash", "tool_input": {"command": "ffuf -u http://10.0.0.5/FUZZ -w w.txt"}}, env)
    run_hook("recon-capture.py",
             {"tool_name": "Bash", "tool_input": {"command": "nuclei -u http://10.0.0.5"}}, env)
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/login"}}, env).stdout
    assert "RECON COMPLETENESS" not in out
    rec = (vault / "targets" / "acme" / ".recon-tools").read_text()
    assert "content" in rec and "nuclei" in rec


def test_recon_completeness_escalates_then_caps(vault):
    # fire-once was ignored under momentum on two boxes; escalate but bound the noise
    env = _env(vault)
    fires = sum(
        "RECON COMPLETENESS" in run_hook(
            "recon-capture.py",
            {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/x"}}, env).stdout
        for _ in range(5))
    assert fires == 3   # _RECON_GAP_CAP: more than once, not unbounded
    assert (vault / "targets" / "acme" / ".recon-gap-fires").read_text().strip() == "3"


def test_recon_completeness_silent_when_solved(vault):
    # once the box is owned, recon completeness is moot -> a post-solve curl must not nudge
    state = vault / "targets" / "acme" / "state.md"
    state.write_text(state.read_text() + "\n## STATUS: SOLVED\nowned it\n", encoding="utf-8")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/x"}}, _env(vault)).stdout
    assert "RECON COMPLETENESS" not in out


def test_web_evidence_fires_without_capture(vault):
    # web activity but neither a page render nor a saved source -> nudge naming BOTH missing axes
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash",
                    "tool_input": {"command": "curl -s http://10.0.0.5/blog/"}}, _env(vault)).stdout
    assert "WEB EVIDENCE" in out
    assert "missing: render, source" in out
    assert (vault / "targets" / "acme" / ".web-cap-fires").read_text().strip() == "1"


def test_web_evidence_silent_once_render_and_source_captured(vault):
    env = _env(vault)
    run_hook("recon-capture.py",
             {"tool_name": "Bash",
              "tool_input": {"command": "bash scripts/capture.sh web acme blog http://10.0.0.5/blog/"}}, env)
    run_hook("recon-capture.py",
             {"tool_name": "Bash",
              "tool_input": {"command": "curl -s http://10.0.0.5/blog/ > poc/blog-source.html"}}, env)
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/blog/x"}}, env).stdout
    assert "WEB EVIDENCE" not in out
    rec = (vault / "targets" / "acme" / ".web-cap").read_text()
    assert "render" in rec and "source" in rec


def test_web_evidence_silent_when_solved(vault):
    state = vault / "targets" / "acme" / "state.md"
    state.write_text(state.read_text() + "\n## STATUS: SOLVED\nowned it\n", encoding="utf-8")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "curl -s http://10.0.0.5/blog/"}}, _env(vault)).stdout
    assert "WEB EVIDENCE" not in out


def test_screenshot_on_finding_fires_per_distinct_flag(vault):
    # once-per-engagement under-shot a multi-level chain; fire per distinct finding instead
    env = _env(vault)

    def shot(resp):
        return run_hook("recon-capture.py",
                        {"tool_name": "Bash", "tool_input": {"command": "cat /root/flag"},
                         "tool_response": resp}, env).stdout

    assert "FINDING landed" in shot("the flag is flag{alpha}")   # first finding -> nudge
    assert "FINDING landed" not in shot("the flag is flag{alpha}")  # same flag -> deduped
    assert "FINDING landed" in shot("next level flag{bravo}")     # distinct flag -> re-fires


def test_engagement_init_reports_state(vault):
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "acme" in out
    assert "Recent engagement log" in out  # surfaces private log


def test_engagement_init_surfaces_evidence_count(vault):
    # observability: deliberate poc shots are surfaced at SessionStart (silent at zero)
    poc = vault / "targets" / "acme" / "poc"
    poc.mkdir(parents=True, exist_ok=True)
    (poc / "01-foothold.png").write_bytes(b"x")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "evidence: 1 poc shot(s)" in out and "scripts/status.py" in out


def test_engagement_init_surfaces_tunnel_safe(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: true\n---\n\n"
        "# Scope\n\n## In scope\n- 10.0.0.5\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "tunnel_safe: curl+nc only (scanners kill the pivot)" in out


def test_engagement_init_silent_when_tunnel_safe_unset(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "---\ntype: engagement-scope\ntunnel_safe: false\n---\n\n"
        "# Scope\n\n## In scope\n- 10.0.0.5\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "tunnel_safe: curl+nc only" not in out


def _import_recon_capture():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "recon_capture", os.path.join(HOOKS, "recon-capture.py"))
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


def test_inner_cmds_extracts_vm_sh_wrapper():
    rc = _import_recon_capture()
    assert rc.inner_cmds("bash /root/vm.sh 'nmap -sV 10.0.0.5'") == ["nmap -sV 10.0.0.5"]


def test_inner_cmds_extracts_ssh_wrapper():
    rc = _import_recon_capture()
    assert rc.inner_cmds("sshpass -p x ssh kali@host 'nuclei -u https://x'") == ["nuclei -u https://x"]


def test_inner_cmds_extracts_wsl_wrapper():
    rc = _import_recon_capture()
    inners = rc.inner_cmds("wsl -d kali -u kali -- gobuster dir -u http://x")
    assert "gobuster dir -u http://x" in inners


def test_inner_cmds_empty_when_no_wrapper():
    rc = _import_recon_capture()
    assert rc.inner_cmds("nmap -sV x") == []


def test_inner_cmds_ignores_quoted_mention_not_at_command_position():
    # false positive guard: a vm.sh mention quoted inside an unrelated command's
    # argument (here, an echo string) must NOT be extracted -- vm.sh was never invoked.
    rc = _import_recon_capture()
    assert rc.inner_cmds("df -h; echo \"use vm.sh 'nmap -sV 10.0.0.5' for scanning\"") == []


def test_inner_cmds_extracts_vm_sh_wrapper_through_sudo():
    # command-position still works after peeling a leading sudo wrapper.
    rc = _import_recon_capture()
    assert rc.inner_cmds("sudo bash /root/vm.sh 'nmap -sV x'") == ["nmap -sV x"]


def test_inner_cmds_extracts_wsl_wrapper_multiline():
    # MULTILINE false-negative fix: wsl ... -- cmd followed by a newline + more text
    # must still extract the inner command (previously relied on `$` without re.MULTILINE).
    rc = _import_recon_capture()
    inners = rc.inner_cmds("wsl -d kali -u kali -- gobuster dir -u http://x\necho done")
    assert "gobuster dir -u http://x" in inners


# ---- Area 1 (always-capture-evidence): inner_cmds() loop/exec-shape awareness ----

def test_inner_cmds_strips_loop_do_prefix():
    # a `do <wrapper>; done` loop body segment was previously blind (the "do " prefix
    # made the vm.sh re.match, anchored at segment start, fail) -- a curl inside a
    # for...do...done loop must still get unwrapped.
    rc = _import_recon_capture()
    cmd = "for i in 1 2; do bash /root/vm.sh 'curl -s http://10.10.10.10/flag'; done"
    assert "curl -s http://10.10.10.10/flag" in rc.inner_cmds(cmd)


def test_inner_cmds_strips_then_prefix():
    rc = _import_recon_capture()
    cmd = "if true; then bash /root/vm.sh 'nmap -sV 10.0.0.5'; fi"
    assert "nmap -sV 10.0.0.5" in rc.inner_cmds(cmd)


def test_inner_cmds_recurses_into_bash_c():
    # bash -c '<payload>' is the same bridge-wrapper problem as vm.sh/ssh/wsl: the real
    # work sits inside the quoted -c argument.
    rc = _import_recon_capture()
    assert "curl -s http://10.10.10.10/flag" in rc.inner_cmds(
        "bash -c 'curl -s http://10.10.10.10/flag'")


def test_inner_cmds_recurses_into_sh_c_nested_wrapper():
    # a wrapper NESTED inside a -c payload (vm.sh called from inside a sh -c body) must
    # also unwrap -- inner_cmds recurses into the extracted -c payload.
    rc = _import_recon_capture()
    inners = rc.inner_cmds("sh -c \"bash /root/vm.sh 'nuclei -u https://x'\"")
    assert "nuclei -u https://x" in inners


def test_inner_cmds_recurses_into_heredoc():
    rc = _import_recon_capture()
    cmd = "bash <<'EOF'\ncurl -s http://10.10.10.10/flag\nEOF"
    assert "curl -s http://10.10.10.10/flag" in rc.inner_cmds(cmd)


def test_inner_cmds_still_empty_for_plain_command():
    # regression guard: the widening must not spuriously invent inners for a plain command.
    rc = _import_recon_capture()
    assert rc.inner_cmds("nmap -sV x") == []
    assert rc.inner_cmds("python3 solve.py") == []


def test_invokes_detects_probe_tool_through_wrappers():
    rc = _import_recon_capture()
    for cmd in (
        "bash /root/vm.sh 'nmap -sV 10.0.0.5'",
        "sshpass -p x ssh kali@host 'nuclei -u https://x'",
        "wsl -d kali -u kali -- gobuster dir -u http://x",
    ):
        inners = rc.inner_cmds(cmd)
        hit = rc.invokes(cmd, rc.PROBE_TOOLS) or next(
            (m for ic in inners if (m := rc.invokes(ic, rc.PROBE_TOOLS))), None)
        assert hit is not None, cmd
    # must stay a non-match: tool name merely mentioned in a path, no wrapper syntax
    assert rc.invokes("ls /root/nuclei-templates", rc.PROBE_TOOLS) is None
    no_inners = rc.inner_cmds("ls /root/nuclei-templates")
    assert not any(rc.invokes(ic, rc.PROBE_TOOLS) for ic in no_inners)


def test_recon_capture_recognizes_added_natives():
    rc = _import_recon_capture()
    # discovery tools now fire the recon/state + fingerprint path
    for t in ("naabu -host x", "dnsx -l hosts", "katana -u https://x", "gau target.com",
              "amass enum -d x", "gowitness scan -f urls", "arjun -u https://x",
              "masscan -p1-65535 10.0.0.0/8"):
        assert rc.invokes(t, rc.RECON_TOOLS) is not None, t
        assert rc.invokes(t, rc.PROBE_TOOLS) is not None, t
    # testers fingerprint their output
    for t in ("sqlmap -u 'http://x?id=1'", "dalfox url https://x", "swaks --to a@b --server mx"):
        assert rc.invokes(t, rc.PROBE_TOOLS) is not None, t
    # secret scanners route to loot.md
    for t in ("trufflehog filesystem ./src", "gitleaks detect -s ."):
        assert rc.invokes(t, rc.CRED_TOOLS) is not None, t
    # a bare mention in a path arg is still not an invocation
    assert rc.invokes("ls /opt/katana/", rc.RECON_TOOLS) is None


def test_recon_capture_flips_oob_on_callback_via_grep_poll(vault):
    # OOB auto-correlation (a KEPT behavior): a waiting oob.md row flips to HIT when its
    # token appears in a command's output. Polling a saved OAST/Collaborator log with grep
    # (a doc-command) must still flip it -- OOB correlation runs BEFORE the doc-command skip.
    eng = vault / "targets" / "acme"
    token = "oastxyz9k"
    (eng / "oob.md").write_text(
        "---\ntype: engagement-oob\n---\n\n# OOB\n\n"
        "| token | sink | class | planted | status | source |\n"
        "|-------|------|-------|---------|--------|--------|\n"
        "| %s | http://t/?url= | ssrf | 2026-07-16 | waiting | |\n" % token,
        encoding="utf-8")
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "grep %s /tmp/collab.log" % token},
               "tool_response": "1.2.3.4 - - GET /%s HTTP/1.1 200" % token}
    out = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "OOB HIT auto-correlated" in out
    assert "HIT" in (eng / "oob.md").read_text()      # row flipped to HIT on disk


def test_recon_capture_oob_silent_without_callback(vault):
    # no token in the output -> row stays waiting, no OOB block emitted
    eng = vault / "targets" / "acme"
    (eng / "oob.md").write_text(
        "---\ntype: engagement-oob\n---\n\n# OOB\n\n"
        "| token | sink | class | planted | status | source |\n"
        "|-------|------|-------|---------|--------|--------|\n"
        "| tok12345 | http://t/?url= | ssrf | 2026-07-16 | waiting | |\n",
        encoding="utf-8")
    payload = {"tool_name": "Bash", "tool_input": {"command": "nmap -sV t"},
               "tool_response": "80/tcp open http"}
    out = run_hook("recon-capture.py", payload, _env(vault)).stdout
    assert "OOB HIT" not in out
    assert "waiting" in (eng / "oob.md").read_text()   # unchanged


def _write_board(eng, weaponize_body):
    (eng / "Approach.md").write_text(
        "---\ntype: engagement-approach\n---\n\n# Board\n\n"
        "## 1. Recon\n- [x] nmap\n\n"
        "## 2. Weaponize\n" + weaponize_body + "\n\n"
        "## 3. Deliver\n- [ ] shell\n", encoding="utf-8")


def test_gate1_nudges_on_exploit_before_weaponize(vault):
    # exploit tool + Weaponize all [ ] -> GATE 1 nudge fires once, marker written
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [ ] searchsploit + wiki CVE lookup\n- [ ] pick payload")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "sqlmap -u http://t/?id=1 --batch"},
                    "tool_response": "sqlmap testing"}, _env(vault)).stdout
    assert "GATE 1" in out and "Weaponize" in out
    assert (eng / ".gate1-nudged").exists()


def test_gate1_silent_when_weaponize_started(vault):
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [~] searchsploit + wiki CVE lookup\n- [ ] pick payload")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "hydra -l admin -P rock ssh://t"},
                    "tool_response": "x"}, _env(vault)).stdout
    assert "GATE 1" not in out


def test_gate1_silent_on_recon_command(vault):
    # a recon tool is not exploitation -> no GATE 1 nudge even with Weaponize undone
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [ ] searchsploit + wiki CVE lookup")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "nmap -sV t"},
                    "tool_response": "80 open"}, _env(vault)).stdout
    assert "GATE 1" not in out


def test_gate1_fires_once(vault):
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [ ] searchsploit")
    (eng / ".gate1-nudged").write_text("")   # already nudged this engagement
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "sqlmap -u http://t --batch"},
                    "tool_response": "x"}, _env(vault)).stdout
    assert "GATE 1" not in out


def _write_empty_board(eng):
    # an Approach.md that EXISTS but was never built: frontmatter + gate legend + empty section
    # headers + a 4a table with header/separator only. No `- [ ]` checklist items, no data rows.
    # The legend line's `[ ]`/`[x]`/... are prose (not `- [ ]` list items) and must not count.
    (eng / "Approach.md").write_text(
        "---\ntype: engagement-approach\n---\n\n# Kill-Chain Board\n\n"
        "Status: `[ ]` todo | `[~]` doing | `[x]` done | `[-]` n/a | `[!]` deadend\n"
        "GATE 1 (wiki): no hand-rolled exploit until its Weaponize wiki item is `[x]`.\n\n"
        "## 1. Recon\n\n## 2. Weaponize\n\n## 4. Exploit\n\n### 4a. Foothold\n"
        "| id | asset | vuln class | arsenal | skill | tool | status | poc | poc_kind |\n"
        "|----|-------|-----------|---------|-------|------|--------|-----|----------|\n",
        encoding="utf-8")


def test_board_nudge_fires_on_exploit_with_empty_board(vault):
    # exploit-shaped cmd + Approach.md exists but has no board rows -> BOARD NOT BUILT nudge, marker set
    eng = vault / "targets" / "acme"
    _write_empty_board(eng)
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "sqlmap -u http://t/?id=1 --batch"},
                    "tool_response": "sqlmap testing"}, _env(vault)).stdout
    assert "BOARD NOT BUILT" in out and "campaign.py board" in out
    assert (eng / ".board-nudged").exists()


def test_board_nudge_silent_when_board_has_rows(vault):
    # a board with real checklist items is 'built' -> no BOARD NOT BUILT nudge
    eng = vault / "targets" / "acme"
    _write_board(eng, "- [ ] searchsploit + wiki CVE lookup")
    out = run_hook("recon-capture.py",
                   {"tool_name": "Bash", "tool_input": {"command": "sqlmap -u http://t --batch"},
                    "tool_response": "x"}, _env(vault)).stdout
    assert "BOARD NOT BUILT" not in out


def test_board_nudge_fires_once(vault):
    eng = vault / "targets" / "acme"
    _write_empty_board(eng)
    cmd = {"tool_name": "Bash", "tool_input": {"command": "sqlmap -u http://t --batch"},
           "tool_response": "x"}
    first = run_hook("recon-capture.py", cmd, _env(vault)).stdout
    second = run_hook("recon-capture.py", cmd, _env(vault)).stdout
    assert "BOARD NOT BUILT" in first and "BOARD NOT BUILT" not in second


def test_close_out_nudges_walkthrough_when_solved_stale(vault):
    # SOLVED state + no walkthrough.md (stale) -> Stop hook nudges to run walkthrough
    eng = vault / "targets" / "acme"
    (eng / "state.md").write_text(
        (eng / "state.md").read_text() + "\n## STATUS: SOLVED\n", encoding="utf-8")
    out = run_hook("close-out.py", {}, _env(vault)).stdout
    assert "Close-out" in out and "walkthrough" in out.lower()


def test_close_out_silent_when_not_solved(vault):
    out = run_hook("close-out.py", {}, _env(vault)).stdout
    assert out.strip() == ""


def test_close_out_nudges_learn_when_walkthrough_done(vault):
    # SOLVED + a real (non-stale) walkthrough + no .learn-done -> nudge to run learn
    eng = vault / "targets" / "acme"
    (eng / "state.md").write_text(
        (eng / "state.md").read_text() + "\n## STATUS: SOLVED\n", encoding="utf-8")
    (eng / "walkthrough.md").write_text(
        "# Walkthrough - acme\n\n## 1. Recon\nran nmap, found ssh + web\n\n"
        "## Evidence\n| shot | caption |\n|------|---------|\n| ![](poc/01.png) | login |\n",
        encoding="utf-8")
    out = run_hook("close-out.py", {}, _env(vault)).stdout
    assert "Close-out" in out and "learn" in out.lower()


def test_engagement_init_surfaces_wiki_candidates(vault):
    inbox = vault / "targets" / "acme" / "wiki-candidates"
    inbox.mkdir()
    (inbox / "foo-default.md").write_text(
        "---\ntarget_page: cheatsheets/default-credentials.md\nkind: default-cred\n"
        "slug: foo-default\nsource_eng: acme\ndate: 2026-07-06\nstatus: pending\n---\n\n"
        "| Foo | any | admin | admin | vendor | x |\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    # collapsed into the one-line `harness:` maintenance summary
    assert "harness:" in out
    assert "wiki-candidates:1" in out
    assert "wiki-promote.py --list" in out


def test_engagement_init_silent_no_wiki_candidates(vault):
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "wiki-candidates" not in out


def test_engagement_init_counts_candidate_with_extra_spacing(vault):
    # FIX 1: 'status:  pending' (two spaces) must still count as pending.
    # wiki_candidate_count must PARSE frontmatter (via _engagement._frontmatter,
    # the same tolerant parser wiki-promote.py's pending-detection uses) instead
    # of a raw "status: pending" (single-space) substring match, which silently
    # undercounts a promotable candidate at SessionStart.
    inbox = vault / "targets" / "acme" / "wiki-candidates"
    inbox.mkdir()
    (inbox / "foo-default.md").write_text(
        "---\ntarget_page: cheatsheets/default-credentials.md\nkind: default-cred\n"
        "slug: foo-default\nsource_eng: acme\ndate: 2026-07-06\nstatus:  pending\n---\n\n"
        "| Foo | any | admin | admin | vendor | x |\n", encoding="utf-8")
    out = run_hook("engagement-init.py", {"source": "startup"}, _env(vault)).stdout
    assert "wiki-candidates:1" in out


def test_scope_guard_drops_deadend_arm():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "skills", "hooks", "scope-guard.py"), encoding="utf-8").read()
    assert "Deadends" not in src
    assert "deadend_hits" not in src
    assert "DEAD-END" not in src


def test_fingerprint_hits_is_routing_only():
    import os, re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "skills", "hooks", "recon-capture.py"), encoding="utf-8").read()
    body = re.search(r"def fingerprint_hits\(blob\):.*?\n    return out\n", src, re.S).group(0)
    for banned in ("try {tests}", "don't hand-roll", "arsenal: consult", "reuse: ", "tools: lean on"):
        assert banned not in body, banned
    assert "Skill(%s)" in body and "detected" in body




def _write_scope(vault, in_scope=(), out_of_scope=(), flags=()):
    """Write a scope.md into the fixture 'acme' engagement for scope-guard tests."""
    lines = ["---", "type: engagement-scope"]
    lines += ["%s: true" % f for f in flags]
    lines += ["---", "", "# Scope", "", "## In scope"]
    lines += (["- " + h for h in in_scope] or ["-"])
    lines += ["", "## Out of scope"]
    lines += (["- " + h for h in out_of_scope] or ["-"])
    (vault / "targets" / "acme" / "scope.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- scope-guard enforcing decision path (safety properties a + b) ---

def test_scope_guard_denies_out_of_scope_ipv4(vault):
    # safety property (b): an OOS IPv4 host must be denied
    _write_scope(vault, in_scope=["10.0.0.5"], out_of_scope=["10.9.9.0/24"])
    out = run_hook("scope-guard.py", {"tool_name": "Bash",
                   "tool_input": {"command": "nmap -sV 10.9.9.42"}}, _env(vault)).stdout
    assert '"permissionDecision": "deny"' in out and "out-of-scope" in out and "10.9.9.42" in out


def test_scope_guard_denies_out_of_scope_host_and_skips_filename(vault):
    _write_scope(vault, in_scope=["app.example.com"], out_of_scope=["prod.example.com"])
    deny = run_hook("scope-guard.py", {"tool_name": "Bash",
                    "tool_input": {"command": "curl https://prod.example.com/api"}}, _env(vault)).stdout
    assert '"deny"' in deny and "prod.example.com" in deny
    # FILE_EXT branch: config.yml / app.py look host-shaped but are filenames -> not a target -> allowed
    ok = run_hook("scope-guard.py", {"tool_name": "Bash",
                  "tool_input": {"command": "cat config.yml app.py notes.md"}}, _env(vault)).stdout
    assert ok.strip() == ""


def test_scope_guard_denies_roe_forbidden_tooling(vault):
    env = _env(vault)
    _write_scope(vault, in_scope=["10.0.0.5"], flags=["no_bruteforce"])
    bf = run_hook("scope-guard.py", {"tool_name": "Bash",
                  "tool_input": {"command": "hydra -l admin -P rockyou.txt ssh://10.0.0.5"}}, env).stdout
    assert '"deny"' in bf and "no_bruteforce" in bf
    _write_scope(vault, in_scope=["10.0.0.5"], flags=["no_dos"])
    dos = run_hook("scope-guard.py", {"tool_name": "Bash",
                   "tool_input": {"command": "nmap -T5 --min-rate 90000 10.0.0.5"}}, env).stdout
    assert '"deny"' in dos and "no_dos" in dos
    _write_scope(vault, in_scope=["10.0.0.5"], flags=["passive_only"])
    pas = run_hook("scope-guard.py", {"tool_name": "Bash",
                   "tool_input": {"command": "nuclei -u http://10.0.0.5"}}, env).stdout
    assert '"deny"' in pas and "passive_only" in pas


def test_scope_guard_allows_in_scope_with_active_out_of_scope(vault):
    # safety property (a): a valid in-scope command is NOT blocked even when an out_of_scope list is active
    _write_scope(vault, in_scope=["10.0.0.5", "app.example.com"],
                 out_of_scope=["10.9.9.0/24", "prod.example.com"])
    out = run_hook("scope-guard.py", {"tool_name": "Bash",
                   "tool_input": {"command": "nmap -sV 10.0.0.5; curl https://app.example.com/api"}},
                   _env(vault)).stdout
    assert out.strip() == ""


def test_scope_guard_denies_out_of_scope_ipv6(vault):
    # safety property (b), IPv6 under-block fix: IP_RE is IPv4-only, so this was NOT denied before
    _write_scope(vault, in_scope=["2001:db8:1::5"], out_of_scope=["2001:db8:dead::/48"])
    out = run_hook("scope-guard.py", {"tool_name": "Bash",
                   "tool_input": {"command": "nmap -6 2001:db8:dead::1"}}, _env(vault)).stdout
    assert '"deny"' in out and "out-of-scope" in out and "2001:db8:dead::1" in out


def test_scope_guard_allows_param_ip_against_in_scope_host(vault):
    # safety property (a), over-block fix: in-scope host, OOS IP only in a query param
    # (SSRF/redirect testing) -> must NOT deny
    _write_scope(vault, in_scope=["app.example.com"], out_of_scope=["10.9.9.0/24"])
    out = run_hook("scope-guard.py", {"tool_name": "Bash",
                   "tool_input": {"command": "curl 'http://app.example.com/x?next=10.9.9.42'"}},
                   _env(vault)).stdout
    assert out.strip() == ""


def test_scope_guard_denies_option_assigned_out_of_scope_target(vault):
    # safety property (b), under-block fix: an OOS target passed as --url=/-u= must be denied.
    # The old blanket `=`-strip hid it and let the out-of-scope host escape the guard.
    _write_scope(vault, in_scope=["app.example.com"],
                 out_of_scope=["10.9.9.0/24", "prod.example.com"])
    env = _env(vault)
    ip = run_hook("scope-guard.py", {"tool_name": "Bash",
                  "tool_input": {"command": "curl --url=http://10.9.9.42/"}}, env).stdout
    assert '"deny"' in ip and "10.9.9.42" in ip
    host = run_hook("scope-guard.py", {"tool_name": "Bash",
                    "tool_input": {"command": "wpscan --url=https://prod.example.com"}}, env).stdout
    assert '"deny"' in host and "prod.example.com" in host


def test_scope_guard_allows_ssrf_payload_in_data_flag(vault):
    # over-block fix preserved for the POST/header vector: an OOS URL that is an SSRF PAYLOAD in
    # a -d/--data value (not the target) against an in-scope host must NOT deny.
    _write_scope(vault, in_scope=["app.example.com"], out_of_scope=["10.9.9.0/24"])
    out = run_hook("scope-guard.py", {"tool_name": "Bash",
                   "tool_input": {"command": "curl -d 'redirect=http://10.9.9.42/' http://app.example.com/"}},
                   _env(vault)).stdout
    assert out.strip() == ""


def test_scope_guard_fails_open_on_malformed_json(vault):
    p = subprocess.run(["python3", os.path.join(HOOKS, "scope-guard.py")],
                       input="garbage{", capture_output=True, text=True, env=_env(vault), timeout=20)
    assert p.returncode == 0
    assert "permissionDecision" not in p.stdout


def test_scope_guard_fails_open_on_malformed_scope(vault):
    # garbage scope.md must not crash the guard; a clean in-scope command is still allowed
    (vault / "targets" / "acme" / "scope.md").write_bytes(
        b"\xff\xfe not yaml ## In scope\n- [unclosed\x00 garbage")
    p = run_hook("scope-guard.py", {"tool_name": "Bash",
                 "tool_input": {"command": "nmap -sV 10.0.0.5"}}, _env(vault))
    assert p.returncode == 0
    assert "permissionDecision" not in p.stdout


def test_scope_guard_escape_hatch_downgrades_to_advisory(vault):
    """The skills/hooks/.enforce-off marker turns every deny into an advisory warning, so a
    false block can never trap the operator."""
    _write_scope(vault, in_scope=["10.0.0.5"], out_of_scope=["10.9.9.0/24"])
    marker = os.path.join(HOOKS, ".enforce-off")
    env = _env(vault)
    try:
        open(marker, "w").close()
        out = run_hook("scope-guard.py", {"tool_name": "Bash",
                       "tool_input": {"command": "nmap 10.9.9.42"}}, env).stdout
        assert "permissionDecision" not in out
        assert "additionalContext" in out and "advisory" in out
    finally:
        if os.path.exists(marker):
            os.remove(marker)


def test_web_evidence_gaps(tmp_path):
    """Close-out web-evidence gate: a SOLVED web box needs recon cards + render/source; else gaps.
    Non-web boxes are silent; fully-evidenced boxes return []."""
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("_eng_wg", os.path.join(HOOKS, "_engagement.py"))
    e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
    d = tmp_path
    (d / "poc").mkdir(); (d / "recon").mkdir()
    (d / "state.md").write_text("## STATUS: SOLVED\n| h | http | 80 | x | root | THM{x} | y |\n", encoding="utf-8")
    g = e.web_evidence_gaps(str(d))
    assert any("recon cards" in x for x in g)
    assert any("render" in x for x in g)
    (d / "recon" / "01-nmap.png").write_bytes(b"x")
    (d / "poc" / "01-home-source.html").write_text("<html>", encoding="utf-8")
    assert e.web_evidence_gaps(str(d)) == []
    # non-web box (only ssh/22) -> gate silent
    (d / "state.md").write_text("## STATUS: SOLVED\n| h | ssh | 22 | x | root | THM{x} | y |\n", encoding="utf-8")
    assert e.web_evidence_gaps(str(d)) == []


def test_paths_write_gap(tmp_path):
    """State-discipline reflex: loot captured but Killchain.md still empty -> gap = loot row count;
    once a path row exists (or loot is still stub) -> 0. Header/separator rows never count."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_eng_pg", os.path.join(HOOKS, "_engagement.py"))
    e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
    d = tmp_path
    loot_hdr = "| item | type | source | where | status |\n|------|------|--------|-------|--------|\n"
    paths_hdr = "| path | stage | status | blocker | next-move |\n|------|-------|--------|---------|-----------|\n"
    # both stubs (header+separator only) -> no findings -> no gap
    (d / "loot.md").write_text(loot_hdr, encoding="utf-8")
    (d / "Killchain.md").write_text(paths_hdr, encoding="utf-8")
    assert e.paths_write_gap(str(d)) == 0
    # loot has 2 findings, paths still stub -> gap = 2
    (d / "loot.md").write_text(loot_hdr + "| admin cred | cred | web | login | works |\n| id_rsa | key | ftp | ssh | works |\n", encoding="utf-8")
    assert e.paths_write_gap(str(d)) == 2
    # write a path row -> gap clears
    (d / "Killchain.md").write_text(paths_hdr + "| web->cred->ssh | user | done | - | - |\n", encoding="utf-8")
    assert e.paths_write_gap(str(d)) == 0
    # fail-open on missing dir
    assert e.paths_write_gap(None) == 0


def test_unsprayed_cred_gap(tmp_path):
    """Cred-reuse reflex: >=2 credential rows in loot.md + not solved + no spray/reuse line in
    Deadends.md -> gap = cred row count. A single cred, a solved box, or a logged spray -> 0."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_eng_cs", os.path.join(HOOKS, "_engagement.py"))
    e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
    d = tmp_path
    hdr = "| cred | value | source | works on |\n|------|-------|--------|----------|\n"
    (d / "state.md").write_text("# State\n", encoding="utf-8")
    (d / "Deadends.md").write_text("# Deadends\n", encoding="utf-8")
    # one cred only -> not yet a reuse gap
    (d / "loot.md").write_text(hdr + "| app admin | password s3cret | web | login |\n", encoding="utf-8")
    assert e.unsprayed_cred_gap(str(d)) == 0
    # two creds, nothing sprayed -> gap = 2
    (d / "loot.md").write_text(hdr + "| app admin | password s3cret | web | login |\n"
                                     "| db | password hunter2 | .env | mysql |\n", encoding="utf-8")
    assert e.unsprayed_cred_gap(str(d)) == 2
    # a non-credential row (a flag) must not count toward the gap
    (d / "loot.md").write_text(hdr + "| app admin | password s3cret | web | login |\n"
                                     "| flag1 | THM{aaa} | robots.txt | n/a |\n", encoding="utf-8")
    assert e.unsprayed_cred_gap(str(d)) == 0
    # two creds but a spray is logged -> gap clears
    (d / "loot.md").write_text(hdr + "| app admin | password s3cret | web | login |\n"
                                     "| db | password hunter2 | .env | mysql |\n", encoding="utf-8")
    (d / "Deadends.md").write_text("- [x] cred spray of both passwords vs ssh/su -- all rejected\n",
                                   encoding="utf-8")
    assert e.unsprayed_cred_gap(str(d)) == 0
    # the `user / password` loot form counts even without the word "password"
    (d / "Deadends.md").write_text("# Deadends\n", encoding="utf-8")
    (d / "loot.md").write_text(hdr + "| app admin | administrator / Th1s_1s | source | web |\n"
                                     "| db | clocky_user / seG3mY4 | .env | mysql |\n", encoding="utf-8")
    assert e.unsprayed_cred_gap(str(d)) == 2
    # solved box never nudges
    (d / "state.md").write_text("## STATUS: SOLVED\n", encoding="utf-8")
    assert e.unsprayed_cred_gap(str(d)) == 0
    # fail-open on missing dir
    assert e.unsprayed_cred_gap(None) == 0


# --- hunt-trigger framework-meta guard + intent-gate tightening (0.4) ---

def test_hunt_trigger_api_methodology_does_not_fire(vault):
    # the exact hard false-fire: "document the api security testing methodology in the wiki"
    # HARD-fired hunt-api because the adjacent "testing" satisfied the intent gate. The
    # intent-gate tightening (_expand_span masks the bordering "testing") keeps it out of a
    # MANDATORY load; a mild soft "consider" is acceptable (it does mention api security).
    out = run_hook("hunt-trigger.py",
                   {"prompt": "document the api security testing methodology in the wiki"},
                   _env(vault)).stdout
    assert "MANDATORY" not in out


def test_hunt_trigger_framework_meta_prompts_silent(vault):
    # prompts ABOUT the harness itself (a config file, or "the harness") must not route a hunt
    # skill. Narrow by design: only unambiguous harness references silence a vuln keyword.
    env = _env(vault)
    for prompt in (
        "update the ssrf trigger in triggers.json",
        "improve the deserialization fingerprint in the playbook.json",
        "review the sqli detection methodology for the harness",
    ):
        out = run_hook("hunt-trigger.py", {"prompt": prompt}, env).stdout
        assert out.strip() == "", prompt


def test_hunt_trigger_offensive_prompt_with_meta_words_still_fires(vault):
    # the meta guard must NOT silence a real hunt just because it uses a common word like
    # "documentation" / "methodology" - those appear constantly in genuine target work.
    env = _env(vault)
    idor = run_hook("hunt-trigger.py",
                    {"prompt": "read the api documentation and test each endpoint for idor"}, env).stdout
    assert "Skill(hunt-idor)" in idor, idor
    ssrf = run_hook("hunt-trigger.py",
                    {"prompt": "exploit the ssrf per the pentest methodology"}, env).stdout
    assert "Skill(hunt-ssrf)" in ssrf, ssrf


def test_hunt_trigger_wiki_app_target_still_fires(vault):
    # bare "wiki" is NOT a meta key: a wiki APP (MediaWiki/Confluence/DokuWiki) is a
    # common pentest target, so an offensive prompt against one must still fire.
    out = run_hook("hunt-trigger.py",
                   {"prompt": "exploit xss in the target's mediawiki app"}, _env(vault)).stdout
    assert "Skill(hunt-xss)" in out and "Relevant skill" in out


def test_hunt_trigger_intent_gate_ignores_adjacent_test_noun(vault):
    # intent-gate tightening (no meta words): a trailing "testing" bordering the "api security"
    # keyword is a noun phrase, not intent -> hunt-api must NOT fire hard.
    out = run_hook("hunt-trigger.py",
                   {"prompt": "write up the api security testing steps for the client report"},
                   _env(vault)).stdout
    assert "Relevant skill" not in out          # not a hard MANDATORY fire


def test_hunt_trigger_genuine_vuln_still_fires_despite_guard(vault):
    # the guard must not silence real target work
    env = _env(vault)
    ssrf = run_hook("hunt-trigger.py", {"prompt": "test ssrf on the login endpoint"}, env).stdout
    assert "Skill(hunt-ssrf)" in ssrf and "Relevant skill" in ssrf
    sqli = run_hook("hunt-trigger.py", {"prompt": "exploit the sqli behind the search box"}, env).stdout
    assert "Skill(hunt-sqli)" in sqli and "Relevant skill" in sqli


# --- wiki-reindex auto-reindex hook (2.1) ---

def _reindex_env(vault):
    """Point qmd at the fixture AND drop the qmd bin dir from PATH, so a real `qmd update`
    can never fire against the fixture (which would pollute the real ~/.qmd index). python3
    stays resolvable for the hook subprocess itself."""
    import shutil
    env = _env(vault)
    env["QMD_VAULT"] = str(vault)
    py = shutil.which("python3") or "/usr/bin/python3"
    qmd = shutil.which("qmd")
    parts = [os.path.dirname(py), "/usr/bin", "/bin"]
    if qmd:
        parts = [p for p in parts if p != os.path.dirname(qmd)]
    env["PATH"] = ":".join(dict.fromkeys(parts))
    return env


def test_wiki_reindex_acts_on_wiki_edit(vault):
    stamp = vault / ".wiki-reindex-stamp"
    assert not stamp.exists()
    run_hook("wiki-reindex.py",
             {"tool_name": "Edit",
              "tool_input": {"file_path": str(vault / "wiki" / "techniques" / "foo.md")}},
             _reindex_env(vault))
    assert stamp.exists()                       # a wiki .md edit records a (debounced) reindex


def test_wiki_reindex_skips_non_wiki_edit(vault):
    env = _reindex_env(vault)
    run_hook("wiki-reindex.py",
             {"tool_name": "Edit",
              "tool_input": {"file_path": str(vault / "targets" / "acme" / "state.md")}}, env)
    assert not (vault / ".wiki-reindex-stamp").exists()   # non-wiki path -> no-op
    # a wiki-dir path that is NOT markdown is also skipped
    run_hook("wiki-reindex.py",
             {"tool_name": "Write",
              "tool_input": {"file_path": str(vault / "wiki" / "index.json")}}, env)
    assert not (vault / ".wiki-reindex-stamp").exists()


def test_wiki_reindex_debounces_burst(vault):
    env = _reindex_env(vault)
    ev = {"tool_name": "Edit",
          "tool_input": {"file_path": str(vault / "wiki" / "payloads" / "xss.md")}}
    run_hook("wiki-reindex.py", ev, env)
    first = (vault / ".wiki-reindex-stamp").stat().st_mtime
    run_hook("wiki-reindex.py", ev, env)         # immediate second edit within the window
    assert (vault / ".wiki-reindex-stamp").stat().st_mtime == first   # not re-fired


def test_wiki_reindex_malformed_exits_zero(vault):
    p = subprocess.run(["python3", os.path.join(HOOKS, "wiki-reindex.py")],
                       input="garbage", capture_output=True, text=True, env=_env(vault), timeout=20)
    assert p.returncode == 0
    assert not (vault / ".wiki-reindex-stamp").exists()


# --- fail-open across every hook (2.3a) ---

@pytest.mark.parametrize("payload", ["garbage", ""])
@pytest.mark.parametrize("hook", [
    "scope-guard.py", "hunt-trigger.py", "session-guard.py",
    "engagement-init.py", "recon-capture.py", "wiki-reindex.py"])
def test_all_hooks_fail_open(vault, hook, payload):
    p = subprocess.run(["python3", os.path.join(HOOKS, hook)],
                       input=payload, capture_output=True, text=True, env=_env(vault), timeout=25)
    assert p.returncode == 0, (hook, payload, p.stderr)
    assert "permissionDecision" not in p.stdout, (hook, payload, p.stdout)


def test_playbook_cognito_not_off_incognito():
    # word-boundary fix: "incognito" must NOT route hunt-cloud; a real cognito surface still does
    rc = _import_recon_capture()
    recs = rc.fingerprint_records("browse http://dev.incognito.com/login")
    assert "hunt-cloud" not in [s for _l, sp in recs for s in (sp.get("skills") or [])]
    recs2 = rc.fingerprint_records("AWS cognito user pool idp")
    assert "hunt-cloud" in [s for _l, sp in recs2 for s in (sp.get("skills") or [])]


def test_playbook_fires_xss_on_reflected_script_and_dom_sink():
    # new web-source hint: a reflected <script>/event-handler or a DOM sink routes hunt-xss
    rc = _import_recon_capture()
    def sk(b): return [s for _l, sp in rc.fingerprint_records(b) for s in (sp.get("skills") or [])]
    assert "hunt-xss" in sk("the page reflects <script>alert(1)</script> unescaped")
    assert "hunt-xss" in sk("el.innerHTML = location.hash")
    assert sk("a normal html page about cats") == []          # benign -> no fire


def test_playbook_fires_ssrf_on_fetch_sink():
    # new web-source hint: a URL-fetch param/sink taking input routes hunt-ssrf
    rc = _import_recon_capture()
    def sk(b): return [s for _l, sp in rc.fingerprint_records(b) for s in (sp.get("skills") or [])]
    for blob in ("GET /preview?url=http://169.254.169.254", "r = requests.get(user_url)",
                 "$x = file_get_contents($_GET[u]);"):
        assert "hunt-ssrf" in sk(blob), blob


def test_playbook_xss_not_off_generic_name_field():
    # a generic name="name" form field must NOT route hunt-xss; a search field still does
    rc = _import_recon_capture()
    recs = rc.fingerprint_records('<input name="name" type="text" required>')
    assert "hunt-xss" not in [s for _l, sp in recs for s in (sp.get("skills") or [])]
    recs2 = rc.fingerprint_records('<input name="search" placeholder="Search">')
    assert "hunt-xss" in [s for _l, sp in recs2 for s in (sp.get("skills") or [])]


def test_close_out_fires_eval_metrics_when_solved(vault):
    import shutil
    eng = vault / "targets" / "acme"
    (eng / "state.md").write_text(
        (eng / "state.md").read_text() + "\n## STATUS: SOLVED\n", encoding="utf-8")
    (eng / ".events.jsonl").write_text(
        '{"ts":"2026-07-17T02:00:00+00:00","kind":"tool","tool":"Bash"}\n', encoding="utf-8")
    (vault / "scripts").mkdir(exist_ok=True)
    shutil.copy(os.path.join(REPO, "scripts", "eval_metrics.py"),
                str(vault / "scripts" / "eval_metrics.py"))
    run_hook("close-out.py", {}, _env(vault))
    assert (eng / ".eval-written").exists()
    assert "## Metrics (auto)" in (eng / "eval.md").read_text()


# --- GATE 1 wiki-first: inline the mapped page + per-skill escalating nudge ---

def _load_rc():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_rc_g1", os.path.join(HOOKS, "recon-capture.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def test_wiki_index_prefers_the_substantive_twin(vault, monkeypatch):
    """Duplicate basenames across the wiki (payloads/xss.md vs techniques/web/xss.md) must not
    silently drop one: the index keeps the LARGEST file. This is the exact dict-collision bug
    that once made wiki-wiring-audit invent false orphans."""
    rc = _load_rc()
    import _engagement
    w = os.path.join(_engagement.VAULT, "wiki")
    os.makedirs(os.path.join(w, "payloads"), exist_ok=True)
    os.makedirs(os.path.join(w, "techniques", "web"), exist_ok=True)
    open(os.path.join(w, "payloads", "xss.md"), "w").write("tiny\n")
    big = os.path.join(w, "techniques", "web", "xss.md")
    open(big, "w").write("## Bypass\n" + ("x" * 500) + "\n")
    monkeypatch.setattr(rc, "_wiki_index", rc._wiki_index)
    assert rc._wiki_index().get("xss") == big


def test_wiki_excerpt_inlines_the_bypass_section(vault):
    """The routing nudge must hand over the documented bypasses, not just name the page --
    removing the detour is the whole point of the fix."""
    rc = _load_rc()
    import _engagement
    d = os.path.join(_engagement.VAULT, "wiki", "techniques", "web")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "ssrf.md"), "w").write(
        "---\ntitle: ssrf\n---\n\n## Intro\nprose\n\n"
        "### Blocklist bypass\n| Case-variation | http://LoCaLHosT/admin |\n"
        "| Decimal | 2130706433 |\n\n## Next section\nignored\n")
    text, rel = rc._wiki_excerpt(["ssrf"])
    assert "LoCaLHosT" in text and "2130706433" in text
    assert "ignored" not in text                      # stops at the next heading
    assert rel.endswith("ssrf.md")
    assert rc._wiki_excerpt(["no-such-page"]) == ("", "")


def test_wiki_excerpt_keeps_subsections_and_resolves_path_form_refs(vault):
    """Two bugs the first version shipped with, caught by smoke-testing against the real wiki:
    (1) breaking on ANY heading returned a section title plus a blank line, because a '## X'
    section is immediately followed by its own '### Y' child -- break only on a same-or-higher
    level heading; (2) playbook.json writes refs both as 'ssrf' and as 'payloads/ssrf', and the
    path form must resolve to THAT page, not to whichever basename twin the index prefers."""
    rc = _load_rc()
    import _engagement
    w = os.path.join(_engagement.VAULT, "wiki")
    os.makedirs(os.path.join(w, "payloads"), exist_ok=True)
    os.makedirs(os.path.join(w, "techniques", "web"), exist_ok=True)
    open(os.path.join(w, "techniques", "web", "dupe.md"), "w").write(
        "## Bypasses\n\n### Child one\nkeep-me\n\n### Child two\nalso-keep\n\n## After\ndrop-me\n"
        + "padding\n" * 50)
    open(os.path.join(w, "payloads", "dupe.md"), "w").write("## Bypasses\npayload-twin\n")
    text, rel = rc._wiki_excerpt(["dupe"])
    assert "keep-me" in text and "also-keep" in text     # subsections survive
    assert "drop-me" not in text                          # same-level heading ends it
    # path-form ref must pick the payloads twin even though the index prefers the larger file
    text2, rel2 = rc._wiki_excerpt(["payloads/dupe"])
    assert "payload-twin" in text2 and rel2.endswith(os.path.join("payloads", "dupe.md"))


def test_wiki_excerpt_ignores_headings_inside_code_fences(vault):
    """A `# comment` on the first line of a ```bash/```powershell block is NOT a markdown
    heading. Treating it as one broke on a live box: every wiki payload section that opens with
    a commented command truncated to the section title + a blank line (2 lines). The excerpt
    must only break on a real heading OUTSIDE a code fence."""
    rc = _load_rc()
    import _engagement
    d = os.path.join(_engagement.VAULT, "wiki", "techniques", "ad")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "enum.md"), "w").write(
        "---\ntitle: enum\n---\n\n"
        "## Key payloads / examples\n\n"
        "```powershell\n"
        "# Rapid domain overview (this # is a comment, not a heading)\n"
        "Get-ADUser -Filter *\n"
        "# Another comment line\n"
        "Get-ADComputer -Filter *\n"
        "```\n\n"
        "## Next real heading\ndropped\n")
    text, rel = rc._wiki_excerpt(["enum"])
    assert "Get-ADUser" in text and "Get-ADComputer" in text   # fence contents survive
    assert "dropped" not in text                                # the real ## heading still ends it
    assert len(text.splitlines()) > 4                           # not truncated to title+blank


def test_gate1_unmet_only_claims_what_telemetry_proves(vault):
    """Per-skill escalation, and a routed skill counts as satisfied once it is invoked OR any
    wiki page is read. Never asserts 'not read' without the telemetry to back it."""
    rc = _load_rc()
    import _engagement
    d = _engagement.active_dir()
    ev = os.path.join(d, ".events.jsonl")

    def w(rows):
        with open(ev, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    # nothing routed -> nothing to nudge
    w([{"kind": "tool", "tool": "Bash"}])
    assert rc._gate1_unmet(d) is None
    # routed + never invoked + no wiki read -> nudge 1/3, naming the skill
    w([{"kind": "route", "routed": "hunt-ssrf"}])
    assert rc._gate1_unmet(d)[0] == "hunt-ssrf"
    assert rc._gate1_unmet(d)[2] == 1
    # escalates while still ignored, then stops at the cap
    rc._gate1_record(d, "hunt-ssrf", 3)
    assert rc._gate1_unmet(d) is None
    # invoking the skill satisfies it
    rc._gate1_record(d, "hunt-ssrf", 0)
    w([{"kind": "route", "routed": "hunt-ssrf"},
       {"kind": "tool", "tool": "Skill", "skill": "hunt-ssrf"}])
    assert rc._gate1_unmet(d) is None
    # so does reading a wiki page (the skill is only the vehicle)
    w([{"kind": "route", "routed": "hunt-ssrf"},
       {"kind": "tool", "tool": "Read", "wiki": "techniques/web/ssrf.md"}])
    assert rc._gate1_unmet(d) is None


def test_tool_telemetry_records_wiki_reads_only(vault):
    """A Read under wiki/ is recorded (it is the proof the page was opened); a Read of a target
    file must NOT be -- the events log stays free of client paths."""
    import _engagement
    env = _env(vault)
    wiki_file = os.path.join(_engagement.VAULT, "wiki", "techniques", "web", "ssrf.md")
    os.makedirs(os.path.dirname(wiki_file), exist_ok=True)
    open(wiki_file, "w").write("x\n")
    run_hook("tool-telemetry.py",
             {"tool_name": "Read", "tool_input": {"file_path": wiki_file}}, env)
    run_hook("tool-telemetry.py",
             {"tool_name": "Read", "tool_input": {"file_path": "/tmp/loot/creds.txt"}}, env)
    rows = [json.loads(l) for l in
            open(os.path.join(_engagement.active_dir(), ".events.jsonl"), encoding="utf-8")]
    wikis = [r.get("wiki") for r in rows if r.get("wiki")]
    assert wikis == ["techniques/web/ssrf.md"]
    assert not any("creds.txt" in json.dumps(r) for r in rows)


# --------------------------------------------- close-out: auto-build walkthrough on SOLVED

def test_close_out_autobuilds_walkthrough_on_solved(vault):
    # the hook locates build-walkthrough.py under <vault>/scripts (via _engagement.VAULT, same as
    # its autocard/eval calls); the fixture vault has no scripts/, so symlink the real one in (its
    # realpath still resolves _engagement from the real repo, and it reads CLAUDEBRAIN_VAULT).
    sdir = vault / "scripts"
    sdir.mkdir(exist_ok=True)
    os.symlink(os.path.join(REPO, "scripts", "build-walkthrough.py"), sdir / "build-walkthrough.py")
    eng = vault / "targets" / "acme"
    with open(eng / "state.md", "a", encoding="utf-8") as fh:
        fh.write("\n## STATUS: SOLVED\n")
    os.makedirs(eng / "poc", exist_ok=True)
    (eng / "poc" / "01-shell.png").write_bytes(b"\x89PNG\r\n")           # a card for the gallery
    assert not (eng / "walkthrough.md").is_file()                        # absent before the hook
    p = run_hook("close-out.py", {}, _env(vault))
    # the hook auto-assembled the walkthrough scaffold + Evidence gallery
    assert (eng / "walkthrough.md").is_file(), p.stdout + p.stderr
    text = (eng / "walkthrough.md").read_text(encoding="utf-8")
    assert "## Evidence" in text and "![](poc/01-shell.png)" in text
    # narrative stubs remain -> the draft-narrative nudge still fires (not silently "done")
    assert "walkthrough" in p.stdout.lower()


def test_close_out_silent_when_not_solved(vault):
    # a non-SOLVED engagement must NOT get a walkthrough built or a close-out nudge
    eng = vault / "targets" / "acme"
    p = run_hook("close-out.py", {}, _env(vault))
    assert not (eng / "walkthrough.md").is_file()
    assert "walkthrough.md is not assembled" not in p.stdout


def test_drift_reminder_removed():
    import os
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "skills", "hooks", "recon-capture.py")
    src = open(p).read()
    assert "_drift_reminder" not in src and "import datetime" not in src
