# delegate + metasploit Skills — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two on-demand harness skills — `delegate` (autonomous sub-agent exploit-run with a checklist + false-root guardrail) and `metasploit` (a hunt-burp-style msfconsole framework-driver) — and wire them into routing (triggers.json, playbook.json) and the cross-referencing skills.

**Architecture:** Two new `SKILL.md` files under `skills/workflow/`, each terse markdown following the vault's existing skill voice (model: `skills/burp/hunt-burp/SKILL.md`, ~100 lines, points to wiki cheatsheets rather than re-teaching syntax). Plus data-only routing edits (2 JSON files) and small prose cross-refs in 3 existing files.

**Tech Stack:** Markdown (Obsidian Flavored: `[[wikilinks]]`, `Skill(x)` refs), JSON (triggers.json, playbook.json), Python 3 stdlib for validation.

**Spec:** `docs/specs/2026-08-17-metasploit-delegate-skills.md`

## Global Constraints

- **No new hooks, no code logic.** Skills are markdown; routing is data (triggers.json/playbook.json).
- **Wiki-first, no duplication.** `metasploit` POINTS to `wiki/cheatsheets/metasploit.md` for syntax; it does not copy it. `delegate` promotes the existing `ctf-workflow/SKILL.md:81-86` prose into a reusable skill.
- **Vault voice:** terse, no em-dashes (use commas/semicolons), no emojis, concrete values not `$VAR` in example commands (per `feedback_human_poc_commands`). Match `hunt-burp` length/tone.
- **Client-data boundary:** both skills are GENERIC (no target IPs/creds/hostnames). The worked examples in `delegate` use placeholder tokens (`<vpn-ip>`, `<target>`, `<user>`), never real engagement data.
- **Every `[[wiki-page]]` and `Skill(x)` reference must resolve** to an existing file/skill.
- Commits: this repo commits only on the operator's go; commit steps are provided but the operator decides when to run them.

---

### Task 1: Create the `delegate` skill

**Files:**
- Create: `skills/workflow/delegate/SKILL.md`
- Test: `tests/test_new_skills.py` (created here, extended in Task 2/3)

**Interfaces:**
- Produces: an invokable skill named `delegate` (discovered by basename). References `Skill(metasploit)` (created in Task 2) and the wiki pages listed below.

- [ ] **Step 1: Write the skill file**

Frontmatter (verbatim):
```markdown
---
name: delegate
description: Autonomous sub-agent hand-off for a fiddly, fully-specified exploit-compile / escalation RUN - the main agent stays on strategy and the board while a cheap sub-agent runs an exact copy-paste checklist behind a false-root/hostname guardrail. Use for "delegate", "offload", "hand this to a sub-agent", "spin a haiku", or the moment a foothold plus a working escalation vector is identified. Main agent dispatches, waits (no parallel duplicate), integrates the result.
---
```

Body — write terse prose (hunt-burp voice) under these exact headings, from this substance:

- `# Delegate: sub-agent exploit-run` — one-line purpose.
- `## When to delegate / when NOT` — delegate: a foothold + a WORKING escalation vector identified; OR a fiddly fully-specified multi-step compile/run (compile a C PoC, deliver+run an ELF, drive `su`/`sudo`/`screen -r`, msfvenom+`multi/handler` catch). Keep on the main agent: recon, judgement-heavy vector selection, anything not fully specified.
- `## Model choice` — `haiku` for mechanical/fully-specified; `sonnet` for judgement-heavy multi-step (e.g. a JS-heavy per-route-CSRF authed backend RCE). One line each.
- `## The checklist (a delegation is only as good as its checklist)` — required slots, each a bold label + one-line why: **(a) confirmed access/primitive** spelled out; **(b) exact copy-paste commands** with real IPs/paths, no `$VAR`; **(c) egress/port constraints** (egress-tested LPORT); **(d) the false-root guardrail** (see next section); **(e) fragile-box discipline** if applicable (serial, long timeouts, no fuzzers); **(f) report-back contract** (return the primitive/creds/flag + evidence path; do not pivot further without the main agent). State: under-specify any slot and the sub-agent flails (endgame takeaway).
- `## False-root/hostname guardrail (MANDATORY every delegation)` — a returned `uid=0`/root is trusted ONLY if `hostname` == the target AND the expected uid; else the shell died back to the Kali box (which runs as root; `$(...)`/backticks substitute locally, the false-RCE trap) -> re-pop. The sub-agent MUST report `hostname` alongside any `id`.
- `## Main-agent discipline` — keep driving the board; dispatch ONE sub-agent at a time (serial); do NOT duplicate its work in parallel; WAIT for completion; on return persist the primitive/creds/flag to `state.md`/`loot.md`/`Killchain.md` before the next move.
- `## Mechanism` — dispatch via the Agent tool: `subagent_type` general-purpose, `model` per the choice above, the checklist as the prompt, an explicit return/report contract. This skill's invocation IS the standing authorization to use the Agent tool mid-engagement.
- `## Worked examples` — 3-4 ready checklists using PLACEHOLDER tokens only: (1) catch a meterpreter as a service acct (egress-tested LPORT, inline base64 ELF via panel RCE, guardrail); (2) `ssh2john`->crack->`ssh-keygen -p` strip->SSH chain; (3) sudo `screen -r <name>` -> `Ctrl-A c` root (guardrail hostname==target); (4) openssl-caps `.so`-constructor root. Keep each ~4-6 lines.
- `## Client-data boundary` — one line: examples use placeholders; never put real target data in this skill.

- [ ] **Step 2: Write the validation test**

```python
# tests/test_new_skills.py
import os, re
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)

def _skill(name):
    return os.path.join(VAULT, "skills", "workflow", name, "SKILL.md")

def _frontmatter_ok(path):
    txt = open(path, encoding="utf-8").read()
    return txt.startswith("---") and "\nname:" in txt[:400] and "\ndescription:" in txt[:1200]

def _refs_resolve(path):
    """Every [[wiki]] and Skill(x) ref in the file resolves to an existing wiki page or skill dir."""
    txt = open(path, encoding="utf-8").read()
    missing = []
    for m in re.findall(r"\[\[([^\]|#]+)", txt):
        slug = m.strip().split("/")[-1]
        hits = []
        for root, _, files in os.walk(os.path.join(VAULT, "wiki")):
            if slug + ".md" in files:
                hits.append(root)
        if not hits:
            missing.append("[[%s]]" % m)
    for m in set(re.findall(r"Skill\(([a-z0-9-]+)\)", txt)):
        found = any(os.path.isfile(os.path.join(VAULT, "skills", sub, m, "SKILL.md"))
                    for sub in ("workflow", "hunt", "burp", ""))
        if not found:
            missing.append("Skill(%s)" % m)
    return missing

def test_delegate_frontmatter():
    assert _frontmatter_ok(_skill("delegate"))

def test_delegate_refs_resolve():
    assert _refs_resolve(_skill("delegate")) == []
```

- [ ] **Step 3: Run the test**

Run: `cd <VAULT> && python3 -m pytest tests/test_new_skills.py -k delegate -v`
Expected: `test_delegate_frontmatter` PASS; `test_delegate_refs_resolve` PASS **only after** Task 2 creates `metasploit` (the delegate skill references `Skill(metasploit)`). If run before Task 2, `test_delegate_refs_resolve` fails on `Skill(metasploit)` — that is expected; re-run after Task 2. (Do not add a `[[pivoting]]`/`Skill(arsenal)`-style ref that does not resolve.)

- [ ] **Step 4: Commit**

```bash
git add skills/workflow/delegate/SKILL.md tests/test_new_skills.py
git commit -m "skills: add delegate (autonomous sub-agent exploit-run with false-root guardrail)"
```

---

### Task 2: Create the `metasploit` skill

**Files:**
- Create: `skills/workflow/metasploit/SKILL.md`
- Test: extend `tests/test_new_skills.py`

**Interfaces:**
- Consumes: `wiki/cheatsheets/metasploit.md` (must exist — it does, 189 lines), `wiki/cheatsheets/pivoting.md`, `Skill(arsenal)`, `Skill(delegate)`.
- Produces: an invokable skill named `metasploit`.

- [ ] **Step 1: Write the skill file**

Frontmatter (verbatim):
```markdown
---
name: metasploit
description: Drive msfconsole across the workflow - DB-backed recon (db_nmap, auxiliary scanners), version->exploit search/check/run, multi/handler reverse shells (meterpreter-first, plain shell_reverse_tcp backup for Windows/EDR), sessions + local_exploit_suggester + post modules, and autoroute/portfwd/socks pivoting. Points to the metasploit cheatsheet for syntax. Use for "metasploit", "msfconsole", "msfvenom", "meterpreter", "multi/handler", or driving an exploit/reverse-shell through msf.
---
```

Body — terse prose (hunt-burp voice, ~100 lines), each heading a short workflow + a pointer to the cheatsheet (do NOT re-teach syntax):

- `# Metasploit: framework driver` — one-line purpose + "syntax lives in `[[metasploit]]`; this skill is the workflow."
- `## Pre-attack wiki query (MANDATORY)` — `[[metasploit]]` + `Skill(arsenal)` for the fingerprinted tech/CVE before firing (mirror hunt-burp's mandatory wiki-first).
- `## Setup / DB` — `msfconsole -q`, `workspace -a <eng>`, `db_status`; run inside a named tmux tab, never a blind background.
- `## Recon via msf` — `db_nmap`, `auxiliary/scanner/*` (smb/http/ssh version + vuln checks) feeding `hosts`/`services`; complements the ctf-box Phase-1 basics, does not replace them.
- `## Search / select / verify` — `search <app> <ver>` / `search cve:<id>`, `use`, `info`, and `check` BEFORE firing.
- `## Reverse shells` — `multi/handler`; payload meterpreter-first (`linux/x64/meterpreter/reverse_tcp` etc.); plain `shell_reverse_tcp` backup when meterpreter is blocked/unstable (routine on Windows/EDR); `msfvenom` delivery (ELF/EXE/ASPX/PHP -> `[[metasploit]]` MSFVenom section); egress-tested LPORT (80/443/53); `set ExitOnSession false; run -j`.
- `## Sessions / post-ex` — `sessions -i`, `run post/multi/recon/local_exploit_suggester` (the privesc reflex), `post/*`, `getsystem`, `post/multi/manage/shell_to_meterpreter`.
- `## Pivoting` — `autoroute`/`portfwd`/`socks` to reach internal-only ports before hand-rolling SSH `-L` (`[[pivoting]]`).
- `## Verify target (false-root)` — `getuid` + `sysinfo`/hostname == target before trusting a shell.
- `## Interlock + anti-drift` — the fiddly msfvenom-compile + handler catch + escalation run is a prime `Skill(delegate)` hand-off. DRIVE msf for load-bearing exploit/shell requests (operator observes); don't abandon msf for raw scripts post-foothold.
- `## Client-data boundary` — one line.

- [ ] **Step 2: Extend the validation test**

Append to `tests/test_new_skills.py`:
```python
def test_metasploit_frontmatter():
    assert _frontmatter_ok(_skill("metasploit"))

def test_metasploit_refs_resolve():
    assert _refs_resolve(_skill("metasploit")) == []

def test_delegate_and_metasploit_interlock_resolves():
    # now that both exist, the whole set resolves
    assert _refs_resolve(_skill("delegate")) == []
    assert _refs_resolve(_skill("metasploit")) == []
```

- [ ] **Step 3: Run the tests**

Run: `cd <VAULT> && python3 -m pytest tests/test_new_skills.py -v`
Expected: all PASS (both skills' frontmatter + refs resolve; the interlock test confirms `delegate`->`metasploit` and `metasploit`->`delegate` both resolve now).

- [ ] **Step 4: Commit**

```bash
git add skills/workflow/metasploit/SKILL.md tests/test_new_skills.py
git commit -m "skills: add metasploit (msfconsole framework-driver, points to cheatsheet)"
```

---

### Task 3: Wire routing (triggers.json + playbook.json) and cross-references

**Files:**
- Modify: `skills/hunt/triggers.json`
- Modify: `scripts/playbook.json`
- Modify: `skills/workflow/ctf-box/SKILL.md`, `skills/workflow/ctf-workflow/SKILL.md`, `CLAUDE.md`
- Test: extend `tests/test_new_skills.py`

**Interfaces:**
- Consumes: the two skills from Tasks 1-2.
- Produces: routing entries and prose pointers; no code.

- [ ] **Step 1: Write the failing routing test**

Append to `tests/test_new_skills.py`:
```python
import json

def test_triggers_route_new_skills():
    d = json.load(open(os.path.join(VAULT, "skills", "hunt", "triggers.json")))
    t = d["triggers"]
    # both regexes compile and map to the new skills
    for k in t:
        re.compile(k)
    vals = set(t.values())
    assert "metasploit" in vals and "delegate" in vals

def test_playbook_wires_metasploit_and_parses():
    d = json.load(open(os.path.join(VAULT, "scripts", "playbook.json")))
    fps = d["fingerprints"]
    hits = [k for k, v in fps.items() if "metasploit" in (v.get("skills") or [])]
    assert hits, "no fingerprint routes to metasploit"
    # not blanket-applied
    assert len(hits) < len(fps), "metasploit added to every fingerprint (should be msf-strong only)"
```

- [ ] **Step 2: Run it (fails)**

Run: `cd <VAULT> && python3 -m pytest tests/test_new_skills.py -k "triggers or playbook" -v`
Expected: FAIL (routing not wired yet).

- [ ] **Step 3: Add the two `triggers.json` entries**

In `skills/hunt/triggers.json`, under `"triggers"`, add:
```json
"metasploit|msfconsole|msfvenom|meterpreter|multi/handler": "metasploit",
"\\bdelegate\\b|\\boffload\\b|hand (this|it) (off|to a sub)|spin (a|up a) (haiku|sub-?agent)": "delegate"
```
Keep the file valid JSON (watch trailing commas). Preserve existing entries.

- [ ] **Step 4: Wire `metasploit` into `playbook.json` (msf-strong fingerprints only)**

First enumerate candidates: `cd <VAULT> && python3 -c "import json; d=json.load(open('scripts/playbook.json'))['fingerprints']; [print(k) for k,v in d.items() if any(w in (str(v.get('approach',''))+str(v.get('refs',''))).lower() for w in ('searchsploit','metasploit','msf','cve-','eternalblue','smb'))]"`
For EACH printed fingerprint, add `"metasploit"` to its `skills` array (append, don't replace existing skills). Do NOT add it to fingerprints that have no exploit/CVE/msf signal. Keep the JSON valid.

- [ ] **Step 5: Cross-reference prose edits**

- `skills/workflow/ctf-box/SKILL.md`: at Phase 2 Weaponize, add a line pointing to `Skill(metasploit)` for the msf search/exploit path (alongside the existing searchsploit+metasploit reflex); at Phase 3 Deliver, point the handler step to `Skill(metasploit)`; at Phase 4 Exploit, add `Skill(delegate)` for the compile+run + `local_exploit_suggester`.
- `skills/workflow/ctf-workflow/SKILL.md` lines ~81-86: replace the inline delegation checklist prose with a one-line summary + `see Skill(delegate)`.
- `CLAUDE.md`: add two rows to the skills/tools table — `delegate` (autonomous sub-agent exploit-run) and `metasploit` (msfconsole framework-driver).

- [ ] **Step 6: Run all validation**

Run:
```bash
cd <VAULT>
python3 -m pytest tests/test_new_skills.py -v
python3 -c "import json; json.load(open('scripts/playbook.json')); json.load(open('skills/hunt/triggers.json')); print('json ok')"
grep -c 'Skill(delegate)' skills/workflow/ctf-box/SKILL.md skills/workflow/ctf-workflow/SKILL.md
grep -c 'Skill(metasploit)' skills/workflow/ctf-box/SKILL.md
grep -c 'delegate\|metasploit' CLAUDE.md
bash scripts/check-leaks.sh 2>/dev/null | tail -3 || true   # confirm no client data in the new files
```
Expected: all pytest PASS; JSON ok; each grep >= 1; check-leaks clean.

- [ ] **Step 7: Commit**

```bash
git add skills/hunt/triggers.json scripts/playbook.json skills/workflow/ctf-box/SKILL.md skills/workflow/ctf-workflow/SKILL.md CLAUDE.md tests/test_new_skills.py
git commit -m "wire delegate + metasploit into triggers/playbook + ctf-box/ctf-workflow/CLAUDE cross-refs"
```

---

### Task 4: Register and final validation

**Files:** none (machine-setup + full-suite gate)

- [ ] **Step 1: Register the new skills on this machine**

Run: `cd <VAULT> && bash setup/install-skills.sh 2>&1 | tail -5`
(Symlinks each SKILL.md dir into `~/.claude/skills/`. This modifies `~/.claude`, which is per-machine and outside the repo — expected.)

- [ ] **Step 2: Confirm discovery**

Run: `ls -la ~/.claude/skills/ | grep -E 'delegate|metasploit'`
Expected: both symlinks present, pointing into the vault.

- [ ] **Step 3: Full-suite regression**

Run: `cd <VAULT> && python3 -m pytest tests/ -q`
Expected: no NEW failures vs. a baseline (capture `python3 -m pytest tests/ -q > /tmp/baseline.txt` before Task 1 if unsure). The new skills are markdown/JSON only; nothing else should move.

- [ ] **Step 4: Manual smoke (report, do not auto-run)**

Note for the operator: in a fresh session, `Skill(metasploit)` and `Skill(delegate)` should load; and a prompt mentioning "msfconsole"/"meterpreter" or "delegate this to a subagent" should surface the trigger. (Runtime picker behavior is not unit-testable here.)

---

## Notes for the executor

- `<VAULT>` = this machine's vault path (`/mnt/c/Users/TZ/Documents/ObsidianVaults/ClaudeBrain`).
- Author both SKILL.md files by reading `skills/burp/hunt-burp/SKILL.md` first for voice/length, and the spec (`docs/specs/2026-08-17-metasploit-delegate-skills.md`) for substance. Do not exceed ~110 lines per skill.
- `delegate`'s worked examples must use placeholder tokens only (`<target>`, `<vpn-ip>`, `<user>`, `<name>`) — never real engagement data. The `check-leaks.sh` gate in Task 3 enforces this.
- Tasks 1 and 2 are ordered: `delegate` references `Skill(metasploit)`, so `test_delegate_refs_resolve` only fully passes after Task 2. That cross-file dependency is intentional (the interlock).
