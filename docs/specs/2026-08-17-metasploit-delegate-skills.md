---
title: "Two harness skills: delegate (sub-agent exploit-run) + metasploit (framework-driver)"
type: design-spec
tags: [harness, skills, delegation, metasploit, design]
date_created: "2026-08-17"
date_updated: "2026-08-17"
status: approved-for-planning
sources: []
---

# delegate + metasploit skills

Design spec for two new on-demand skills that fill the highest-leverage execution-layer gaps in the
harness (coverage of vuln-class domains is already exhaustive; the cost is in execution — see the
eval.md token/time data, ~14x spread driven by drift + shell juggling + not offloading fiddly runs).

## Problem

1. **No packaged delegation.** Every expensive box's `failures.md` repeats the same missed move:
   hand the exploit-compile + escalation RUN to a cheap sub-agent with an exact copy-paste checklist +
   a false-root/hostname guardrail, while the main agent keeps driving the board (cybercrafted logged
   "0 Haiku sub-agents used = the drift"; endgame/jellyfish logged it rooting a box in ~3.5 min from a
   checklist). It is a standing user preference (`feedback_haiku_subagent_for_escalation`) but exists
   only as scattered prose (e.g. `ctf-workflow/SKILL.md:81-86`), not an invokable skill.
2. **No metasploit framework skill.** msfconsole knowledge lives in `wiki/cheatsheets/metasploit.md`
   (189 lines) but there is no invokable *workflow* skill that drives msf across recon → exploit →
   reverse shells → post-ex, the way `hunt-burp` drives Burp. This session made msfconsole the
   reverse-shell standard in prose; a skill extends that to the whole msf-centric workflow.

## Design decisions (locked)

- **Two separate skills**, one spec (they share the false-root guardrail and interlock; they ship
  together). `delegate` is higher-leverage, authored first; `metasploit`'s exploit-run is the default
  recipe the `delegate` checklist carries.
- **Delegation autonomy = standing authorization (option A).** At the delegation trigger the main
  agent autonomously dispatches a cheap sub-agent (Agent tool) with the checklist + guardrail, then
  WAITS (no parallel duplicate) and integrates the result. The skill IS the "user requested it"
  authorization for the Agent tool during an engagement.
- **Both follow existing precedents:** `metasploit` mirrors `hunt-burp` (framework-driver: mandatory
  pre-attack wiki query → drive-each-capability → hand-off), ~100 lines, POINTS to the cheatsheet for
  syntax (broad coverage, lean depth — no re-teaching msf). `delegate` promotes the existing
  ctf-workflow delegation prose into a reusable skill with worked examples.

## Non-goals

- Not duplicating `wiki/cheatsheets/metasploit.md` syntax into the skill (skill = workflow; cheatsheet
  = syntax; skill points to it).
- Not replacing the hunt-* vuln-class skills or ctf-box — `metasploit` is a complementary framework
  layer the exploit/shell PHASE reaches for (like hunt-burp complements the hunt-* skills).
- No new hooks. Routing is via `triggers.json` (advisory surfacing) only.
- `delegate` does not delegate recon or judgement-heavy exploration — those stay on the main agent.

---

## Component 1 — `delegate` skill

**Location:** `skills/workflow/delegate/SKILL.md`

**Frontmatter:**
- `name: delegate`
- `description:` autonomous sub-agent hand-off for a fiddly, fully-specified exploit-compile /
  escalation RUN — main agent stays on strategy/board, a cheap sub-agent runs the checklist behind a
  false-root/hostname guardrail. Triggers: "delegate", "offload", "hand this to a sub-agent", "spin a
  haiku", and the model-judged trigger "a foothold + a working escalation vector is identified".

**Sections:**
1. **When to delegate / when NOT.** Delegate: a foothold + a working escalation vector identified;
   OR a fiddly fully-specified multi-step compile/run (compile a C PoC, deliver+run an ELF, drive
   `su`/`sudo`/`screen -r`, msfvenom+handler catch). Keep on main: recon, judgement-heavy vector
   selection, anything not fully specified.
2. **Model choice.** `haiku` for mechanical/fully-specified; `sonnet` for judgement-heavy multi-step
   (e.g. a JS-heavy per-route-CSRF authed backend RCE). From endgame's delegation log.
3. **The checklist template (core).** Required slots, each a heading with a one-line "why":
   (a) the confirmed access/primitive spelled out; (b) exact copy-paste commands with real
   IPs/paths, no `$VAR` (per `feedback_human_poc_commands`); (c) egress/port constraints
   (egress-tested LPORT); (d) the false-root guardrail (see 4); (e) fragile-box request discipline
   if applicable (serial, long timeouts, no fuzzers); (f) the report-back contract (what to return:
   the primitive/creds/flag + evidence path; do not pivot further without the main agent).
   Bold rule: "a delegation is only as good as its checklist — under-specify any slot and the
   sub-agent flails" (endgame takeaway).
4. **The false-root/hostname guardrail (mandatory in EVERY delegation).** A returned `uid=0`/root is
   trusted ONLY if `hostname` == the target AND the expected uid; else the shell died back to the
   Kali box (which runs as root; `$(...)`/backticks substitute locally — the false-RCE trap) → re-pop.
   The sub-agent MUST verify and report `hostname` alongside any `id`.
5. **Main-agent discipline.** Keep driving the board; dispatch ONE sub-agent at a time (serial); do
   NOT duplicate its work in parallel (`feedback_fork_no_parallel`); WAIT for completion; on return,
   persist the primitive/creds/flag to `state.md`/`loot.md`/`Killchain.md` before the next move.
6. **Mechanism.** Dispatch via the Agent tool: `subagent_type` general-purpose (or a box agent),
   `model` per §2, the checklist as the prompt, an explicit report-file/return contract. The skill's
   invocation IS the standing authorization for the Agent tool mid-engagement.
7. **Worked examples (baked in, from failures.md).** cybercrafted HP1 (deliver+catch a meterpreter
   as www-data, egress-tested LPORT, inline base64 ELF, GUARDRAIL), HP2 (ssh2john→crack→strip
   passphrase→SSH chain), HP3 (sudo `screen -r` → `Ctrl-A c` root, GUARDRAIL hostname==cybercrafted);
   endgame openssl-caps `.so`-constructor root. Each shown as a ready checklist.

**Interlock:** the msfvenom-compile + `multi/handler` catch + escalation run is the canonical
delegate payload; the checklist's example commands default to the `metasploit` recipe.

## Component 2 — `metasploit` skill

**Location:** `skills/workflow/metasploit/SKILL.md` (mirrors `hunt-burp`, ~100 lines)

**Frontmatter:**
- `name: metasploit`
- `description:` Drive msfconsole across the workflow — DB-backed recon (`db_nmap`, aux scanners),
  version→exploit `search`/`check`/run, `multi/handler` reverse shells (meterpreter-first, plain
  `shell_reverse_tcp` backup for Windows/EDR), sessions + `local_exploit_suggester` + `post/*`,
  and autoroute/portfwd/socks pivoting. Points to `[[metasploit]]` for syntax. Triggers:
  "metasploit", "msfconsole", "msfvenom", "meterpreter", "multi/handler", "reverse shell via msf".

**Sections (each = short workflow + pointer to the cheatsheet, not re-taught syntax):**
1. **Pre-attack wiki query (MANDATORY).** `[[metasploit]]` cheatsheet + `Skill(arsenal)` for the
   fingerprinted tech/CVE (mirrors hunt-burp's mandatory wiki-first).
2. **Setup / DB.** `msfconsole -q`, `workspace -a <eng>`, `db_status`; run inside a named tmux tab
   (per standing tmux discipline), never a blind background.
3. **Recon via msf.** `db_nmap`, `auxiliary/scanner/*` (smb/http/ssh version + vuln checks) feeding
   `hosts`/`services` in the same DB. Complements nmap, does not replace the ctf-box Phase-1 basics.
4. **Search / select / verify.** `search <app> <ver>` / `search cve:<id>`, `use`, `info`, and
   `check` BEFORE firing (verify the target is vulnerable, avoid noisy misfires).
5. **Reverse shells (core).** `multi/handler`; payload meterpreter-first
   (`linux/x64/meterpreter/reverse_tcp` etc.); plain `shell_reverse_tcp` backup when meterpreter is
   blocked/unstable (routine on Windows/EDR); `msfvenom` payload delivery (ELF/EXE/ASPX/PHP → point
   to the cheatsheet's MSFVenom section); egress-tested LPORT (80/443/53); `set ExitOnSession false;
   run -j`.
6. **Sessions / post-ex.** `sessions -i`, `run post/multi/recon/local_exploit_suggester` (the privesc
   reflex), `post/*`, `getsystem`, `post/multi/manage/shell_to_meterpreter`.
7. **Pivoting.** `autoroute`/`portfwd`/`socks` to reach internal-only ports before hand-rolling SSH
   `-L` (→ `[[pivoting]]`).
8. **Verify target (false-root).** `getuid` + `sysinfo`/`hostname` == target before trusting a shell.
9. **Interlock + anti-drift.** The fiddly msfvenom-compile + handler catch + escalation run is a
   prime `Skill(delegate)` hand-off. DRIVE msf for load-bearing exploit/shell requests (operator
   observes); don't abandon msf for raw scripts post-foothold (mirrors hunt-burp anti-drift + the
   CLAUDE.md Burp-first-doesn't-stop-at-foothold rule).
10. **Client-data boundary + hand-off** (standard skill footer).

---

## Integration

1. **`skills/hunt/triggers.json`** — add two `triggers` entries (regex → skill):
   - `"metasploit|msfconsole|msfvenom|meterpreter|multi/handler"` → `"metasploit"`
   - `"\\bdelegate\\b|\\boffload\\b|hand (this|it) (off|to a sub)|spin (a|up a) (haiku|sub-?agent)"` →
     `"delegate"`
   (Model-judged delegation trigger — "foothold + escalation vector identified" — stays a `delegate`
   in-skill instruction, not a regex, since it is not a keyword.)
2. **Cross-refs (small prose edits):**
   - `ctf-box/SKILL.md`: Phase 2 Weaponize → note `Skill(metasploit)` for the msf search/exploit path
     (alongside the existing searchsploit+metasploit reflex); Phase 3 Deliver → `Skill(metasploit)`
     for the handler; Phase 4 Exploit → `Skill(delegate)` for the compile+run + `local_exploit_suggester`.
   - `ctf-workflow/SKILL.md:81-86`: replace the inline delegation prose with a pointer to
     `Skill(delegate)` (keep one summary line).
   - `CLAUDE.md`: add `delegate` and `metasploit` rows to the skills/tools table.
3. **`scripts/playbook.json`** — deterministic routing. Each `fingerprints` entry is
   `{regex: {prio, approach, skills[], tests, refs}}`. Add `"metasploit"` to the `skills[]` of the
   msf-strong fingerprints: entries whose `approach`/`refs` already reference searchsploit /
   metasploit / a CVE exploit / a known-exploitable service version (SMB/Windows services, and any
   version-known service where `search <tech>` reliably yields a `use`-able module). The plan
   enumerates the concrete set by grepping the file; do NOT blanket-add to every fingerprint (noise).
4. **Registration:** re-run `bash setup/install-skills.sh` (symlinks each SKILL.md dir by basename
   into `~/.claude/skills/`). No code change — discovery is by basename.

## Testing / validation (low-ceremony, no unit tests)

- Frontmatter valid (name/description present) on both new SKILL.md — reuse the existing skills lint
  if present (`scripts/` lint or `campaign-doctor` skill-set check); else a one-shot check.
- Every `[[wiki-page]]` and `Skill(x)` cross-reference in both skills RESOLVES (the referenced file
  exists) — a small `python3` check over the two files, or the existing wiki-gaps/link checker.
- `triggers.json` still parses as JSON and the two new regexes compile (`python3 -c "import json,re;
  [re.compile(k) for k in json.load(open('skills/hunt/triggers.json'))['triggers']]"`).
- Manual: `Skill(metasploit)` and `Skill(delegate)` appear in the `/skills` picker after
  install-skills.sh.

## File change summary

| File | Change |
|------|--------|
| `skills/workflow/delegate/SKILL.md` | CREATE (Component 1) |
| `skills/workflow/metasploit/SKILL.md` | CREATE (Component 2) |
| `skills/hunt/triggers.json` | add 2 trigger regexes |
| `skills/workflow/ctf-box/SKILL.md` | Phase 2/3/4 cross-ref edits |
| `skills/workflow/ctf-workflow/SKILL.md` | lines 81-86 → pointer to `Skill(delegate)` |
| `scripts/playbook.json` | add `"metasploit"` to msf-strong fingerprints' `skills[]` |
| `CLAUDE.md` | 2 new skills-table rows |
| (run) `setup/install-skills.sh` | register the two new skills |

## Resolved decisions
- Skill name = `delegate` (confirmed).
- `metasploit` IS wired into `playbook.json` deterministically (Integration §3), not just via triggers.
