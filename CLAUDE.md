# Pentesting & Bug Bounty Wiki: Schema

---

## Quick reference

| Operation | Action |
|---|---|
| Query | `qmd_query "..."` via `wiki-search` MCP -> read results -> synthesise |
| Ingest skip check | Read frontmatter only; skip page if ingest slug already in `sources:` |
| Re-index / wiki status | `wiki` skill |
| Git clone | Always WSL: `wsl -d kali-linux -u kali -- git clone <url> /home/kali/<name>` |
| Run tooling against a target | Kali VM over SSH: `bash /root/vm.sh '<cmd>'` (VPN route + tools + chromium live there) -> `docs/virtual-machine.md` |

---

## Skills and tools

| Task                                          | Use                                                                                    |
| --------------------------------------------- | -------------------------------------------------------------------------------------- |
| Multi-step planning                           | `superpowers:brainstorming` then `superpowers:writing-plans`                           |
| Execute a plan                                | `superpowers:subagent-driven-development`                                              |
| Debug unexpected behavior                     | `superpowers:systematic-debugging`                                                     |
| About to claim done                           | `superpowers:verification-before-completion`                                           |
| Write/edit vault `.md`                        | `obsidian:obsidian-markdown`                                                           |
| Fetch URL for ingest                          | `WebFetch` tool                                                                        |
| Read vault file                               | `Read` tool with machine path (see below)                                              |
| Search vault                                  | `qmd_query` (semantic) or `qmd_search` (keyword) via `wiki-search` MCP                 |
| Maintain wiki index (re-index, status)        | `wiki` skill                                                                           |
| Load engagement playbook / FIND schema        | Read `targets/TARGETS.md`                                                              |
| Audit CLAUDE.md (full review)                 | `claude-md-management:claude-md-improver`                                              |
| Update CLAUDE.md (targeted session learnings) | `claude-md-management:revise-claude-md`                                                |
| Session end / pause work                      | `gsd:pause-work` (optional plugin) or the manual pause-work steps                                                                       |
| Parallel independent tasks                    | `superpowers:dispatching-parallel-agents`                                              |
| Run a full bb/pt/ctf engagement autonomously  | `bb-workflow` / `pt-workflow` / `ctf-workflow` skill (driver: `scripts/campaign.py`; the single source of truth for the execution loop) |
| Check the workflow driver is set up on this machine | `campaign-health` skill (`scripts/campaign-doctor.py`)                            |
| About to attack a web endpoint                | `hunt-<type>` skill (see auto-triggers below)                                            |
| Driving a web target through Burp (proxy-history triage, Repeater/Intruder/Collaborator) | `hunt-burp` skill (Burp MCP; setup [[burp-mcp]])              |
| Starting recon on any target                  | wiki-recon skill                                                                       |
| Manual login / MFA the agent can't do headlessly (Smart-ID, Mobile-ID, captcha) + drive & observe via CDP | `chrome-devtools-browser` skill (visible chromium on the VM via `scripts/browser-visible.sh` + chrome-devtools MCP) |
| Validating / moving finding to Completed      | triage then evidence skills                                                            |
| Vuln/CVE research on a target (binary/repo/app/firmware) | `research` skill (scaffolds `raw/research/<project>/`)                       |
| Hand a fiddly, fully-specified exploit-compile/escalation run to a sub-agent | `delegate` skill (autonomous sub-agent exploit-run; false-root/hostname guardrail mandatory) |
| Drive msfconsole (recon, exploit search/run, reverse shells, post-ex) | `metasploit` skill (msfconsole framework-driver; cheatsheet [[metasploit]]) |

Vault-local skills live under `skills/`: `skills/hunt/` (the `hunt-*` vuln-class skills + the shared `hunt-core` spine every hunt assumes), `skills/workflow/` (engagement PROCESS skills: `arsenal`/`wiki-arsenal`, `triage`, `evidence`, `coverage`, `ingest`, `next-move`, `wiki-recon`, `nday`, `research-ingest`, `delegate`, `metasploit`, `ctf-box`, `ctf-category`, `screenshot`, `chrome-devtools-browser`, `learn`, `walkthrough`), `skills/burp/` (`hunt-burp` + `screenshot-burp`, the Burp MCP driver + Repeater-PoC capture; driver scripts in `scripts/burp/`, host setup in `setup/burp/`), and the standalone `wiki/`, `research/`, `disclosure/`, `code-review/`. They load on demand via the Skill tool (descriptions in the `/skills` picker), discovered by basename so directory placement is organizational only. `arsenal` delegates to `wiki-arsenal`; the `hunt-*` skills inline their own `qmd_query` and assume `hunt-core`. `claude-md-improver/` is an offline fallback for the `claude-md-management` plugin. MCP/hook/plugin troubleshooting: `skills/skills-setup.md`.

Search rule: never read `wiki/index.md` to find pages - always search first. MCP tool names: `mcp__wiki-search__qmd_query` (semantic), `mcp__wiki-search__qmd_search` (keyword).

`session/memory.md` holds long-term editorial patterns. Load it when making editorial or tagging decisions.

---

## Hunt Skill Auto-Triggers

The `hunt-trigger.py` UserPromptSubmit hook matches your prompt against `skills/hunt/triggers.json` (single source of truth): an explicit vuln-type term injects a **MANDATORY** `Skill(<hunt>)` directive, a surface term (e.g. "login form", "upload field") a softer "consider `Skill(...)`". Treat a hard directive as a real instruction unless genuinely irrelevant (say why in one line). When you SKIP a fingerprint-routed hunt (correctly, or because another hunt already covers it), write the one-line reason to `targets/<eng>/log.md` (or `Deadends.md`) so the close-out drift-count separates a real miss from a correct skip. Edit `triggers.json` to change mappings, not this table; full mechanics (incl. leak-safe telemetry) in `docs/auto-triggers.md`.

Vuln-type rows (SSRF/XSS/SQLi/IDOR/RCE/auth/federation/injection/m365/vpn -> matching hunt skill) live in `triggers.json`, fired by the hook. Only the model-judged rows remain here:

| Condition | Skill |
|-----------|-------|
| Starting recon on target (subdomains, endpoints, surface) | wiki-recon |
| "Is this valid?", "should I report?", finding needs confirmation | triage |
| Moving finding Research -> Completed | triage then evidence |

---

## Engagement discipline (state-first, anti-loop)

**Engagement workflow (the driver is the plan).** For any bb/pt/ctf engagement run `Skill(bb-workflow)`,
`Skill(pt-workflow)`, or `Skill(ctf-workflow)`. The deterministic driver `scripts/campaign.py` owns
pass state, generates the killchain board from recon, and prints the exact next action (Skill + tool)
every turn. It is the single source of truth for the discipline this section describes: it ENFORCES as
gates G1 wiki/arsenal-first, G2 skill-first, G3 typed evidence, G4 deadend-first, G5 depth-first, G7
no-ask, G8 tool-first, plus pre-board recon (passes 0-4), the read-whole gate, the effort-ceiling stop
condition, OOB and two-account readiness, ban control, and budget/report-only. When it runs, follow its
`next` output literally. Health check on a new machine: `Skill(campaign-health)`.

**Execution loop (per offensive step, ALWAYS).** The hooks are advisory and can misfire or go silent
(e.g. when the `wiki-search` MCP drops). During a campaign the driver above is the enforcement and the
steps below are what it sequences; off-campaign (driver unavailable, or a quick manual engagement) run
each step in order yourself, do not skip under momentum:
0. **Board-first.** Work `targets/<eng>/Approach.md` (the plan board) one open item (`[ ]`/`[~]`)
   at a time, marking `[x]` as each lands. In a campaign the driver generates this board and enforces
   its gates: no exploit before the row's arsenal card (G1), no `[x]` without a `poc/` image (G3), and
   an exhausted vector goes `[!]` + one `Deadends.md` line then you move to the next open item, never
   re-running `[!]` (G4); off-campaign, honor the board's own GATE 1/2/3 lines by hand.
1. **Wiki-first, reference-map before qmd (qmd is ~15-30s, so it is hint-driven).** Before exploiting
   a fingerprinted service/class: (a) FIRST read the mapped pages directly - the hunt skill's `## Wiki`
   section (domain MOC + primary page + anchors) and one-hop from the MOC. That is an instant `Read`
   and answers the anticipated case with zero qmd latency. (b) Fire `qmd_query`/`qmd_search` (via the
   `wiki-search` OR `caveman-shrink` MCP) ONLY when you have a concrete hint the map does not cover - a
   specific sink/version/CVE, an observed escape (a `<script>` context, an SSRF-reaching function).
   Each call is slow, so it is a targeted deepen, not a blanket pre-attack step; equally, do NOT
   hand-roll from memory when a targeted qmd would answer. `Skill(wiki-arsenal)` still gives the fast
   parallel lookup ("deep" for the synthesized card). MCP-independent fallback: `bash
   scripts/wiki-query.sh "<tech> exploit"` (`-k` for an exact CVE/tool string) wraps the SAME index.
   NEVER degrade to ad-hoc grep or skip the wiki.
2. **Tools, not hand-rolls; then READ the output whole.** Reach for the installed tool
   (nmap/ffuf/nuclei/httpx/nxc/sqlmap/borg/...), never a hand-rolled `curl`/`/dev/tcp` loop; if none
   fits, say why in one line. Enumerate NON-STANDARD installed tools (borg/borgmatic/restic/duplicity,
   backup + secret managers) as a loot/privesc lead - a leaked backup passphrase + a reused key beats
   grinding a hardened-container escape. Then READ what it returns END-TO-END - the full scan output,
   every fetched source / `.js` / inline `<script>` / button `onclick` / `href`, each response - never
   let a keyword grep BE the read (just as step 1 never degrades wiki-lookup to grep). The initial
   attack vector repeatedly hides in an AJAX handler / commented route a narrow `grep` skips.
3. **Capture the request AND each landing, live.** `capture.sh req` the real request+response for every
   exploit/lead request, and screenshot each success to `poc/` the moment
   it lands (`capture.sh ev` / `capture.sh tmux` / `shot.py`), never at the end. Evidence is captured
   live now (no auto-card staging). NEVER hand-write / fabricate an evidence card.
4. **Persist immediately.** A host/cred/path/flag lands -> write `state.md`/`loot.md`/`Killchain.md` before
   the next move; a dead-end -> one `Deadends.md` line.
5. **Close out.** Objective landed (both flags, or a target-severity finding) -> set `## STATUS: SOLVED`
   in state.md at once, then run the per-type close-out chain the driver prints (`campaign.py`'s
   `closeout` config, echoed by the bb/pt/ctf workflow skill). Run it exactly as printed.

Token control and real findings come from the same rule: do not repeat work.

- **Scope-first.** Read `targets/<eng>/scope.md` before acting. Never touch an out-of-scope target or use forbidden tooling (`no_bruteforce`/`no_dos`/`passive_only` flags). The `next-move` analyzer already filters out-of-scope hosts and suppresses spray/active probing per RoE; respect the same bounds in everything else.
- **State-first.** Before any recon, spray, or exploit attempt, read the active engagement `state.md`, `loot.md`, `Killchain.md`, and `Deadends.md`. Never re-run a documented dead-end or re-spray a known-failed cred without new input (new cred, new pivot, new payload class).
- **Stop condition.** A vector is exhausted after a bounded effort (e.g. OOB sink: ~30-40 payloads zero callbacks; spray: full user x pass matrix once). On exhaustion: append one line to `Deadends.md` + update `Killchain.md` status, then switch vector. Do not grind, do not re-loop.
- **When stuck, call `Skill(redteamlead)` BEFORE grinding (recurring, expensive miss).** Two mechanical tells that a vector is the WRONG DOOR, not that the tooling needs another pass: the target starves under your own exploit loop (repeated `000`/timeout/empty-reply = you are DoSing it), or **>=2 verified hashes fail the primary wordlist** (the creds are out-of-band: an email/note/KeePass, a config, a second service). At either tell - or any "I'm stuck / which vector / should I keep hammering this / where do I go" - call `Skill(redteamlead)`: it reads state+evidence+wiki and returns ranked directions with an explicit STOP. Engineering around a hostile channel (per-char verify-fix, min-of-2 sampling, gentler pacing) IS the tell you are on the wrong vector, not a reason to keep going. A `/redteamlead` reminder in the engagement prompt is a real instruction, not optional; not calling it while stuck for hours is a documented failure (a recent box: hours lost to a box-crashing blind-SQLi hash-grind while the real foothold was an unenumerated file-read/LFI - one RTL call would have surfaced it). The vector-doubt + widen `recon-capture.py` nudges now surface this automatically.
- **Capture as you go.** After a recon/cred tool runs, extract results into `state.md`/`loot.md` immediately (state-first discipline: capture the moment a tool returns). Prose in chat is lost; tables persist across sessions and devices.
- **Tooling-first.** Use the installed tool (nmap/ffuf/nuclei/nxc/linpeas), not a hand-rolled bash reimplementation - better output, fires the fingerprint router, and `recon-capture.py` snaps it to evidence. Hand-rolled bash only when no tool fits (say why). Enforced by the `ctf-box` + `hunt-*` skills, not a runtime hook.
- **Read-first (recon), not grep.** Before declaring any page/endpoint/file enumerated, READ its full source end-to-end: every `.js` bundle + inline `<script>`, every button `onclick`/`href`, every returned response/config. A keyword grep is NOT a read: the initial attack vector repeatedly hides in an AJAX handler / commented route / alternate endpoint that a narrow `grep <keyword>` skips (THM Buzz: the `/fetch` pickle sink lived in an unopened `dropdown.js`). Use grep to LOCATE inside a huge file, then read the surrounding block; never let grep BE the read. Enforced by the `ctf-box` + `wiki-recon` skills, not a runtime hook.
- **OOB-gate blind bugs.** Blind SSRF/SSTI/SQLi claims need an out-of-band callback, never inference. Enforced per hunt skill.
- **Reuse loot.** Reuse captured creds across `state.md` hosts before researching new ones. Default/known creds first (look up vendor defaults via context7, see [[default-credentials]]); broad spraying of captured creds is a last resort, not an early or auto move.
- **Distill reusable knowledge.** When an engagement yields a default cred or a reusable API request pattern, add the **generic** form (product + cred / endpoint + impact, no client specifics) to `wiki/cheatsheets/default-credentials.md` or `api-request-findings.md`. Next engagement, check these first. Client specifics stay in `targets/<eng>/`. At close-out, `Skill(learn)` sweeps the whole completed engagement for any generic lesson still missing from `wiki/` and promotes the delta through the leak-gated stage (`wiki-stage.py`) -> promote (`wiki-promote.py`) pipeline; run it once the engagement is `SOLVED` and its walkthrough is assembled.

---

## Behavior hooks

Output/mode plugins installed: **ponytail** (lazy-code discipline - YAGNI, stdlib/native first, shortest working diff) auto-activates at SessionStart via its own hook (level `full`; switch with `/ponytail lite|full|ultra`), and governs what you build, not prose. **caveman** (prose compression - terse output, drop articles/filler, fragments OK) is manual per session via `/caveman`.

SessionStart also auto-loads `session/hot.md`. No manual reads needed.

Engagement-state hooks (live via `~/.claude/vault-hooks` symlink -> `skills/hooks/`). All fail open (any error -> allow, never trap). Policy: **deterministic guards ENFORCE (deny the tool call); semantic reflexes ADVISE (inject a suggestion).** Enforcement is reserved for no-judgement checks (scope/RoE) where blocking the wrong action costs zero tokens; judgement calls (wiki-first, tools-not-manual, intended-path) stay advisory because a false block wastes more time than it saves. Escape hatch for a bad block: `touch skills/hooks/.enforce-off`. Full mechanics in `docs/auto-triggers.md`; the behaviorally-relevant summary:

| Hook | Event | Effect |
|------|-------|--------|
| `engagement-init.py` | SessionStart | Self-heals the engagement file set; injects state summary + top next-moves + session cache + OOB HITs + drift warnings. |
| `hunt-trigger.py` | UserPromptSubmit | Routes to hunt skills from `triggers.json` (surfaces the relevant Skill; the skill carries the mandate); leak-safe telemetry to `.trigger-fire.jsonl`. Skips injected/non-prompt content. |
| `recon-capture.py` | PostToolUse/Bash | Routes detected tech -> the hunt Skill (`playbook.json`), auto-correlates OOB callbacks (waiting -> HIT), and fires a once-per-engagement GATE-1 wiki-first nudge when an exploit-shaped command runs while `Approach.md` Weaponize is undone. Framework-meta guard suppresses false fires. Advisory. |
| `scope-guard.py` | PreToolUse/Bash | ENFORCES (denies the command) on out-of-scope host/IP (CIDR-aware) or RoE-forbidden tooling. Fail-open; `.enforce-off` marker downgrades to advisory. |
| `session-guard.py` | PreToolUse/Write | Warns when a write would put a client marker into a generic `session/*` file. Advisory, never blocks. |

Register/repair the set per-device with `bash setup/install-hooks.sh`; `engagement-init` warns at SessionStart if a hook is unregistered (canonical set in `scripts/check-hooks.py`).

Active engagement set by `targets/active.md`. Create one with `bash setup/new-engagement.sh <name> <pentest|bugbounty|ctf>`. Per-type schema from `setup/templates/<type>/`; `engagement_type` in state.md frontmatter drives analyzer + self-heal. Pentest/bugbounty files: `targets/<eng>/{state,loot,Killchain,Approach,log,scope,walkthrough,eval,Vuln-index,Deadends,oob}.md` + `ingest/` + `poc/` (curated exploit/PoC/flag shots) (all self-healed by `engagement-init`). ctf files (lean, live-loop only): `targets/<eng>/{state,loot,Approach,scope,Deadends}.md` + `ingest/` + `poc/`; `Killchain.md`/`log.md` stay pentest/bugbounty-only artifacts (a ctf's live attack chain lives in `state.md`'s `## Chain`/`## Status` sections instead), and `walkthrough.md`/`eval.md`/`decisions.md` self-create on demand at their trigger (close-out/`Skill(learn)`/`/redteamlead`) rather than being scaffolded upfront. `eval.md` = per-engagement AGENT self-assessment (tokens/time/drift estimates), filled at close-out by `Skill(learn)`. `Approach.md` = the wiki-wired plan board (phase checklist + `### 4a` coverage table + the three GATE lines). `Killchain.md` = the evolving discovered attack chain (open/blocked attack-path rows + the Confirmed-chain header). `walkthrough.md` = full copy-pasteable boot-to-root reproduction (distinct from the terse `log.md` audit); `log.md` doubles as the per-engagement continuity cache (its newest block is surfaced at SessionStart, so client narrative goes there, never in generic `session/hot.md`). Missing wiki pages surfaced by `scripts/wiki-gaps.py`.

Framework subsystems (each is a script + an on-demand skill; detail in `docs/auto-triggers.md`):

| Subsystem | Entry point | Key rule |
|-----------|-------------|----------|
| Ingest | `ingest` skill | Drop raw output in `targets/<eng>/ingest/`; the skill synthesizes -> state/loot/Killchain then archives. |
| Next-move | `scripts/next_move.py` / `next-move` | Ranks moves (type + scope aware). Update tables after acting so the next run re-ranks. |
| Fingerprint testing | `scripts/playbook.json` | Maps tech -> targeted tests + hunt skill + the `wiki/payloads/` arsenal. Extend both as you learn new tech. |
| Chaining | `scripts/chains.json` / `next-move` | Data-driven `finding -> pivot` edges (horizontal complement to playbook's vertical fingerprint->test). A CONFIRMED/PARTIAL finding surfaces ranked pivot candidates; suggestions only, `gate:oob` edges need an operator callback first. Add edges, no code. |
| Coverage | `Approach.md` 4a table / `coverage` skill | Per-asset untested classes live in the plan board's `### 4a` table. Add a row with status `[x]` + a `poc/` image when you test a class, or the gap recurs (`next_move.py` surfaces `[gap]` moves). |
| Finding quality | `scripts/find-lint.py` | Findings scaffold from `setup/templates/_find.md`; run find-lint before /evidence and before a report. |

**Client-data boundary (hard rule):** all client/engagement specifics (hosts, IPs, creds, domains, findings, narrative) live ONLY under `targets/<eng>/` (git-ignored). Never write them into `session/*`, `wiki/`, tracked `docs/`, scripts, or commit messages; per-engagement narrative goes to `targets/<eng>/log.md` (audit + continuity cache). `session-guard.py` advises on violations; run `bash scripts/check-leaks.sh` before sharing. Full detail: `docs/sharing.md`.

---

## Machine-specific vault access

Per-machine hostnames and vault paths live in the git-ignored `CLAUDE.local.md`
(copy `CLAUDE.local.example.md` to create it), kept out of the published repo.
The path resolvers (`setup/vault-path.sh`) and hooks self-locate or read
`OBSIDIAN_VAULT` / `QMD_VAULT`, so a single-machine setup needs no local file.

@CLAUDE.local.md

---

## Directory structure

```
TORCH/
├── CLAUDE.md   <- this file (+ README.md, LICENSE)
├── targets/    <- engagements (PRIVATE, git-ignored; ALL client data lives here)
├── wiki/       <- knowledge base: techniques/ payloads/ tools/ cheatsheets/ (+ index, moc)
├── session/    <- hot.md (startup cache) · log.md (audit) · memory.md (editorial)
├── docs/       <- workflows, page-types, auto-triggers, virtual-machine, setup, sharing, conventions, layout
├── scripts/    <- automation (next_move, status, capture.sh, shot.py, lint-*, wiki-*, vm-*, burp/, ...)
├── setup/      <- bootstrap.sh, install-hooks.sh, install-skills.sh, new-engagement.sh, templates/, burp/
├── skills/     <- hunt/ (hunt-* + hunt-core) · workflow/ (triage/evidence/coverage/ingest/ctf-box/learn/walkthrough/...) · burp/ · wiki/ research/ disclosure/ code-review/ + hooks/
└── raw/        <- research/ · assets/ (read-only) · git/ (clones)
```

Full annotated tree + per-file notes: `docs/layout.md`.

**Rules:**
- `raw/` is read-only. Exceptions: populate `raw/git/` via git clone (WSL only), and `raw/research/<project>/` research workspaces created by `setup/new-research.sh` (the `research` skill writes loop state there). Research on public targets is not client data; client/engagement work still lives only under `targets/`.
- `wiki/` and `targets/` are fully owned by Claude. Create, update, and cross-reference freely.
- `wiki/index.md` and `session/log.md` updated after every ingest, query-that-produces-a-page, and lint pass (framework work only; client/engagement narrative goes to `targets/<eng>/log.md`).
- Update `CLAUDE.md` when vault structure changes; `docs/setup.md` for machine/path changes; `docs/conventions.md` for editorial standards changes.

Read `targets/TARGETS.md` for the engagement playbook: FIND naming, severity definitions, directory structure, and the wiki integration rule.

**Session end:** Before closing any session, run pause-work (`gsd:pause-work` if the gsd plugin is installed on this machine, else do the steps manually). Generic/framework summary -> `session/hot.md`, `session/log.md`, `session/memory.md` (no client specifics). Client/engagement narrative -> `targets/<eng>/log.md` (audit + continuity cache) ONLY.

---

## Page types and frontmatter

Full schema in `docs/page-types.md`. **Skip rule:** during ingest, read only the frontmatter first. If the ingest slug is already in `sources:`, skip the page entirely. Only read full content when you will update it.

---

## Wiki Workflows

Read `docs/workflows.md` before performing any ingest, target session, lint, or query. When a technique appears in multiple sources, synthesise all into one technique page; do not create one page per source.

---

## Output rules

- **Brevity during engagements/tool-loops (output tokens are billed).** When working a target (recon -> foothold -> privesc) or any multi-step tool loop, keep prose MINIMAL: one short line before a tool batch stating intent, and lead the next turn with the RESULT/finding, not a recap. No per-step paragraphs, no restating what a command will do (the command is shown), no narrating the plan you already gave. Full prose is for the deliverables that need it (a report, a walkthrough, a design/brainstorm, an explicit explanation the user asked for), not for the play-by-play. A 40-min box should not cost a paragraph per step.
- Never use em-dashes (`--`). Use a comma, semicolon, or rewrite the sentence. (`--` is permitted inside code blocks as a CLI flag.)
- Never use emojis.
- Do not narrate what you are doing with echo/printf inside commands (label banners, "now doing X" lines, `=== ... ===` / `== x ==` / `-- x --` separators). You already explain each step in your normal response text, so echoing it into the command is duplicate noise, and the harness already shows every command with its own output. Run commands directly.
- **Concrete values, not shell variables, in target commands.** The operator watches the live terminal, so write commands a human would type: real IPs/URLs/paths inline (`curl -s http://10.1.1.5:8080/api`), not `T=http://...; curl "$T/api"` or `$VAR` placeholders. Reserve variables for genuinely repeated long secrets (a captured token/cookie). walkthrough.md is already var-free; hold live commands to the same bar.
- **Shell interaction: one command, clean output, NO markers (`docs/shell-interaction.md`).** Driving a live shell (reverse shell, interactive session, the Kali VM), the tooling already frames output for you: `bash /root/vm.sh '<cmd>'` and the `vm-rsh.sh`/`win-rsh.sh` drivers return the complete output of ONE command, echo stripped. So: one command per tool call; NEVER inject sentinel/marker/delimiter/nonce strings or split a literal to dodge the echo; don't chain unrelated actions; type it the way an operator would (plain `$env:`/`$_` - the driver escapes for the bridge, don't hand-encode); shortest command that answers the question. Output empty/weird -> PROBE with a bare `whoami` (a username = alive + the empty result was real; nothing = stuck, stop; a non-username = the reverse shell died back to the ATTACKER prompt, the false-RCE trap - re-pop it), never add instrumentation. `$`-heavy/multi-statement enum -> host a readable `.ps1` and run it in-memory via an `IEX(DownloadString(...))` cradle, not a marker-wrapped one-liner.
- **Send interesting requests to Burp, not just curl.** When you confirm or want to probe a noteworthy request (SSRF, LFI, SQLi/injection, a deser payload, an auth bypass), push it into **Burp Repeater** via `Skill(hunt-burp)` / the Burp MCP (or `scripts/capture.sh burp` for a PoC) so the operator can replay and inspect it manually. curl is fine for quick loops; the load-bearing exploit requests belong in Repeater for operator visibility. Prefer the NATIVE Burp MCP tools (`mcp__burp__*`) when connected; the `burp-mcp-cli.py` SSH bridge is the fallback (the native server only attaches at session start and will be absent if the VM was down then - a session restart re-attaches it). Brute/fuzz belongs in **Intruder** (`send_to_intruder`), not a hand-rolled loop, so the operator watches it live.
- **Burp-first does NOT stop at foothold (anti-drift).** The recurring failure: land RCE/a shell, then abandon Burp for raw `curl`/`vm.sh`/python-urllib scripts, and the operator loses all visual observation of the exploitation. Once a foothold lands, KEEP driving load-bearing requests through Burp Repeater (post-auth API calls, the injection that reads the flag, each privesc-relevant fetch) - the operator is watching Burp, not your terminal. A quick throwaway loop over the bridge is fine; the requests that MATTER (the ones you'd screenshot) go through Repeater to the end of the box. If you catch yourself scripting the whole post-foothold phase off-Burp, that IS the drift - stop and route it back.
- Never add a `Co-Authored-By` trailer, a "Generated with Claude Code" line, or any similar attribution footer to git commit messages or PR bodies. (Overrides the harness default that appends one.)

---

## Image handling

Never copy image embeds (`![[Pasted image *.png]]` or `![](url)`) into wiki pages. Reconstruct commands as code blocks from context. Wiki pages must be image-free.
