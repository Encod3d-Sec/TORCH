---
name: learn
description: Post-engagement knowledge harvest AND harness retrospective - after a box/bugbounty/pentest/CTF is completed, first diff how the engagement was EXECUTED against the skills/hooks that governed it (what discipline was skipped) and improve the harness, then sweep the whole engagement for GENERIC reusable knowledge NOT already in wiki/ and land it via the leak-gated stage->promote pipeline. Use at close-out or when asked to "extract learnings", "what did we learn", "harvest lessons into wiki", "distill this engagement", "post-mortem into the wiki", "what did we do wrong", "improve the harness from this box".
---

# Learn: harness retrospective + wiki knowledge harvest

The close-out retrospective, in two phases:
- **Phase 0 (process):** diff how the engagement was EXECUTED against the discipline the
  skills/hooks prescribe, find where the operator (you) or the harness drifted, and fix the
  harness so the next box does not repeat it. This is the "improve the harness on it" half.
- **Phases 1-7 (knowledge):** read the WHOLE finished engagement, diff it against the existing
  wiki, and promote only the DELTA as durable, generic knowledge. The safety net that catches
  everything not captured live during the box.

The client-data boundary is enforced by code, not by this prose: engagement-derived
content reaches `wiki/` ONLY through `wiki-stage.py` -> `wiki-promote.py`, which runs
`check-leaks.sh` and fails closed. This skill READS the engagement and WRITES only
generic knowledge; it never edits the engagement's own files.

## When it fires
- At close-out: run `Skill(learn)` once the engagement is marked
  `## STATUS: SOLVED` (OWNED/ROOTED/COMPLETE) AND its `walkthrough.md` is assembled
  (the CLAUDE.md execution-loop close-out step).
  It self-clears the moment this skill writes `<eng>/.learn-done`.
- On demand: "extract learnings", "what did we learn", "harvest lessons", "distill",
  "post-mortem into the wiki" - the same steps apply.

## Phase 0: Process retrospective (harness self-improvement) - DO FIRST

Before harvesting knowledge, ask: **did we execute the way the skills/hooks told us to, and
where we did not, whose fault is it - mine, or the harness's for not catching me?** The point is
not self-flagellation; it is to turn each drift into a concrete harness change so the next
engagement cannot repeat it.

### 0a. Diff execution against discipline
Re-read the skills that governed this engagement (`ctf-box`, the `hunt-*` used, the CLAUDE.md
execution loop) and check each mandated step against what actually happened on disk:

| Discipline it prescribes | How to check it was (not) done | Common drift |
|---|---|---|
| Recon tooling complete (nmap AND ffuf AND nuclei-read for web) | `ls targets/$ENG/recon/*.png`, `.recon-tools` marker, tmux window names, `log.md` | ffuf never run; nuclei launched but output never read |
| Screenshot EVERY finding as it lands | count deliberate `poc/*.png` vs findings in `Killchain.md`; `.screenshot-nudged` | shots only at the very end; transient states lost |
| Wiki-first before exploiting each fingerprinted service | wiki queries in transcript / `log.md` | jumped to exploitation from memory |
| A hook nudge fired -> was it acted on? | grep the transcript for a nudge (e.g. "switch to ffuf") whose action never followed | nudge ignored under momentum |
| State-first / capture-as-you-go | `state.md`/`loot.md` updated mid-box vs all-at-end | prose-in-chat lost |

**If the engagement ran under the campaign driver** (`bb/pt/ctf-workflow`), pull its own numbers -
they say precisely where the driver fought the operator, no guessing:

```
python3 scripts/campaign.py --eng <ENG> ledger --json
```

`drift` = network calls the driver never emitted (improvisation off the board); `dry_rounds` /
`reframe_lenses_used` = how hard the campaign had to reframe to find anything; `paused_hosts` = hosts
that banned us; `board.dead` vs `board.closed` = the exhaustion-to-finding ratio. A high drift or a
long lens list is the retro's starting point.

For each drift, name the **root cause** honestly: a *skill* that under-specified, a *hook* that
should have fired a reflex but did not (or fired and was ignorable), or a *me* failure the harness
had no mechanism to catch.

### 0b. Turn each drift into a harness change
Route each finding to its fix TARGET and make the change (small+clear -> apply now with the
normal edit+test loop; larger -> record as a proposed item for operator approval):
- **Reflex gap** (a capture/coverage signal the harness could have caught) -> add/extend a hook
  in `skills/hooks/` (stay within "reflexes = capture/route", NOT methodology), with a test in
  `tests/`. Run `python3 -m pytest tests/ -q` green before moving on.
- **Discipline under-specified** -> tighten the governing skill (`ctf-box`/`hunt-*`): make the
  step an explicit ordered checklist item, not buried prose. Skill bodies carry lesson PROSE +
  `[[wikilink]]` ONLY - never inline runnable exploit/rootkit/PoC code (magic-signal dumps,
  syscall PoCs, CVE exploits, reversing walks). That code is the KNOWLEDGE half: promote it to a
  `wiki/` page through the Phase 5-6 gate and point the skill at it with a one-line "try X (see
  [[page]])". A skill body loads wholesale into model/API context on EVERY invocation, so raw
  offensive code there trips the Claude API safety classifier (real: ctf-box's LKM-rootkit +
  CVE-PoC lessons got flagged on load, forcing a manual purge) and bloats context. Prose that
  says WHAT to try in WHAT order belongs in the skill; the code that does it belongs in the wiki.
- **Script/analyzer gap** -> extend `scripts/` (coverage, next_move, find-lint) to surface it.

### 0c. Log the retrospective (generic, tracked)
Append a dated section to `docs/superpowers/harness-retro.md` (create if missing): the drifts
found, their root cause, and the harness change made or proposed. This doc is about the HARNESS,
so it is generic and tracked - describe failures generically ("on a web box ffuf was skipped"),
never with client host/IP/cred.

**Naming the engagement in this tracked file:** use its dir name ONLY when that name is a neutral
codename (`<platform>_<boxname>`). Many engagement dirs are named after the target itself (a host, a
product, a client short-name) - writing one of those into `harness-retro.md` publishes a client
marker, and `check-leaks.sh` derives its marker list from `targets/` dir names, so it WILL fail the
gate. When the dir name is target-derived, describe the engagement generically instead ("a Symfony
API target", "a single-host web bug-bounty campaign") and name nothing. Run `bash
scripts/check-leaks.sh` after writing the retro; a FAIL here almost always means the dir name leaked.

### 0d. Fill the engagement's agent eval (per-engagement, gitignored)
`targets/$ENG/eval.md` (self-healed from `_eval.md`) has two halves - auto (real data) and judgement (you):

**Auto first - REAL numbers, no estimation:**
```bash
python3 scripts/eval_metrics.py $ENG --write
```
This injects a `## Metrics (auto)` block from the hook telemetry (`.events.jsonl`) + the session
transcript recorded in `.metrics.json`: exact skill / hook / tool call counts, auto-detected drift
signals (every scope-guard block, state-discipline nudge, leak-warn), the start->finish time delta +
idle-filtered active time, and the box's token usage (windowed to its active period). NEVER hand-type
these - the transcript is ground truth (a real box's true output was ~12x an earlier hand-estimate).

**Then the judgement half - only you can write it:** in the same file, fill the Drift moments (what
the auto drift-count can't say: WHY each drift happened + the one-line fix), What went right, and the
Scores. The auto block counts drift; you narrate its cause. Dead-ends come from `Deadends.md`.
Unlike the retro (generic, tracked), eval.md is per-engagement and may name specifics (gitignored `targets/`).

Only after Phase 0 is done, proceed to the knowledge harvest below.

## Steps (Phases 1-7: wiki knowledge harvest)

### 1. Resolve the engagement
```bash
ENG=$(cat targets/active.md)
TYPE=$(grep -m1 engagement_type targets/$ENG/state.md | cut -d: -f2 | tr -d ' ')
```
Confirm close-out (`## STATUS:` heading in `state.md`) or that the operator asked
explicitly. Do not harvest an in-flight engagement unless asked.

### 2. Inventory what the engagement taught
Read the full engagement and list every candidate GENERIC lesson:
- `state.md` - tech/service/version that mattered and how it was handled.
- `loot.md` - default or vendor-known creds (NOT client-set passwords).
- `Killchain.md` + `walkthrough.md` - the chain that actually worked, with exact commands.
- `Deadends.md` - what failed. Negative knowledge is reusable: a bypass that does NOT
  work on tech X, a default cred changed in vendor version Y, a false-positive pattern.
- `Vuln-index.md` / `Vulns/` - findings and their reusable exploitation technique.
- `Approach.md`, `log.md` - anything else non-obvious that recurs.

A candidate is worth harvesting only if it is REUSABLE on the next engagement. Skip
one-off client trivia.

### 3. Generalize + strip client specifics
Rewrite each candidate to its generic form: product + technique/cred/endpoint +
impact. Drop every client host, IP, domain, and client-set credential value. Client
specifics stay under `targets/<eng>/`. (The leak gate will refuse anything that slips
through, but strip up front - do not lean on the gate.)

**Compact to the DELTA, not a re-explanation.** A staged candidate is the MINIMAL new reusable
primitive + its one gotcha (a technique delta is typically < ~15 lines), NOT a re-teach of what the
target page already covers. Before promote, re-read the target section (Phase 4) and cut every line
already there -- keep ONLY what the wiki did not have. A verbose dump that repeats known material is
a failed harvest even if it promotes.

### 4. Dedup against the wiki (the skip rule)
For each generic candidate, search the wiki first:
```
mcp__wiki-search__qmd_query   # semantic: concept / technique / intent
mcp__wiki-search__qmd_search  # keyword: exact tool name, CVE id, payload string
```
Find the home page (one class = one page). Read only its frontmatter and the relevant
section. If the technique/payload/cred is ALREADY covered there, SKIP it - wiki has it.
Keep only the delta. This step is the whole point: "extract stuff we haven't had yet".

### 5. Route each survivor through stage
Never hand-edit `wiki/` with engagement-derived content. Stage it:
```bash
# default / vendor-known credential -> the cred cheatsheet
python3 scripts/wiki-stage.py --kind default-cred --slug <product>-default \
  --body '| <product> | <version> | <user> | <pass> | observed | <generic note> |'

# reusable request / payload pattern -> the api-request cheatsheet
python3 scripts/wiki-stage.py --kind api-pattern --slug <product>-<endpoint> \
  --body '| <product> | <endpoint> | <method> | <request/payload> | <auth> | <reveals> |'

# technique / bypass / tool-gotcha that ENRICHES an existing page
python3 scripts/wiki-stage.py --kind technique --slug <slug> \
  --target-page techniques/<area>/<page>.md
# then edit targets/$ENG/wiki-candidates/<slug>.md to APPEND the generic '## Heading' body
# (append below the staged frontmatter -- do NOT overwrite the file, or you drop `status: pending`
#  and `wiki-promote --list` will show nothing to promote)
```

**Genuinely new class with no home page:** `wiki-promote` merges into an EXISTING
page and skips a missing target. So first create a CONTENT-FREE generic scaffold
(frontmatter per `docs/page-types.md` + the section headings only, zero engagement
data), then stage the body against it so the substance still arrives through the gate:
```bash
# 1. scaffold wiki/techniques/<area>/<slug>.md: frontmatter + empty section headings
# 2. stage the generic body:
python3 scripts/wiki-stage.py --kind technique --slug <slug> \
  --target-page techniques/<area>/<slug>.md
```
For an external source that also informs the lesson (a CVE writeup, an advisory), hand
that part to `Skill(research-ingest)` rather than duplicating it here.

### 6. Promote through the leak gate
```bash
python3 scripts/wiki-promote.py --list            # review pending candidates
python3 scripts/wiki-promote.py --review <slug>    # read one in full
python3 scripts/wiki-promote.py --promote all      # leak-checked merge + re-index
```
Promote runs `check-leaks.sh` on each body and refuses (writes nothing) on a client
marker. Report what promoted, what was refused, and why. `--promote` also appends a
generic delta-yield tally (date, engagement_type, count) to `docs/wiki-delta-log.md`;
a zero-yield harvest is worth a sanity check (was the sweep actually run, or is the wiki
already saturated for this box).

### 7. Re-index, lint, self-clear
```bash
python3 scripts/lint-wiki.py -q        # must be clean (broken links, stale index)
# only if a NEW page was created:
python3 scripts/gen_index.py && python3 scripts/build_moc.py && qmd update
touch targets/$ENG/.learn-done         # marks this engagement's learn pass done
```
Log one GENERIC line to `session/log.md` (e.g. "learn: promoted 3 -> jwt-attacks,
default-credentials") and an audit line to `targets/$ENG/log.md`. Never put a client
host/IP/domain in either.

## Guardrails
- **Generic only, gate-enforced.** All engagement-derived writes go stage -> promote;
  the leak check is the code boundary. A new page is a content-free scaffold; its
  substance still comes through the gate.
- **Dedup first.** Enrich the existing page; do not create a second page for a class
  wiki already covers. `qmd` before staging, every time.
- **No fabrication.** Harvest only what the engagement files actually record. If a
  lesson is not backed by the state/loot/Killchain/walkthrough/Deadends record, drop it.
- **Read-only on the engagement.** Phase 0 may edit HARNESS files (`skills/`, `skills/hooks/`,
  `scripts/`, `tests/`, `docs/superpowers/harness-retro.md`) and Phases 1-7 write to `wiki/`
  (via the gate) and the `.learn-done` marker - but NEVER the engagement's own findings/narrative.
- **No offensive code in a skill body.** A tightened skill (`ctf-box`/`hunt-*`) gets lesson prose +
  `[[wikilinks]]` only. Runnable exploit/rootkit/PoC code lives in `wiki/` (through the Phase 5-6
  gate) and is referenced by link, never inlined - the skill loads into API context wholesale and
  the classifier flags raw offensive code (it has). Reversing walks, syscall PoCs, magic-signal
  dumps, CVE exploits = wiki page + a one-line skill pointer.
- **Phase 0 changes ship green.** Any hook/script edit lands with a test and a passing
  `python3 -m pytest tests/ -q`; do not leave the harness broken by an improvement.
- **Retro log is generic + tracked.** `harness-retro.md` describes harness failures generically
  (no client host/IP/cred); the leak boundary still applies.

Report: **Phase 0** - drifts found, root cause each, harness changes made vs proposed, retro-log
path, test status. **Phases 1-7** - candidates found, skipped-as-already-in-wiki, staged,
promoted, refused, pages touched (and any new page created), lint status.
