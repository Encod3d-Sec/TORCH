---
name: bb-workflow
description: Autonomous bug-bounty campaign driver. Runs a full programme end to end with no operator approvals - the deterministic driver (scripts/campaign.py) owns pass state, generates the killchain board from recon, and prints the exact next action (including which Skill and tool to run) every turn. Use when starting or resuming a bug-bounty engagement, "run the bb workflow", "hunt this program", "9-pass campaign", or when handed a *.scope wildcard to test for TIER1 findings. Single agent, refuter-verified, wiki-first, tool-first.
---

# bb-workflow

The driver is the plan. You run one command, do exactly what it prints, record the result, repeat.
Nothing here is advisory: the gates are enforced by `scripts/campaign.py`, so follow its output
literally rather than improvising. This exists because prose routing failed - 22 Skill calls against
341 hand-rolled curls in the reference campaign; the board fixes that by making the mandate tool
output, fresh every turn.

## The loop

```
python3 scripts/campaign.py next        # prints ONE required-action block
# do EXACTLY what it lists, in order
python3 scripts/campaign.py note <row> --arsenal <slug>     # after Skill(wiki-arsenal)
python3 scripts/campaign.py done <row> --poc <img> --kind req   # | --dead R | --park Q | --find F
# repeat
```

## Start / resume

1. `python3 scripts/campaign.py init --type bb` - validates `scope.md` + the autonomy envelope,
   repairs `engagement_type`/schema, prints the Deadends size. If it exits 2, fix what it names
   (an empty `scope.md` is the one thing it cannot invent - fill it from the programme brief first).
2. Passes 0-3 (OSINT/Wayback, crawl, fingerprint, CVE) feed `state.md`. Read every JS bundle and
   handler end to end (`Skill`-less; volume-reduce first: source-map, drop vendor, beautify, read).
   Grep never substitutes for the read.
3. `python3 scripts/campaign.py board` - writes the killchain 4a rows. Refuses on an empty state.
4. Enter the loop. `next` serves one row, depth-first, one open row at a time.

## Gates (the driver enforces; do not fight them)

- **G1** no exploit action until the row's arsenal card exists (`Skill(wiki-arsenal)` fills it).
- **G2** a row cannot close unless its mapped `Skill(hunt-*)` actually fired.
- **G3** a row cannot close without typed evidence: `req` (default), `burp`, or `web` (visual classes
  only). A page render is not evidence of a bug.
- **G8** run the mapped tool before hand-rolling; the driver warns if you skipped it.

## Autonomy

No approvals. Out-of-envelope work **parks** to `decisions.md` and the loop moves on - it never blocks
and never asks a question. A confirmed TIER1 is written up and chained but does not stop the run; the
campaign ends when the board is exhausted (two dry reframe rounds) or the request budget is spent.

## Discipline (carried, not restated - hunt-core owns the gates)

- **Do NOT** invoke `superpowers:brainstorming` or `superpowers:writing-plans` mid-campaign, and keep
  no parallel `TaskCreate` list. The board is the plan.
- One agent. The only subagent is the refuter, spawned by `done --find` before a finding is recorded
  CONFIRMED. No hunter fan-out (it exhausted the weekly quota last time).
- Load-bearing exploit requests go through Burp Repeater when it is reachable; degrade to
  `capture.sh req` when it is not. Never block on Burp.
- Scope and the enumeration ceiling come from `scope.md`, never from this skill.

## Close-out

When `next` prints the close-out chain, run it: `Skill(triage)` -> `Skill(evidence)` ->
`Skill(report)` -> `Skill(learn)`.

## If the driver is unavailable

Manual fallback, same gates by hand: read `killchain.md`, take the top open row for the current
asset, run its wiki lookup then its hunt skill, capture `req` evidence, mark it `[x]`; on exhaustion
one `Deadends.md` line and `[!]`.
