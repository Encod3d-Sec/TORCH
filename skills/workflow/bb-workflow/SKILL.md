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

## Browser observation (chrome-devtools MCP)

The programme's targets are internet-reachable, so **drive them through a real browser**, not just
`curl` - a modern site's real attack surface is only visible rendered. Use the `chrome-devtools` MCP:

- **Pass 1 crawl:** `navigate_page` to each app, then `list_network_requests` - the XHR/fetch calls a
  page makes reveal the **API endpoints/routes** a static crawl never sees (this is exactly the lead a
  curl-only recon misses). `take_snapshot` for the rendered DOM; `evaluate_script` to read client
  config / `__NEXT_DATA__` / JS globals.
- **Confirmation + evidence:** DOM-XSS fires in the real DOM (`evaluate_script` / console); a rendered
  `take_screenshot` of the exploited state is a valid `web` PoC (G3).

Caveat: chrome-devtools drives a **local** browser, so it only reaches internet targets. For a
VPN-boxed host it cannot connect - use the VM-side browser (`scripts/browser.sh` / `capture.sh web`)
as the equivalent. `pt-workflow` / `ctf-workflow` default to the VM browser for that reason.

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
- **RCE-first:** with >1 vector open, take the code-exec one first - it is the attack vector with
  impact; chase lower-impact classes only after code-exec is ruled out or the target needs them.
- **Read whole, not grep:** on a post-foothold host where a sudoer has no findable password and the
  usual vectors dead-end, READ `/etc/pam.d/{sudo,su}` + `/etc/sudoers.d/*` and linpeas output WHOLE -
  a `pam_ssh_agent_auth`/`pam_exec`/`NOPASSWD` line is the tell a grep skips. See [[linux-privesc]].
- **Long tools:** run pspy/linpeas via `bash scripts/vm-bg.sh <eng> <win> '<tool>'` (stages to
  `/dev/shm`, runs in the stabilized shell, `--read`/`--wait 120` the logfile); never retry a broken
  tool pattern >2x - switch method or call `Skill(redteamlead)`.

## Close-out

When `next` prints the close-out chain, run it: `Skill(triage)` -> `Skill(evidence)` ->
`Skill(report)` -> `Skill(learn)`.

## If the driver is unavailable

Manual fallback, same gates by hand: read `Approach.md`, take the top open row for the current
asset, run its wiki lookup then its hunt skill, capture `req` evidence, mark it `[x]`; on exhaustion
one `Deadends.md` line and `[!]`.
