---
name: pt-workflow
description: Autonomous pentest campaign driver. Runs a scoped engagement end to end with no operator approvals - the deterministic driver (scripts/campaign.py) owns pass state, generates the killchain board from recon, and prints the exact next action (Skill + tool) every turn. Use when starting or resuming a pentest, "run the pt workflow", "work this CIDR/domain", or when handed a client SoW/scope to reach a stated objective or domain admin. Single agent, refuter-verified, wiki-first, tool-first. Deliverable is a client report.
---

# pt-workflow

The driver is the plan. Run one command, do exactly what it prints, record the result, repeat. The
gates are enforced by `scripts/campaign.py`; follow its output literally.

## The loop

```
python3 scripts/campaign.py next
python3 scripts/campaign.py note <row> --arsenal <slug>
python3 scripts/campaign.py done <row> --poc <img> --kind req   # | --dead R | --park Q | --find F
```

## Start / resume

1. `python3 scripts/campaign.py init --type pt` - validates `scope.md` + envelope, repairs
   type/schema. An empty `scope.md` must be filled from the client SoW first (CIDRs, domains, RoE,
   lockout policy). The lockout policy and any destructive-op limits live in `scope.md`, not here.
2. Passes 1-3 feed `state.md` - rustscan/nmap/nxc/LDAP/kerbrute/BloodHound per the recon defaults,
   which yield to `scope.md`'s allowed tooling. Read service output end to end.
3. `python3 scripts/campaign.py board` - writes the 4a rows (plus 4b lateral/privesc/DCSync for the
   pentest approach). Refuses on empty state.
4. Enter the loop, depth-first, one open row at a time.
5. **When a shell/session lands on a host** (reverse shell via `vm-scan.sh --win shell`, or
   meterpreter via `--win msf`), record it: `python3 scripts/campaign.py foothold <host> --win shell`
   (or ride it on the closing find with `done ... --win`). The driver flips that host's `state.md`
   row to `access=foothold`, routes its 4b lateral/privesc rows through `vm-rsh --win <win>`
   (persistent session + operator visibility), and prints `tmux attach -t <eng>` for takeover.

## Gates

Same as the shared driver: G1 arsenal-first, G2 skill-first, G3 typed evidence, G8 tool-first. AD
attacks route through `Skill(hunt-ad)`; local privesc through `Skill(hunt-windows)` /
`Skill(hunt-macos)`; the driver names which per row.

## Autonomy

No approvals. Out-of-envelope work parks to `decisions.md`; the loop never blocks. A spray is gated by
the lockout policy in `scope.md` (the envelope), never attempted blind. Destructive AD operations
(Zerologon and similar) park unless the envelope authorises them.

## Discipline

- Do NOT invoke `superpowers:brainstorming`/`writing-plans` mid-run; keep no parallel task list.
- One agent; the refuter is the only subagent (`done --find`).
- Load-bearing requests through Burp when reachable; degrade to `capture.sh req` otherwise.
- Scope, lockout policy and destructive-op limits come from `scope.md`.

## Close-out

Run the printed chain: `Skill(triage)` -> `Skill(evidence)` -> `Skill(report)` -> `Skill(learn)`.
**The pentest deliverable is a client report**, not a CTF walkthrough. The report generator must run
with `PATH=/opt/prep_report/.venv/bin:$PATH` or every finding loses its severity callout box.

## If the driver is unavailable

Manual fallback: read `killchain.md`, take the top open row for the current host, run its wiki lookup
then its hunt skill, capture `req` evidence, mark `[x]`; on exhaustion one `Deadends.md` line + `[!]`.
