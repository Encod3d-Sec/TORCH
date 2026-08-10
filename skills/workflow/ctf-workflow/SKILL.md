---
name: ctf-workflow
description: Autonomous CTF / boot-to-root campaign driver. Runs a box end to end with no operator approvals - the deterministic driver (scripts/campaign.py) owns pass state, generates the killchain board from recon, and prints the exact next action (Skill + tool) every turn. Use when handed a box/IP to own end to end, "run the ctf workflow", "root this box", "foothold to root". Single agent, wiki-first, tool-first. OSINT is OFF unless you invoke with an osint argument. Delegates box recipes to ctf-box.
---

# ctf-workflow

The driver is the plan. Run one command, do exactly what it prints, record the result, repeat. The
gates are enforced by `scripts/campaign.py`.

## The loop

```
python3 scripts/campaign.py next
python3 scripts/campaign.py note <row> --arsenal <slug>
python3 scripts/campaign.py done <row> --poc <img> --kind req   # | --dead R | --park Q | --find F
```

## Start / resume

1. `python3 scripts/campaign.py init --type ctf` - validates `scope.md` (for a box, scope is just
   the target IP/host) + envelope.
2. **OSINT is OFF by default** for CTF (pass 0 is skipped). Only run it if this skill was invoked
   with an explicit `osint` argument - a box's answer is on the box, not in Wayback.
3. Passes 1-3 feed `state.md` - rustscan/nmap + web enum. Read every service banner, page source and
   config end to end.
4. `python3 scripts/campaign.py board` - writes 4a foothold rows plus 4b pspy/linpeas/sudo/docker
   privesc rows for the ctf approach.
5. Enter the loop, depth-first.

## Box recipes

`ctf-workflow` owns pass sequencing and the board; the per-service exploitation recipes live in
`Skill(ctf-box)`, which the driver hands off to - do not duplicate them here. Route a fingerprinted
service to its `Skill(hunt-*)` as the board names it; use `Skill(ctf-category)` for a standalone
challenge (pwn/rev/crypto/forensics/stego).

## Gates

G1 arsenal-first, G2 skill-first, G3 typed evidence (a flag on screen is a valid `web` PoC), G8
tool-first. Privesc always includes pspy + linpeas/winpeas - the board seeds these as 4b rows.

## Autonomy

No approvals. The verifier is optional for CTF (a captured flag self-verifies). Both flags captured ->
set `## STATUS: SOLVED` in state.md, then the driver prints the close-out chain.

## Discipline

- Do NOT invoke `superpowers:brainstorming`/`writing-plans` mid-box; keep no parallel task list.
- One agent. Read service output whole - the foothold hides in the handler a grep skips.
- Reuse captured creds across hosts before researching new ones.

## Close-out

Run the printed chain: `Skill(walkthrough)` -> `Skill(learn)`.

## If the driver is unavailable

Manual fallback: read `killchain.md`, take the top open row, run its wiki lookup then its hunt skill
or `Skill(ctf-box)`, capture evidence, mark `[x]`; on exhaustion one `Deadends.md` line + `[!]`.
