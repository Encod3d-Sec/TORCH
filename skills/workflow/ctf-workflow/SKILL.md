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

Every `next` now prints an `APPROACH:`/`AVOID:`/`REFS:` block for the served row (the distilled
ctf-box method for that vuln class) - read it before acting.

## Start / resume

1. `python3 scripts/campaign.py init --type ctf` - validates `scope.md` (for a box, scope is just
   the target IP/host) + envelope.
2. **OSINT is OFF by default** for CTF (pass 0 is skipped). Only run it if this skill was invoked
   with an explicit `osint` argument - a box's answer is on the box, not in Wayback.
3. Passes 1-3 feed `state.md` - rustscan/nmap + web enum. Read every service banner, page source and
   config end to end.
4. `python3 scripts/campaign.py board` - writes the 4a foothold rows; once an asset is a foothold,
   re-run `board` and it seeds the 4b privesc rows (pspy/linpeas auto + the manual checklist) for
   that asset.
5. Enter the loop, depth-first.
6. **When a foothold lands** (a reverse shell in a tmux window via `vm-scan.sh --win shell`, or a
   meterpreter/msfconsole session via `--win msf`), record it: `python3 scripts/campaign.py foothold
   <target> --win shell` (or `--win msf`; or ride it on the closing find with `done ... --win`). The
   driver flips the asset's `state.md` row to `access=foothold` and routes its 4b privesc rows through
   `vm-rsh --win <win>` (persistent session + operator visibility past foothold), and prints `tmux
   attach -t <eng>` for manual takeover. msf itself is operator-attach / drop-to-shell, not
   `vm-rsh`-driven (its wrapper frames a bash shell, not the `msf6 >` REPL). **After recording a
   foothold, re-run `python3 scripts/campaign.py board` so the 4b privesc rows are seeded** - `next`
   will not surface them until you do.
7. **Web RCE -> a real shell, THEN stabilize -- do not ride one-liners (recurring drift).** The
   moment code-exec lands (a web-RCE primitive, an LFI->session-poison, a deser gadget), STOP
   hand-poking one-shot payloads: (a) **catch it with a real handler by default** - `msfconsole`'s
   `exploit/multi/handler` -> meterpreter, or `pwncat-cs` (record via `campaign.py foothold <target>
   --win msf`, step 6). Reserve `vm-scan.sh --win shell <eng> <target> 'nc -lvnp <port>'` for when
   msf/pwncat are unavailable: a raw nc pane's `Ctrl-C` kills the LISTENER (dropping the shell back
   to your own prompt, the false-root attacker-prompt trap) and it has no session management, while
   meterpreter also carries `post/multi/recon`/`local_exploit_suggester` escalation modules and
   built-in file transfer. (b) **Before picking the LPORT, test target egress on common ports
   (80/443/53)** - high ports like 4444 are frequently filtered, so pick an egress-allowed LPORT.
   (c) If you did fall back to raw nc, **stabilize it immediately** with `bash
   scripts/vm-stabilize.sh --win shell <eng>` (pty + job control + window size). (d) Then record the
   foothold (step 6) and drive with `vm-rsh`. An unstabilized nc shell (no job control, mid-line
   wrapping) is what makes post-ex drift back into one-liners. Full discipline: `Skill(ctf-box)`
   Phase 3 (Deliver). The `recon-capture` hook fires this reflex once on the first service-account
   `id`.

## Box recipes

`ctf-workflow` owns pass sequencing and the board; the per-service exploitation recipes live in
`Skill(ctf-box)`, which the driver hands off to - do not duplicate them here. Route a fingerprinted
service to its `Skill(hunt-*)` as the board names it; use `Skill(ctf-category)` for a standalone
challenge (pwn/rev/crypto/forensics/stego).

## Browser observation

A box is VPN-boxed, so the local `chrome-devtools` MCP browser cannot reach it - use the **VM-side
browser** (`scripts/browser.sh <url>` / `capture.sh web`) to render a JS-heavy web service and read
its DOM + network requests (the rendered XHR/fetch calls reveal API routes a `curl` crawl misses -
often the intended path). Rendered screenshots of the flag/exploited state are valid `web` PoCs.

## Gates

G1 arsenal-first, G2 skill-first, G3 typed evidence (a flag on screen is a valid `web` PoC), G8
tool-first. Privesc always includes pspy + linpeas/winpeas - the board seeds these as 4b rows once
an asset is recorded as a foothold (re-run `board` after `foothold`/`done --win` to seed them).

Once a foothold and a working escalation vector are identified, delegating the exploit compile +
escalation run to a sub-agent with a precise copy-paste checklist works well - keep the
main agent driving the board. A delegation is only as good as its checklist; REQUIRED elements:
(a) the confirmed access/primitive spelled out, (b) exact copy-paste commands, (c) a
false-root/false-RCE guardrail - verify `hostname` matches the target AND the expected uid before
trusting a returned `uid=0`/shell, since the Kali VM runs as root and `$(...)`/backticks substitute
LOCALLY, (d) the slow/fragile-target request discipline (serial, long timeouts) if the box needs it.
Model heuristic: Sonnet for judgement-heavy multi-step exploitation, Haiku 4.5 for mechanical,
fully-specified steps (decrypt a credential store, compile-and-run a known exploit).

Prefer a clean post-ex command channel over driving `msf sessions -c` (delayed output, quoting
pain): a webshell writing enum output to a web-served file then `curl` it, or a single-tool
read/decrypt done locally on already-exfiltrated data.

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

Manual fallback: read `Approach.md`, take the top open row, run its wiki lookup then its hunt skill
or `Skill(ctf-box)`, capture evidence, mark `[x]`; on exhaustion one `Deadends.md` line + `[!]`.
