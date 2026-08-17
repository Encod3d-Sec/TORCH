---
name: metasploit
description: Drive msfconsole across the workflow - DB-backed recon (db_nmap, auxiliary scanners), version->exploit search/check/run, multi/handler reverse shells (meterpreter-first, plain shell_reverse_tcp backup for Windows/EDR), sessions + local_exploit_suggester + post modules, and autoroute/portfwd/socks pivoting. Points to the metasploit cheatsheet for syntax. Use for "metasploit", "msfconsole", "msfvenom", "meterpreter", "multi/handler", or driving an exploit/reverse-shell through msf.
---

# Metasploit: framework driver

Drive msfconsole for recon, exploit, reverse shells, and post-ex. Syntax lives in
`[[metasploit]]`; this skill is the workflow that strings it together.

## Pre-attack wiki query (MANDATORY)
Before firing any exploit module, query the fingerprinted tech/CVE: read `[[metasploit]]`
directly for syntax, then `Skill(arsenal)` for the matching module/payload/technique. Never fire
a module from memory when a targeted lookup would confirm the right one/target index.

## Setup / DB
`msfconsole -q` in a named tmux tab, never a blind background job, the operator needs to see
sessions land live. `workspace -a <eng>` scopes loot to the engagement, `db_status` confirms the
Postgres backend is up before anything else. Cheatsheet: Setup + Database sections.

## Recon via msf
`db_nmap` writes straight to `hosts`/`services`; layer `auxiliary/scanner/*` (smb/http/ssh
version + vuln checks) on top for anything plain nmap scripts miss. This complements the
ctf-box Phase-1 basics, it does not replace them, run both.

## Search / select / verify
`search <app> <ver>` or `search cve:<id>`, `use`, `info` to read the module's CVE refs and
target list, `check` before `run`/`exploit` whenever the module supports it, a non-destructive
exploitability test beats a blind fire. Cheatsheet: Search and Selection + Options and Running.

## Reverse shells
`multi/handler` catches. Payload choice: meterpreter first
(`linux/x64/meterpreter/reverse_tcp` / `windows/x64/meterpreter/reverse_tcp`), fall back to plain
`shell_reverse_tcp` when meterpreter is blocked or unstable, routine on hardened Windows/EDR.
Delivery via `msfvenom` (ELF/EXE/ASPX/PHP, cheatsheet's MSFVenom section has every format).
Egress-test the LPORT (80/443/53 before 4444). Background the handler correctly:
`set ExitOnSession false; run -j` so it keeps catching new sessions.

## Sessions / post-ex
`sessions -i` to interact, `run post/multi/recon/local_exploit_suggester` is the privesc reflex
on every fresh session, then targeted `post/*` modules, `getsystem`, and
`post/multi/manage/shell_to_meterpreter` to upgrade a plain shell. Cheatsheet: Sessions and Jobs
+ Post-Exploitation Modules.

## Pivoting
`autoroute`/`portfwd`/`socks` through a session to reach internal-only ports before hand-rolling
SSH `-L`. Full syntax and proxychains setup: `[[pivoting]]`.

## Verify target (false-root)
Before trusting any shell or privesc claim: `getuid` + `sysinfo`/hostname must match the actual
target. A `uid=0` that doesn't match the target is the false-root trap, the session died back to
the attacker box. Same guardrail `Skill(delegate)` enforces on manual exploit runs.

## Interlock + anti-drift
The fiddly msfvenom-compile -> handler-catch -> escalation-run sequence is a prime
`Skill(delegate)` hand-off: fully specified, mechanical, cheap-model-shaped. DRIVE msf for every
load-bearing exploit/shell request so the operator watches sessions land; don't abandon msf for
raw scripts once a foothold lands.

## Client-data boundary
Sessions, loot, and creds stay in the msf DB workspace + `targets/<eng>/`; never paste a real
host/cred/hashdump into `wiki/` or `session/*`.
