---
name: delegate
description: Autonomous sub-agent hand-off for a fiddly, fully-specified exploit-compile / escalation RUN - the main agent stays on strategy and the board while a cheap sub-agent runs an exact copy-paste checklist behind a false-root/hostname guardrail. Use for "delegate", "offload", "hand this to a sub-agent", "spin a haiku", or the moment a foothold plus a working escalation vector is identified. Main agent dispatches, waits (no parallel duplicate), integrates the result.
---

# Delegate: sub-agent exploit-run

Hand a fiddly, fully-specified exploit-compile or escalation run to a cheap sub-agent so the main
agent stays on strategy and the board.

## When to delegate / when NOT

Delegate when a foothold plus a WORKING escalation vector is identified, or the step itself is a
fiddly fully-specified multi-step compile/run: compile a C PoC, deliver and run an ELF, drive
`su`/`sudo`/`screen -r`, msfvenom + `multi/handler` catch. Keep on the main agent: recon, judgement-
heavy vector selection, anything not fully specified. An unconfirmed vector is not a delegation, it
is a guess wearing a checklist.

## Model choice

`haiku` for mechanical, fully-specified steps: compile-and-run a known exploit, decrypt a credential
store. `sonnet` for judgement-heavy multi-step work: a JS-heavy per-route-CSRF authed backend RCE.

## The checklist (a delegation is only as good as its checklist)

Every delegation needs all six slots filled. Under-specify one and the sub-agent flails; that is the
usual failure mode, not a weak sub-agent.

- **(a) confirmed access/primitive**, spelled out; don't make the sub-agent rediscover it.
- **(b) exact copy-paste commands**, real IPs/paths inline, no `$VAR`; the sub-agent cannot watch a
  live terminal to sanity-check a substitution.
- **(c) egress/port constraints**, an egress-tested LPORT, not a guess at 4444.
- **(d) the false-root guardrail** (next section), non-negotiable.
- **(e) fragile-box discipline** if applicable: serial requests, long timeouts, no fuzzers.
- **(f) report-back contract**: return the primitive/creds/flag plus evidence path; do not pivot
  further without the main agent.

## False-root/hostname guardrail (MANDATORY every delegation)

A returned `uid=0`/root is trusted ONLY if `hostname` matches the target AND the expected uid holds.
Otherwise the shell died back to the Kali box, which runs as root; `$(...)`/backticks there substitute
LOCALLY, the false-RCE trap. The fix is re-pop, not celebrate. The sub-agent MUST report `hostname`
alongside any `id` output, every time, no exceptions.

## Main-agent discipline

Keep driving the board while the sub-agent works. Dispatch ONE sub-agent at a time, serial; never
duplicate its target in parallel. WAIT for completion before the next move. On return, persist the
primitive/creds/flag to `state.md`/`loot.md`/`Killchain.md` before doing anything else.

## Mechanism

Dispatch via the Agent tool: `subagent_type` general-purpose, `model` per the choice above, the
checklist as the prompt, an explicit return/report contract written into the prompt itself. This
skill's invocation IS the standing authorization to use the Agent tool mid-engagement; no separate
approval needed.

## Worked examples

Each uses placeholder tokens only.

**(1) Catch a meterpreter as a service account**
Confirmed: RCE via the admin panel upload field on `<target>`. Egress-test the LPORT first (80/443
before 4444). Start `multi/handler` on the Kali VM, then deliver an inline base64 ELF payload through
the panel RCE. Report back `hostname` + `id` + the session log path.

**(2) `ssh2john` -> crack -> `ssh-keygen -p` strip -> SSH chain**
Confirmed: a private key at `<path>` protected by a passphrase. Run `ssh2john <path> > <hash-file>`,
crack with the standard wordlist, then `ssh-keygen -p -f <path>` to strip the passphrase, then
`ssh -i <path> <user>@<target>`. Report the cracked passphrase and the resulting shell's
`hostname` + `id`.

**(3) sudo `screen -r <name>` -> `Ctrl-A c` root**
Confirmed: `sudo -l` shows `screen` unrestricted and a root-owned session `<name>` is running. Run
`sudo screen -r <name>`, then send `Ctrl-A c` to spawn a new window inside the root screen. Report
`hostname` + `id` from inside that window before touching anything else; the guardrail applies here too.

**(4) openssl-caps `.so` constructor root**
Confirmed: the `openssl` binary carries `cap_setuid+ep`. Compile a `.so` with a constructor that execs
a shell, run it via `openssl req -engine <path-to-so>`, then confirm `hostname` + `id` inside the new
shell before reporting root.

Once a working checklist and guardrail confirm a primitive, hand the box's actual next step to
`Skill(metasploit)` when the run is msf-shaped (handler catch, module-driven exploit); this skill
covers the delegation pattern itself, not the msf mechanics.

## Client-data boundary

Worked examples use placeholders only; never put a real target IP, hostname, or credential into this
skill file.
