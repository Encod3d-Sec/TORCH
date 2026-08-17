---
title: "Harness discipline via the driver (posture lines + RTL stop-tell counters)"
type: design-spec
tags: [harness, campaign-driver, retrospective, design]
date_created: "2026-08-17"
date_updated: "2026-08-17"
status: approved-for-planning
sources: []
---

# Harness discipline via the driver

Design spec for making four recurring CTF/box behaviors reliable by encoding them in the
deterministic driver (`scripts/campaign.py`) and hardening skill prose, WITHOUT a throttling
enforcement hook. Derived from the `failures.md` retros across thm_cybercrafted, thm_endgame,
thm_frank, thm_gla, thm_intranet, thm_jellyfish, thm_jurassic, thm_mountaineer.

## Problem

Four behaviors keep failing across boxes:

1. **`redteamlead` never called at stop-conditions.** cybercrafted F4 ("RTL should have been
   called after the 2nd failed rule set"), mountaineer (2 uncrackable hashes + box crashing under
   load = wrong vector, kept grinding), jurassic (sqlmap ban misread as server load), intranet
   (SQLi-decoy + rockyou rabbit-holes, ~60-70% of wall-clock).
2. **Hand-rolling instead of the installed tool.** endgame (hand-rolled group_concat UNION paging
   instead of sqlmap), mountaineer (hand-rolled time-based extractor), gla (urllib loops).
3. **Reverse shells not driven through msfconsole.** cybercrafted F1 (nc froze; operator: "WHY ARE
   WE NOT USING MSFCONSOLE?"), jellyfish HEADLINE 1 (raw nc cost most of the box, false-root traps),
   intranet F10 (Ctrl-C on unstabilized nc → false-RCE trap).
4. **Exploit search not run through exploitdb + msfconsole first** on version-known services.

## Root cause

The rules for all four ALREADY exist in `ctf-box`/`hunt-core` prose and partly in the driver. They
drift under momentum because **nothing deterministic re-asserts them once the driver is off — and
the driver is off on exactly the fast/manual boxes where the failures happened**:

- jurassic: "Never ran board/next/done, ledger drift 8/8, discipline gates went unenforced."
- mountaineer: "drift=47, board empty, we freewheeled."
- intranet F1: driver `init` crashed → whole box hand-driven → "none of the anti-rabbit-hole gates
  existed" (their own words: the upstream cause of both big rabbit-holes).
- frank: box solved by hand, driver stuck at PASS 0/9.
- Contrast endgame, where the driver + delegation ran and discipline held cleanly.

Secondary: the hooks that exist either miss or false-fire. `drift-guard.py` only arms at `pass>=5`
(fast boxes fall first) and escalates to a hard `deny`; `recon-capture.py` fired a FALSE "stabilize
your nc shell" nudge at frank's legitimate SSH session. That is the "hooks throttle the whole
engagement" problem.

## Design decisions (locked)

- **Carrier: driver-centric (A) + skill-prose (C).** The driver deterministically re-asserts the
  four behaviors; skill prose is hardened to match. No new heuristic enforcement hook.
- **Hook posture: A1 — declaw.** Remove the throttling `deny`/nudge code. Enforcement lives in the
  driver, which cannot block a tool call. Only pure-fact guards (scope/RoE) keep a `deny`.
- **Reverse-shell rule: catch every pop through `msfconsole multi/handler`.** Payload meterpreter
  first; plain `shell_reverse_tcp`/listener backup when meterpreter is blocked or unstable (routine
  on Windows/EDR — the stager dies, a normal shell survives). Banned: raw `nc` as the default catch
  on a box where meterpreter would work. SSH / `evil-winrm` / existing-cred footholds stay as-is.
  **pwncat-cs is dropped** from the handler options.
- **Ambition: Approach 2 (driver posture lines + fast-box friction fix + hook declaw) + the RTL
  stop-tell counter** from Approach 3.

## Already shipped (do NOT rebuild)

Verified present in `scripts/campaign.py` during design:

- **Envelope-init crash — fixed.** `_heal_scope_envelope` + `CTF_ENVELOPE_DEFAULTS`
  (campaign.py:120-154) self-heal the 8 envelope keys at init. (intranet/frank F1.)
- **SOLVED-aware close-out — fixed.** `cmd_next` short-circuits to `_closeout` on a
  `## STATUS: SOLVED|OWNED|ROOTED|COMPLETE` marker via `_is_solved`/`_SOLVED_RE`
  (campaign.py:1119, 157-168). (frank F4.)

The remaining reliability gap is that the driver is not RUN, addressed below by making its output
worth running every turn (posture lines even pre-board) plus a hard skill mandate.

## Non-goals

- No new enforcement/throttling hook. No `deny` added anywhere except the existing scope/RoE guard.
- No conversion of SSH/cred footholds to meterpreter (rule 3 governs the pop, not every session).
- Not touching bb (bug-bounty) web-recon flow beyond the shared prose; the four behaviors are
  boot-to-root / version-known-service shaped (ctf + pt).

---

## Section 1 — Driver posture lines (`scripts/campaign.py`)

Context-filtered lines (NOT a static banner — agents tune banners out), emitted from BOTH the
pre-board path (`_pre_board_next`, campaign.py:1281) and the row path (`cmd_next`, ~1206-1266) so
running `next` pays off on turn 1 of a fast box.

1. **msf-shell line** — print only when the served row's `vuln class` ∈ `CODE_EXEC_CLASSES`
   (already defined, campaign.py:1038: rce/cmdi/ssti/deserialization/upload/file-write/sqli) AND the
   served asset has no live foothold session yet (`st["footholds"].get(asset)` is falsy — i.e. you
   are about to pop, not already in). This is the deterministic "foothold-imminent" condition; once a
   session exists the line is redundant and suppressed. Text: catch the pop through
   `msfconsole multi/handler`; meterpreter first,
   plain-shell/listener backup for Windows/EDR; no raw-nc default; SSH/cred footholds stay as-is.
2. **searchsploit+msf line** — print in fingerprint/cve passes (`pass` 2-3) or when a served row is
   version-known. Text: `searchsploit <app> <ver>` + `msfconsole -qx 'search <app>'` BEFORE
   hand-rolling or deep-diving a CVE. (Pass 3 `_pre_board_next` guidance already says searchsploit
   once; this makes it a per-turn reminder.)
3. **no-handroll** — fold into the EXISTING `G8: tool-first` line (campaign.py:1257), do not add a
   new line: append "no hand-rolled /dev/tcp/curl/urllib request loops; if no tool fits, say why in
   one line."

Scope: ~30 lines, confined to the two output builders. No new state.

**Check:** a small `test_posture.py` (or `__main__` self-check) asserting: a code-exec row's `next`
output contains "multi/handler"; a non-code-exec row's does not; a version-known/fingerprint-pass
output contains "searchsploit".

## Section 2 — RTL stop-tell counters

The only new state. Makes "call redteamlead" deterministic instead of the current soft "consider"
(campaign.py:1211).

**Passive detector** — extend `recon-capture.py` (PostToolUse/Bash), NOT a new hook file. It
already reads tool output via `_response_text(data)` (recon-capture.py:253) and already has a
`hashcat|john` regex in `CRED_TOOLS` (line 30). In `main()`, after the existing parse:

- `crack_fail` — command invoked `john`/`hashcat` AND output matches `No password hashes cracked`
  / "0 ... cracked" / empty-cracked → increment `.campaign.json["tells"]["crack_fail"]`.
- `box_000` — command is an HTTP exploit/probe AND output shows HTTP `000` / empty-reply / timeout
  → increment `.campaign.json["tells"]["box_000"]`; reset to 0 on a normal 2xx/3xx/4xx from the
  same host (consecutive-only).

This detector ONLY writes counters — no `deny`, no `additionalContext` injection → it cannot
throttle. Consistent with A1: enforcement stays in the driver.

**Driver reads it** — `cmd_next` emits a hard STOP when a threshold trips, before serving the row:

- `crack_fail >= 2` → "STOP: 2 verified hashes failed the wordlist → creds are out-of-band
  (email/note/KeePass/config). Call `Skill(redteamlead)` before a 3rd, or read the app's other
  surfaces (LFI/source, second vhost, mail)."
- `box_000 >= 3` → "STOP: the box is starving under your own exploit loop (3x 000/timeout). A vector
  that DoSes a lab box is almost never intended — serialize, or call `Skill(redteamlead)` to
  re-pick the vector."

**Reset:** a `redteamlead` firing is already observable in `.events.jsonl` (written by
`tool-telemetry.py`; read pattern exists as `_skill_fired_since`, campaign.py:656). When a
`Skill(redteamlead)` event is newer than the last tell increment, zero the counters.

Thresholds justified by the data: `crack_fail>=2` (mountaineer, cybercrafted), `box_000>=3`
(jurassic, jellyfish, mountaineer).

**Check:** `test_tells.py` — seed `.campaign.json` with `crack_fail:2` and assert `cmd_next` prints
the RTL STOP; seed a fresh `.events.jsonl` redteamlead event and assert the counter resets.

## Section 3 — Declaw the throttling hooks

- **`skills/hooks/drift-guard.py`**: remove the escalating `permissionDecision: deny` (off-board
  streak ≥3 → block, ~lines 296-307) and the 5-min time-based `auto-rtl` nudge (~lines 248-259).
  The RTL trigger moves to the tell-counters (Section 2, a real signal vs. 5-min-idle noise). Keep
  the self-kill advisory (never denies). **scanner-cap: downgrade from `deny` to advisory** (keep
  the fragile-box DoS warning from jurassic/mountaineer, drop its teeth).
- **`skills/hooks/recon-capture.py`**: remove the exploit-phase "stabilize your nc shell" nudge
  (~lines 886-905; false-fired on frank's SSH). Keep OOB auto-correlation and add the Section-2
  passive counters.
- **Untouched:** `scope-guard.py` (scope/RoE fact-`deny` — never false-fires on judgment).

**Check:** feed each hook a synthetic PreToolUse/PostToolUse payload (legit SSH `id`, a normal 2nd
scanner) and assert no `permissionDecision: deny` and no stabilize nudge in output. Assert scope
out-of-scope host still denies.

## Section 4 — Skill prose hardening

- **`skills/workflow/ctf-box/SKILL.md`**:
  - Line 94: "Prefer a real handler over a raw nc listener" → **MUST**: catch every reverse-shell
    pop through `msfconsole multi/handler`; meterpreter-first, plain `shell_reverse_tcp`/listener
    backup for Windows/EDR; SSH/evil-winrm/cred footholds stay as-is. **Remove pwncat-cs.**
  - Line 85: searchsploit + msfconsole search from reflex → hard step on any version fingerprint.
  - Line 88: the two stop-tells (box starves / 2 hashes fail) from "call RTL when the next door is
    not obvious" → "call RTL on the FIRST tell" (matches the Section-2 thresholds).
  - Add a top-of-skill mandate: **run `campaign.py next` before every exploit step** (the
    frictionless-driver forcing function that replaces the removed `deny`).
- **`skills/hunt/hunt-core/SKILL.md`**: stop-conditions aligned to the counter thresholds
  (2 failed cracks / 3x box-000 = RTL, not grind).
- **`skills/workflow/ctf-workflow/SKILL.md`** and **`pt-workflow/SKILL.md`**: reassert the
  per-step driver-run mandate.

## Section 5 — Belt-and-suspenders (small)

- **`setup/templates/{ctf,pentest,bugbounty}/scope.md`**: seed the 8 envelope keys with per-type
  defaults (ctf defaults already exist as `CTF_ENVELOPE_DEFAULTS`). The `_heal_scope_envelope`
  self-heal already prevents the crash, so this is cosmetic hygiene, not load-bearing — include
  only if cheap.

---

## File change summary

| File | Change | Section |
|------|--------|---------|
| `scripts/campaign.py` | posture lines in `_pre_board_next` + `cmd_next`; read tell-counters → RTL STOP; reset on redteamlead event | 1, 2 |
| `skills/hooks/recon-capture.py` | add passive `crack_fail`/`box_000` counters; remove stabilize nudge | 2, 3 |
| `skills/hooks/drift-guard.py` | remove off-board `deny` + time-based auto-rtl; scanner-cap `deny`→advisory | 3 |
| `skills/workflow/ctf-box/SKILL.md` | msf-must, drop pwncat, searchsploit-must, RTL-on-first-tell, driver-run mandate | 4 |
| `skills/hunt/hunt-core/SKILL.md` | stop-conditions aligned to thresholds | 4 |
| `skills/workflow/ctf-workflow/SKILL.md`, `pt-workflow/SKILL.md` | per-step driver-run mandate | 4 |
| `setup/templates/*/scope.md` | seed envelope keys (optional) | 5 |

## Verification

- Unit checks per Sections 1-3 (posture presence/absence, tell→RTL, hook no-throttle).
- `Skill(campaign-health)` smoke test (init → board → next) still passes after the campaign.py
  edits.
- Prose changes: no test; reviewed against the reverse-shell rule wording above.

## Open item for review

Keeping scanner-cap as ADVISORY vs. deleting it entirely — spec keeps it advisory (targets a real
repeated DoS, but is a judgment call so it loses its `deny`). Flip to delete if preferred.
