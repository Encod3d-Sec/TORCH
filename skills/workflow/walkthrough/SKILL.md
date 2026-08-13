---
name: walkthrough
description: Assemble a report-ready walkthrough.md for a SOLVED engagement - populate the Evidence gallery from the poc/ images captured during the engagement, and draft the step-by-step reproduction from state/loot/log (Killchain.md for pentest/bugbounty, state.md's Chain/Status for ctf) without fabricating. Use when asked to "write the walkthrough", "assemble the walkthrough", "close out the box/engagement", or at close-out once an engagement is marked SOLVED.
---

# Walkthrough auto-assembly

Turn a solved engagement into the full, report-ready `targets/<eng>/walkthrough.md`: rendered
evidence, a populated `## Evidence` gallery, and a drafted narrative, so the operator only
reviews/polishes instead of assembling from scratch.

## Convention: mark close-out explicitly

At close-out, write a STATUS heading into `state.md`:
```
## STATUS: SOLVED
```
(`OWNED` / `ROOTED` / `COMPLETE` also count.) This is the close-out signal: once present, the
CLAUDE.md execution loop runs `Skill(walkthrough)` (then `Skill(learn)`).

## Steps

### (a) Confirm the evidence is on disk (capture any missing key state now)
Evidence is captured LIVE during the engagement, straight into `poc/` (via `capture.sh` /
`Skill(screenshot)`) -- there is no staging/drain step anymore. Confirm the PNGs are on disk,
and if a key state (foothold shell, the flag, an exploited render) was never captured, capture
it now before assembling:
```bash
ls targets/<eng>/poc/*.png targets/<eng>/poc/**/*.png 2>/dev/null
# missing a key state? capture it live, e.g.:
#   bash scripts/capture.sh ev <eng> <slug> <url> "<cmd-label>"
```
A walkthrough with an empty gallery means evidence was not captured as steps landed -- fix that
by capturing the reproducible states now, not by fabricating.

### (b) Scaffold + gallery
```bash
python3 scripts/build-walkthrough.py <eng>
```
Idempotent: scaffolds the walkthrough structure from the framework template if missing, and
populates the `## Evidence` gallery from every rendered card on disk. Never clobbers existing
narrative -- safe to re-run after step (a).

### (c) Draft the narrative -- never fabricate
Read `state.md` (for ctf, also its `## Chain`/`## Status` sections, the live working copy of
the attack path and the SOLVED/flags marker) and `loot.md` for the active engagement; for
pentest/bugbounty also read `Killchain.md` and `log.md` (a ctf engagement has neither; its live
chain and narrative live in `state.md` instead). Write the step-by-step reproduction into the
non-Evidence sections (Access -> Recon -> Foothold -> Privilege escalation -> root/flag), using
the EXACT commands, creds, and per-step results already captured in those files. If a fact needed
for a section is not present in the state files, do NOT invent it; leave a clearly marked
`_TODO: <what is missing>_` for the operator instead.

**Record HOW each vuln was DISCOVERED, not only the exploit.** Every Foothold/Privesc step carries a
short "found via:" note - the probe/test/observation that revealed the bug (e.g. "found via:
registered a tag-marker username, saw it reflected unescaped in the users table"), so the reader can
re-FIND it, not just re-fire the payload. The discovery step IS part of the reproduction; a
walkthrough that only shows the working exploit hides how you got there.

**Rewrite each command to the HUMAN form for the reader (technical team / client).** `log.md` holds
the messy automation that actually ran (base64/pty wrappers, `export`s, `;`-merged diagnostic
pipelines) - the walkthrough must NOT. Each step is ONE standalone command a person would type:
concrete values + FULL paths, no `$VAR`/`export` (inline an env var on the one command,
`KRB5CCNAME=/tmp/x.ccache impacket-... `), no `;`/`&&` chains, no `echo` banners. A merged
diagnostic from log.md becomes 2-3 clean single commands here. Interactive sub-steps (an smbclient
`get`, an `su` + password) are shown as the plain human action, not scripted.

### (d) Preserve exploit scripts
Copy any exploit script (payload, escape/forge script, webshell) into
`targets/<eng>/poc/scripts/`, the same exploit-script-preservation discipline `ctf-box` and `screenshot` use --
the reviewer needs the code and the state together, not just a screenshot. **Save it as `<name>.md`
with the code in a ```` ```py ````/```` ```sh ````/```` ```js ```` fence, NOT a bare `.py`/`.sh`/`.js`** -
Obsidian only previews `.md`/images in the GUI, so a raw-extension script is invisible to the operator
reading the walkthrough. Reference the `.md` from the matching step; inline the actual payload as a
fenced block in the step itself so the walkthrough is self-contained.

### (e) Verify complete
Before finishing, confirm:
- no unfilled template markers remain (`<entrypoint>`, `<foothold`, or a bare `- target:` /
  `- reach:` stub line), and
- the `## Evidence` gallery has at least one rendered image reference row.

If either check fails, go back and fill the gap (more evidence to drain, more narrative to draft)
rather than leaving the walkthrough half-done.

## Scope and safety
All output stays under `targets/<eng>/` (gitignored) -- never write client data into `session/*`
or `wiki/`. Every step here is best-effort: `build-walkthrough.py` is idempotent and no-clobber.
Real client engagements still go through `Skill(evidence)` for redaction before the walkthrough
ships in a report; CTF/lab work can skip that.

## On demand
Invoke this skill directly whenever you are ready to write the walkthrough, assemble the
walkthrough, or close out the box/engagement -- the same steps apply.
