---
name: campaign-health
description: Health check for the bb/pt/ctf workflow driver subsystem - verifies everything is in place so every machine runs the same. Checks vault-content consistency (scripts present, JSON valid, routing wired, all 69 tool pages carry phase:, the tool index resolves, the hook edits are in place) AND per-machine wiring (the three workflow skills symlinked, hooks registered, imports work), then runs a live init->board->next smoke test. Use when setting up the workflow on a new machine, after a vault sync, when the driver misbehaves, or on "bb-health", "campaign health", "is the workflow set up", "check hooks and scripts", "why is the board not working".
---

# campaign-health

The vault syncs across machines; `~/.claude` (hook registration, skill symlinks, deps) does **not**.
So "it works here" does not mean "it works there". This skill confirms both halves before you rely on
`bb-workflow` / `pt-workflow` / `ctf-workflow` on this machine.

## Run it

```
python3 scripts/campaign-doctor.py            # summary (only WARN/FAIL shown)
python3 scripts/campaign-doctor.py --verbose   # every check
```

Exit 0 = all green. Exit 1 = at least one FAIL; the driver will not run correctly here until fixed.

## What it checks

- **A. vault content** - the driver's scripts exist, every campaign JSON is valid, each type's
  `approach` exists in `playbook.json` and `coverage-classes.json`, the two hook edits (recon-capture
  emits `spec['tools']`, tool-telemetry logs binaries) are present, all 69 `wiki/tools/` pages carry
  `phase:`, and `campaign.tool_index()` resolves an invocation for every tool.
- **B. machine wiring** - the three workflow skills are authored and symlinked into `~/.claude/skills`,
  hooks are registered (via `check-hooks.py`), and `_engagement` imports.
- **C. live smoke test** - `init -> board -> next` against a throwaway copy of the fixture, asserting
  the board writes rows and `next` withholds the exploit at G1.

## Fixing what it reports

- **WARN (machine wiring)** - usually one setup script the doctor names:
  `bash setup/install-skills.sh` (skills) or `bash setup/install-hooks.sh` (hooks).
- **FAIL (vault content)** - a stale sync or a partial edit. Re-pull the vault; if a tool page lost
  its `phase:`, re-run `python3 scripts/tool-phase-backfill.py --write`.

Run this first on any new machine, and after every vault sync, so all machines run the same driver.
