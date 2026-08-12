# Engagement Playbook

This file is the canonical reference for how target engagements are structured in this vault.
The file set below is self-healed by the `engagement-init` hook; start a new engagement with
`bash setup/new-engagement.sh <name> <pentest|bugbounty|ctf>`.

---

## Directory Structure

```
targets/<eng>/                  # created by new-engagement.sh, self-healed by engagement-init
├── scope.md            -- in/out-of-scope + RoE flags (no_bruteforce/no_dos/passive_only)   [all types]
├── state.md            -- primary target map: host/service/access table (per-type columns)  [all types]
├── loot.md             -- captured credentials / keys / flags + reuse map                    [all types]
├── Killchain.md         -- open/blocked attack paths + next moves (LIVE attack-chain tracker) [pentest/bugbounty; ctf: folds into state.md's ## Chain/## Status]
├── log.md              -- append-only audit trail (terse)                                     [pentest/bugbounty]
├── walkthrough.md      -- full copy-pasteable boot-to-root reproduction (FINAL attack chain) [all types, self-created at close-out if missing; scaffolded upfront for pentest/bugbounty]
├── Deadends.md         -- false positives + exhausted/blocked vectors (anti-loop)             [all types]
├── ingest/             -- raw tool output, consumed by the ingest skill                       [all types]
├── recon/              -- auto-captured scan-tool screenshot cards (nmap/ffuf/nuclei/...)     [all types]
├── poc/                -- curated exploit/PoC/flag screenshots + PoC scripts                  [all types]
├── coverage.md         -- per-asset vuln classes tested       [pentest/bugbounty; ctf: --with-coverage]
├── oob.md              -- out-of-band callback tracking        [pentest/bugbounty; ctf: --with-oob]
├── Vuln-index.md       -- finding index by severity + chains   [pentest/bugbounty; ctf: slim list, on demand]
└── Vulns/              -- FIND-NNN-SEVERITY-slug.md, created on the first FIND (pentest/bugbounty)
    ├── Research/       -- in-progress, not yet confirmed
    ├── Completed/      -- confirmed findings (moved here after triage passes)
    ├── False Positive/ -- disproven findings
    └── Skipped-but-usefull/  -- valid but out-of-scope or de-prioritised
```

Not auto-created: `Vulns/` is made on the first FIND (pentest/bugbounty); make a
`reports/` dir or a `scope/` IP/domain sub-list by hand only if an engagement needs
them. A ctf engagement omits `coverage.md`, `oob.md`, and the severity `Vuln-index.md`
at init (all dead across THM rooms); create them on demand with `--with-coverage` /
`--with-oob`, or `ensure_optional_file()` when a coverage check or a blind bug runs. A
ctf engagement ALSO omits `Killchain.md` and `log.md` entirely (its live attack chain
lives in `state.md`'s own `## Chain`/`## Status` sections instead), and `walkthrough.md`
/ `eval.md` / `decisions.md` self-create on demand at their own trigger rather than
being scaffolded upfront, see `setup/templates/ctf/state.md`.

---

## FIND Naming Convention

Individual finding files live in `Vulns/` and are named:

```
FIND-XXX-SEVERITY-short-slug.md
```

- `XXX` -- zero-padded sequential number (001, 002, ...)
- `SEVERITY` -- one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `short-slug` -- kebab-case description, e.g. `influxdb-auth-bypass` or `supabase-open-signup`

Examples:
```
FIND-001-CRITICAL-influxdb-cve-2019-20933.md
FIND-007-HIGH-adfs-user-enumeration-timing.md
FIND-015-MEDIUM-s3-buckets-publicly-listable.md
```

---

## Severity Definitions

| Severity | Meaning |
|----------|---------|
| CRITICAL | Direct impact: unauthenticated RCE, plaintext credential exposure, admin takeover |
| HIGH | Significant risk requiring auth or chaining: SSRF, SQLi, privilege escalation, auth bypass |
| MEDIUM | Limited direct impact or requires chaining: info disclosure, misconfiguration, version exposure |
| LOW | Minimal risk: weak headers, minor misconfig, non-sensitive info disclosure |
| INFO | Fingerprinting, surface mapping, version banners |

---

## Vuln-index.md Format

This severity index is a pentest/bugbounty artifact. A ctf room does not init it:
its attack chain has one live home (`Killchain.md`, read by next_move) and one final
home (`walkthrough.md`, the TL;DR chain line and the boot-to-root recipe). If a ctf
writeup wants a flat findings roll-up, `ensure_optional_file("vuln-index")` creates
the slim `setup/templates/ctf/vuln-index.md` (a plain list, no severity/CVSS, no Key
Attack Chains). Keep chain narrative out of a ctf Vuln-index; it belongs in Killchain.md /
walkthrough.

```markdown
---
title: "<Target> — Confirmed Finding Writeups Index"
engagement: <Legal entity name>
tester: <email>
date_retested: YYYY-MM-DD
scope: ~N IPs/domains
---

## CRITICAL
| ID | Title | Host | Status |
|----|-------|------|--------|
| [FIND-001](Vulns/Completed/FIND-001-CRITICAL-...) | Short title | host:port | CONFIRMED |

## HIGH
...

## MEDIUM
...

## INFO / LOW
...

---

## Severity Count

| Severity | Count | Confirmed | Notes |
|----------|-------|-----------|-------|
| Critical | N | N | -- |
...

---

## Key Attack Chains

**Chain 1 -- Name:**
`FIND-XXX` -> `FIND-YYY` -> impact description
```

Status values: `CONFIRMED`, `PARTIAL (reason)`, `CLOSED`, `VERSION CONFIRMED / PoC pending`

---

## state.md / scope.md

`state.md` is the primary target map: one markdown table, one row per host/asset, with
per-engagement-type entity columns (pentest: host/ip; bugbounty: asset/url; ctf: target)
plus services, access, owned, and notes. `next_move` and `coverage` read it, so keep it
current -- capture recon output into it immediately (or drop raw output in `ingest/` and run
the ingest skill). Column templates live in `setup/templates/<type>/state.md`.

`scope.md` holds the in/out-of-scope entries and the RoE flags (`no_bruteforce` / `no_dos` /
`passive_only`) that `scope-guard` and `next_move` honor. Read it before any action.

---

## Deadends.md Discipline

Log a dead-end entry **immediately** when a path is exhausted, not at end of session.
This prevents re-testing the same paths in future sessions.

```markdown
## False Positives
1. <host/finding> -- <why it is not a real finding>

## Dead-ends
- [ ] <what was tried> -- <why it failed or is blocked>
```

Dead-ends include: timing oracles hardened, default creds rotated, endpoint 404'd, IP-blocked,
requires account we do not have. Include enough context to avoid re-testing.

---

## Wiki Integration Rule

Before attacking any service: `qmd query "<service or technique>"` and read the matching
technique page. This surfaces known bypass variants, default credentials, and CVE payloads
already documented in the wiki.
Invoke the matching hunt skill -- it handles the wiki query internally and provides FIND-schema-aware methodology.

After confirming a novel bypass or CVE chain: update the relevant `wiki/techniques/` page.
Do not create per-finding wiki pages -- findings belong in `Vulns/`, knowledge belongs in `wiki/`.

---

## Finding File Template

`setup/templates/_find.md` is the single source of truth for a finding's structure.
Scaffold every FIND from it and run the linter before /evidence:

    cp setup/templates/_find.md targets/<eng>/Vulns/FIND-NNN-SEVERITY-slug.md
    python3 scripts/find-lint.py

`_find.md` sections: `## Description`, `## Proof of Concept`, `## Impact`,
`## Remediation`, `## References` (References optional).

find-lint gates on: the `FIND-NNN-SEVERITY-` filename severity; non-empty
Description, Proof of Concept, Impact, and Remediation sections; and, for
HIGH/CRITICAL only, a real `cvss:` vector (an `AV:...` token) plus a non-empty
`affected:` target. It WARNs (does not fail) when the CVSS band disagrees with the
filename severity. Do not keep a second inline copy of the template here; edit
`_find.md` and this pointer stays correct.
