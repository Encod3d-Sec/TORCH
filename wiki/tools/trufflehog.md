---
title: "TruffleHog"
type: tool
tags: [secrets, credentials, source-code, git, bug-bounty]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: recon
---

## Purpose

**TruffleHog** hunts secrets across git history, filesystems, S3, CI, and more, and crucially **verifies** them (live-checks a candidate key against its provider) so you report proven-live credentials, not entropy noise.

## Install / setup

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
# or: apt install trufflehog
```

## Core usage

```bash
trufflehog git https://github.com/org/repo             # full git history
trufflehog filesystem ./checkout --only-verified       # local dir, verified only
trufflehog github --org=target --only-verified
trufflehog git file://. --since-commit HEAD~50
```

## Common use cases

```bash
# exposed .git dumped locally -> scan the whole history, see [[git-exposure]]
trufflehog git file://./dumped-git --only-verified
# secrets in historical JS bundles (pair with gau-fetched JS)
trufflehog filesystem ./js-dump --only-verified
```

## Tips and gotchas

- `--only-verified` is the killer feature: it turns "maybe a key" into "confirmed working key" and slashes false positives.
- Scans minified JS and old commits, where live keys often hide.
- For fast static regex-only sweeps `gitleaks` is quicker; TruffleHog wins on verification.
- Report only verified, in-scope keys; a live key is proof, an unverified match is a lead. See [[secret-hunting]] / [[hardcoded-secrets-enumeration]].

## Related techniques

[[secret-hunting]], [[hardcoded-secrets-enumeration]], [[git-exposure]]

## Sources

Vault-resident; TruffleHog docs.
