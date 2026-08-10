---
title: "Scope - campaign-fixture"
type: engagement-scope
tags: [engagement, scope, roe]
date_created: "2026-08-07"
date_updated: "2026-08-07"
no_bruteforce: false
no_dos: false
passive_only: false
tunnel_safe: false
# --- campaign autonomy envelope (Task 6) ---
autonomy: full
enum_cap: 5
write_policy: none
oob_allowed: true
scanners: conditional
budget_requests: 5000
rate_per_host: 2
target_severity: HIGH
sources: []
---

# Scope - campaign-fixture

## In scope
- *.example.lt

## Out of scope
- billing.example.lt

## Allowed tooling
- subfinder, httpx, ffuf, nuclei, sqlmap

## Rules of engagement
- Object enumeration cap 5 identifiers.
