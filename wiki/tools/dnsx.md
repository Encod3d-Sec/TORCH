---
title: "dnsx"
type: tool
tags: [recon, dns, subdomain-enumeration, automation, bug-bounty]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: scan
---

## Purpose

**dnsx** (ProjectDiscovery) is a fast multi-purpose DNS toolkit: bulk-resolve a host list, filter to live records, brute subdomains, and pull specific record types at scale.

## Install / setup

```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

## Core usage

```bash
cat subs.txt | dnsx -silent                           # keep only resolvable
cat subs.txt | dnsx -a -resp                           # A records with values
dnsx -d target.com -w words.txt -silent                # subdomain brute
cat subs.txt | dnsx -cname -resp                        # CNAMEs (takeover leads)
```

## Common use cases

```bash
subfinder -d t -silent | dnsx -silent | httpx -silent  # enum -> resolve -> probe
dnsx -l cidr-ptr.txt -ptr -resp -silent                 # reverse DNS on a range
cat subs.txt | dnsx -cname -resp | grep -Ei 's3|azure|github' # dangling records
```

## Tips and gotchas

- Supply a fresh, fast resolver list with `-r`; public resolvers rate-limit and can be poisoned.
- Wildcard DNS inflates results; dnsx has wildcard filtering, but verify.
- Dangling CNAMEs feed [[subdomain-takeover]]; resolve before probing with [[wiki/tools/httpx]].
- Sits between subdomain enum ([[subfinder]] / [[amass]]) and HTTP probing.

## Related techniques

[[subfinder]], [[amass]], [[wiki/tools/httpx]]

## Sources

Vault-resident; ProjectDiscovery dnsx docs.
