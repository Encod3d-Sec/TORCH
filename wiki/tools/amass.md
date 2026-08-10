---
title: "amass"
type: tool
tags: [recon, subdomain-enumeration, osint, attack-surface, bug-bounty]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: recon
---

## Purpose

**amass** (OWASP) maps an organization's external attack surface: deep subdomain enumeration from passive OSINT sources plus active DNS resolution/brute, and ASN/CIDR/organization relationships as a graph.

## Install / setup

```bash
go install -v github.com/owasp-amass/amass/v4/...@master   # or: apt install amass
# add API keys in ~/.config/amass/config.yaml for many more passive sources
```

## Core usage

```bash
amass enum -passive -d target.com -o subs.txt      # passive only, quiet, fast
amass enum -active -brute -d target.com -o subs.txt # active resolution + brute
amass intel -org "Target Inc"                       # discover ASNs/orgs
amass intel -asn 13335 -whois -d target.com
```

## Common use cases

```bash
amass enum -passive -d target.com | httpx -silent   # -> live hosts, see [[httpx]]
amass enum -df domains.txt -o subs.txt              # multiple root domains
amass db -names -d target.com                        # query the local graph db
```

## Tips and gotchas

- Passive is quiet but incomplete; active brute is loud and slow. Match to RoE.
- v4 changed subcommand syntax from v3 (`enum`/`intel`/`db`); old guides drift.
- For raw subdomain speed [[subfinder]] wins; amass is for depth + ASN/graph mapping.
- Do not enumerate out-of-scope org assets just because `intel` surfaces them.

## Related techniques

[[subfinder]], [[wiki/tools/httpx]], [[network-discovery]], [[web-attack-surface]]

## Sources

Vault-resident; OWASP Amass docs.
