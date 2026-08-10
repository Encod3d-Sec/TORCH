---
title: "katana"
type: tool
tags: [recon, crawler, web, bug-bounty, attack-surface]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: recon
---

## Purpose

**katana** (ProjectDiscovery) is a fast web crawler: it spiders a target for endpoints, forms, and JS-referenced URLs, with an optional headless mode for JS-heavy single-page apps.

## Install / setup

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Core usage

```bash
katana -u https://target.com -silent                  # standard crawl
katana -u https://target.com -jc -jsl                  # parse JS for endpoints
katana -u https://target.com -headless                 # render SPA / JS routes
echo https://target.com | katana -d 3 -kf all -o urls.txt
```

## Common use cases

```bash
katana -u https://t -jc -jsl -silent | httpx -silent   # crawl -> probe live, see [[httpx]]
gau target.com | katana -silent                         # seed with historical URLs, see [[gau]]
katana -u https://t -field url,path -silent
```

## Tips and gotchas

- `-jc`/`-jsl` extract endpoints from JS bundles; `-headless` finds client-side routes but is slower.
- `-d` (depth) and `-c` (concurrency) trade coverage against noise.
- Crawl plus [[gau]] historical URLs together for the fullest surface, then dedupe and probe.
- Respect scope and robots per RoE; headless crawling can be loud.

## Related techniques

[[gau]], [[wiki/tools/httpx]], [[web-attack-surface]]

## Sources

Vault-resident; ProjectDiscovery katana docs.
