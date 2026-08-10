---
title: "gau"
type: tool
tags: [recon, urls, osint, bug-bounty, attack-surface]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: recon
---

## Purpose

**gau** (getallurls) pulls known URLs for a domain from the Wayback Machine, Common Crawl, OTX, and URLScan: historical endpoints, parameters, and files you would never find by crawling the live site.

## Install / setup

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

## Core usage

```bash
gau target.com                                        # all known URLs
gau --subs target.com                                 # include subdomains
echo target.com | gau --threads 5 --o urls.txt
gau target.com | grep -E '\.js(\?|$)' | sort -u        # historical JS
```

## Common use cases

```bash
gau --subs target.com | httpx -silent -mc 200          # which old URLs still live
gau target.com | grep -Ei '\?(id|url|file|redirect)='  # param-bearing leads
gau target.com | katana -silent                         # seed the crawler, see [[katana]]
```

## Tips and gotchas

- Results include dead, duplicate, and noise URLs; dedupe and [[wiki/tools/httpx]]-filter before use.
- Historical params are gold for [[idor]] / [[wiki/payloads/ssrf]] and forgotten endpoints.
- Old JS pulled from Wayback often leaks endpoints/keys (see [[javascript-source-map-exploitation]]).
- Complementary to `waybackurls`; run both for coverage.

## Related techniques

[[katana]], [[wiki/tools/httpx]], [[web-attack-surface]]

## Sources

Vault-resident; gau project docs.
