---
title: "httpx"
type: tool
tags: [recon, bug-bounty, http, enumeration, automation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: scan
---

## Purpose

**httpx** (ProjectDiscovery) is a fast multi-purpose HTTP probe: it takes a list of hosts/subdomains and reports which are live, with status, title, tech, and more. The "which of these resolve and serve HTTP" step of recon.

## Install / setup

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# note: not the python 'httpx' lib - this is the recon binary
```

## Core usage

```bash
cat subs.txt | httpx -silent                       # live URLs only
httpx -l subs.txt -sc -title -td -ip               # status, title, tech, IP
```

## Common use cases

```bash
# Full recon pipeline
subfinder -d target.com -silent | httpx -silent -sc -title -td -o live.txt
cat live.txt | nuclei -severity high,critical      # -> [[nuclei]]

# Enrich + filter
httpx -l hosts.txt -status-code -content-length -web-server -tech-detect
httpx -l hosts.txt -mc 200,302 -o reachable.txt    # match status codes
httpx -l hosts.txt -fc 404 -path /admin,/.git/config   # probe paths, filter 404
httpx -l hosts.txt -screenshot                     # headless screenshots
httpx -l hosts.txt -favicon                        # favicon hash -> fingerprint origin
```

## Tips and gotchas
- `-silent` for clean pipe output; without it you get the banner.
- `-favicon` hash pivots to other hosts running the same app (Shodan `http.favicon.hash:`); useful for [[wiki/payloads/ssrf]]/origin-IP discovery.
- Default probes both http/https and common ports; widen with `-ports`. Tune `-rate-limit`/`-threads` to respect RoE.
- Chain order: `subfinder/amass -> httpx -> nuclei/gowitness`. Capture output into `targets/<eng>/` for the engagement state.

## Related techniques
[[web-attack-surface]], [[service-enumeration]]; pairs with [[wiki/tools/nuclei]], [[wiki/tools/ffuf]].

## Sources
