---
title: "subfinder"
type: tool
tags: [recon, osint, subdomain-enumeration, bug-bounty, attack-surface]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: recon
---

## Purpose

**subfinder** (ProjectDiscovery) is a fast passive subdomain enumeration tool: it pulls subdomains from dozens of public sources (cert transparency, passive DNS, search engines) without touching the target. The front of the recon pipeline -> feed into [[wiki/tools/httpx]] -> [[wiki/tools/nuclei]].

## Install / setup

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# add API keys for more sources: ~/.config/subfinder/provider-config.yaml
```

## Core usage

```bash
subfinder -d target.com -silent
subfinder -d target.com -all -silent          # use all sources (needs API keys)
subfinder -dL roots.txt -silent -o subs.txt   # many root domains
```

## Common use cases

```bash
# Full passive recon pipeline
subfinder -dL roots.txt -all -silent | httpx -silent -sc -title -td | tee live.txt
cat live.txt | nuclei -severity high,critical

# Combine sources for max coverage (subfinder misses some; union them)
subfinder -d t.com -silent > s1; amass enum -passive -d t.com -silent > s2
sort -u s1 s2 > all_subs.txt

# Recursive (enumerate subs of subs)
subfinder -d target.com -recursive -silent
```

## Tips and gotchas
- Passive only - it will not find subdomains absent from public data; add **DNS brute force** (`puredns`/`shuffledns` + a wordlist) and permutations (`alterx`) for full coverage.
- API keys (Censys, SecurityTrails, Shodan, VirusTotal, GitHub) dramatically increase results - configure them.
- Always resolve + probe results with [[wiki/tools/httpx]] before scanning; many subdomains are dead. Capture into `targets/<eng>/` for scope tracking.

## Related techniques
[[web-attack-surface]], [[secret-hunting]]. Pipeline with [[wiki/tools/httpx]], [[wiki/tools/nuclei]], [[gowitness]].

## Sources
