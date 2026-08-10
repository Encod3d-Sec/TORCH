---
title: "gowitness"
type: tool
tags: [recon, screenshots, bug-bounty, attack-surface, triage]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: recon
---

## Purpose

**gowitness** screenshots web pages at scale using a headless Chrome, so you can eyeball a large host list and quickly spot logins, admin panels, default installs, and odd apps. The visual triage step after subdomain + HTTP probing.

## Install / setup

```bash
go install github.com/sensepost/gowitness@latest
# needs Chrome/Chromium present
```

## Core usage

```bash
gowitness scan file -f live.txt --write-db          # screenshot a host list
gowitness scan single -u https://target.com
gowitness report server                              # browse results at http://localhost:7171
```

## Common use cases

```bash
# Full pipeline: enumerate -> probe -> screenshot -> review
subfinder -d t.com -silent | httpx -silent | gowitness scan file -f - --write-db
gowitness report server     # grid view -> spot admin panels, default pages, login forms

# From an nmap web-ports scan
gowitness scan nmap -f scan.xml --service-contains http
```

## Tips and gotchas
- The point is **fast human triage**: scan thousands, then scroll the grid for the 1% worth manual testing (admin/login/upload/staging/default installs).
- Sort/filter the report by title, status, or technology to cluster similar apps (one bug often repeats across a fleet).
- Feed the interesting hosts to [[wiki/tools/nuclei]] and the relevant `hunt-*` skill. Respect scope/RoE - it does load each page (active).

## Related techniques
[[web-attack-surface]], [[service-enumeration]]. Pipeline with [[subfinder]], [[wiki/tools/httpx]], [[wiki/tools/nuclei]].

## Sources
