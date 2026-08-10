---
title: "WhatWeb"
type: tool
tags: [recon, fingerprinting, web, enumeration, bug-bounty]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: recon
---

## Purpose

**WhatWeb** fingerprints web technologies from HTTP responses: CMS, frameworks, servers, JS libraries, analytics, and versions, with tunable aggression.

## Install / setup

```bash
apt install whatweb        # ships on Kali
```

## Core usage

```bash
whatweb https://target.com                             # single, passive (one request)
whatweb -a 3 https://target.com                         # aggressive (more requests)
whatweb -i live.txt --log-brief=fp.txt                  # bulk from a host list
whatweb --colour=never https://t | tee wf.txt
```

## Common use cases

```bash
httpx -l subs.txt -silent | whatweb -i - --log-brief=fp.txt   # fingerprint live hosts
whatweb -a 3 https://t | grep -Eo '[A-Za-z]+\[[0-9.]+\]'      # tech + version -> CVE lookup
```

## Tips and gotchas

- `-a 1` is passive (one request); `-a 3`/`-a 4` are louder and poke plugins/paths.
- Version strings drive n-day lookups; confirm the exact version before searchsploit.
- At scale, `httpx -td` is faster; WhatWeb is richer per target. The detected tech feeds the playbook fingerprint router.
- Leads into [[cms-exploitation]] once a CMS/version is identified.

## Related techniques

[[wiki/tools/nuclei]], [[cms-exploitation]], [[web-attack-surface]]

## Sources

Vault-resident; WhatWeb docs.
