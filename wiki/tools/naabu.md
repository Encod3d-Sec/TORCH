---
title: "naabu"
type: tool
tags: [recon, port-scanning, network, automation, bug-bounty]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: scan
---

## Purpose

**naabu** (ProjectDiscovery) is a fast SYN/CONNECT port scanner built for pipelines: find open ports across a host list quickly, then hand off to nmap for version detection.

## Install / setup

```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest   # SYN needs libpcap
```

## Core usage

```bash
naabu -host 10.0.0.5 -silent                           # top ports
naabu -host 10.0.0.5 -p -                               # all 65535
cat hosts.txt | naabu -top-ports 1000 -o open.txt
naabu -host t -nmap-cli 'nmap -sV -sC'                  # naabu -> nmap on open ports only
```

## Common use cases

```bash
cat hosts.txt | naabu -top-ports 100 -silent | httpx -silent  # open web services
naabu -host t -p 80,443,8080,8443 -silent                      # targeted web ports
```

## Tips and gotchas

- SYN mode needs root + libpcap; otherwise it falls back to slower CONNECT scans.
- Through a tunnel/pivot a full-range fast scan can exhaust conntrack and kill the pivot; throttle `-rate` and prefer `-top-ports` (same caution as [[wiki/tools/nmap]] / [[wiki/tools/rustscan]]).
- Use `-nmap-cli` so version detection stays targeted to open ports (far faster than nmap alone).
- Feed results into [[wiki/tools/httpx]] to find and fingerprint web services.

## Related techniques

[[wiki/tools/nmap]], [[wiki/tools/httpx]], [[network-discovery]]

## Sources

Vault-resident; ProjectDiscovery naabu docs.
