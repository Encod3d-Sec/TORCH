---
title: "linPEAS"
type: tool
tags: [linux, privilege-escalation, enumeration, post-exploitation, ctf]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: postex
---

## Purpose

**linPEAS** (PEASS-ng) is the standard Linux privilege-escalation enumeration script: it sweeps a host for misconfigurations, credentials, writable files, SUID/capabilities, cron/timers, and known-CVE surfaces, colour-ranked by exploit likelihood.

## Install / setup

Part of [[peass]].

```bash
# run from memory, no disk write:
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## Core usage

```bash
./linpeas.sh                                          # full sweep
./linpeas.sh -a                                        # all checks (thorough, slow)
./linpeas.sh > lp.txt; less -r lp.txt                  # keep coloured output
```

## Common use cases

```bash
# first move after a Linux foothold; 95%+-likely findings are highlighted red/yellow
./linpeas.sh -o SysI,Devs,AvaSof,ProCronSrvcsTmrsSocks # scope to sections
# pair with pspy to catch cron/root processes linpeas can only hint at, see [[pspy]]
```

## Tips and gotchas

- It is loud and reads many files; EDR/monitoring will see it. On hardened engagements prefer targeted manual checks.
- Enumerate first (misconfig, sudo, SUID, caps, writable services) before reaching for kernel CVEs; most boxes fall to a misconfig.
- Grep the output for passwords, keys, and history files it surfaces.
- Full methodology in [[linux-privesc]].

## Related techniques

[[linux-privesc]], [[peass]], [[pspy]]

## Sources

Vault-resident; PEASS-ng docs.
