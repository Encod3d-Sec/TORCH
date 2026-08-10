---
title: "Nuclei"
type: tool
tags: [recon, scanning, bug-bounty, web, automation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: scan
---

## Purpose

**Nuclei** is a fast, template-driven vulnerability scanner: it sends community + custom YAML templates against targets to detect CVEs, misconfigurations, exposures, and default creds at scale. The backbone of automated bug-bounty recon.

## Install / setup

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates        # pull the community template set (~/.local/nuclei-templates)
```

## Core usage

```bash
nuclei -u https://target.com
nuclei -l hosts.txt                       # list of URLs (feed from httpx)
cat subs.txt | httpx -silent | nuclei     # pipeline: resolve -> probe -> scan
```

## Common use cases

```bash
# Severity-scoped (cut noise on large scopes)
nuclei -l live.txt -severity critical,high -o hits.txt

# By tag / template type
nuclei -l live.txt -tags cve,exposure,takeover
nuclei -l live.txt -t http/cves/2024/ -t http/misconfiguration/

# Single CVE check across scope
nuclei -l live.txt -id CVE-2024-XXXX

# Custom template
nuclei -u https://t -t my-templates/custom-check.yaml

# Rate-limited + resumable for big/owned scopes
nuclei -l live.txt -rl 50 -c 25 -resume
```

## Tips and gotchas
- Run behind [[wiki/tools/httpx]] (only scan live hosts) - scanning dead hosts wastes time and rate budget.
- `-severity` and `-tags` are essential on real scopes; the default full set is noisy and slow.
- Respect RoE: nuclei is active/loud. On `no_dos`/rate-limited engagements set `-rl`/`-c` low; some templates are intrusive (default-login, fuzzing) - scope with `-tags` or `-exclude-tags intrusive`.
- Write custom templates for program-specific patterns; keep them in `targets/<eng>/` not the shared wiki. Custom-template syntax, fuzzing/DAST, and anti-block evasion (rate/proxy/IP-rotation/self-hosted OOB): [[nuclei-arsenal]].

## Related techniques
Recon pipeline with [[wiki/tools/httpx]]; findings feed the hunt skills. See [[nuclei-arsenal]] (custom + evasion), [[wordlists]], [[cve-arsenal]], [[recon-dorks]], [[web-attack-surface]].

## Sources
