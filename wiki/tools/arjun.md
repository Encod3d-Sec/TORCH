---
title: "Arjun"
type: tool
tags: [recon, parameter-discovery, web, bug-bounty, fuzzing]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: recon
---

## Purpose

**Arjun** finds hidden HTTP parameters (GET/POST/JSON) that a target accepts but does not document, by diffing responses across a large parameter wordlist with binary-search chunking to keep request counts low.

## Install / setup

```bash
pipx install arjun        # or: pip install arjun
```

## Core usage

```bash
arjun -u https://t/api/endpoint                     # GET params
arjun -u https://t/api -m POST                       # POST body
arjun -u https://t/api -m JSON                        # JSON body
arjun -u https://t/api -w custom-params.txt -oT out.txt
```

## Common use cases

```bash
arjun -u https://t/profile -m GET --stable           # flaky target -> stable mode
arjun -i live-urls.txt -m GET -oT params.txt          # bulk from a URL list
# discovered params often unlock IDOR / SSRF / mass-assignment -> test each by hand
```

## Tips and gotchas

- Chunking cuts requests but it is still active traffic; throttle with `-T`/`--delay`.
- Hidden params are a common lead into [[idor]], SSRF, and undocumented functionality.
- Confirm a "found" param actually changes behaviour before building a finding.
- Feed the discovered params into [[wiki/tools/ffuf]] / sqlmap / manual testing. See [[api-testing]].

## Related techniques

[[api-testing]], [[wiki/tools/ffuf]], [[web-attack-surface]]

## Sources

Vault-resident; Arjun project docs.
