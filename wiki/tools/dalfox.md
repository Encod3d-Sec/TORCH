---
title: "Dalfox"
type: tool
tags: [xss, scanner, web, bug-bounty, automation]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: scan
---

## Purpose

**Dalfox** is a fast parameter-analysis and XSS scanner: it finds reflection/DOM sinks, generates context-aware payloads, optionally verifies with a headless browser, and reports the working PoC.

## Install / setup

```bash
go install github.com/hahwul/dalfox/v2@latest        # or: apt install dalfox
```

## Core usage

```bash
dalfox url https://t/search?q=1                       # single URL
dalfox url https://t/ -b your.oob.domain              # blind XSS via an OOB host
cat urls.txt | dalfox pipe                             # bulk from stdin
dalfox url https://t/ --custom-payload payloads.txt
```

## Common use cases

```bash
gau target.com | dalfox pipe --only-poc               # scan historical URLs, see [[gau]]
katana -u https://t -silent | dalfox pipe -b OOB       # crawl -> scan, see [[katana]]
dalfox url https://t/ -H "Authorization: Bearer X"     # authed context
```

## Tips and gotchas

- Verify hits by hand for the report; automated PoCs can be context-fragile.
- Use `-b`/`--blind` with an OOB collaborator for stored/blind XSS.
- `--mining-dom` and `--mining-dict` widen parameter discovery.
- Confirm findings against the [[xss]] payload/context matrix before reporting.

## Related techniques

[[xss]], [[wiki/tools/nuclei]]

## Sources

Vault-resident; Dalfox project docs.
