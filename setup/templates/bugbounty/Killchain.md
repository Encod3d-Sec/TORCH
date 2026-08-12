---
title: "Kill-Chain - {{ENGAGEMENT}}"
type: engagement-killchain
engagement_type: bugbounty
tags: [engagement, killchain, bugbounty]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
sources: []
---

# Attack Paths - {{ENGAGEMENT}}

Chain graph toward impact. Dead paths cross-ref Deadends.md.

## Confirmed chain so far

`(recon) -> ...`   <!-- the realized spine; append each confirmed hop as a finding lands -->

`path`: chain notation, e.g. `ssrf->imds->creds->ato`
`status`: open / blocked / done / dead

| path | stage | status | blocker | next-move |
|------|-------|--------|---------|-----------|
