---
title: "Kill-Chain - {{ENGAGEMENT}}"
type: engagement-killchain
engagement_type: ctf
tags: [engagement, killchain, ctf]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
sources: []
---

# Attack Paths - {{ENGAGEMENT}}

Chain toward user/root. Dead paths cross-ref Deadends.md.

## Confirmed chain so far

`(recon) -> ...`   <!-- the realized spine; append each confirmed hop as a finding lands -->

`path`: chain notation, e.g. `lfi->log-poison->rce->suid-root`
`status`: open / blocked / done / dead

| path | stage | status | blocker | next-move |
|------|-------|--------|---------|-----------|
