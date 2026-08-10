---
title: "Source ledger - {{ENGAGEMENT}}"
type: engagement-source-ledger
tags: [engagement, source-ledger, read-discipline]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
---

# Source ledger - {{ENGAGEMENT}}

Every source artifact per asset (JS bundle, inline script, .js.map, handler endpoint, form action,
onclick/href, __NEXT_DATA__/RSC). Pass 1 cannot complete while any row for the current asset has
`read: no`. `read` flips to yes only after the app code is read whole (source-map -> drop vendor ->
beautify -> read). Grep against an artifact with no `read: yes` is grep-as-read and is withheld.

| asset | artifact | bytes | read | extraction |
|-------|----------|-------|------|------------|
