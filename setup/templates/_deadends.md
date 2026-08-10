---
title: "Deadends - {{ENGAGEMENT}}"
type: engagement-deadends
tags: [engagement, deadends, anti-loop]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
sources: []
---

# Deadends - {{ENGAGEMENT}}

Anti-loop record. Log a dead-end immediately when a vector is exhausted or disproven, not at end of
session, so the same pair is never re-tested. **This table is machine-read: `campaign.py board`'s G4
suppresses any `asset x class` pair listed here from every future board.** The first four columns are
structured for that lookup; `reopen-if` names the condition that would justify revisiting (a new
credential, a new payload class, a version change), so a genuinely-closed vector is not permanent if
the ground shifts. Put free-text nuance in `why exhausted`.

`campaign.py done <row> --dead <reason>` appends a row here automatically.

| asset | class | what was tried | why exhausted | date | reopen-if |
|-------|-------|----------------|---------------|------|-----------|

## False positives

Disproven findings (not an asset x class exhaustion): one line each, `<host/finding> -- <why not real>`.

-
