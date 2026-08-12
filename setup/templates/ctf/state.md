---
title: "Engagement State - {{ENGAGEMENT}}"
type: engagement-state
engagement_type: ctf
tags: [engagement, state, ctf]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
# flags_expected: how many scored flags the room has (base + user + root, ...), read off the
# room's answer boxes. The close-out reflex compares captured flags vs this so a missed/decoy
# flag can't slip past a SOLVED. Leave "" until you know it; the reflex then reminds you to set it.
flags_expected: ""
sources: []
---

# State - {{ENGAGEMENT}}

Target / service inventory. Drop raw scans (nmap, gobuster) in `ingest/`, then synthesize.

`access`: none / port-open / foothold / user / root

| target | service | port | foothold | access | flag | notes |
|--------|---------|------|----------|--------|------|-------|

## Chain

Ordered attack-path hops, operator-maintained live (same discipline that keeps the table's
`notes` column current; nothing auto-writes this section). One line per hop:

`stage: what happened -> what it opens up`

-

## Status

Close-out marker and flags go HERE, below the table, so a mid-box edit can never split the host
table again.

`## STATUS: SOLVED` (also accepts OWNED/ROOTED/COMPLETE) marks the box done, the trigger the
close-out reflex, walkthrough auto-assembly, and learn harvest all watch for.

Flags captured (mirror the table's `flag` column so the count is visible without scrolling; the
close-out reflex still verifies the real count in loot.md against `flags_expected` above):
-
