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
