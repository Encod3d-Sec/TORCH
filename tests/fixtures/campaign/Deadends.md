---
title: "Deadends - campaign-fixture"
type: engagement-deadends
tags: [engagement, deadends]
date_created: "2026-08-07"
date_updated: "2026-08-07"
---

# Deadends - campaign-fixture

Anti-loop record. G4 reads this to suppress an already-exhausted asset x class pair.

| asset | class | what was tried | why exhausted | date | reopen-if |
|-------|-------|----------------|---------------|------|-----------|
| asset-2 | sqli | sqlmap -r req.txt --batch, error + boolean + time | WAF 403 on every payload, no oracle after 40 reqs | 2026-08-06 | new WAF bypass or origin IP |
