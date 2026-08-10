---
title: "Write ledger - {{ENGAGEMENT}}"
type: engagement-write-ledger
tags: [engagement, write-ledger]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
---

# Write ledger - {{ENGAGEMENT}}

Every write to a live target, logged BEFORE firing (both legs of a write-verify-revert). Only under
`write_policy: own-records-only` or `full`. Never write to a pre-existing record holding another
party's data. Real sensitive data received -> stop, destroy, report.

| when | host | request (verb + path) | leg | reverted | ledgered-before-firing |
|------|------|----------------------|-----|----------|------------------------|
