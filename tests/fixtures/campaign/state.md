---
title: "Engagement State - campaign-fixture"
type: engagement-state
engagement_type: bugbounty
tags: [engagement, state, bugbounty]
date_created: "2026-08-07"
date_updated: "2026-08-07"
sources: []
---

# State - campaign-fixture

Asset / endpoint inventory. Drop raw recon (subfinder/httpx/nuclei) in `ingest/`, then synthesize.

`access`: none / recon / tested / vuln

| asset | url | endpoint | param | tech | access | notes |
|-------|-----|----------|-------|------|--------|-------|
| asset-1 | https://bstorage.example.lt | /minio | | MinIO Console RELEASE.2022-10-24 | recon | edge:none |
| asset-2 | https://api.example.lt | /graphql | id | GraphQL Apollo Server; sql error observed | recon | edge:cloudflare |
| asset-3 | https://www.example.lt | /fetch | url | webhook fetcher ?url=https://internal | recon | SSRF-shaped url param |
| asset-4 | https://shop.example.lt | /coupon/redeem | code | Node Express | recon | per-account coupon limit enforced |
