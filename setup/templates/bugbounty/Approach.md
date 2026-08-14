---
title: "Approach - {{ENGAGEMENT}}"
type: engagement-approach
engagement_type: bugbounty
tags: [engagement, approach, board]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
sources: []
# current_phase / entered_because: OPTIONAL. Set current_phase to the display label the
# board uses (e.g. "Phase 4 Exploit") and entered_because to the finding/edge that justified
# the transition. When set, status.py + SessionStart report this instead of the heuristic;
# a citation naming an out-of-scope asset is ignored. Leave unset to use the auto-heuristic.
current_phase: ""
entered_because: ""
---
# Kill-Chain Board - {{ENGAGEMENT}}

Status: `[ ]` todo | `[~]` doing | `[x]` done | `[-]` n/a | `[!]` deadend (-> Deadends.md)
GATE 1 (wiki): no hand-rolled exploit until its Weaponize wiki item is `[x]`.
GATE 2 (poc):  no exploit step goes `[~]`->`[x]` without a poc/ image.
GATE 3 (loop): a vector exhausted -> mark `[!]`, one Deadends line, move to the next open item. Never re-run `[!]`.

## 1. Recon  ([[web-attack-surface]] · [[wiki/cheatsheets/recon]])
- [ ] subfinder + amass + dnsx (subdomains) -> [[subfinder]] [[amass]] [[dnsx]]
- [ ] httpx probe + gowitness               -> [[wiki/tools/httpx]] [[gowitness]]
- [ ] dump TLS cert SANs for hidden vhosts: `echo | openssl s_client -connect <ip>:443 -servername <host> 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"`  -> [[cdn-waf-bypass]]
- [ ] gau + katana crawl (urls, .js)        -> [[gau]] [[katana]] [[javascript-source-map-exploitation]]
- [ ] arjun param mining                     -> [[arjun]]
- [ ] nuclei                                 -> [[wiki/tools/nuclei]] [[nuclei-arsenal]]
- [ ] trufflehog / .git / secrets            -> [[trufflehog]] [[git-exposure]] [[secret-hunting]]
- [ ] wiki-query EACH fingerprinted tech/version   <-- GATE 1 source

## 2. Weaponize  ([[owasp-top-10]] · [[oob-callbacks]] · [[cve-arsenal]])
- [ ] pick payload class from wiki/payloads/ -> Skill(arsenal)
- [ ] CVE lookup for named tech/version      -> [[cve-arsenal]]
- [ ] stage PoC into poc/scripts/

## 3. Deliver  ([[burp-mcp]] · [[api-security]])
- [ ] deliver via burp repeater / curl       -> [[burp-mcp]]
- [ ] token / cookie / cred reuse            -> loot.md
- [ ] fuzz params / request items            -> [[wiki/tools/ffuf]] [[arjun]]

## 4. Exploit

### 4a. Findings  (subsumes coverage.md: asset x class x status)
| id | asset | vuln class | arsenal | skill | tool | status | poc | poc_kind |
|----|-------|-----------|---------|-------|------|--------|-----|----------|

route by class: Skill(arsenal) -> Skill(`hunt-<class>`)
chains to impact: e.g. ssrf -> imds -> creds -> ato  -> [[imds-cloud-metadata]] [[account-takeover]]

### 4c. Impact
- [ ] impact demonstrated (ATO / data / RCE) + poc image
- [ ] FIND scaffolded + triaged        -> Skill(triage) then Skill(evidence)
