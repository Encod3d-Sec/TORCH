---
title: "Rate-Limit Bypass"
type: technique
tags: [rate-limit-bypass, brute-force, http2, graphql, waf-bypass, web]
phase: exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-web]
---

# Rate-Limit Bypass

## What it is

Techniques to defeat a request throttle so brute-force, OTP guessing, and enumeration remain viable. Beyond classic IP-header spoofing, the high-yield modern bypasses exploit where the counter lives (which endpoint, which value, which connection, which PoP). Related: [[cdn-waf-bypass]], [[account-takeover]].

## Classic IP-header spoofing
Rotate the apparent source with `X-Forwarded-For`, `X-Originating-IP`, `X-Client-IP`, or a double `X-Forwarded-For`. Automate per-request source rotation with `fireprox` (disposable AWS API Gateway) or Burp IPRotate.

## Where the counter lives

- **Endpoint/path variants** - the limiter guards `/verify` but not `/api/v2/verify`, or `/Sign-up` vs `/signup`. Add a junk param (`/resetpwd?x=1`) when the gateway keys on endpoint+params.
- **Blank-char padding on the fuzzed value** - make each attempt look unique: `code=1234%0a`, plus `%00 %09 %0d %20` variants.
- **HTTP/2 multiplexing** - limiters that count TCP connections (or HTTP/1.1 requests) miss parallel streams on one connection:

```bash
seq 1 100 | xargs -I@ -P0 curl -k --http2-prior-knowledge -X POST \
  -H 'Content-Type: application/json' -d '{"code":"@"}' https://target/api/v2/verify
```

- **GraphQL aliases** - many independent mutations in one request, the limiter counts one:

```graphql
mutation { a: verify(code:"111111"){token} b: verify(code:"222222"){token} c: verify(code:"333333"){token} }
```

- **Batch/bulk REST endpoints** (`/v2/batch`, array bodies) sidestep a limiter placed only on legacy single endpoints.
- **WebSocket/gRPC upgrade** - edge limiters often inspect only the initial HTTP request; after a `101 Upgrade`, spray inside the socket (`websocat`, `grpcurl` streaming).
- **CDN PoP-sharded counters** - Cloudflare states counters are not shared across data centers; rotate egress across regions so each PoP keeps an independent bucket.
- **Sliding-window timing** - read `X-RateLimit-Reset`, fire a full burst just before reset then another burst immediately after.
- **Keep trying past the limit** - even after 429/401 kicks in, the correct value can still return 200 (the limiter throttles before validating).

## Tools
- `fireprox` - per-request source IP rotation via disposable AWS API Gateway.
- Burp IPRotate - AWS-backed IP rotation extension.
- Turbo Intruder - tune `requestsPerConnection` (100-1000) for HTTP/2 stream collapse.

## Sources
- HackTricks (pentesting-web) (slug: hacktricks-web).

## Two-layer limiter: app counter (XFF-keyed) vs fail2ban (real-IP)

A target can run BOTH an app/WAF rate rule that keys on `X-Forwarded-For` AND a fail2ban jail that
bans the real TCP source. A **unique XFF per request** defeats the app counter (each request looks
like a new client) - but fail2ban never reads the header, so a burst still bans your real IP, and
that ban drops even GETs to a connection reset (curl `%{http_code}` = `000`), not a clean 429/403.
So the two layers need opposite tactics at once: rotate XFF to beat the app limit, AND keep
concurrency low/sequential so the real-IP jail's per-window/per-connection threshold is not tripped.
Probe both thresholds first (how many rotating-XFF requests before 403; how many concurrent before
`000`) before committing to a brute. An app "restart"/status endpoint - or fail2ban `bantime` expiry
- clears the ban; escalating `bantime` means aggressive retries get you banned LONGER, not faster.

<!-- promoted-slug: xff-vs-fail2ban-two-layer -->
