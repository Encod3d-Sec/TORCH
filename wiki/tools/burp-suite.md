---
title: "Burp Suite"
type: tool
tags: [htb, proxy, scanner, thm, tool, web]
date_created: 2026-05-08
date_updated: 2026-07-04
sources: [cpts-web-proxies, thm-burpsuite, portswigger-extensions, git-portswigger-all-labs, git-portswigger-mcp-server]
phase: scan
---

## Purpose

Burp Suite is the industry-standard web proxy and penetration testing toolkit for intercepting, modifying, repeating, fuzzing, and scanning HTTP/HTTPS traffic between a browser and web applications.

## Drive Burp from an AI client (MCP)

To let Claude read proxy history and drive Repeater/Intruder/Collaborator directly,
run the "MCP Server" BApp and use the `hunt-burp` skill. Full setup, the tool
inventory, and the AI-driven workflow live on [[burp-mcp]]. This page covers the
manual GUI, Intruder, Scanner, and the BApp catalog.

## Install / Setup

Burp Suite Community is pre-installed on Kali/PwnBox. The professional version adds an unlimited-speed Intruder and the automated scanner.

### Proxy configuration

Burp listens on `127.0.0.1:8080` by default.

**Option 1 — Use Burp's built-in browser:**  
`Proxy > Intercept > Open Browser` — launches a pre-configured Chromium that automatically routes all traffic through Burp.

**Option 2 — Configure Firefox manually:**  
1. Install [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) extension.
2. Add a proxy: `127.0.0.1:8080`, name it `Burp`.
3. Click the FoxyProxy icon and select `Burp` to activate.

**CA Certificate (required for HTTPS):**  
1. With Burp proxy active in Firefox, browse to `http://burp`.
2. Download the CA Certificate.
3. In Firefox go to `about:preferences#privacy` > View Certificates > Authorities > Import.
4. Trust for websites and email.

Change Burp's listening port: `Proxy > Proxy settings > Proxy listeners`.

### Proxychains (for CLI tools)

Edit `/etc/proxychains.conf`:

```
#socks4 127.0.0.1 9050
http 127.0.0.1 8080
```

```bash
proxychains -q curl http://TARGET
proxychains -q sqlmap -u http://TARGET/?id=1
```

### Route MSF through Burp

```bash
use auxiliary/scanner/http/robots_txt
set PROXIES HTTP:127.0.0.1:8080
```

## Core Usage

### Proxy — Intercept, Forward, Drop

The Proxy tab is the central feature. Toggle interception with the `Intercept is on/off` button.

- **Forward**: send the intercepted request unmodified.
- **Drop**: discard the request.
- **Action**: context menu for sending to other tools (Repeater, Intruder, Scanner).
- `Ctrl+R`: send to Repeater.
- `Ctrl+I`: send to Intruder.

**HTTP History** (`Proxy > HTTP History`) logs all requests that have passed through, even when interception is off. Right-click any request to send it to another tool.

**Intercepting responses**: `Proxy > Options > Intercept Server Responses` to intercept and modify responses.

**Automatic modifications**: `Proxy > Options > Match and Replace` to add, remove, or replace headers/body content automatically on every request or response.

### Repeater — Modify and Resend

Repeater lets you manually replay and modify individual requests.

1. Send a request from Proxy History with `Ctrl+R` or right-click > `Send to Repeater`.
2. Switch to the Repeater tab (`Ctrl+Shift+R`).
3. Modify the request.
4. Click `Send`.
5. Inspect the response in the right pane.

Tip: Right-click inside the request > `Change Request Method` to toggle between GET and POST without rewriting the request.

### Decoder

Located at `Decoder` tab or accessible via the Inspector panel within Proxy/Repeater.

Supports: URL encode/decode, HTML, Base64, ASCII hex, Unicode, Gzip.

```
Input: eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
Decode as Base64 → {"username":"guest", "is_admin":false}
```

Shortcut in Repeater: select text, right-click > `Convert Selection > URL > URL-encode key characters` or `Ctrl+U`.

### Comparer

Highlights differences between two requests or responses. Useful for spotting what changes between a TRUE and FALSE response in blind injection testing.

### Collaborator (Pro)

Burp Collaborator provides an out-of-band (OOB) server for detecting interactions like DNS lookups and HTTP requests that cannot be observed in-band. Used to detect blind SSRF, blind XXE, blind command injection via DNS exfiltration, and similar issues.

## Intruder — Fuzzing and Brute Force

Intruder performs automated attacks by iterating payloads at marked positions in a request. Community edition is throttled to ~1 request/second; Pro has unlimited speed.

### Workflow

1. Send request to Intruder (`Ctrl+I`).
2. Go to `Intruder > Positions` tab.
3. Clear auto-markers, then select the parameter value and click `Add §` (or wrap manually with `§value§`).
4. Go to `Payloads` tab and configure the wordlist.
5. Optionally configure `Settings` (Grep - Match, threads, retries).
6. Click `Start Attack`.

### Attack types

| Type | Positions | Behaviour |
|---|---|---|
| **Sniper** | 1+ positions | Uses one wordlist; iterates through each position separately |
| **Battering Ram** | 1+ positions | Uses one wordlist; places same value in all positions simultaneously |
| **Pitchfork** | 2+ positions | Uses one wordlist per position; iterates all in lock-step |
| **Cluster Bomb** | 2+ positions | One wordlist per position; tests all combinations (Cartesian product) |

### Payload types

- **Simple List**: wordlist file or manual entries.
- **Runtime file**: loads lines on-the-fly (useful for huge wordlists to avoid memory issues).
- **Character Substitution**: define substitution rules, Burp generates permutations.
- **Numbers**: generate numeric sequences.
- **Dates**: generate date sequences.

### Payload processing

Rules applied to each payload item before sending. Examples:

- `Add prefix`: prepend `admin:` before each password (for Base64-encoded auth).
- `Encode: Base64`: encode the processed payload.
- `Skip if matches regex: ^\..*$`: skip items starting with a dot.

### Grep and filtering results

- `Settings > Grep - Match`: flag responses containing a specific string (e.g., `200 OK`, `Welcome`).
- `Settings > Grep - Extract`: extract a field from the response for display in the results table.
- Sort results by `Status`, `Length`, or your grep column to identify hits.

### Common Intruder use cases

```
# Directory fuzzing
GET /§FUZZ§/ HTTP/1.1
Wordlist: /usr/share/seclists/Discovery/Web-Content/common.txt

# Password brute force (Cluster Bomb, 2 positions)
POST /login
username=§user§&password=§pass§

# Token/OTP brute force (Sniper, 1 position)
GET /reset?token=§123§
Wordlist: generated numeric list 100-200

# Header value fuzzing (User-Agent manipulation)
User-Agent: §FUZZ§
```

## Scanner (Pro Only)

Burp Scanner performs automated vulnerability scanning.

### Passive scan

Analyses captured traffic without sending new requests. Identifies issues like missing security headers, XSS patterns in DOM, and cookie flags.

- Right-click request in Proxy History > `Do passive scan`.
- Results appear in `Dashboard > Issue activity`.

### Active scan

Sends crafted payloads to verify vulnerabilities including SQLi, XSS, Command Injection, Path Traversal, XXE, SSRF.

- Right-click request > `Do active scan`, or click `New Scan` on Dashboard.
- Select `Crawl and Audit` to also spider the site first.
- Use `Audit checks - critical issues only` preset to focus on exploitable vulnerabilities.

### Target scope

- `Target > Site map`: right-click target > `Add to scope`.
- `Target > Scope`: view/edit included and excluded paths.
- Adding first item to scope prompts Burp to restrict to in-scope items only.

### Crawler

Crawls links within the target to build a full site map.

- `New Scan > Crawl` (or `Crawl and Audit`).
- Preset configurations: `Crawl strategy - fastest`, `Crawl limit - 10 minutes`.
- Add login credentials under `Application login` for authenticated crawling.

### Reporting

`Target > Site map` > right-click target > `Issues > Report issues for this host`. Export as HTML for appendix documentation.

## Extensions

### BApp Store

`Extensions > BApp Store`. Sort by popularity.

Notable extensions:

| Extension | Source | Use |
|---|---|---|
| **Active Scan++** | BApp Store | Additional active scan checks; Host header attacks, XXE edge cases |
| **Logger++** | BApp Store | Advanced request/response logging with filtering and grep |
| **Turbo Intruder** | BApp Store | High-speed Intruder replacement using a Python script engine; handles race conditions |
| **Autorize** | BApp Store | Tests for IDOR/authorisation bypass by replaying requests as lower-privilege user |
| **JWT Editor** | BApp Store | Decode, modify, re-sign, and attack JSON Web Tokens; algorithm confusion and key injection |
| **Param Miner** | BApp Store | Discover hidden/unlinked parameters by mining JS, page source, and wordlists |
| **InQL** | BApp Store | GraphQL schema introspection, query generation, and attack automation |
| **Hackvertor** | BApp Store | Tag-based encoding transformations applied automatically on send; WAF bypass |
| **CSRF Scanner** | BApp Store | Automated CSRF detection |
| **Decoder Improved** | BApp Store | Extended encoding/hashing tab |
| **Backslash Powered Scanner** | BApp Store | Detects server-side template injection and related issues |
| **JS Link Finder** | BApp Store | Extracts endpoints from JavaScript files |
| **Retire.JS** | BApp Store | Flags vulnerable JavaScript libraries |
| **Headers Analyzer** | BApp Store | Analyses security-related response headers |
| **DOM Invader** | Built-in (browser) | DOM XSS sink tracking and prototype pollution detection via Burp's Chromium browser |
| **Clickbandit** | Built-in (`Burp` menu) | Interactive clickjacking PoC generator |

### Turbo Intruder

Turbo Intruder is a Burp extension that bypasses the Community edition rate limit by implementing its own HTTP engine. Particularly useful for:

- Race condition attacks (send many requests within the same server processing window).
- High-speed brute forcing.
- Custom attack scripting with Python.

Install from BApp Store. After sending a request to Turbo Intruder (right-click > Extensions > Turbo Intruder > Send to Turbo Intruder), configure the Python script template.

→ Full usage with scripts: [[race-conditions]]

### JWT Editor

Install from BApp Store. Adds a **JWT** tab to Repeater for decoding, modifying, and re-signing tokens without leaving Burp.

- **Keys tab**: generate RSA, ECDSA, and symmetric keys for algorithm confusion attacks.
- **JWT tab in Repeater**: edit header/payload fields directly; sign with a stored key or strip signature (`alg: none`).
- `portswigger/sig2n` Docker tool works alongside JWT Editor for RSA n/e confusion attacks.

→ Full usage: [[jwt-attacks]]

### Param Miner

Install from BApp Store. Discovers unlinked parameters by brute-forcing parameter names against the target using JS mining, page source scraping, and a built-in wordlist.

1. Right-click any request in Proxy History > Extensions > Param Miner > **Guess params**.
2. Results appear in `Extensions > Param Miner > Output` tab.
3. Newly discovered parameters often trigger cache poisoning gadgets.

→ Full usage: [[web-cache-poisoning]], [[web-cache-deception]]

### DOM Invader

Built into Burp's Chromium browser (no install needed). Enable via the browser DevTools panel > **DOM Invader** tab.

- Automatically injects canary strings and tracks them through DOM sources and sinks.
- Reports when a canary reaches a dangerous sink (`innerHTML`, `eval`, `document.write`, etc.).
- **Prototype pollution mode**: enable to detect gadgets and auto-generate PoC exploits.
- **postMessage mode**: logs all `postMessage` events with origin and data for analysis.

→ Full usage: [[dom-attacks]], [[prototype-pollution]]

### InQL

Install from BApp Store. Provides a dedicated **GraphQL** tab in Repeater for introspection and query building.

1. Send a GraphQL endpoint to the InQL tab.
2. Click **Analyse** to auto-enumerate the schema (types, queries, mutations).
3. Use the built-in query editor to craft and send queries directly.
4. Bypass introspection blocks by injecting newlines: `\n__schema` in the query.

→ Full usage: [[graphql-attacks]]

### Hackvertor

Install from BApp Store. Wrap any request value in Hackvertor tags to apply encoding transformations automatically on every send.

```
<@base64_2>payload<@/base64_2>
<@urlencode_2>payload<@/urlencode_2>
<@hex_entities>payload<@/hex_entities>
```

Useful for WAF bypass when the application decodes values server-side before processing. Nest tags for multi-stage encoding.

→ Full usage: [[xxe]], [[xss]]

### Clickbandit

Built into Burp — no install needed. Access via `Burp > Clickbandit` in the menu bar.

1. Click **Copy Clickbandit to clipboard**.
2. Open target site in browser, open DevTools console.
3. Paste the Clickbandit script and press Enter.
4. Click **Start** and interact with the page to record clicks.
5. Click **Finish**, then **Save** to download the PoC HTML file.

→ Full usage: [[clickjacking]]

## Common Use Cases

### Intercept and manipulate a request

```
1. Turn interception ON (Proxy > Intercept).
2. Submit form in browser.
3. In intercept pane, modify parameter (e.g., ip=1 → ip=;ls;).
4. Click Forward.
```

### Brute force login with Intruder

```
1. Intercept POST /login with username=admin&password=test.
2. Send to Intruder (Ctrl+I).
3. Set attack type: Sniper.
4. Mark §password§ as payload position.
5. Load rockyou.txt as Simple List.
6. Settings > Grep Match: add "Welcome" or "dashboard".
7. Start Attack. Sort by grep column.
```

### Decode a session cookie

```
1. Find Set-Cookie in Proxy History response.
2. Copy value (e.g., Base64-encoded JSON).
3. Decoder tab > Paste > Decode as Base64.
4. Modify value (e.g., "is_admin":false → "is_admin":true).
5. Encode as Base64.
6. Paste modified cookie back into a repeated request.
```

### Enumerate with Cluster Bomb (username + password)

```
Attack type: Cluster Bomb
Position 1: username=§user§
Position 2: password=§pass§
Payload set 1: usernames.txt
Payload set 2: passwords.txt
```

## Tips and Gotchas

- Community edition Intruder is throttled to ~1 request/second. Use Turbo Intruder extension or CLI tools (`ffuf`, `hydra`) for speed-sensitive attacks.
- When Base64 credentials are required (HTTP Basic Auth), use Intruder payload processing: add prefix `admin:`, then add encoding rule `Base64`.
- Burp Inspector (visible in Proxy and Repeater) provides quick inline decoding; useful for rapidly understanding encoded values.
- Disable proxy interception (`Intercept is off`) when you just want to browse and log traffic to HTTP History.
- Scope control prevents Burp from scanning or sending requests to unintended hosts.
- Match and Replace rules (Proxy settings) can automatically add headers (e.g., `X-Forwarded-For: 127.0.0.1`) to every request.
- For HTTPS on non-standard ports, Burp's CA certificate installation is mandatory; otherwise the browser will reject intercepted connections.
- `Ctrl+Z` inside any editor pane in Burp undoes changes; very useful when editing requests.

## Related Techniques

- [[sql-injection]]
- [[xss]]
- [[authentication-attacks]]
- [[access-control]]
- [[file-upload]]
- [[os-command-injection]]
- [[race-conditions]]
- [[jwt-attacks]]
- [[web-cache-poisoning]]
- [[web-cache-deception]]
- [[dom-attacks]]
- [[prototype-pollution]]
- [[graphql-attacks]]
- [[clickjacking]]
- [[xxe]]

## Sources

- CPTS Web Proxies module (HTB Academy)
- TryHackMe: Burpsuite CTFs (AgentSudo, Enum & Brute force)
- PortSwigger Academy: Extensions / Turbo Intruder
- Source files: `/raw/assets/courses/CPTS/13. WEB Proxies/`, `/raw/assets/courses/TryHackMe/13. THM WEB/Burpsuite/`
