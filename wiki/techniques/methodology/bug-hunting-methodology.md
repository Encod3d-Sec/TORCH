---
title: Bug Hunting Methodology
type: technique
tags: [cloud, linux, methodology, network, recon, reference-import, web, windows]
phase: recon
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Bug Hunting Methodology

## What it is

Technical reference for **Bug Hunting Methodology** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Bug hunting follows a structured recon-then-exploit cycle: passive recon maps the attack surface using search engines, Shodan, favicon hashing, and DNS enumeration before any direct interaction with the target. Active recon then probes discovered endpoints for common web vulnerabilities (IDOR, SSRF, XSS, SQLi, authentication bypasses) using manual testing and automated scanners, prioritizing endpoints that handle user-controlled input or internal service calls. Tracking all discovered assets, tested endpoints, and potential findings in a structured format prevents duplicate work and ensures complete coverage of the defined scope.

This page covers hunting a single target. When the same cycle runs across many hosts, sessions, or
agents at once, the coordination layer has its own failure modes (unverified claims, uncounted
requests, duplicate filings, severity drift): see [[multi-agent-campaign-orchestration]]. For keeping
an individual probe safe by construction, see [[safe-probing-and-controls]].

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Passive Recon

* Using [shodan.io](https://www.shodan.io/), [fofa.info](https://en.fofa.info/), [zoomeye.ai](https://www.zoomeye.ai/) or [odin.io](https://search.odin.io/hosts) to detect similar app

```ps1
# https://github.com/glennzw/shodan-hq-nse
nmap --script shodan-hq.nse --script-args 'apikey=<yourShodanAPIKey>,target=<hackme>'
```

* Search for similar websites using the same favicon: [pielco11/fav-up](https://github.com/pielco11/fav-up) or slightly different icon: [profundis.io/favicon-matcher](https://profundis.io/tools/favicon-matcher)

```ps1
python3 favUp.py --favicon-file favicon.ico -sc
python3 favUp.py --favicon-url https://domain.behind.cloudflare/assets/favicon.ico -sc
python3 favUp.py --web domain.behind.cloudflare -s
```

* Search inside Shortener URLs: [shorteners.grayhatwarfare.com](https://shorteners.grayhatwarfare.com/), [utkusen/urlhunter](https://github.com/utkusen/urlhunter)

```ps1
urlhunter --keywords keywords.txt --date 2020-11-20
```

* Search inside Buckets: [buckets.grayhatwarfare.com](https://buckets.grayhatwarfare.com/)

* Using [The Wayback Machine](https://archive.org/web/) to detect forgotten endpoints

```powershell
# Look for JS files, old links
curl -sX GET "http://web.archive.org/cdx/search/cdx?url=<targetDomain.com>&output=text&fl=original&collapse=urlkey&matchType=prefix"
```

* Using [laramies/theHarvester](https://github.com/laramies/theHarvester)

```python
python theHarvester.py -b all -d domain.com
```

* Look for private information in [GitHub](https://github.com) repositories with [michenriksen/GitRob](https://github.com/michenriksen/gitrob.git)

```bash
gitrob analyze johndoe --site=https://github.acme.com --endpoint=https://github.acme.com/api/v3 --access-tokens=token1,token2
```

* Perform Google Dorks search: [ikuamike/GoogleDorking.md](https://gist.github.com/ikuamike/c2611b171d64b823c1c1956129cbc055)

```ps1
site: *.example.com -www
intext:"dhcpd.conf" "index of"
intitle:"SSL Network Extender Login" -checkpoint.com
```

* Enumerate subdomains using HackerTarget

```ps1
curl --silent 'https://api.hackertarget.com/hostsearch/?q=targetdomain.com' | grep -o '\w.*targetdomain.com'
```

* Enumerate endpoints using CommonCrawl
```powershell
echo "targetdomain.com" | xargs -I domain curl -s "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.targetdomain.com&output=json" | jq -r .url | sort -u
```

## Active Recon

### Network Discovery

* Subdomains enumeration
    * Enumerate already found subdomains: [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder), [OWASP/Amass](https://github.com/OWASP/Amass)

```ps1
subfinder -d hackerone.com
amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com
```

    * Permutate subdomains: [infosec-au/altdns](https://github.com/infosec-au/altdns)
    * Bruteforce subdomains: [Josue87/gotator](https://github.com/Josue87/gotator)
    * Resolve subdomains to IP with [blechschmidt/massdns](https://github.com/blechschmidt/massdns), remember to use a good list of resolvers like [trickest/resolvers](https://github.com/trickest/resolvers)

```ps1
massdns -r resolvers.txt -o S -w massdns.out subdomains.txt
```

    * Subdomain takeovers: [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

* Network discovery
    * Scan IP ranges with `nmap`, [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) and [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)
    * Discover services, version and banners

* Review latest acquisitions

* ASN enumeration
    * [projectdiscovery/asnmap](https://github.com/projectdiscovery/asnmap): `asnmap -a AS45596 -silent`
    * [asnlookup.com](http://www.asnlookup.com)

* DNS Zone Transfer

```ps1
host -t ns domain.local
domain.local name server master.domain.local.

host master.domain.local        
master.domain.local has address 192.168.1.1

dig axfr domain.local @192.168.1.1
```

### Web Discovery

#### Common Files

* `security.txt`: A file that provides contact info for reporting security issues with your site (like an email or PGP key).

```ps1
Contact: mailto:security@example.com
```

* `sitemap.xml`: Lists all the important URLs of your site so search engines can index them efficiently.

```ps1
<urlset>
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
</urlset>
```

* `robots.txt`: Tells search engine crawlers which pages or files they can or cannot access on your site.

```ps1
User-agent: *
Disallow: /admin/
```

#### Enumerate Files and Folders

Enumerate all accessible files and subdirectories. Once the underlying technology has been identified, prioritize the use of targeted wordlists rather than generic ones. Technology specific wordlists such as those provided by Assetnote ([https://wordlists.assetnote.io](https://wordlists.assetnote.io)), significantly improve coverage and efficiency. Examples include `httparchive_parameters_top_1m_2026_01_27.txt`, `httparchive_directories_1m_2026_01_27.txt`, and `httparchive_php_2026_01_27.txt`.

* [OJ/gobuster](https://github.com/OJ/gobuster)
* [ffuf/ffuf](https://github.com/ffuf/ffuf)
* [bitquark/shortscan](https://github.com/bitquark/shortscan)

```ps1
ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'
gobuster dir -a 'Mozilla' -e -k -l -t 30 -w mydirfilelist.txt -c 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/'
```

Identify and enumerate backup and temporary files that may have been unintentionally exposed. These files often contain source code, credentials, or sensitive configuration data and are commonly created by editors, deployment processes, or manual backups.

* [mazen160/bfac](https://github.com/mazen160/bfac)

```bash
bfac --url http://example.com/test.php --level 4
bfac --list testing_list.txt
```

Crawl the website's pages and resources to identify additional attack surface and expand the assessment perimeter.

* [hakluke/hakrawler](https://github.com/hakluke/hakrawler)
* [projectdiscovery/katana](https://github.com/projectdiscovery/katana)

```powershell
katana -u https://tesla.com
echo https://google.com | hakrawler
```

#### Next.js Endpoints

In Next.js, `window.__BUILD_MANIFEST` is a runtime global variable that the framework automatically injects into the client-side JavaScript bundle.

Go to `DevTools->Console` and execute this JavaScript code:

```js
console.log(window.__BUILD_MANIFEST)
console.log(__BUILD_MANIFEST.sortedPages)
```

If you inspect your app in the browser console (for a production build), you might see something like this:

```js
{__rewrites: {…}, /: Array(10), /404: Array(8), /500: Array(4), /_error: Array(1), …}
/: (10) ['static/chunks/2852872c-b605aca0298c2109.js', 'static/chunks/3748-2a8cf394c7270ee0.js']
/404: (8) ['static/chunks/2852872c-b605aca0298c2109.js', 'static/chunks/3748-2a8cf394c7270ee0.js']
/500: (4) ['static/chunks/3748-2a8cf394c7270ee0.js', 'static/chunks/1221-b44c330d41258365.js']
/[slug]: (30) ['static/chunks/2852872c-b605aca0298c2109.js', 'static/chunks/29107295-4cc022cea922dbb4.js']
/_error: ['static/chunks/pages/_error-6ddff449d199572c.js']
/about/[slug]: (31) ['static/chunks/2852872c-b605aca0298c2109.js']
```

#### JS and HTML Comments

Retrieve comments in source code.

```html
<!-- HTML Comment -->
// JS Comment
```

#### Internet Archive

Identify historical URLs and endpoints by reviewing archived content from sources such as the Wayback Machine and the Internet Archive.

* [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls)
* [lc/gau](https://github.com/lc/gau)

```ps1
gau --o example-urls.txt example.com
gau --blacklist png,jpg,gif example.com
```

#### Hidden Parameters

Search for `hidden` parameters:

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner)
* [s0md3v/Arjun](https://github.com/s0md3v/Arjun)
* [Sh1Yo/x8](https://github.com/Sh1Yo/x8)

```ps1
x8 -u "https://example.com/?something=1" -w <wordlist>
```

#### Map Technologies

* Web service enumeration using [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) or [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)
    * Favicon hash
    * JARM fingerprint
    * ASN
    * Status code
    * Services
    * Technologies (Github Pages, Cloudflare, Ruby, Nginx,...)

```ps1
httpx -title -tech-detect -status-code -follow-redirects -jarm -asn -json -silent -ports 80,443 -l urls.txt
```

* Look for WAF with [projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck) and identify the real IP with [christophetd/CloudFlair](https://github.com/christophetd/CloudFlair)

```ps1
echo www.hackerone.com | cdncheck -resp
www.hackerone.com [waf] [cloudflare]
```

* Take screenshots for every websites using [sensepost/gowitness](https://github.com/sensepost/gowitness)

#### Manual Testing

Explore the website with a proxy:

* [Caido - A lightweight web security auditing toolkit](https://caido.io/)
* [ZAP - OWASP Zed Attack Proxy](https://www.zaproxy.org/)
* [Burp Suite - Community Edition](https://portswigger.net/burp/communitydownload)

#### Automated vulnerability scanners

* [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei):

```ps1
nuclei -u https://example.com
```

* [Burp Suite's web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
* [sullo/nikto](https://github.com/sullo/nikto)

```ps1
./nikto.pl -h http://www.example.com
```

## Looking for Web Vulnerabilities

* Explore the website and look for vulnerabilities listed in this repository: SQL injection, XSS, CRLF, Cookies, ....
* Test for Business Logic weaknesses
    * High or negative numerical values
    * Try all the features and click all the buttons
* [The Web Application Hacker's Handbook Checklist](https://web.archive.org/web/20210126221152/https://gist.github.com/gbedoya/10935137)

* Subscribe to the site and pay for the additional functionality to test

* Inspect Payment functionality - [@gwendallecoguic](https://twitter.com/gwendallecoguic/status/988138794686779392)
  > If the webapp you're testing uses an external payment gateway, check the doc to find the test credit numbers, purchase something and if the webapp didn't disable the test mode, it will be free

  From [https://stripe.com/docs/testing](https://stripe.com/docs/testing#cards) : "Use any of the following test card numbers, a valid expiration date in the future, and any random CVC number, to create a successful payment. Each test card's billing country is set to U.S."

  Test card numbers and tokens  

  | NUMBER           | BRAND          | TOKEN          |
  | :-------------   | :------------- | :------------- |
  | 4242424242424242 | Visa           | tok_visa       |
  | 4000056655665556 | Visa (debit)   | tok_visa_debit |
  | 5555555555554444 | Mastercard     | tok_mastercard |

  International test card numbers and tokens

  | NUMBER           | TOKEN          | COUNTRY        | BRAND          |
  | :-------------   | :------------- | :------------- | :------------- |
  | 4000000400000008 | tok_at         | Austria (AT)   | Visa           |
  | 4000000560000004 | tok_be         | Belgium (BE)   | Visa           |
  | 4000002080000001 | tok_dk         | Denmark (DK)   | Visa           |
  | 4000002460000001 | tok_fi         | Finland (FI)   | Visa           |
  | 4000002500000003 | tok_fr         | France (FR)    | Visa           |

## References

* [Nmap CheatSheet - HackerTarget](https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/)
* [Yahoo phpinfo.php disclosure - Patrik Fehrenbach - January 20, 2013](https://blog.wss.sh/bugbounty-yahoo-phpinfo-php-disclosure/)
* [Bug Bounty Masterclass - Wiz, Gal Nagli](https://www.wiz.io/bug-bounty-masterclass)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[burp-suite]]
- [[wiki/tools/ffuf]]
- [[gobuster]]
- [[gowitness]]
- [[wiki/tools/httpx]]
- [[nikto]]
- [[wiki/tools/nmap]]
- [[wiki/tools/nuclei]]
- [[subfinder]]

## A completed handshake is not a live service

Recurred independently at least twice in the same estate, on both a bare in-scope IP and a
discovered non-CDN-fronted subdomain: a raw TCP-connect probe reports 443/8080 as open, but `curl`
and `openssl s_client` each get zero bytes back on either port. A filtering device (or a
non-terminating load balancer) can complete the three-way handshake and then drop everything that
follows.

Generic rule: never record a port as a live service from a connect-scan result alone. Confirm with
a protocol-speaking client (curl for HTTP/S, openssl s_client for raw TLS, or the specific
protocol's own handshake) before spending further effort on it.

## A recovering connection drop is a throttle, not a ban

A host began refusing connections outright after roughly 40 requests sent at about one per second,
then answered normally again about a minute later with no change in source IP or credentials.
Misreading this burst-then-recover shape risks two wrong conclusions: that the host is down, or
that the source has been banned - both would send testing down the wrong path (origin-bypass
hunting, or IP/persona rotation) for a problem that is neither.

Generic rule: on any unexplained connection refusal, wait roughly a minute and retry unchanged
before concluding a ban or an outage. A rate-limit throttle that self-clears is the far more common
explanation on a shared or CDN-fronted host.

## DNS-check scope hostnames before chasing their CVEs

On one estate, a large fraction of the "juicy" scope hostnames (named after internal tools with
known CVE histories) had no public A/AAAA record at all - internal-only, unreachable from outside.
A `000`/connection-refused from curl on such a host means "no DNS record", not "host is down" and
not "WAF blocked"; re-probing it over HTTP repeatedly wastes a whole sweep.

The same pattern killed several source-derived vulnerability candidates in one pass purely on DNS:
a hostname with genuinely vulnerable-looking code in its public repo, and no live public host
serving it in this program's scope, is not testable and should be recorded as such immediately
rather than revisited.

Generic rule: resolve every scope hostname with a direct DNS query FIRST, before any HTTP probing,
and keep the resolved/NXDOMAIN split visible so nobody re-chases an internal-only name.

## Fast tell for a redirect-only host with no origin

Two separate hosts in one estate turned out to be nothing but a CDN-level redirect rule pointing at
a third-party SaaS product, with no origin application of their own. The tell was fast and cheap: a
handful of redirect-manipulation probes (varying the path, query string, and common override
headers) all produced the exact same `Location` value, byte for byte.

Generic rule: when a host's every response is a redirect, run a small batch of redirect-
manipulation probes before investing in content discovery or scanners. If the `Location` never
varies, there is no origin behind the redirect to find, and further enumeration on that host is
provably wasted effort - stop and move to the next asset.

## Use a fresh scratch file per target

A fingerprinting pass wrote each host's fetched page to the same shared temp file. When a fetch
failed for the current host, the file still held the PREVIOUS host's content, and the script
reported that stale `<title>` (or other extracted field) as belonging to the new host - a
plausible-looking but entirely invented result. This recurred independently in a second, unrelated
probe against a different host later in the same engagement.

Generic rule for any scripted per-host loop that shells out to a file-based tool: write to a
fresh/unique file per target (a temp file keyed by hostname, or `mktemp` per iteration), or at
minimum check the fetch's own exit code/freshness before trusting anything read back from disk.

## Read the vendor's source before more probing

An endpoint returned 200 with an empty result set unauthenticated, while sibling endpoints on the
same API returned 401 - ambiguous from outside (a missing authorization check that happens to leak
nothing today, or correct scoping producing an empty set for an anonymous caller). The product was
a known open-source platform, so the question was settled definitively by reading the public
policy/controller source for that one action, with zero further requests sent to the target: the
200-vs-401 split turned out to be a framework artifact (an empty authorized scope resolves 200,
an explicit authorization failure raises and becomes 401), not a missing check.

Generic rule: before spending further probes on an ambiguous external observation, check whether
the product is open source. If it is, reading the one relevant file is usually cheaper, more
definitive, and touches the target zero further times.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).

BUDGET SERVER ERRORS, NOT JUST REQUESTS. On products whose error handler files a ticket and pages an on-call engineer, the binding constraint is the number of 500s you cause, not your request count. Track them in a separate ledger with a hard cap.

THE TRAP: route-existence probing is itself a 500-generating technique. A GET against an unknown path feels free because you expect a 404, but a routed-but-erroring path throws. 'GET is read-only' does not mean 'GET is safe'.

MITIGATIONS THAT WORK:
- Recover the client's real call contract from the JS bundle FIRST, then send well-formed requests. A well-formed call to a live endpoint returns data or a clean 4xx; a guessed one throws.
- Prefer endpoints already observed returning structured 4xx JSON; they are safe to iterate against.
- When a probe class produces two errors, stop the class rather than varying the payload.

Real numbers from one engagement: 98 requests against a 1000 budget, but 6 server errors against a self-imposed cap of 4. Requests were never the limit.

<!-- promoted-slug: budget-500s-not-just-requests -->

A CONTROL THAT VARIES THE WRONG VARIABLE PRODUCES FALSE CONFIDENCE, NOT SAFETY. Control-first testing is necessary but not sufficient: if the control changes a different variable than the one actually gating the endpoint, it manufactures a boundary that does not exist.

CANONICAL CASE - the 403 that is not an auth boundary. You test an endpoint authenticated (200) and anonymous (403), and conclude authentication is required. But if the endpoint enforces an anti-CSRF header, your anonymous request omitted BOTH the session cookie and the token, so you measured 'no token', not 'no session'. Many apps hand a fresh session cookie AND a fresh CSRF token to any caller on one GET of the home page - so an unauthenticated attacker mints both and gets the full response. The boundary you reported does not exist.

THE CORRECT CONTROL MATRIX. Vary ONE variable at a time:
  cookie + token  -> baseline
  no cookie + token (minted anonymously)  <- THE ONE PEOPLE SKIP. This is the real auth test.
  cookie + no token   -> isolates CSRF enforcement
  no cookie + no token -> tells you almost nothing on its own

DISTINGUISH WHO EMITTED THE 403: an application 403 is small and carries the app's own headers (its request-id/counter); an edge/WAF 403 is large and carries CDN ray-id/error-code markers. Reporting a WAF block as an application control is the same class of error.

GENERALISATION: before claiming any boundary, write down which single variable your control changed, and confirm it is the variable the server actually keys on. If you cannot name it, you do not have a control.

<!-- promoted-slug: 403-may-be-csrf-not-auth -->

<!-- promoted-slug: a-bare-tcp-connect-scan-e-g-nc-z-reporting-a-port-open-is-no -->

<!-- promoted-slug: a-burst-triggered-connection-refusal-that-recovers-within-ro -->

<!-- promoted-slug: a-scope-hostname-with-no-public-dns-record-burns-effort-desp -->

<!-- promoted-slug: a-static-edge-redirect-only-host-zero-origin-application-beh -->

<!-- promoted-slug: reusing-one-local-scratch-temp-file-path-across-sequential-p -->

<!-- promoted-slug: when-a-target-runs-known-open-source-software-an-externally -->

## Triaging a port that accepts TCP but returns zero bytes

Extends the "a connect-scan open port is not a live service" rule. When a raw TCP connect
succeeds but a protocol client (curl / openssl s_client) gets zero bytes, CLASSIFY with one cheap
`connect()`-timing test before guessing exotic protocols. Four common causes:

- **fail2ban / firewall REJECT or DROP (you are banned):** the SYN itself fails, `connect()`
  refuses fast (RST) or times out; the handshake never completes. Trigger is usually your own
  volume (a full `-p-` scan or a tight poller). SSH often stays up because it is a different jail,
  that is the tell it is a per-service ban, not the box being down. Fix: stop, wait the bantime,
  then interact gently (one connection, >=60-90s apart, no browser/parallel lanes).
- **Forwarder with a dead backend (service down or still booting):** `connect()` SUCCEEDS in
  ~0.05s, then the socket closes with zero bytes the instant you send a byte. A NAT/port-forward
  (socat, iptables DNAT, an emulator host bridge) accepted on the host side but the backend is not
  listening. Very common on emulated IoT/router boxes (FirmAE/QEMU): the host boots fast (SSH
  answers) while the guest firmware httpd/telnet behind the forwards is slow or failed, so ALL
  forwarded ports behave identically. Fix: patient gentle poll; the box may need a re-deploy if the
  firmware never comes up. See [[firmware-hardware]].
- **Custom binary protocol:** `connect()` succeeds and the service HOLDS the connection open (no
  instant close), waiting for a framed message; it closes only on clearly-wrong input (a full HTTP
  request). Identify with the vendor protocol (TP-Link Kasa 9999 = length-prefixed XOR-JSON, MQTT
  CONNECT, Modbus MBAP, ...). See [[network-service-attacks]].
- **TLS on a non-standard port:** plain HTTP gets "empty reply"; `openssl s_client` either
  handshakes (real TLS) or EOFs immediately (not TLS -> fall back to the cases above).

Decision key: does `connect()` complete? No -> banned/down. Yes + instant close on send -> dead
backend. Yes + holds open -> custom protocol (or awaiting a TLS ClientHello). Run this FIRST; it
collapses a long protocol-guessing loop (TP-Link / MQTT / h2c / UDP) into one measurement.

```python
import socket, time
t = time.time()
try:
    s = socket.create_connection((IP, PORT), timeout=8)
    print("connect %.2fs" % (time.time() - t))        # fast = not banned
    s.sendall(b"GET / HTTP/1.0\r\n\r\n"); s.settimeout(8)
    d = s.recv(256)
    print("reply" if d else "instant-close -> dead backend / booting")
except Exception as e:
    print("SYN failed -> banned or down: %r" % e)
```

<!-- promoted-slug: silent-port-triage -->
