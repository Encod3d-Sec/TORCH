---
title: "Recon Cheatsheet"
type: cheatsheet
tags: [cheatsheet, enumeration, git-poc, htb, network, nmap, osint, recon, thm, web]
date_created: 2026-05-08
date_updated: 2026-06-18
sources: [cpts-web-recon, cpts-nmap, thm-osint, git-claude-osint, git-One-Liners]
---

## Bug Bounty Full Recon Pipeline (One-Liner Chain)

```bash
# Full pipeline: subdomain → resolve → port scan → HTTP → crawl → nuclei
subfinder -d target.com -all | anew subs.txt
shuffledns -d target.com -r resolvers.txt -w subdomains-huge.txt | anew subs.txt
dnsx -l subs.txt -r resolvers.txt | anew resolved.txt
naabu -l resolved.txt -nmap -rate 5000 | anew ports.txt
httpx -l ports.txt | anew alive.txt
katana -list alive.txt -silent -nc -jc -kf all -fx -xhr \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif | anew urls.txt
nuclei -l urls.txt -es info,unknown -ept ssl -ss template-spray | anew nuclei.txt
```

```bash
# Filter juicy subdomains (dev/admin/API likely targets)
subfinder -d target.com -silent | dnsx -silent | cut -d' ' -f1 \
  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'
```

```bash
# Compact single-step pipeline: subfinder → dnsx → naabu → httpx → katana → nuclei
subfinder -d target.com -all -recursive | dnsx -silent | naabu -silent | httpx -silent | katana -silent | nuclei -silent
```

---

## Mass XSS Pipeline

```bash
# Collect all historical URLs, filter reflected parameters, run Gxss + dalfox
subfinder -d target.com | gau | Gxss -c 100 | dalfox pipe --skip-bav
```

**Gxss** identifies parameters that reflect input back in the response. **dalfox** then tests those reflected parameters for executable XSS. The `--skip-bav` flag skips browser-based verification (faster in automated pipelines).

Alternative using gospider for live crawling:

```bash
gospider -S alive.txt -c 10 -d 5 \
  --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" \
  | grep "code-200" | awk '{print $5}' | grep "=" | qsreplace -a | dalfox pipe
```

```bash
# Wayback-sourced XSS: archived URLs → gf XSS filter → dalfox
waybackurls target.com | gf xss | sed 's/=.*/=/' | sort -u | dalfox pipe
```

---

## Port Scanning

```bash
# RustScan fast discovery → Nmap service detection
rustscan -a target -- -sV -sC

# Nmap: quick top-1000 SYN scan
sudo nmap -sS -sV -sC --top-ports 1000 -oA quick target

# Nmap: full port scan + version + scripts
sudo nmap -p- -sV -sC --min-rate 5000 -oA full target

# Nmap: UDP top ports
sudo nmap -sU --top-ports 200 -oA udp target

# Nmap: host discovery only (subnet sweep)
sudo nmap 10.129.2.0/24 -sn -oA sweep
```

---

## WHOIS

```bash
whois example.com                                 # Domain registration, registrant, name servers
sudo apt install whois -y                         # Install if missing
```

Key fields: registrar, creation/expiry dates, registrant org, name servers, admin contact.

---

## DNS Enumeration

```bash
# Basic lookups with dig
dig example.com                                   # Default A record
dig example.com A                                 # IPv4
dig example.com AAAA                              # IPv6
dig example.com MX                                # Mail servers
dig example.com NS                                # Name servers
dig example.com TXT                               # TXT records (SPF, DKIM, verification)
dig example.com CNAME                             # Aliases
dig example.com SOA                               # Start of Authority
dig example.com ANY                               # All records (often blocked by modern servers)
dig @1.1.1.1 example.com                          # Query specific resolver (Cloudflare)
dig +trace example.com                            # Full DNS resolution path
dig -x 192.168.1.1                                # Reverse lookup
dig +short example.com                            # Short answer only
dig +noall +answer example.com                    # Answer section only

# Zone transfer attempt (AXFR)
dig axfr @<nameserver> example.com                # Succeeds only on misconfigured servers
# Example against intentionally vulnerable target:
dig axfr @nsztm1.digi.ninja zonetransfer.me

# nslookup (quick checks)
nslookup example.com
nslookup -type=MX example.com
```

---

## Subdomain Enumeration

```bash
# dnsenum (automated DNS + zone transfer + brute force)
dnsenum --enum example.com \
        -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
        -r --threads 10

# ffuf subdomain brute force (DNS-based, public only)
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u https://FUZZ.example.com/ -ic -c -t 100

# gobuster dns
gobuster dns -d example.com \
     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Certificate Transparency logs (passive, no interaction with target)
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' | sort -u
# Filter for specific subdomains (e.g., dev):
curl -s "https://crt.sh/?q=example.com&output=json" \
     | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

---

## Virtual Host Discovery

```bash
# Add target to /etc/hosts first:
echo "10.10.10.1  target.htb" | sudo tee -a /etc/hosts

# ffuf VHost fuzzing (Host header injection — finds public AND private vhosts)
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://target.htb/ -H 'Host: FUZZ.target.htb' -c -ic
# Filter out baseline response size (e.g., if default is 986 bytes):
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://target.htb/ -H 'Host: FUZZ.target.htb' -c -ic -fs 986

# gobuster vhost
gobuster vhost -u http://target.htb \
     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     --append-domain -t 64
```

---

## Directory and File Fuzzing

```bash
# ffuf directory enumeration
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://target.com/FUZZ -t 100 -ic -c

# ffuf with extensions
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://target.com/FUZZ -e .php,.html,.txt -t 100 -ic -c

# ffuf recursive with PHP extension
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://target.com/FUZZ -recursion -recursion-depth 1 -e .php -t 100 -ic -c -v

# ffuf filter: hide 403 responses
ffuf -u http://target.com/FUZZ \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt \
     -fc 403

# ffuf only show 200 OK
ffuf -u http://target.com/FUZZ \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt \
     -mc 200

# gobuster dir
gobuster dir -u http://target.com \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -t 64 -o gobuster_dir.txt

# gobuster dir with extensions
gobuster dir -u http://target.com \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -x .php,.html,.txt -t 64

# gobuster with TLS bypass
gobuster dir -u https://target.com -w wordlist.txt -k -t 64
```

---

## Parameter Fuzzing

```bash
# ffuf GET parameter discovery
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://target.com/page.php?FUZZ=value -c -ic -t 100 -fs <baseline_size>

# ffuf POST parameter discovery
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://target.com/page.php -X POST -d 'FUZZ=value' \
     -H 'Content-Type: application/x-www-form-urlencoded' -c -ic -t 100 -fs <baseline_size>

# ffuf POST value fuzzing (sequential IDs)
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ffuf -w ids.txt:FUZZ -u http://target.com/page.php -X POST -d 'id=FUZZ' \
     -H 'Content-Type: application/x-www-form-urlencoded' -c -ic -fs <baseline_size>
```

---

## Hidden Parameter Discovery

```bash
# x8: brute-force hidden GET/POST parameters against live targets
subfinder -d target.com -silent -all -recursive | httpx -silent \
  | sed 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w parameters.txt -o output.txt'

# arjun: fast hidden-param discovery (multi-method, infers from response diff)
arjun -u https://target.com/api/endpoint -m GET,POST -oT params.txt
arjun -i live-urls.txt -t 20 -oJ arjun.json   # bulk over a URL list

# paramspider: mine archived URLs for parameter names (passive)
paramspider -d target.com --exclude png,jpg,css,js -o paramspider.txt

# Reflected parameter hunting (for XSS scope)
python3 reflection.py urls.txt | grep "Reflection found" \
  | awk -F'[?&]' '!seen[$2]++' | tee reflected.txt
```

---

## JavaScript Analysis (Endpoint + Secret Mining)

Modern SPAs hide most of their real attack surface (internal API routes, debug params, API keys, cloud bucket names) inside JS bundles. Crawling URLs is not enough; mine the JS itself.

```bash
# 1. Collect JS file URLs (from crawl + archives)
cat live-urls.txt | katana -jc -silent | grep -iE '\.js($|\?)' | sort -u > jsfiles.txt
echo target.com | gau --subs | grep -iE '\.js($|\?)' | sort -u >> jsfiles.txt
# subjs: pull <script src> + inline script URLs from live hosts
cat live-hosts.txt | subjs | sort -u >> jsfiles.txt
sort -u jsfiles.txt -o jsfiles.txt

# 2. Extract endpoints/paths from each JS file
#   LinkFinder (regex endpoint extractor)
while read u; do python3 linkfinder.py -i "$u" -o cli; done < jsfiles.txt | sort -u > js-endpoints.txt
#   getJS (download + list) then feed back through extractors
cat live-hosts.txt | getJS --complete | sort -u >> jsfiles.txt
#   jsluice (fast Go extractor: URLs AND secrets from JS/JSON)
while read u; do curl -s "$u" | jsluice urls; done < jsfiles.txt | jq -r '.url' | sort -u >> js-endpoints.txt

# 3. Hunt secrets/keys inside the JS
while read u; do curl -s "$u" | jsluice secrets; done < jsfiles.txt | tee js-secrets.json
#   SecretFinder (regex: AWS keys, Google API, JWTs, Firebase, etc.)
while read u; do python3 SecretFinder.py -i "$u" -o cli; done < jsfiles.txt | sort -u > js-secrets.txt
#   trufflehog over downloaded JS dir (verified-secret mode)
trufflehog filesystem ./js_dump/ --only-verified

# 4. Resolve mined endpoints to live, then re-crawl/attack
cat js-endpoints.txt | httpx -silent -mc 200,201,204,301,302,401,403,500 -o live-js-endpoints.txt
```

Source-map recovery (when `.js.map` exposed) reconstructs original source - see [[javascript-source-map-exploitation]]. Mined keys often unlock cloud (see [[imds-cloud-metadata]] / cloud bucket section below); blind endpoints feed [[oob-callbacks]]-gated SSRF tests.

**Obfuscated/computed secrets: run the JS in node instead of hand-tracing it.** When a key/algorithm
is not a literal string but the OUTPUT of obfuscated logic (a minified IIFE, a computed constant),
grep finds nothing useful. Execute the file itself and print the value instead of reverse-engineering
the obfuscation by eye:

```bash
node -e "$(cat api.js); console.log(c)"    # load the file's scope, then dump the variable it computed
```

Far faster than manually stepping through minified/obfuscated JS when you only need the resulting
value, not a full understanding of the algorithm.

**Modern CMS/SPA admin panels are JS-rendered — `curl` sees only the shell.** A `curl`-driven crawl
against a JS/SPA-rendered admin panel (React/Vue dashboards, a modern Joomla 4+ admin, most modern
CMS back-ends) returns an empty shell `<div id="app">` with no real markup — don't grind a
template-editor RCE, a form submission, or any interaction over raw curl against one of these; drive
a real browser (headless Chromium, `Skill(screenshot)`/`browser.sh`) or the actual foothold surface
is elsewhere on the target.

**Never serial-curl a numeric/name range.** A `for i in $(seq ...); do curl ...; done` loop fetches
one URL at a time and turns a 10-minute enumeration into 40 minutes. Fan out threaded from the first
open port instead:

```bash
ffuf -t 80 -w <(seq -f '%04g' 0 9999) -u http://TARGET/path/FUZZ/ -mc 200
# or: xargs -P50 -I{} curl -s http://TARGET/path/{}
```

---

## Favicon Hash Fingerprinting

```bash
# Get favicon hash for tech stack fingerprinting / Shodan correlation
curl https://favicon-hash.kmsec.uk/api/?url=https://target.com/favicon.ico | jq

# Shodan search by favicon hash (match across internet-facing assets)
# shodan search "http.favicon.hash:<HASH>"
```

---

## Web Fingerprinting

```bash
# Banner grabbing with curl
curl -I http://target.com                         # HTTP headers (server, x-powered-by)
curl -I https://target.com

# WhatWeb
whatweb target.com                                # Identify CMS, frameworks, versions

# WAF detection
wafw00f target.com                                # Identify Web Application Firewall

# Nikto software ID (low-noise tuning)
nikto -h target.com -Tuning b

# Nikto full scan
nikto -h target.com

# Nikto multi-port
nikto -h 10.10.10.1 -p 80,8080,8443
```

---

## Web Archives and OSINT

```bash
# Wayback Machine (web browser)
# https://web.archive.org/ — search for target domain, browse historical snapshots

# waybackurls (dump all archived URLs)
git clone https://github.com/tomnomnom/waybackurls && cd waybackurls
go build
./waybackurls example.com                        # List all archived URLs

# crt.sh for subdomain discovery via SSL certificates
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' | sort -u
```

---

## Google Dorking

```bash
# Common operators
site:example.com                                  # All indexed pages on domain
site:example.com inurl:login                      # Login pages
site:example.com inurl:admin                      # Admin panels
site:example.com filetype:pdf                     # PDF files
site:example.com filetype:sql                     # SQL files (DB dumps)
site:example.com inurl:config.php                 # Config files
site:example.com (ext:conf OR ext:cnf)            # Config file extensions
site:example.com inurl:backup                     # Backup directories
intitle:"index of" "backup" site:example.com      # Open directory with backups
filetype:log "password" site:example.com          # Log files with passwords

# SSH keys exposed on GitHub
site:github.com "BEGIN OPENSSH PRIVATE KEY"
ext:nix "BEGIN OPENSSH PRIVATE KEY"

# Cloud credentials
intext:"aws_access_key_id" | intext:"aws_secret_access_key" filetype:json | filetype:yaml

# More dorks: https://www.exploit-db.com/google-hacking-database
```

---

## Automated Recon Frameworks

```bash
# FinalRecon (headers + whois + ssl + crawl + dns + subdomains)
pip3 install -r requirements.txt  # after cloning https://github.com/thewhiteh4t/FinalRecon
./finalrecon.py --headers --whois --url http://example.com
./finalrecon.py --full --url http://example.com

# theHarvester (emails, subdomains, hosts from search engines)
theHarvester -d example.com -b google,bing,linkedin -l 500

# ReconSpider (Scrapy-based crawl)
python3 ReconSpider.py http://example.com
cat results.json | jq '.emails'
cat results.json | jq '.comments'
```

---

## Hosts File Management

```bash
# Add a single entry
echo "10.10.10.1  target.htb" | sudo tee -a /etc/hosts

# Add multiple entries
sudo sh -c 'echo "10.10.10.1  admin.target.htb" >> /etc/hosts'
sudo sh -c 'echo "10.10.10.1  dev.target.htb"   >> /etc/hosts'

# View current entries
cat /etc/hosts
```

---

---

## Passive Subdomain Enumeration (External / OSINT)

```bash
T="target.com"

# Certificate Transparency — all-time subdomains (no interaction with target)
curl -sk "https://crt.sh/?q=%25.${T}&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct-subs.txt

# crt.sh CDX deep mining (includes expired/revoked certs)
curl -sk "https://crt.sh/?q=%25.${T}&output=json&deduplicate=Y" \
  | jq -r '.[].name_value' | sort -u

# Subfinder (7-source passive stack: crt.sh, VirusTotal, AlienVault, Shodan, etc.)
subfinder -d $T -all -recursive -silent | tee subfinder.txt
sort -u ct-subs.txt subfinder.txt > all-subs.txt

# Resolve live subdomains
dnsx -l all-subs.txt -a -resp-only -silent | sort -u > live-ips.txt

# Shodan InternetDB (free, no key, 1 req/sec) — ports + vulns per IP
for ip in $(cat live-ips.txt); do
  curl -sk "https://internetdb.shodan.io/$ip" | jq -c '{ip, ports, vulns: .vulns[:3]}'
  sleep 1
done | tee internetdb.jsonl

# Wayback CDX — all archived URLs for legacy path discovery
curl -sk "https://web.archive.org/cdx/search/cdx?url=*.${T}/*&output=json&collapse=urlkey&fl=original" \
  | jq -r '.[] | .[0]' | sort -u > wayback-urls.txt

# Wayback CDX — legacy app paths (ASP/PHP/JSP/CFML — often forgotten)
curl -sk "https://web.archive.org/cdx/search/cdx?url=*.${T}/*&output=json&collapse=urlkey&fl=original&filter=original:.*\.(asp|php|jsp|cfm)" \
  | jq -r '.[] | .[0]' | sort -u
```

---

## Passive Subdomain APIs (Single-Query)

Direct API queries for when you need a quick passive enumeration hit without running a full tool stack:

```bash
T="target.com"

# BufferOver — forward DNS data
curl -s "https://dns.bufferover.run/dns?q=.${T}" | jq -r '.FDNS_A[]' | cut -d',' -f2

# CertSpotter — certificate issuances with SAN expansion
curl -s "https://certspotter.com/api/v1/issuances?domain=${T}&include_subdomains=true&expand=dns_names" \
  | jq '.[].dns_names[]' -r | sort -u

# JLDC (Anubis)
curl -s "https://jldc.me/anubis/subdomains/${T}" | jq -r '.[]'

# ThreatMiner — passive DNS
curl -s "https://api.threatminer.org/v2/domain.php?q=${T}&rt=5" | jq -r '.results[]'

# AlienVault OTX — passive DNS hostnames
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${T}/passive_dns" \
  | jq -r '.passive_dns[].hostname' | sort -u

# Censys (requires API credentials)
censys search "parsed.names: ${T}" --fields "parsed.names" 2>/dev/null \
  | jq -r '.results[].parsed.names[]' | sort -u
```

---

## Email Harvesting (6-source Stack)

```bash
T="target.com"
HUNTER_KEY="..."
INTELX_KEY="..."

# 1. Hunter.io (25 free/month)
curl -sk -H "X-Api-Key: $HUNTER_KEY" \
  "https://api.hunter.io/v2/domain-search?domain=$T&limit=100" \
  | jq -r '.data.emails[] | .value' > emails-hunter.txt

# 2. crt.sh SAN extraction (certs sometimes include admin emails)
curl -sk "https://crt.sh/?q=%25.${T}&output=json" \
  | jq -r '.[].name_value' \
  | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort -u >> emails-misc.txt

# 3. DuckDuckGo SERP scrape
curl -sk "https://html.duckduckgo.com/html/?q=%22%40${T}%22" \
  | grep -oE "[a-zA-Z0-9._%+-]+@${T}" | sort -u >> emails-misc.txt

# 4. Bing SERP scrape (complementary index)
curl -sk -A "Mozilla/5.0" "https://www.bing.com/search?q=%22%40${T}%22&count=50" \
  | grep -oE "[a-zA-Z0-9._%+-]+@${T}" | sort -u >> emails-misc.txt

# 5. Wayback CDX — archived contact pages
curl -sk "https://web.archive.org/cdx/search/cdx?url=${T}/contact*&output=json&fl=original" \
  | jq -r '.[] | .[0]' | head -5  # visit these archived pages for emails

# Dedup all sources
cat emails-*.txt | sort -u > all-emails.txt

# Email pattern inference (8 templates — mark TENTATIVE until corroborated)
# {first}.{last}@domain  |  {first}{last}@domain  |  {first}@domain
# {f}{last}@domain       |  {first}.{l}@domain    |  {last}@domain
# {first}_{last}@domain  |  {first}-{last}@domain
```

---

## Breach Lookup

```bash
T="target.com"

# HudsonRock Cavalier — FREE, unauthenticated, infostealer logs (HIGHEST ROI)
# By domain (canonical first call)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=$T" | jq .

# By email (batch)
for email in $(cat all-emails.txt); do
  curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=$email" \
    | jq --arg e "$email" -c '{email: $e, total: .total_corporate_services, stealers: .stealers}'
  sleep 1
done | tee hudsonrock.jsonl

# HIBP (requires paid key)
for email in $(cat all-emails.txt); do
  curl -sk -H "hibp-api-key: $HIBP_KEY" \
    "https://haveibeenpwned.com/api/v3/breachedaccount/$email"
done > hibp.jsonl

# Severity: ≥10 employees → CRITICAL SSO_EXPOSURE | 1-9 → HIGH | ≥1 user → MEDIUM
grep -c '"total":[1-9]' hudsonrock.jsonl   # count compromised employees
```

---

## Identity Fabric Probes

```bash
T="target.com"

# Microsoft 365 tenant GUID extraction
curl -sk "https://login.microsoftonline.com/${T}/.well-known/openid-configuration" \
  | jq -r '.issuer'

# Federation status (Managed vs Federated IdP)
curl -sk "https://login.microsoftonline.com/getuserrealm.srf?login=admin@${T}" | jq .

# MX record (mail.protection.outlook.com → M365 confirmed)
dig +short MX $T

# SSO subdomain sweep
for p in auth login sso idp iam identity accounts oauth; do
  curl -sk -m 5 -I "https://${p}.${T}/" -w "${p}.${T} → %{http_code}\n" -o /dev/null
done

# SAML metadata (5 paths)
for path in /saml/metadata /FederationMetadata/2007-06/FederationMetadata.xml \
            /federationmetadata/2007-06/federationmetadata.xml \
            /simplesaml/saml2/idp/metadata.php /auth/saml2/metadata; do
  curl -sk -m 10 -I "https://${T}${path}" -w "$path → %{http_code}\n" -o /dev/null
done

# Okta slug discovery
for slug in ${T%%.*} ${T%%.*}-dev ${T%%.*}-staging ${T%%.*}-prod; do
  curl -sk -m 5 -I "https://${slug}.okta.com/" -w "${slug}.okta.com → %{http_code}\n" -o /dev/null
done
```

---

## API Discovery (Swagger / GraphQL)

```bash
T="https://target.com"

# Swagger/OpenAPI — 28 paths
for path in swagger.json swagger.yaml swagger-ui.html swagger-ui/ swagger-resources \
  api-docs api-docs.json api/swagger api/swagger.json api/swagger-ui.html \
  api/v1/swagger.json api/v2/swagger.json api/v3/api-docs v2/api-docs v3/api-docs \
  openapi.json openapi.yaml openapi/v1 openapi/v3 docs redoc rapidoc \
  api/docs api/documentation .well-known/openapi swagger/v1/swagger.json swagger/v2/swagger.json; do
  STATUS=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "$T/$path")
  [ "$STATUS" = "200" ] && echo "FOUND: $path ($STATUS)"
done

# GraphQL — 13 paths + introspection probe
for path in graphql graphiql api/graphql v1/graphql v2/graphql query api/query \
  gql altair playground subscriptions graphql/console api/v1/graphql; do
  STATUS=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -X POST "$T/$path" \
    -H 'Content-Type: application/json' \
    -d '{"query":"{__typename}"}')
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "GraphQL candidate: $path ($STATUS)"
done

# Full introspection query (try on any discovered GraphQL endpoint)
curl -sk -X POST "$T/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery{__schema{types{name kind fields{name type{name kind}}}queryType{name}mutationType{name}}}"}'
```

---

## Always-On HTTP Checks (15 Paths)

Run against every alive webapp — cheap, high signal:

```bash
T="https://target.com"

# .git/config → CRITICAL if [core] present
curl -sk -m 10 "$T/.git/config" | grep -E '\[core\]|\[remote|repositoryformatversion' && echo "CRITICAL: .git/config"

# .git/HEAD → HIGH
curl -sk -m 10 "$T/.git/HEAD" | grep -E '^ref:' && echo "HIGH: .git/HEAD"

# .env → CRITICAL if env vars present
curl -sk -m 10 "$T/.env" | grep -E '^[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*=' && echo "CRITICAL: .env"

# Spring Boot actuators → CRITICAL
curl -sk -m 10 "$T/actuator/env" | grep -E '"propertySources"' && echo "CRITICAL: /actuator/env"
curl -sk -m 10 -o /dev/null -w '%{http_code}' "$T/actuator/heapdump" | grep 200 && echo "CRITICAL: /actuator/heapdump"

# phpinfo → HIGH
curl -sk -m 10 "$T/phpinfo.php" | grep -i 'PHP Version' && echo "HIGH: /phpinfo.php"
curl -sk -m 10 "$T/info.php"    | grep -i 'PHP Version' && echo "HIGH: /info.php"

# Elasticsearch → HIGH
curl -sk -m 10 "$T/_cat/indices" | grep -v 'html' && echo "HIGH: /_cat/indices"

# Jenkins script console → HIGH
curl -sk -m 10 "$T/console" | grep -i 'Script Console' && echo "HIGH: /console"

# Tomcat Manager → HIGH
curl -sk -m 10 "$T/manager/html" | grep -i 'Tomcat' && echo "HIGH: /manager/html"

# Apache server-status → MEDIUM
curl -sk -m 10 "$T/server-status" | grep -i 'Apache Server Status' && echo "MEDIUM: /server-status"
curl -sk -m 10 "$T/server-info"   | grep -i 'Apache Server Information' && echo "MEDIUM: /server-info"

# Orphaned WordPress install → LOW
curl -sk -m 10 "$T/wp-admin/install.php" | grep -i 'WordPress Installation' && echo "LOW: /wp-admin/install.php"

# Disclosure policy (info)
curl -sk -m 10 "$T/.well-known/security.txt" | grep -i 'contact' && echo "INFO: security.txt"

# Robots.txt — disallowed paths become next-tier wordlist
curl -sk -m 10 "$T/robots.txt" | grep 'Disallow:' | awk '{print $2}'
```

---

## Cloud Bucket Enumeration

```bash
STEM="targetco"    # company name / bucket stem
REGION="us-east-1" # try us-east-1, us-west-2, eu-west-1, ap-southeast-1

# Prefix × suffix × stem permutations
for prefix in "" "backup-" "assets-" "static-" "dev-" "prod-"; do
  for suffix in "" "-backup" "-assets" "-static" "-media" "-data" "-uploads" \
                "-dev" "-prod" "-staging" "-logs" "-private" "-public" "-dump" "-archive"; do
    candidate="${prefix}${STEM}${suffix}"

    # S3
    STATUS=$(curl -sk -m 5 -I "https://${candidate}.s3.amazonaws.com/" -w '%{http_code}' -o /dev/null)
    case $STATUS in
      200) echo "CRITICAL PUBLIC: s3://${candidate}" ;;
      403) echo "EXISTS PRIVATE: s3://${candidate}" ;;
      301) echo "REDIRECT: s3://${candidate}" ;;
    esac

    # GCS
    STATUS=$(curl -sk -m 5 -I "https://${candidate}.storage.googleapis.com/" -w '%{http_code}' -o /dev/null)
    [ "$STATUS" = "200" ] && echo "CRITICAL PUBLIC: GCS gs://${candidate}"
    [ "$STATUS" = "403" ] && echo "EXISTS PRIVATE: GCS gs://${candidate}"

    # Azure Blob
    STATUS=$(curl -sk -m 5 -I "https://${candidate}.blob.core.windows.net/" -w '%{http_code}' -o /dev/null)
    [ "$STATUS" = "200" -o "$STATUS" = "400" ] && echo "EXISTS: Azure ${candidate}"
  done
done
```

---

## Subdomain Takeover (27-Provider Fingerprints)

```bash
# For each CNAME-pointed subdomain, check the CNAME target and response body
# Key providers and their "available for claim" signatures:

# GitHub Pages — CNAME: *.github.io → body: "There isn't a GitHub Pages site here."
# Heroku        — CNAME: *.herokuapp.com → body: "No such app"
# AWS S3        — CNAME: *.s3*.amazonaws.com → body: "NoSuchBucket"
# Azure Apps    — CNAME: *.azurewebsites.net → body: varies
# Shopify       — CNAME: shops.myshopify.com → body: "Sorry, this shop is currently unavailable."
# Squarespace   — CNAME: *.squarespace.com → body: "No Such Account"
# Surge.sh      — CNAME: *.surge.sh → body: "project not found"
# Fastly        — CNAME: various → Fastly-specific 404
# Pantheon      — CNAME: *.pantheonsite.io → body contains "gods are wise"
# Ngrok         — CNAME: *.ngrok.io → body: "Tunnel not found"
# Webflow       — CNAME: *.webflow.io → body: "Site not found"
# Zendesk       — CNAME: *.zendesk.com → body: "Help Center Closed"
# Intercom      — CNAME: *.intercom.help → "Not found"
# Statuspage    — CNAME: *.statuspage.io → "Not found"
# Tumblr        — CNAME: *.tumblr.com → body: "Whatever you were looking for doesn't currently exist."
# Bitbucket     — CNAME: *.bitbucket.io → "Repository not found"

# Automated check with subjack or subzy:
subjack -w all-subs.txt -t 100 -ssl -o takeover-candidates.txt
```

---

## Security Header Audit

```bash
T="https://target.com"

# Fetch and check all 6 security headers (per response)
curl -sk -m 10 -I "$T" | grep -iE 'strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy'

# Missing headers → findings:
# HSTS missing on /login or /admin → HIGH
# CSP missing → MEDIUM (XSS impact)
# X-Frame-Options missing → LOW (clickjacking)
# X-Content-Type-Options missing → LOW
# Referrer-Policy missing → INFO
# Permissions-Policy missing → INFO
```

---

## Priority Order (Highest ROI First)

When time is constrained, work in this order:

```
1. Breach lookup     — HudsonRock Cavalier (free); gives plaintext creds for corp SSO
2. GitHub recon      — code-search dorks; fastest path to cloud keys + .env files
3. Always-on HTTP    — 15 paths; exposed .git/.env/actuator = instant CRITICAL
4. Cloud buckets     — listable bucket = CRITICAL with minimal effort
5. Shodan/ports      — VPN concentrators, RDP, Jenkins, Elasticsearch are high-value pivots
6. Email harvest     — feeds breach lookup + phishing lists
7. Web tech / WAF    — triage hundreds of hosts; know the stack before probing
8. Wayback CDX       — archived JS has hard-coded keys; removed admin paths
9. DNS + email sec   — SPF/DMARC gaps enable email spoofing; TXT tokens reveal SaaS tenancies
10. Certificates     — CT-log catches forgotten subdomains; weak ciphers = cheap findings
```

---

## Key Wordlists Reference

```
# Directories
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/wordlists/dirb/common.txt

# Files
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt

# Extensions
/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt

# Parameters
/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Subdomains
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# Passwords
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt

# Usernames
/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

### The JS bundle is the ONLY map of a POST-only JSON API (dir scanners are blind to it)

For a JS/SPA front-end, reading the bundle is not merely *better* than content discovery - it is
often the *only* way to see the API, because feroxbuster / ffuf / gobuster structurally cannot find
a POST-only JSON API:

- **They send GET.** A route registered only for `POST` (e.g. `/api/move`, `/api/settings`) returns
  `404`/`405` to the scanner's GET, so it is filtered out as a miss.
- **A bare `/api` 404s**, so recursive modes (`-d 2`) never treat it as a directory and never descend
  to try `/api/<word>`. Deep, method-specific routes are unreachable by a top-level word list.
- Net result: the scanners' output lists only static assets (`/css`, `/js/app.js`, `/`) and you can
  wrongly conclude "no hidden routes". The endpoints, their methods, request-body shapes, feature
  flags, and client-side gates are all spelled out in the JS `fetch(...)`/`axios`/`XMLHttpRequest`
  calls instead.

So on any Express/Node/SPA target, grep the client JS FIRST and treat it as the endpoint map:

```bash
curl -s http://TARGET/js/app.js | grep -nE "fetch\(|axios|XMLHttpRequest|/api/|/v[0-9]/|token|secret|key|admin"
```

Then probe each mined route with its real method (`curl -X POST ... -H 'Content-Type: application/json' -d '{...}'`);
verbose error strings from these routes frequently name the exact server-side property/gate to attack
(a reward/authorization flag, a missing session key). Preserve the load-bearing excerpt as evidence
with `capture.sh snippet` so the walkthrough cites the code, not just "the JS revealed the API". See
[[javascript-source-map-exploitation]] and [[api-testing]].

<!-- promoted-slug: js-api-map-scanners-blind -->

## `<product>-<component>-<env>.<apex>` gives you the whole family

Find one host of the form `<product>-<component>-<env>.<apex>` and you can enumerate the rest by substitution: `<component>` over the backing tools (the API gateway, the workflow engine, the GitOps controller, the dashboards, the front end, the database) and `<env>` over `dev`, `tst`, `qa`, `staging`, `prod`. A sibling family is usually fronted by ONE identity proxy, so they all return the same challenge page and you can clear the set in a handful of requests.

What matters is the posture DIFFERENTIAL, not the gate:

- The `-tst` twin of a gated product commonly has self-registration enabled where production returns a registration-disabled error. Confirm behaviourally (submit a malformed-but-present address and see whether it reaches field validation) rather than trusting a config flag.
- Test instances publish API plans and specs that production does not, including keyless plans over back-end operations that would be Critical if the back end were healthy.

Gotcha: a gated instance is a genuine hardening win worth citing as a positive control in the report - especially for products that are normally found wide open. Do not grind on the gate.

<!-- promoted-slug: one-dev-staging-naming-convention-enumerates-a-whole-product -->

## CTF flag accounting: sweep ALL flags before declaring a box done

The instant you have root/full access on a CTF box, enumerate EVERY flag on the filesystem before
reporting any single one as "the" user/root flag — a box can legitimately hide more than the two you
expect:

```bash
grep -RIn 'THM{' / --exclude-dir={proc,sys,dev,run,mnt} 2>/dev/null   # swap the platform's format
grep -RIn 'flag{\|HTB{\|picoCTF{' / --exclude-dir={proc,sys,dev,run,mnt} 2>/dev/null
```

- **A flag file with a troll marker/joke text is a decoy**, not a scored flag — a room's tell that
  you found a distractor, not the real one.
- **Multiple shell-capable users means the scored "user flag" may belong to a LATER user** reached by
  lateral movement, not whoever you got a shell as first. A fast root shortcut (e.g. a `sudo
  NOPASSWD` script straight to root) can skip the intended lateral step entirely — after getting
  root, check whether the box had a second/third user you never pivoted to, since the scored flag may
  live there.
- **Some platforms plant an intro flag OFF the target box entirely** — a TryHackMe room's "Base Flag"
  is commonly an HTML comment in the ROOM PAGE source on the platform site (view-source on the task
  page, not the target IP), never findable by any full-filesystem grep on the box. If a scored flag
  is nowhere on disk after a real full-FS grep, check the room/task page source before assuming you
  missed a file.
- **Verify file state with `wc -c` + `md5sum`, not a single `ls`.** A box mid-redeploy/reset can show
  a transient wrong size on one `ls`; a byte-count + hash agreeing across a couple of reads is the
  real confirmation that you read the whole, current file — CTF platforms redeploy/reset boxes under
  you more often than a live client engagement would.

<!-- promoted-slug: ctf-flag-accounting-sweep-all-flags -->
