---
title: "Information Disclosure"
type: technique
tags: [h1, information-disclosure, recon, web]
phase: recon
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [h1-scraped-information-disclosure, git-portswigger-all-labs]
---

## What it is

Unintended exposure of sensitive data — credentials, tokens, PII, internal infrastructure details, source code, or business logic — through misconfigured endpoints, verbose error messages, debug interfaces, or insecure direct access to internal resources.

## How it works

Applications expose sensitive data when they: return stack traces or internal paths in error responses, leave debug endpoints enabled in production, store secrets in client-accessible locations (JS bundles, HTML source, git repos), or fail to restrict access to administrative or internal APIs.

## Attack phases

Recon and exploitation — information disclosure often enables other attacks by revealing credentials, tokens, or internal architecture.

## Prerequisites

- Access to the target application (often unauthenticated)
- Ability to trigger error states or access unprotected endpoints

## Methodology

1. Check JS bundles and HTML source for hardcoded secrets, API keys, internal URLs and developer comments
2. Enumerate hidden/debug endpoints: `/.env`, `/.git/`, `/actuator/`, `/debug/`, `/api/docs`
3. Trigger error states with malformed input — look for stack traces, file paths, version strings
4. Check HTTP response headers for server version, framework, internal IPs
5. Review client-side storage (localStorage, sessionStorage, cookies) for tokens
6. Test API responses for fields that shouldn't be returned (other users' data, admin fields)
7. Check `robots.txt` and `sitemap.xml` for disclosed hidden directories or sensitive endpoints
8. Test for directory listing on sensitive paths (backup dirs, upload dirs)
9. Guess common backup file suffixes: `.bak`, `.old`, `.orig`, `.tmp`, `~`, `.swp`
10. Send `TRACE` HTTP request to reveal internal headers added by proxies or middleware (e.g., `X-Custom-IP-Authorization`)
11. Check for exposed `.git/` or `.svn/` directory — dump with `git-dumper` and inspect commit history for deleted secrets
12. Use Burp Suite's Engagement Tools → Find Comments to harvest HTML/JS comments at scale

## Key payloads / examples

```bash
# Common sensitive file paths
/.env
/.git/config
/actuator/env
/actuator/heapdump
/api/swagger.json
/api/graphql (introspection)
/_profiler/  # Symfony
/telescope   # Laravel
```

## Real-World Examples (HackerOne — paid reports)

Source: HackerOne disclosed reports, paid bounties only. 184 total paid, 12 critical, top bounty $25,000.

### Pattern 1: API endpoint leaking sensitive fields in JSON response (Critical — HackerOne, $25,000)

[Report #3000510](https://hackerone.com/reports/3000510) found that the `/reports/:id.json` endpoint on HackerOne's own platform leaked sensitive user attributes — including private email addresses and other PII — when the report had a "reporter summary" present. The field was included in JSON serialisation that was not meant to be user-visible. Pattern: JSON serialisation of complex ORM objects often includes more fields than intended; API responses should be built from explicit allow-lists of fields, not serialised model objects directly. The $25,000 bounty reflects that this affected HackerOne's own users (hackers submitting reports).

### Pattern 2: Quick Actions JSON serialisation leaking all Runner tokens (Critical — GitLab, $12,000)

[Report #509924](https://hackerone.com/reports/509924) found that when a GitLab Project model was serialised to JSON as part of the Quick Actions feature, *all* Runner registration tokens for that project were included in the response — including tokens that the requesting user did not have permission to see. A project member without admin rights could trigger this serialisation to harvest runner tokens, then register a malicious CI runner to intercept pipeline jobs and exfiltrate secrets. Pattern: feature-specific JSON serialisation code that reuses the full model object rather than a view-model is a recurring source of over-exposure.

### Pattern 3: Middleware bypass allowing files in allowed_paths to be read (Critical — GitLab, $10,000)

[Report #850447](https://hackerone.com/reports/850447) exploited a bypass in `gitlab-workhorse`'s multipart middleware. The `Gitlab::Middleware::Multipart` component maintained an `allowed_paths` list for file uploads, but a crafted multipart request could cause workhorse to serve files from those allowed paths directly to the attacker. This disclosed application-internal files (uploads, attachments) that should have required authentication. Pattern: proxy/middleware components that sit in front of an application and make access decisions based on path lists are worth auditing for bypass — the middleware and the backend often disagree on path canonicalisation.

### Pattern 4: Exposed production database via unauthenticated Presto coordinator (Critical — Grab, $5,000)

[Report #266766](https://hackerone.com/reports/266766) found a Grab (ride-hailing) BigData Presto coordinator running without authentication on a public IP. Anyone could connect and run SQL queries against production analytics tables containing ride history, user PII, and financial data. Pattern: internal data infrastructure (Presto, Hadoop, Elasticsearch, Kibana, InfluxDB, Grafana) frequently ships with authentication disabled by default and gets exposed when deployed without network-level controls. These are reliable targets during external recon — check for ports 8080/9200/9300/3000/5601 on cloud IPs.

### Pattern 5: SSRF via Office file thumbnail generation disclosing internal metadata (Critical — Slack, $4,000)

[Report #671935](https://hackerone.com/reports/671935) found that Slack's Office document thumbnail generation made outbound requests to URLs embedded in the document. A crafted `.docx` referencing `http://169.254.169.254/` (AWS metadata) caused the thumbnail service to fetch instance metadata and return it in the response. This is information disclosure enabling privilege escalation (IAM credentials). Pattern: file preview, thumbnail, and conversion services are SSRF hotspots — they process attacker-supplied content in a server-side process, often with privileged network access.

### Pattern 6: Tor Browser SFTP URI exposing real local IP address (Critical — Tor, $3,000)

[Report #253429](https://hackerone.com/reports/253429) found that the Linux Tor Browser Bundle (TBB) would process `sftp://` URIs by invoking the local SFTP client, which connected directly (not through Tor). This connection revealed the user's real IP address to the SFTP server — defeating the entire purpose of using Tor. Pattern: anonymity tools are held to a higher standard of information disclosure than normal apps; any non-Tor outbound connection is critical. Also demonstrates that URI handler leakage (tel:, sftp:, smb://) is a general privacy/disclosure risk in desktop clients.

### Pattern 7: Exposed AWS S3 bucket with iOS test build source and credentials (Critical — Slack, $1,500)

[Report #404822](https://hackerone.com/reports/404822) found a publicly accessible AWS S3 bucket containing Slack iOS test builds, configuration files, and embedded API keys. The bucket was likely created during development and never restricted to private access. Pattern: S3 bucket enumeration (via cert transparency, JS source, error messages, brute-forcing common naming patterns like `company-dev`, `company-staging`, `company-ios-builds`) is a standard recon step. Exposed buckets frequently contain credentials, source code, backups, or database dumps.

### Pattern 8: Jira API token exposed in public CI build logs (Critical — inDrive / Mozilla, $1,500 each)

Two separate reports ([#1785145](https://hackerone.com/reports/1785145) for inDrive, [#2467999](https://hackerone.com/reports/2467999) for Mozilla) found credentials in places they should never be. The inDrive report found a Jira API token in a public CI/CD log giving full access to the company's Jira instance. The Mozilla report found Jira credentials shared in a Mozilla Slack channel that was accessible to external guests. A third related Mozilla report ([#2915647](https://hackerone.com/reports/2915647), $1,500) found a Netlify authentication token in public Mozilla CI logs. Pattern: CI/CD systems (GitHub Actions, CircleCI, Jenkins) that log environment variables are a major credential leak vector — particularly when `set -x` or verbose logging is enabled in shell scripts.

### Pattern 9: Open production Jenkins instance (High — Snapchat, $15,000)

[Report #231460](https://hackerone.com/reports/231460) found a Snapchat production Jenkins instance accessible without authentication. This gave full read access to build configurations, environment variables, secrets, and potentially RCE via the Jenkins script console (Groovy). The $15,000 bounty for a high-severity disclosure reflects the severity upgrade when information disclosure directly enables RCE. Pattern: Jenkins, TeamCity, and similar CI servers are extremely high-value targets; default installations have no authentication and the script console gives OS-level RCE.

### Pattern 10: JFrog Artifactory credentials exposed on GitHub (High — Snapchat, $15,000)

[Report #911606](https://hackerone.com/reports/911606) found Snapchat JFrog Artifactory credentials (username and password) committed to a public GitHub repository. The credentials gave access to `snapchat.jfrog.io` — the company's internal artifact repository storing compiled binaries and build dependencies. Pattern: GitHub dorking for company-specific strings (`org:snapchat password`, `org:company artifactory`, `org:company api_key`) is one of the highest-return recon activities. Secrets in git history persist even after deletion from the working tree — use `trufflehog`, `gitleaks`, or `git log -S` to find them.

### Pattern 11: GraphQL mutation leaking all hacker email addresses (High — HackerOne, $12,500)

[Report #2032716](https://hackerone.com/reports/2032716) found that the `SaveCollaboratorsMutation` GraphQL operation on HackerOne returned the email address of any hacker by their username — without requiring the querying user to have any relationship with that hacker. An attacker could enumerate all HackerOne usernames and harvest email addresses for phishing. Pattern: GraphQL mutations and queries that involve user objects often return the full user model; email fields should be explicitly excluded unless the relationship justifies exposure. Introspection (`__schema`, `__type`) helps enumerate all fields a type exposes.

### Pattern 12: VK Android app remote information disclosure via exposed PlayerProxy port (Critical — VK.com, $700)

[Report #292761](https://hackerone.com/reports/292761) found that the VK Android app opened a local HTTP proxy port (`PlayerProxy`) that was accessible to other apps and potentially to adjacent network attackers. The proxy would forward requests including authentication tokens, allowing a malicious co-installed app or a network attacker to steal the user's VK session. Pattern: mobile apps that spin up local HTTP servers or expose local ports create attack surface for both local privilege escalation and information disclosure — test with `adb shell netstat -tlnp` to enumerate open ports in the app's process.

## Detection and defence

- **Explicit field allow-lists** in API serialisers — never serialise full model objects; build dedicated view models or use serialiser libraries with field restrictions
- **Scan public repositories and CI logs** for secrets using `trufflehog`, `gitleaks`, or GitHub secret scanning before shipping
- **Restrict access to internal infrastructure** (Jenkins, Grafana, Elasticsearch, Presto) with authentication and network controls — never expose on public IPs without auth
- **Audit S3 bucket policies** for `s3:GetObject` granted to `*` (public); use AWS Config rules or CloudTrail to alert on public bucket creation
- **Disable verbose logging in CI/CD** — never use `set -x` in scripts that process secrets; mask sensitive variables in CI platforms
- **Review GraphQL schema** for over-exposed fields; disable introspection in production or restrict it to authenticated admins
- **Local port binding** in mobile apps should use `127.0.0.1` not `0.0.0.0`; validate that content served via local proxies does not include auth tokens in URLs or headers

## Sources

- HackerOne disclosed reports — paid bounties, category: information-disclosure

## From the Wild

### HTB — DevVortex (2023)
- **Technique variant**: Joomla Information Disclosure + RCE
- **Attack path**: Exploit Joomla CVE-2023-23752 to leak DB creds, access admin panel, template RCE for shell, apport-cli (CVE-2023-1326) for root

## PortSwigger Labs

### Lab 1 — Information disclosure in error messages (Apprentice)

Modify a numeric parameter (e.g., `?productId=abc`) to trigger a server-side exception. The error response leaks the backend framework name and version (e.g., `Apache Struts 2 2.3.31`) which can be used to identify known CVEs.

**Key technique:** Submit non-numeric/invalid values to typed parameters to force verbose error output.

---

### Lab 2 — Information disclosure on debug page (Apprentice)

HTML source comments reference `/cgi-bin/phpinfo.php`. Browsing to that path exposes a full `phpinfo()` page including environment variables like `SECRET_KEY`.

**Key technique:** Use Burp Suite Engagement Tools → Find Comments (Target → Site Map → right-click → Engagement Tools → Find Comments) to discover commented-out path hints at scale.

```
GET /cgi-bin/phpinfo.php HTTP/2
```

The response includes PHP configuration, environment variables, and server internals. Extract `SECRET_KEY` from the `<td class="e">SECRET_KEY</td>` row.

**Common phpinfo / debug paths to probe:**
```
/cgi-bin/phpinfo.php
/phpinfo.php
/info.php
/test.php
/_profiler/         # Symfony
/telescope          # Laravel
/actuator/env       # Spring Boot
```

---

### Lab 3 — Source code disclosure via backup files (Apprentice)

`robots.txt` discloses a `/backup` directory. Directory listing is enabled, revealing a `.bak` file. The backup contains source code with a hardcoded PostgreSQL password in a `ConnectionBuilder` instantiation.

**Key technique:**
1. Always fetch `/robots.txt` first — `Disallow` entries often point to sensitive directories
2. Check for directory listing on any discovered path
3. Guess backup suffixes for known files: `.bak`, `.old`, `.orig`, `.tmp`, `~`

```
GET /robots.txt        → reveals /backup
GET /backup/           → directory listing shows ProductTemplate.java.bak
GET /backup/ProductTemplate.java.bak  → hardcoded DB password in source
```

---

### Lab 4 — Authentication bypass via information disclosure (Apprentice)

Send a `TRACE` request to reveal internal headers injected by a reverse proxy. The `TRACE` response echoes all received headers — including `X-Custom-IP-Authorization` appended by the proxy. Use this discovered header to spoof `127.0.0.1` and access the admin panel as a trusted local request.

**Key technique:**
```http
TRACE /my-account?id=carlos HTTP/2
```

Response reveals:
```
X-Custom-IP-Authorization: <your-real-IP>
```

Re-send with spoofed value to bypass IP-based admin access control:
```http
GET /admin HTTP/2
X-Custom-Ip-Authorization: 127.0.0.1
```

**Note:** `TRACE` is disabled in most modern servers but worth checking. It discloses headers added between the client and backend (load balancers, WAFs, CDNs).

---

### Lab 5 — Information disclosure in version control history (Practitioner)

The production server exposes its `.git` directory. Dump the full repository with `git-dumper`, then inspect the commit log for a commit titled "Remove admin password from config". Diff the commits to extract the deleted plaintext password.

**Step-by-step:**
```bash
# Install
git clone https://github.com/arthaud/git-dumper.git

# Dump exposed .git
python3 git_dumper.py https://<LAB-ID>.web-security-academy.net/.git ./dumped/

# Inspect history
cd dumped
git log

# Diff to find deleted secret
git diff <older-commit> <newer-commit>
# Output shows: -ADMIN_PASSWORD=<plaintext>  →  +ADMIN_PASSWORD=env('ADMIN_PASSWORD')
```

## Directory-listing-exposed logs can leak the one (input, output) pair a crypto scheme needs

An `autoindex on`-style open log directory (`ffuf`/manual browse to `/logs/`) is not just a source of
credentials — a single leaked application log line can be exactly enough to BREAK a weak token/crypto
scheme even without full source access. If a log records a real (known-input, generated-output) pair
for a token/invite-code/reset-code generator, that one pair is often sufficient to recover an unknown
seed constant offline and forge tokens for any other input. See [[cryptography-attacks]] (PRNG /
`mt_rand` seed-recovery section) for the forging technique once you have the pair — the discovery
vector here is simply: fuzz for open log directories (`/logs/`, `/log/`, `/debug/`) on any app with a
custom token scheme, and read every line of what you find, not just the most recent one.

**Key insight:** Secrets removed in a commit still exist in git history. Even a public repo with a "deleted credentials" commit is fully compromised — rotate all affected credentials immediately. Use `trufflehog` or `gitleaks` to scan history automatically.
