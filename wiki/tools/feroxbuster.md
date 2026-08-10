---
title: "feroxbuster"
type: tool
tags: [brute-force, enumeration, recon, web]
date_created: 2026-05-12
date_updated: 2026-07-02
sources: [0xdf-htb-agile, 0xdf-htb-alert, 0xdf-htb-analytics, 0xdf-htb-artificial, 0xdf-htb-backend, 0xdf-htb-backendtwo, 0xdf-htb-barrier, 0xdf-htb-blurry, 0xdf-htb-boardlight, 0xdf-htb-bolt, 0xdf-htb-bountyhunter, 0xdf-htb-broscience, 0xdf-htb-busqueda, 0xdf-htb-cap, 0xdf-htb-cat, 0xdf-htb-driver]
phase: fuzz
---

## Purpose

**feroxbuster** is a fast, recursive content-discovery tool written in Rust. It brute-forces web paths using a wordlist, automatically recurses into discovered directories, and filters false-positive 404-like responses without requiring manual tuning. Created by Ben "epi" Risher.

## Install / setup

```bash
# Kali (apt)
sudo apt install feroxbuster

# Cargo (Rust)
cargo install feroxbuster

# GitHub releases (pre-compiled binary)
# https://github.com/epi052/feroxbuster/releases
```

Global config file (read automatically): `/etc/feroxbuster/ferox-config.toml`

Set persistent defaults there to avoid repeating flags on every run. Common overrides from 0xdf's config across all HTB writeups: `wordlist`, `status_codes = "All"`, `extract_links = true`.

## Core usage

```bash
feroxbuster -u <URL>
```

### Key flags

| Flag | Description |
|------|-------------|
| `-u URL` | Target URL (required) |
| `-w WORDLIST` | Wordlist path (default: raft-medium-directories.txt from config) |
| `-x php,html` | Append extensions to every word; test with and without |
| `-t N` | Threads (default: 50) |
| `-d N` | Recursion depth limit (default: 4) |
| `--no-recursion` | Disable recursion entirely; useful when output is too noisy |
| `--force-recursion` | Recurse even if the path does not end with `/`; critical for API path enumeration |
| `-C 404,405` | **Filter** (hide) these response codes from output |
| `-S 4,104` | Filter responses by size in bytes; comma-separated list |
| `-m GET,POST` | HTTP methods to test; default is GET only |
| `-k` | Ignore TLS certificate errors (HTTPS targets) |
| `-H "Header: value"` | Add a custom HTTP header; use for auth tokens or basic auth |
| `--dont-extract-links` | Disable automatic link extraction (enabled by default in v2.9+) |
| `--dont-filter` | Disable automatic 404-like response filtering |
| `-o FILE` | Write results to a file |

## Common use cases

### Standard web enumeration

```bash
feroxbuster -u http://10.10.11.100
```

Defaults: 50 threads, raft-medium-directories.txt, recursion depth 4, all status codes, extract links, auto-filter 404-like responses.

### PHP site enumeration

```bash
feroxbuster -u http://target.htb -x php
```

Tests every word with and without the `.php` extension. Seen on: alert, boardlight, bountyhunter, broscience, cap, cat, driver.

### HTTPS target with self-signed cert

```bash
feroxbuster -u https://target.htb -x php -k --no-recursion
```

`-k` skips certificate validation. `--no-recursion` controls output volume on PHP-heavy sites (broscience).

### Adding a custom HTTP header (e.g. basic auth)

```bash
feroxbuster -u http://10.10.11.106 -x php \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```

Seen on driver: first run without auth shows all 401s; second run with the header finds the actual paths. Use a lowercase wordlist for Windows IIS targets (case-insensitive filesystems).

### API path discovery with force-recursion

```bash
feroxbuster -u http://10.10.11.161/api --force-recursion
```

Without `--force-recursion`, feroxbuster only recurses into paths that return with a trailing slash. API routes like `/api/v1` never include one. This flag forces recursion regardless. Seen on backend: found `/api`, `/api/v1`, `/api/v1/admin`, `/api/v1/admin/file`.

### API enumeration with multi-method and code/size filtering

```bash
feroxbuster -u http://10.10.11.161/api/v1/user -C 404,405 -m GET,POST -S 4,104
```

`-C 404,405` hides noise codes. `-S 4,104` hides empty and boilerplate responses. `-m GET,POST` probes both methods per word. Seen on backend and backendtwo.

### Full API scan combining all flags

```bash
feroxbuster -u http://10.10.11.162 --force-recursion -C 404,405 -m GET,POST
```

From backendtwo. Then follow up with a POST-only pass on a specific sub-path:

```bash
feroxbuster -u http://10.10.11.162/api/v1/user -C 404,405 -m POST
```

### WordPress plugin enumeration

```bash
feroxbuster -u http://backdoor.htb/wp-content/plugins \
  -w plugins.txt
```

Targets a specific sub-path with a custom wordlist. Found on backdoor.

### Non-standard port

```bash
feroxbuster -u http://target.vl:8080
```

Include the port in the URL. Seen on barrier (Tomcat on 8080), found `/manager/html` and `/host-manager/html`.

## Tips and gotchas

**Auto-filter for 404-like responses.** feroxbuster sends a probe request with a random path and analyses the response. If the server returns a non-standard error page (e.g. a Flask 404 is 207 bytes, nginx 404 is 162 bytes), feroxbuster creates filters for those signatures automatically. The output banner prints something like:

```
404  GET  2l  10w  207c  Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
```

This happens before enumeration begins and eliminates thousands of false positives on apps with custom error pages. Seen on agile (two 404 variants), alert (403 + two 404 variants), boardlight (three variants), barrier, artificial, cat.

**Status code reporting changed across versions.** In v2.5 and earlier, feroxbuster reported only a hardcoded allow-list: `[200,204,301,302,307,308,401,403,405,500]`. From v2.9+ the default is "All Status Codes!" and you use `-C` to filter out the ones you do not want to see. Prefer the newer workflow.

**`--force-recursion` is essential for API targets.** Without it, feroxbuster only recurses into paths whose server response redirects with a trailing slash. REST APIs never do this, so entire subtrees are missed.

**`-C` filters codes you do NOT want; it is not an allow-list.** Common mistake: new users expect `-C 200` to show only 200s. It actually hides 200s. Use it to remove noise codes like 404 and 405.

**`-S` size filtering.** When the same boilerplate content is returned for every unmatched route, every response will be the same size. Pass that size to `-S` to filter it out. You can pass multiple sizes: `-S 4,104`.

**Wordlist choice matters.** The default `raft-medium-directories.txt` is a good general-purpose wordlist. On Windows targets, switch to the lowercase variant to avoid case-sensitivity issues. On sites with known small attack surfaces, `raft-small-words.txt` reduces runtime significantly (busqueda, blurry).

**Version banner.** feroxbuster always prints the config file path, version, and flags used in the banner. The `New Version Available` line is informational only; it does not affect scanning.

**OpenSSL compatibility issue.** On Ubuntu hosts with newer OpenSSL defaults, evil-winrm (and other Ruby tools) may fail with connection errors. A similar issue can affect feroxbuster's HTTPS scanning. Fix by adjusting `/etc/ssl/openssl.cnf`. See [[evil-winrm]] tips for details.

**Scan Management Menu.** Pressing Enter during a scan opens an interactive menu to pause, add or remove filters, or adjust thread count in real time without restarting.

## Related techniques

- Web content discovery
- Directory and file enumeration
- API endpoint enumeration
- Virtual host enumeration

## Sources

Synthesised from 0xdf HTB writeups: agile, alert, analytics, artificial, backend, backendtwo, barrier, blurry, boardlight, bolt, bountyhunter, broscience, busqueda, cap, cat, driver.

Cross-reference: [[wiki/tools/ffuf]] covers subdomain/VHost fuzzing, GET/POST parameter fuzzing, and response matching/filtering. Use ffuf when you need DNS-based subdomain enumeration or fine-grained matcher logic. Use feroxbuster when you need automatic recursion or API path tree discovery.
