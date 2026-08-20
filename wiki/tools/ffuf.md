---
title: "FFuf"
type: tool
tags: [enumeration, htb, recon, thm, tool, web]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-ffuf, thm-ffuf]
phase: fuzz
---

## Purpose

FFuf (Fuzz Faster U Fool) is a fast, flexible web fuzzer used for directory enumeration, subdomain discovery, virtual host detection, and parameter/value fuzzing.

## Install / Setup

Pre-installed on Kali (PwnBox). Install manually:

```bash
sudo apt install ffuf -y
# or build from source:
go install github.com/ffuf/ffuf/v2@latest
```

## Core Usage

At minimum, supply `-u` (URL) and `-w` (wordlist). The keyword `FUZZ` marks where the wordlist entries are injected:

```bash
ffuf -u http://target.com/FUZZ -w /path/to/wordlist.txt
```

Custom keywords are supported — suffix the wordlist path with `:KEYWORD`:

```bash
ffuf -u http://target.com/NORAJ -w wordlist.txt:NORAJ
```

### Key Flags

| Flag               | Description                                                   |
|--------------------|---------------------------------------------------------------|
| `-w wordlist:KEY`  | Wordlist with optional keyword assignment                     |
| `-u URL`           | Target URL; place `FUZZ` (or custom keyword) in the URL      |
| `-t N`             | Number of threads (default 40; use 100 for speed)            |
| `-c`               | Coloured output                                               |
| `-ic`              | Ignore comment lines in wordlists (strips copyright headers)  |
| `-v`               | Verbose output (show full URL for each result)                |
| `-e .php,.html`    | Append extensions to each wordlist entry                      |
| `-X POST`          | Use POST method                                               |
| `-d "data"`        | POST data body; place `FUZZ` within the value                |
| `-H "Header: val"` | Add/override a header                                         |
| `-b "cookie"`      | Add a cookie                                                  |
| `-x http://proxy`  | Route traffic through a proxy                                 |
| `-replay-proxy URL`| Only send matched results through the proxy                   |
| `-rate N`          | Limit requests per second                                     |
| `-recursion`       | Enable recursive scanning of found directories                |
| `-recursion-depth N` | Limit recursion depth (1 = one level deep)                  |

### Matchers (keep results that match)

| Flag     | Description                                  |
|----------|----------------------------------------------|
| `-mc`    | Match HTTP status codes (default: 200,204,301,302,307,401,403,405) |
| `-ml`    | Match response line count                    |
| `-mr`    | Match by regexp                              |
| `-ms`    | Match response size (bytes)                  |
| `-mw`    | Match response word count                    |

### Filters (hide results that match)

| Flag     | Description                                  |
|----------|----------------------------------------------|
| `-fc`    | Filter by HTTP status code(s)                |
| `-fl`    | Filter by line count                         |
| `-fr`    | Filter by regexp                             |
| `-fs`    | Filter by response size                      |
| `-fw`    | Filter by word count                         |

## Common Use Cases

### Directory Fuzzing

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://target.com/FUZZ -t 100 -ic -c
```

### Page / Extension Fuzzing

Determine the extension used by the web app:

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
     -u http://target.com/blog/indexFUZZ -t 100 -ic -c
```

Fuzz for PHP pages in a discovered directory:

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://target.com/blog/FUZZ.php -t 100 -ic -c
```

### Recursive Fuzzing

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://target.com/FUZZ -recursion -recursion-depth 1 -e .php -t 100 -ic -c -v
```

### Subdomain Fuzzing (DNS-based)

Requires the subdomain to have a public DNS record:

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u https://FUZZ.target.com/ -ic -c -t 100
```

### VHost Fuzzing (Host header — finds non-public vhosts)

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://target.com/ -H 'Host: FUZZ.target.com' -c -ic
```

VHost fuzzing will return 200 for everything because the server always responds. Filter out the "default" response size first (look at baseline response size, then filter):

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://target.com/ -H 'Host: FUZZ.target.com' -c -ic -fs 986
```

### GET Parameter Fuzzing

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://target.com/page.php?FUZZ=value -c -ic -t 100 -fs 798
```

### POST Parameter Fuzzing

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://target.com/admin.php -X POST -d 'FUZZ=value' \
     -H 'Content-Type: application/x-www-form-urlencoded' -c -ic -t 100 -fs 798
```

### POST Parameter Value Fuzzing

Generate a sequential wordlist on the fly and pipe into ffuf:

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ffuf -w ids.txt:FUZZ -u http://target.com/admin.php -X POST -d 'id=FUZZ' \
     -H 'Content-Type: application/x-www-form-urlencoded' -c -ic -fs 768
```

Or pipe directly without a file:

```bash
seq 0 255 | ffuf -u 'http://target.com/page.php?id=FUZZ' -c -w - -fw 33
```

### Password Brute Force

```bash
ffuf -u http://target.com/login/ -c \
     -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt \
     -X POST -d 'uname=admin&passwd=FUZZ&submit=Submit' \
     -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'
```

### Filtering Dot-Files (reduce 403 false positives)

```bash
ffuf -u http://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt \
     -fr '/\..*'
```

### Route Traffic Through Burp Suite

```bash
ffuf -u http://target.com/ -w wordlist.txt -x http://127.0.0.1:8080
# Only send matched results to Burp:
ffuf -u http://target.com/ -w wordlist.txt -replay-proxy http://127.0.0.1:8080
```

### Add /etc/hosts Entry for Lab Targets

```bash
sudo sh -c 'echo "10.10.10.1  target.htb" >> /etc/hosts'
```

## Tips and Gotchas

- **VHost vs subdomain fuzzing**: DNS-based subdomain fuzzing (`FUZZ.domain.com`) only finds publicly resolvable subdomains. VHost fuzzing with `-H 'Host: FUZZ.domain.com'` also finds internal/private vhosts that lack DNS records.
- **Filter before matching**: With VHost fuzzing, all responses return 200. Identify the baseline response size (`-fs <size>`) rather than trying to match a success code.
- **`-ic` is important**: SecLists wordlists contain copyright headers which generate false results without this flag.
- **A WAF can 403 the ffuf User-Agent for every path** (Cloudflare does this by default), which turns the whole run into "matches" and hides the real routes. ffuf sends `Fuzz Faster U Fool <version>` unless told otherwise. Sanity-check ONE known-404 path with the scanner UA vs a browser UA before trusting any result set, and pass `-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'` on WAF-fronted targets. Same applies to feroxbuster/nuclei ([[wiki/tools/feroxbuster]], [[wiki/tools/nuclei]]).
- **POST PHP forms**: PHP only accepts `application/x-www-form-urlencoded` for POST data; always add `-H 'Content-Type: application/x-www-form-urlencoded'` or results will be wrong.
- **Double-wordlist performance**: Using two wordlists (`FUZZ1.FUZZ2`) multiplies the total request count (e.g., 90k × 50 = 4.5M requests). Target specific file extensions instead (e.g., `indexFUZZ` against the extensions list).
- **Thread ceiling**: Using `-t 200+` can cause DoS on the target or saturate your connection. `-t 100` is a safer high-speed setting.
- **`-mc 500`**: Useful to find endpoints that cause server errors, which can reveal misconfigured or vulnerable code paths.
- **`-fs 0`**: Filters out empty responses — useful when subdomain fuzzing returns zero-byte replies for invalid subdomains.

## Wordlist Recommendations

| Purpose             | Wordlist Path                                                          |
|---------------------|------------------------------------------------------------------------|
| Directories         | `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt` |
| Directories (large) | `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` |
| Files               | `/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt` |
| Extensions          | `/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt` |
| Subdomains          | `/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Parameters          | `/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt` |

## Related Techniques

- [[gobuster]] — Alternative directory/subdomain fuzzer with a similar feature set
- [[wiki/cheatsheets/recon]] — Broader recon workflow context
- [[wiki/cheatsheets/recon]] — Quick reference including ffuf commands

## Sources

- CPTS FFuf Module (9 files: Intro, Directory, Page, Recursive, Sub-domain, VHost, Filtering, Parameter fuzzing, Hands-on)
- THM Tool FFuf (`Ffuf.md`)
