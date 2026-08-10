---
title: "Gobuster"
type: tool
tags: [enumeration, recon, thm, tool, web]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-gobuster]
phase: fuzz
---

## Purpose

Gobuster is a directory/file brute-forcer and subdomain enumerator written in Go, offering three primary modes: `dir` (directories/files), `dns` (subdomains), and `vhost` (virtual hosts).

## Install / Setup

Pre-installed on Kali. Install manually:

```bash
sudo apt install gobuster -y
# or build from source:
go install github.com/OJ/gobuster/v3@latest
```

## Core Usage

```bash
gobuster <mode> [options]
```

### Global Flags (all modes)

| Flag | Long Flag       | Description                               |
|------|-----------------|-------------------------------------------|
| `-t` | `--threads`     | Number of concurrent threads (default 10) |
| `-v` | `--verbose`     | Verbose output                            |
| `-z` | `--no-progress` | Suppress progress display                 |
| `-q` | `--quiet`       | Suppress banner output                    |
| `-o` | `--output`      | Write results to a file                   |

Increasing threads to 64 (`-t 64`) significantly speeds up scans.

## Modes

### `dir` Mode — Directory and File Enumeration

```bash
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

The URL is the base path Gobuster starts from. To enumerate a specific directory:

```bash
gobuster dir -u http://10.10.10.10/products -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

#### `dir` Flags

| Flag | Long Flag                  | Description                                              |
|------|----------------------------|----------------------------------------------------------|
| `-w` | `--wordlist`               | Wordlist file                                            |
| `-u` | `--url`                    | Target URL (include protocol: `http://` or `https://`)  |
| `-x` | `--extensions`             | File extensions to search for (comma-separated)         |
| `-s` | `--status-codes`           | Positive (allowed) status codes                          |
| `-b` | `--status-codes-blacklist` | Negative (blocked) status codes                          |
| `-k` | `--no-tls-validation`      | Skip TLS/SSL certificate validation                      |
| `-c` | `--cookies`                | Cookies to include with requests                         |
| `-H` | `--headers`                | Add custom HTTP headers (`-H 'Header1: val1'`)           |
| `-n` | `--no-status`              | Suppress status code output                              |
| `-P` | `--password`               | Password for Basic Auth                                  |
| `-U` | `--username`               | Username for Basic Auth                                  |

#### File extension fuzzing

Search a directory for specific file types:

```bash
gobuster dir -u http://10.10.252.123/myfolder \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -x .html,.css,.js
```

Common useful extension sets:
- Web pages: `-x .php,.html,.asp,.aspx`
- Config files: `-x .conf,.config,.bak,.old`
- Docs/data: `-x .txt,.log,.xml,.json`

#### Bypassing invalid SSL certificates

When Gobuster encounters an invalid or self-signed SSL certificate, it will error out. Add `-k` to skip validation:

```bash
gobuster dir -u https://target.com -w wordlist.txt -k
```

### `dns` Mode — Subdomain Brute Force

Enumerates subdomains that have public DNS records:

```bash
gobuster dns -d mydomain.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

#### `dns` Flags

| Flag | Long Flag      | Description                              |
|------|----------------|------------------------------------------|
| `-d` | `--domain`     | Target domain                            |
| `-w` | `--wordlist`   | Wordlist file                            |
| `-c` | `--show-cname` | Show CNAME records                       |
| `-i` | `--show-ips`   | Show resolved IP addresses               |
| `-r` | `--resolver`   | Use a custom DNS resolver (`server:port`) |

### `vhost` Mode — Virtual Host Discovery

VHost mode fuzzes the `Host:` header against a known IP/domain to find virtual hosts, including those without public DNS records:

```bash
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

Extended usage from CPTS Web Recon:

```bash
gobuster vhost -u http://inlanefreight.htb:32551 \
     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     --append-domain -t 200 -xs 400
```

- `--append-domain` automatically appends the base domain to each wordlist entry
- `-xs 400` excludes responses with HTTP status 400

The `-k` flag also works in `vhost` mode to bypass TLS errors.

## Useful Wordlists

### Kali Default

```
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
/usr/share/wordlists/dirbuster/directory-list-1.0.txt
/usr/share/wordlists/dirb/big.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/small.txt
/usr/share/wordlists/dirb/extensions_common.txt   # useful with -x
```

### SecLists (install with `sudo apt install seclists`)

```
/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

## Tips and Gotchas

- The default thread count (10) is slow. Always increase with `-t 64` or higher.
- The URL **must** include the protocol (`http://` or `https://`). Omitting it causes Gobuster to error out.
- `dns` mode only finds subdomains with valid DNS entries. For internal/private vhosts, use `vhost` mode instead.
- `dns` mode with `-c` (CNAME) and `-i` (show IPs) together is not supported — they conflict.
- When enumerating WordPress sites, the directory structure is predictable (`wp-admin`, `wp-content`, `wp-includes`) — use this knowledge to target wordlists.
- Use `-b 404` to suppress 404 responses, or `-s 200` to only show 200 OK results, depending on what you're targeting.

## Related Techniques

- [[wiki/tools/ffuf]] — Alternative fuzzer with more advanced filtering and POST fuzzing support
- [[wiki/cheatsheets/recon]] — Broader context for directory and vhost enumeration
- [[wiki/cheatsheets/recon]] — Quick reference combining Gobuster commands

## Sources

- THM Tool Gobuster (`Gobuster.md`)
- CPTS Web Reconnaissance — VirtualHosts (`7. VirtualHosts.md`)
