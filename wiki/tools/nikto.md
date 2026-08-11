---
title: "Nikto"
type: tool
tags: [enumeration, htb, recon, scanner, thm, tool, web]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-nikto, cpts-web-recon]
phase: scan
---

## Purpose

Nikto is an open-source web server scanner that checks for dangerous files, outdated software, misconfigurations, default credentials, and other common web vulnerabilities.

## Install / Setup

Pre-installed on Kali. Manual install:

```bash
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```

## Core Usage

```bash
nikto -h <target>
```

The `-h` flag accepts an IP address or domain name. Nikto reads advertised HTTP headers and checks for known sensitive files and directories (e.g., `/admin/`, `login.php`, default Apache/Tomcat pages).

### Key Flags

| Flag            | Description                                                   |
|-----------------|---------------------------------------------------------------|
| `-h <host>`     | Target host (IP or domain)                                    |
| `-p <port>`     | Target port(s); comma-separated for multiple: `-p 80,8080`   |
| `-ssl`          | Force SSL mode                                                |
| `-o <file>`     | Output to file (extension determines format: `.html`, `.txt`) |
| `-Format <fmt>` | Explicitly set output format (`html`, `txt`, `csv`, `xml`)   |
| `-Display <N>`  | Control what to show (see table below)                        |
| `-Tuning <N>`   | Limit scan to specific vulnerability categories               |
| `-Plugin <name>`| Run a specific plugin                                         |
| `--list-plugins`| List all available plugins                                    |

### `-Display` Options

| Value | Description                         |
|-------|-------------------------------------|
| `1`   | Show redirects from the server      |
| `2`   | Show cookies received               |
| `E`   | Show errors (useful for debugging)  |

### `-Tuning` Categories

| Code | Category                          |
|------|-----------------------------------|
| `0`  | File Upload                       |
| `2`  | Misconfigurations / Default Files |
| `3`  | Information Disclosure            |
| `4`  | Injection (XSS, HTML)             |
| `8`  | Command Execution                 |
| `9`  | SQL Injection                     |
| `b`  | Software Identification           |

## Common Use Cases

- **Basic scan:**
```bash
nikto -h 10.10.10.1
```

- **Scan multiple ports on one host:**
```bash
nikto -h 10.10.10.1 -p 80,8000,8080
```

- **Software identification only (less noisy):**
```bash
nikto -h inlanefreight.com -Tuning b
```

- **Parse Nmap output to scan multiple hosts:**
```bash
nmap -p80 172.16.0.0/24 -oG - | nikto -h -
```

- **Save output as HTML report:**
```bash
nikto -h http://10.10.10.1 -o report.html
```
  Nikto infers format from the file extension automatically.

- **Run a specific plugin:**
```bash
nikto -h 10.10.10.1 -Plugin apacheuser
```

## What Nikto Checks

- Web server software and version (Apache, Nginx, Tomcat, IIS)
- HTTP methods enabled (PUT, DELETE — may allow file upload/deletion)
- Default installation files and pages (e.g., Tomcat `/examples/servlets/index.html`)
- Sensitive files (configuration files, backup files, admin panels)
- Outdated server software with known vulnerabilities
- Misconfigurations (directory listing, TRACE method enabled)
- Dangerous CGI scripts

## Useful Plugins

| Plugin        | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `apacheusers` | Enumerate Apache HTTP authentication users                                  |
| `cgi`         | Find exploitable CGI scripts                                                |
| `robots`      | Analyse `robots.txt` for disallowed paths                                   |
| `dir_traversal` | Attempt directory traversal (LFI) to read files like `/etc/passwd`       |

```bash
nikto -h 10.10.10.1 -Plugin robots
```

## Limitations

- **Very noisy**: Nikto makes no attempt at stealth. It will almost certainly trigger IDS/WAF alerts.
- **High false-positive rate**: Many findings are informational or require manual verification.
- **Slow on large applications**: Not suitable for time-sensitive engagements.
- **Does not crawl deeply**: Focuses on the root and common paths, not deep application logic.
- **Does not understand application logic**: Cannot test authentication-protected areas without session cookies.

Nikto is best used early in a web recon phase for a quick automated surface scan, followed by manual investigation with tools like Burp Suite.

## Tips and Gotchas

- Nikto is smart enough to infer output format from the file extension with `-o`. Specifying `-Format` is only needed when the extension is ambiguous.
- When scanning a subnet with Nmap piped into Nikto, use `nmap -oG -` (grepable format to stdout) — Nikto reads the grepable format directly.
- Use `-ssl` when scanning HTTPS targets if Nikto isn't detecting the SSL connection automatically.
- Combine with `wafw00f` beforehand to check for WAF presence — Nikto may get blocked or return misleading results if a WAF is active.

## Related Techniques

- [[wiki/tools/nmap]] — Use for port discovery before running Nikto
- [[wiki/cheatsheets/recon]] — Nikto fits into the active fingerprinting phase
- [[wiki/cheatsheets/recon]] — Quick reference for web scanning workflow

## Sources

- THM Tool Nikto (`Nikto.md`)
- CPTS Web Reconnaissance — Fingerprinting (`1. Fingerprinting.md`)
