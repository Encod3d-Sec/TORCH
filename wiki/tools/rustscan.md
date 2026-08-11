---
title: "RustScan"
type: tool
tags: [enumeration, network, recon, scanner, thm, tool]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-rustscan]
phase: scan
---

## Purpose

RustScan is an ultra-fast port scanner written in Rust that discovers open ports in seconds and automatically passes them to Nmap for service/version detection.

## Install / Setup

### Via dpkg (recommended for Kali/Debian):

```bash
wget https://github.com/RustScan/RustScan/releases/download/1.8.0/rustscan_1.8.0_amd64.deb
dpkg -i rustscan_1.8.0_amd64.deb
```

### Via brew (install as user, then add to PATH as root):

```bash
brew install rustscan
export PATH="$PATH:/home/linuxbrew/.linuxbrew/bin/"
```

Check the [RustScan GitHub releases](https://github.com/RustScan/RustScan/releases) for the latest version.

## Core Usage

Basic syntax with Nmap integration:

```bash
rustscan -a <target> -- <nmap flags>
```

Everything after `--` is passed directly to Nmap. RustScan discovers ports first, then hands the open port list to Nmap:

```bash
rustscan -a 10.10.10.1 -- -sV -sC
# Equivalent to: nmap -Pn -vvv -p <open_ports> -sV -sC 10.10.10.1
```

## Common Use Cases

- **Basic scan with service and script detection:**
```bash
rustscan -a 10.10.10.1 -- -sV -sC
```

- **Aggressive Nmap scan:**
```bash
rustscan -a 10.10.10.1 -- -A
```

- **Multiple targets (comma-separated):**
```bash
rustscan -a 127.0.0.1,10.10.10.1
```

- **CIDR range scan:**
```bash
rustscan -a 192.168.0.0/30
```

- **Scan from a hosts file:**
```bash
rustscan -a 'hosts.txt'
```
  `hosts.txt` is a newline-separated list of IPs, hostnames, or CIDR ranges.

- **Host (DNS name) scan:**
```bash
rustscan -a www.google.com
```

- **Single port:**
```bash
rustscan -a 127.0.0.1 -p 53
```

- **Multiple specific ports:**
```bash
rustscan -a 127.0.0.1 -p 53,80,443,8080
```

- **Port range:**
```bash
rustscan -a 127.0.0.1 --range 1-1000
```

- **Random port order (evade IDS/firewall signatures):**
```bash
rustscan -a 127.0.0.1 --range 1-1000 --scan-order "Random"
```

- **Full port scan with version detection:**
```bash
rustscan -a 10.10.10.1 -r 1-65535 -- -sV
```

## Scripting Engine

RustScan includes a scripting engine (RSE) that runs scripts after the scan, taking discovered ports and IPs as input. Supported languages: Python, Shell, Perl, or any binary in `$PATH`.

Controlled via `~/.rustscan_scripts.toml`:

```toml
tags = ["core_approved", "example"]
ports = ["80"]
developer = ["example"]
```

### `--scripts` Argument Options

| Value     | Description                                                         |
|-----------|---------------------------------------------------------------------|
| `None`    | Don't run any scripts                                               |
| `Custom`  | Run all scripts in the scripts folder                               |
| `Default` | Run Nmap (or whatever is in the config file) — this is the default |

Custom Python script format:

```python
#!/usr/bin/python3
#tags = ["core_approved", "example"]
#developer = ["example", "https://example.org"]
#trigger_port = "80"
#call_format = "python3 {{script}} {{ip}} {{port}}"
import sys
print('Script ran with arguments', str(sys.argv))
```

Scripts receive arguments via `sys.argv` in the format defined by `call_format`. Template variables: `{{script}}`, `{{ip}}`, `{{port}}`.

## Tips and Gotchas

- RustScan's speed advantage is in port discovery. It scans ports concurrently at a rate that far exceeds Nmap's default. Nmap then takes the discovered ports and runs its deeper analysis only on those ports — combining both tools' strengths.
- The `--` separator is required. Everything before it is for RustScan; everything after is passed verbatim to Nmap.
- `-Pn` is automatically included in the Nmap invocation (treats all hosts as alive).
- RustScan is not a replacement for Nmap — it's a port discovery front-end. Always chain it with Nmap for service identification.
- For evasion, `--scan-order "Random"` randomises the port order, which disrupts pattern-based IDS detection.
- The default scan covers all ports 1–65535 unless a range or specific ports are specified.

## Related Techniques

- [[wiki/tools/nmap]] — RustScan passes discovered ports to Nmap; Nmap handles service/version detection
- [[wiki/cheatsheets/recon]] — Quick reference for the scanning workflow

## Sources

- THM Tool RustScan (`RustScan.md`)
