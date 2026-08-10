---
title: "Nmap"
type: tool
tags: [enumeration, htb, network, nmap, recon, scanner, tool]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-nmap]
phase: scan
---

## Purpose

Nmap (Network Mapper) is a free, open-source network scanner used to discover hosts and services on a network by sending packets and analysing responses.

## Install / Setup

Pre-installed on Kali Linux. Install on other Debian-based systems:

```bash
sudo apt install nmap -y
```

## Core Usage

```bash
nmap [scan type] [options] {target}
```

Target can be a single IP, hostname, CIDR range (`192.168.1.0/24`), or a file (`-iL hosts.txt`).

### Scan Types

| Flag   | Name                  | Notes                                                  |
|--------|-----------------------|--------------------------------------------------------|
| `-sS`  | TCP SYN (stealth)     | Default when run as root; does not complete 3-way handshake |
| `-sT`  | TCP connect           | Full connection; used without root privileges           |
| `-sU`  | UDP scan              | Slow; combine with `-sS` for full coverage             |
| `-sV`  | Version detection     | Probes open ports for service/version info             |
| `-sC`  | Default script scan   | Runs NSE scripts in the `default` category             |
| `-A`   | Aggressive            | Enables `-sV -sC -O --traceroute`                      |
| `-O`   | OS detection          | Requires root; inaccurate on filtered hosts            |
| `-sn`  | Ping scan (no ports)  | Host discovery only; no port scan                      |

### Host Discovery Options

```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5   # Sweep a subnet
sudo nmap -sn -oA tnet -iL hosts.txt                               # Scan from list
```

| Flag   | Description                        |
|--------|------------------------------------|
| `-PE`  | ICMP echo request                  |
| `-PP`  | ICMP timestamp request             |
| `-PM`  | ICMP address mask request          |
| `-PS`  | TCP SYN ping (default port 80)     |
| `-PA`  | TCP ACK ping                       |
| `-PU`  | UDP ping                           |
| `-Pn`  | Skip host discovery (treat all as up) |

### Port Specification

```bash
nmap -p 22,80,443 target        # Specific ports
nmap -p 1-1000 target           # Port range
nmap -p- target                 # All 65535 ports
nmap --top-ports 100 target     # Top 100 most common ports
nmap --top-ports 1000 target    # Top 1000 (default)
```

### Timing Templates

| Flag  | Name       | Description                                           |
|-------|------------|-------------------------------------------------------|
| `-T0` | Paranoid   | Very slow; IDS evasion                                |
| `-T1` | Sneaky     | Slow; IDS evasion                                     |
| `-T2` | Polite     | Slower; reduces bandwidth/host impact                 |
| `-T3` | Normal     | Default                                               |
| `-T4` | Aggressive | Faster; assumes fast/reliable network                 |
| `-T5` | Insane     | Very fast; may miss results or overwhelm targets      |

### Output Formats

```bash
nmap target -oN output.txt    # Normal (human-readable)
nmap target -oX output.xml    # XML
nmap target -oG output.gnmap  # Grepable
nmap target -oA output        # All three formats at once
```

## Common Use Cases

- **Basic SYN scan with version and default scripts:**
```bash
sudo nmap -sS -sV -sC 10.10.10.1
```

- **Aggressive scan saving all output formats:**
```bash
sudo nmap -A -oA scan_results 10.10.10.1
```

- **Full port scan with version detection:**
```bash
sudo nmap -p- -sV --min-rate 5000 10.10.10.1
```

- **UDP scan on top ports:**
```bash
sudo nmap -sU --top-ports 200 10.10.10.1
```

- **OS detection:**
```bash
sudo nmap -O 10.10.10.1
```

- **Subnet host discovery (no port scan):**
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet
```

- **Scan from a host list:**
```bash
sudo nmap -sn -iL hosts.txt -oA tnet
```

## NSE Scripts

Nmap Scripting Engine (NSE) scripts extend functionality significantly.

```bash
nmap --script=http-enum target              # Run a specific script
nmap --script=vuln target                   # Run all vuln-category scripts
nmap --script="http-*" target               # Wildcard matching
nmap --script=default,safe target           # Multiple categories
nmap --script-args user=admin target        # Pass arguments to a script
nmap --script-help http-enum               # Show help for a script
```

### Script Categories

| Category  | Description                                          |
|-----------|------------------------------------------------------|
| `auth`    | Authentication bypass and credential tests           |
| `brute`   | Brute-force credential attacks                       |
| `default` | Safe, commonly useful scripts (run with `-sC`)       |
| `discovery` | Network asset discovery                            |
| `exploit` | Active exploitation attempts                         |
| `fuzzer`  | Fuzzing inputs                                       |
| `intrusive` | May crash or disrupt the target                    |
| `safe`    | Low-risk scripts                                     |
| `vuln`    | Vulnerability detection                              |

NSE scripts are located at `/usr/share/nmap/scripts/`.

## Firewall / IDS Evasion

```bash
sudo nmap -f target                          # Fragment packets (8-byte frags)
sudo nmap -ff target                         # Fragment into 16-byte chunks
sudo nmap -D RND:10 target                   # Decoy scan with 10 random decoys
sudo nmap -D 10.0.0.1,10.0.0.2,ME target    # Custom decoy IPs
sudo nmap --data-length 50 target            # Pad packets with random data
sudo nmap --source-port 53 target            # Spoof source port (DNS traffic)
sudo nmap -sS -T1 target                     # Slow stealth scan
sudo nmap --scan-delay 500ms target          # Add delay between probes
sudo nmap --max-retries 1 target             # Reduce retransmissions
```

**Fragmentation** breaks packets into smaller pieces to evade packet inspection. **Decoys** make it hard to identify the real scanning IP in logs. **Source port spoofing** with port 53 exploits firewall rules that often trust DNS traffic.

## Tips and Gotchas

- `-sS` requires root (raw socket access). Without root, Nmap falls back to `-sT`.
- `-Pn` is essential when scanning targets behind firewalls that block ICMP — without it, Nmap may mark hosts as down and skip port scanning.
- UDP scanning (`-sU`) is extremely slow. Target specific ports with `-p U:53,161,500` and combine with a TCP scan: `sudo nmap -sSU -p T:22,80,U:53,161 target`.
- `-A` is very noisy — avoid on stealthy engagements; use targeted flags instead.
- The `--min-rate` flag (e.g., `--min-rate 5000`) speeds up scans significantly but may miss results on unstable networks.
- Version detection (`-sV`) significantly increases scan time. Use `--version-intensity 0` for a fast, less accurate version probe.
- Always save output with `-oA` — raw output is easier to re-parse than re-scanning.
- On Windows targets, the host often responds to ICMP but firewalls block many ports, so add `-Pn` if you know the host is alive.

## Related Techniques

- [[wiki/tools/rustscan]] — Ultra-fast port scanner that passes results to Nmap for service detection
- [[wiki/cheatsheets/recon]] — Combined quick reference for full recon workflow
- [[wiki/cheatsheets/recon]] — Active reconnaissance including banner grabbing and service enumeration

## Sources

- CPTS Nmap Module (`NMAP.md`)
- CPTS Web Reconnaissance — Introduction (`1. Introduction.md`)
