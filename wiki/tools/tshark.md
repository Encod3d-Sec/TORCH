---
title: "TShark"
type: tool
tags: [network, thm, tool]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-tool-tshark]
phase: aux
---

## Purpose

TShark is the command-line equivalent of Wireshark for packet capture and analysis — it reads live interfaces or PCAP files, applies display/capture filters, extracts specific fields, generates protocol statistics, follows streams, and exports transferred files.

## Install / setup

```bash
# Usually pre-installed on Kali
sudo apt install tshark

# Check version
tshark -v

# List available capture interfaces
tshark -D
```

## Core usage

```bash
# Capture on interface
tshark -i eth0

# Read a PCAP file
tshark -r file.pcap

# Write capture to file
tshark -w output.pcap

# Verbose output (packet details pane)
tshark -r file.pcap -V

# Hex + ASCII dump
tshark -r file.pcap -x

# Limit to N packets
tshark -r file.pcap -c 10

# Suppress packet output (show stats only)
tshark -q
```

## Common use cases

### Live capture with autostop

```bash
# Stop after 30 seconds
tshark -w capture.pcap -a duration:30

# Stop after file reaches 10 KB
tshark -w capture.pcap -a filesize:10

# Ring buffer: rotate through 5 files of 10 KB each
tshark -w capture.pcap -b filesize:10 -b files:5
```

### Capture filters (BPF syntax — set before capture)

```bash
# Filter by host
tshark -f "host 10.10.10.10"

# Filter by network range
tshark -f "net 10.10.10.0/24"

# Filter by port
tshark -f "port 80"

# Filter by protocol
tshark -f "tcp"
tshark -f "udp"

# Filter by source/destination
tshark -f "src host 10.10.10.10"
tshark -f "dst host 10.10.10.10"
```

### Display filters (Wireshark syntax — applied post-capture)

```bash
# Filter by IP
tshark -r file.pcap -Y 'ip.addr == 10.10.10.10'
tshark -r file.pcap -Y 'ip.src == 10.10.10.10'
tshark -r file.pcap -Y 'ip.dst == 10.10.10.10'

# Filter by TCP port
tshark -r file.pcap -Y 'tcp.port == 80'
tshark -r file.pcap -Y 'tcp.srcport == 443'

# Filter HTTP
tshark -r file.pcap -Y 'http'
tshark -r file.pcap -Y 'http.response.code == 200'
tshark -r file.pcap -Y 'http.request.method == "POST"'

# Filter DNS
tshark -r file.pcap -Y 'dns'
tshark -r file.pcap -Y 'dns.qry.type == 1'   # A records only

# Contains / Matches (regex)
tshark -r file.pcap -Y 'http.server contains "Apache"'
tshark -r file.pcap -Y 'http.request.method matches "(GET|POST)"'
```

### Extract specific fields

```bash
# Extract source and destination IPs
tshark -r file.pcap -T fields -e ip.src -e ip.dst -E header=y

# Extract HTTP host and URI
tshark -r file.pcap -Y 'http.request' \
  -T fields -e http.host -e http.request.uri -E header=y

# Extract DHCP hostnames (deduplicated, counted)
tshark -r file.pcap -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r

# Extract DNS queries (deduplicated, counted)
tshark -r file.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r

# Extract HTTP User-Agents
tshark -r file.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r
```

### Protocol statistics

```bash
# Protocol hierarchy tree
tshark -r file.pcap -z io,phs -q

# Focus on specific protocol in hierarchy
tshark -r file.pcap -z io,phs,udp -q

# Packet length distribution
tshark -r file.pcap -z plen,tree -q

# IP endpoints
tshark -r file.pcap -z endpoints,ip -q

# IP conversations
tshark -r file.pcap -z conv,ip -q

# DNS statistics
tshark -r file.pcap -z dns,tree -q

# HTTP statistics (packet counter, status codes)
tshark -r file.pcap -z http,tree -q

# HTTP requests breakdown
tshark -r file.pcap -z http_req,tree -q

# Expert info (warnings, errors, retransmissions)
tshark -r file.pcap -z expert -q

# All IP hosts
tshark -r file.pcap -z ip_hosts,tree -q

# Destinations and ports
tshark -r file.pcap -z dests,tree -q
```

### Follow streams

```bash
# Follow TCP stream 0 in ASCII
tshark -r file.pcap -z follow,tcp,ascii,0 -q

# Follow TCP stream 1
tshark -r file.pcap -z follow,tcp,ascii,1 -q

# Follow HTTP stream
tshark -r file.pcap -z follow,http,ascii,0 -q

# Follow UDP stream in hex
tshark -r file.pcap -z follow,udp,hex,0 -q
```

### Export transferred objects

```bash
# Export all files transferred over HTTP
tshark -r file.pcap --export-objects http,/tmp/extracted/ -q

# Export SMB transferred files
tshark -r file.pcap --export-objects smb,/tmp/smb_files/ -q

# Export TFTP files
tshark -r file.pcap --export-objects tftp,/tmp/tftp_files/ -q
```

### Extract cleartext credentials

```bash
# Find FTP/HTTP/IMAP/POP/SMTP credentials
tshark -r credentials.pcap -z credentials -q
```

### Capinfos — PCAP summary

```bash
capinfos file.pcap
# Shows: file size, packet count, duration, first/last packet time, hashes
```

## Tips and gotchas

- **Capture vs display filters**: `-f` is capture (BPF syntax, limits what is saved), `-Y` is display (Wireshark syntax, limits what is shown). They use different syntax.
- **Packet numbering**: TShark assigns numbers from the original file, so filtered output does not start at 1. Pipe to `nl` to count: `tshark -r file.pcap -Y 'http' | nl`
- **Combine with CLI tools**: `tshark` output is plain text — pipe through `grep`, `awk`, `cut`, `sort`, `uniq` for efficient analysis.
- **`-q` flag**: Always use `-q` with `-z` statistics flags to suppress individual packet output.
- **Colourised output**: `tshark --color` for Wireshark-style colour coding in terminal.
- **Field extraction tip**: Use multiple `-e` parameters for multiple fields. Always add `-E header=y` to label columns.
- **Valley CTF pattern**: Credentials extracted from PCAP captures found via FTP enumeration — open pcap in TShark or Wireshark to find cleartext passwords.

## Related techniques

- [[cms-exploitation]] — credential recovery from network captures
- [[cicd-attacks]] — traffic analysis of pipeline communications

## Sources

- THM: TShark Basics (tsharkthebasics)
- THM: TShark CLI Wireshark Features (tsharkcliwiresharkfeatures)
- THM: Security Footage CTF
- THM: SMBv2 decrypt
