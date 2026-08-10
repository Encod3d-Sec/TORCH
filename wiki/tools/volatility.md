---
title: "Volatility"
type: tool
tags: [ctf, forensics, memory, dfir, incident-response]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**Volatility** is the standard memory-forensics framework: it parses RAM dumps to recover processes, network connections, injected code, credentials, and files. Volatility 3 (`vol`) is current; many writeups still use Volatility 2 (`vol.py --profile=`).

## Install / setup

```bash
pipx install volatility3        # `vol` ; auto-detects OS (no profile needed)
# Vol2 legacy: git clone volatilityfoundation/volatility ; python2 vol.py
```

## Core usage

```bash
vol -f mem.raw windows.info      # confirm image + build
vol -f mem.raw <plugin>          # plugins are namespaced: windows.* / linux.* / mac.*
```

## Common use cases

```bash
# Processes + command lines
vol -f mem.raw windows.pslist
vol -f mem.raw windows.pstree
vol -f mem.raw windows.cmdline

# Network
vol -f mem.raw windows.netscan

# Files: find then dump
vol -f mem.raw windows.filescan | grep -i flag
vol -f mem.raw windows.dumpfiles --virtaddr 0x<addr>

# Credentials
vol -f mem.raw windows.hashdump        # SAM (NTLM)
vol -f mem.raw windows.lsadump         # LSA secrets
vol -f mem.raw windows.cachedump       # cached domain creds

# Injected / hidden code
vol -f mem.raw windows.malfind

# Registry
vol -f mem.raw windows.registry.printkey --key "Software\\Microsoft\\..."

# Linux
vol -f mem.raw linux.pslist
vol -f mem.raw linux.bash              # recovered shell history
```

## Tips and gotchas
- Vol3 needs no profile but needs matching symbol tables for the OS build; drop custom ISF JSON into the symbols dir for uncommon kernels.
- Vol2 syntax differs: `vol.py -f mem.raw --profile=Win7SP1x64 pslist`. Identify with `imageinfo` (vol2) / `windows.info` (vol3).
- `windows.bash`/`linux.bash`, `cmdline`, and `consoles` often hold the flag directly. `bulk_extractor` complements Volatility for raw string/key carving.

## Related techniques
[[digital-forensics]], [[steganography]]. Cracked hashes -> [[hashcat]], [[password-cracking]].

## Sources
