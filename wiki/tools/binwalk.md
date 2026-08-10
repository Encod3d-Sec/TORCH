---
title: "binwalk"
type: tool
tags: [ctf, forensics, firmware, file-carving, steganography]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**binwalk** scans a file for embedded files and known signatures, then extracts them. Primary uses: firmware unpacking (filesystem + kernel extraction) and CTF forensics/stego (files hidden inside other files).

## Install / setup

```bash
pip install binwalk            # or apt install binwalk
# extraction extras: apt install mtd-utils jefferson sasquatch unblob
```

## Core usage

```bash
binwalk firmware.bin           # signature scan (offsets + descriptions)
binwalk -e firmware.bin        # extract known types to _firmware.bin.extracted/
binwalk -Me firmware.bin       # recursive (matryoshka) extract
binwalk --dd='.*' file         # carve everything regardless of signature
```

## Common use cases

```bash
# Firmware: pull the root filesystem and inspect
binwalk -Me router.bin
ls _router.bin.extracted/      # squashfs-root/, etc -> grep for creds/keys/binaries
grep -rIn "password\|BEGIN .*PRIVATE KEY" _router.bin.extracted/
```
```bash
# CTF: file hidden after an image's EOF (very common)
binwalk image.png              # shows e.g. "Zip archive data" at offset N
binwalk -e image.png           # extracts the zip
```
```bash
# Entropy: spot encrypted/compressed regions (flat high entropy = encrypted)
binwalk -E firmware.bin
```

## Tips and gotchas
- `-e` only extracts signature-known types and respects an extraction allowlist; use `--dd='.*'` or `dd` manually for odd offsets, or try `unblob` for stubborn firmware.
- Squashfs extraction often needs `sasquatch` (vendor-patched); JFFS2 needs `jefferson`.
- Always re-run binwalk/`file`/`exiftool` on every extracted artifact - payloads nest. Pair with [[steganography]] triage.

## Related techniques
[[digital-forensics]], [[steganography]]. Firmware app layer -> mobile-iot pages.

## Sources
