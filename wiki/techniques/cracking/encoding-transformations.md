---
title: "Encoding & Transformations"
type: technique
tags: [bypass, evasion, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [payloadsallthethings]
---

# Encoding and Transformations

## What it is
Encoding and transformations change how data is represented. Attackers use these methods as gadgets to bypass input filters, WAFs, or sanitization routines.

## Unicode Normalization
Unicode normalization converts text into a standardized form. Vulnerabilities arise when an application sanitizes input, but a subsequent system or library normalizes it into a malicious payload.

### Common Normalization Bypasses
*   `‥` (U+2025) normalizes to `..` -> Path Traversal (`‥/‥/etc/passwd`)
*   `＇` (U+FF07) normalizes to `'` -> SQL Injection (`＇ or ＇1＇=＇1`)
*   `＜` (U+FF1C) normalizes to `<` -> XSS (`＜img src=a＞`)
*   `ｐ` (U+FF50) normalizes to `p` -> Extension Bypass (`shell.ｐʰｐ`)

## Punycode
Punycode represents Unicode characters using ASCII (used in IDNs).
*   Visible: `раypal.com` (Cyrillic 'р')
*   Actual: `xn--ypal-43d9g.com`
*   In some SQL collations (like `utf8mb4_0900_as_cs`), similar characters are treated as equal (`'a' = 'ᵃ'`), which can bypass password resets or OAuth checks.

## Base64
Often used to smuggle payloads past simple WAFs.
```bash
echo -n "payload" | base64
```

## External Variable Modification (PHP)
In PHP, functions like `extract($_GET)` import user-controlled data into the global scope. By default (`EXTR_OVERWRITE`), this overwrites existing variables.
```php
// If extract is used:
extract($_GET);
// Attackers can pass ?authenticated=1 or ?page=../../etc/passwd
```
**Fix:** Always use `extract($_GET, EXTR_SKIP)`.

## Identifying an unknown base-encoded blob (CTF)

When a challenge hands you a gibberish blob that looks base-encoded (mixed case, digits, punctuation) and the format is unknown, reach for an automated detector BEFORE hand-rolling a decoder:

- `basecrack -m` (github.com/mufeedvh/basecrack): heuristically identifies the base and decodes. Fastest first move.
- `ciphey`: broader auto-solver (bases plus classical ciphers).
- CyberChef **Magic** (intensive mode): flags the base and chains likely follow-on ops.

Only hand-roll a custom decoder after all three whiff. On an unknown-encoding wall, fan a tool-brute out in parallel with any manual attempt; it usually wins in a fraction of the time.

### The output charset pins the base
The punctuation an encoding is ALLOWED to emit is the fastest fingerprint:

| Tell in the blob | Base | Why |
|---|---|---|
| Only `A-Za-z0-9+/=` | Base64 | standard alphabet |
| Only `A-Z2-7` | Base32 | |
| `!`..`u` (33-117) incl `\` `'` `,` but NOT `v`-`z` | Ascii85 / Adobe base85 | contiguous 33-117 |
| Z85 set `.-:+=^!/*?&<>()[]{}@%$#` (no `\` `'` `,`) | Z85 | ZeroMQ |
| **`\` and `'` BOTH present** | **Base92** | the only common base whose alphabet contains both backslash and apostrophe |

So if Ascii85 / Z85 / RFC1924 all fail AND the data contains `\` and `'`, it is almost certainly **Base92**.

### Base92
- Alphabet (Nathan Hwang / thenoviceoof variant): `!`=0, `#`..`_` = 1..61, `a`..`}` = 62..90 (91 index values), packed 2 chars into 13 bits.
- Length tell: about 1.23 chars per byte, so a 16-byte payload becomes 20 chars and a 17-byte payload becomes 21 chars. Those odd lengths break the clean 5-into-4 grouping of true base85, another hint it is Base92.
- Decode:
  - CyberChef: `From Base92` (prepend a **Fork** with `\n` delimiters to decode several lines at once).
  - basecrack: uses its bundled `src/base92.py` `base92_decode`.
  - Python gotcha: the `base92` PyPI package wants `bytes`, not `str`, and errors on a plain string. Use basecrack's bundled module, or a short reimplementation (2 chars -> `x = ord0*91 + ord1` -> 13 bits, trailing single char -> 6 bits, then regroup to bytes).

### Worked pattern
GPS coordinates hidden in the HTTP `X-Coordinates` header of each request in a pcap decoded (Base92) straight to plain `lat,lng` text; reverse-geocoding each pair (nominatim) named the towns. General lesson: binary-looking base output is not always binary, decode first, then interpret.

Cross-reference: [[digital-forensics]] (pcap header/stream extraction), [[cryptography-attacks]] (CTF crypto route), [[wiki/tools/tshark]].

<!-- promoted-slug: base-encoding-identification -->
