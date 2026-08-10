---
title: "CeWL (Custom Word List generator)"
type: tool
tags: [brute-force, cracking, tool, web, wordlist]
date_created: 2026-07-16
date_updated: 2026-07-16
sources: []
phase: recon
---

## Purpose

**CeWL** crawls a target website and builds a wordlist from the words that appear on it. Reach for it when a login's passwords likely come from the organisation's own site vocabulary (careers page, product names, company values, jargon) rather than a generic dictionary.

## Install / setup

Pre-installed on Kali. Install on Debian-based systems:

```bash
sudo apt install cewl
```

## Core usage

```bash
cewl -d 2 -m 5 -w words.txt http://target/
```

| Flag | Description |
|------|-------------|
| `-d N` | Crawl depth |
| `-m N` | Minimum word length |
| `-w FILE` | Write wordlist to file |
| `--lowercase` | Normalise all words to lowercase |
| `-a` / `--meta` | Also pull metadata authors from documents found |
| `--with-numbers` | Include words containing numbers |

## Common use cases

```bash
# Depth-2 crawl, min word length 5, lowercase, save to file
cewl -d 2 -m 5 -w words.txt --lowercase http://target/

# Include numeric words and document metadata authors (may reveal usernames too)
cewl -d 3 -m 5 -a --with-numbers -w words.txt https://target.com
```

## Combine with mutation rules

CeWL output is raw site vocabulary; it does not add capitalisation, years, or special chars itself. Feed it into a mangling step before brute forcing:

```bash
# hashcat rules
hashcat --force words.txt -r /usr/share/hashcat/rules/best64.rule --stdout | sort -u > mangled.txt

# or john rules
john --wordlist=words.txt --rules --stdout > mangled.txt
```

Or pipe CeWL's words into [[cupp]]'s "keywords" field when the password may blend company vocabulary with the target's personal info. Then feed the resulting list to [[hydra]] against the login.

## Tips and gotchas

- `--lowercase` matters: without it CeWL preserves page casing, which can miss lowercase-only password variants (or vice versa) unless you mangle afterward anyway.
- `-a`/`--meta` pulling document author metadata can double as a username-enumeration side effect on sites that host PDFs/Office docs.
- Depth (`-d`) beyond 2-3 gets noisy fast on large sites; start shallow and widen only if the initial list looks thin.

## Related techniques

- [[cupp]]: combine site keywords with personal-info mutation rules
- [[hydra]]: feed the generated (and mangled) wordlist to `-P`
- [[password-cracking]], [[password-attacks]]

## Sources
