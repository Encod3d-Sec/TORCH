---
title: "John the Ripper"
type: tool
tags: [cracking, passwords, hashes, ctf]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: crack
---

## Purpose

**John the Ripper** (the `-jumbo` build) cracks password hashes and, crucially, ships a large family of **`*2john` extractors** that turn files (ZIP, PDF, Office, SSH keys, KeePass, disk images) into crackable hash formats. CPU-focused and format-rich; the companion to GPU-focused [[hashcat]].

## Install / setup

```bash
apt install john          # get the jumbo build for the *2john tools + extra formats
```

## Core usage

```bash
john --wordlist=rockyou.txt hashes.txt          # wordlist
john --wordlist=rockyou.txt --rules hashes.txt  # wordlist + mangling rules
john --format=NT hashes.txt                      # force a format
john --show hashes.txt                           # show cracked
john --incremental hashes.txt                    # brute (Markov)
```

## Common use cases

```bash
# Extract a hash from a file, then crack (the killer feature)
zip2john secret.zip > h ;        john --wordlist=rockyou.txt h
ssh2john id_rsa     > h ;        john h           # passphrase on an SSH key
office2john doc.docx > h ;        john h
pdf2john file.pdf   > h ;        john h
keepass2john db.kdbx > h ;        john h
# many more: rar2john, 7z2john, bitlocker2john, gpg2john, krb5tgs2john ...

# Identify format if unsure
john --list=formats | grep -i <type>
```

## Tips and gotchas
- `--show` reads the **john.pot** cache of cracked hashes (`~/.john/john.pot`); delete it for a clean re-run.
- Rules multiply a wordlist cheaply (`--rules=Jumbo`/`KoreLogic`); `--incremental` for unknown patterns.
- Use John for the `*2john` extraction and odd CPU formats; pipe the resulting hash to [[hashcat]] (`-m`) when you want GPU speed. Methodology: [[password-cracking]], [[hash-capture-and-cracking]].

## Related techniques
[[password-cracking]], [[hash-capture-and-cracking]], [[cryptography-attacks]]. GPU counterpart: [[hashcat]].

## Sources
