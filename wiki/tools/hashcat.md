---
title: "Hashcat"
type: tool
tags: [cracking, passwords, hashes, gpu, ctf]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: crack
---

## Purpose

**Hashcat** is the GPU-accelerated password recovery tool: it cracks captured hashes (NTLM, Kerberos, web app, archive, disk) using wordlists, rules, masks, and hybrid attacks. The offline counterpart to online tools like [[wiki/tools/hydra]].

## Install / setup

```bash
apt install hashcat        # or download binaries; needs GPU drivers (OpenCL/CUDA) for speed
hashcat -b                 # benchmark / verify devices
```

## Core usage

```bash
hashcat -m <mode> -a <attack> hashes.txt <wordlist|mask> [-r rules]
hashcat -m 1000 ntlm.txt rockyou.txt -O                 # straight wordlist (-O optimized)
hashcat -m 0 hashes.txt rockyou.txt -r rules/best64.rule  # wordlist + rules
hashcat --show -m 1000 ntlm.txt                          # display cracked
```

## Common use cases

```bash
# Identify mode first
hashid '$2y$...'                    # or name-that-hash; then pick -m

# Mask (brute a known pattern): ?l lower ?u upper ?d digit ?s symbol ?a all
hashcat -m 0 hash.txt -a 3 '?u?l?l?l?l?d?d?s'           # e.g. Summer25!
# Hybrid: word + mask
hashcat -m 0 hash.txt -a 6 rockyou.txt '?d?d?d'

# AD / network capture modes
hashcat -m 18200 asrep.txt rockyou.txt -r rules/best64.rule    # AS-REP roast
hashcat -m 13100 kerberoast.txt rockyou.txt -r rules/best64.rule  # Kerberoast TGS
hashcat -m 5600 responder-ntlmv2.txt rockyou.txt              # NTLMv2 (Responder)
hashcat -m 22000 capture.hc22000 wordlist.txt                # WPA/WPA2

# CTF / archive modes (extract hash with *2john first)
zip2john f.zip > h;  hashcat -m 17210 h rockyou.txt          # PKZIP
office2john / pdf2john / ssh2john -> matching -m
```

## Tips and gotchas
- `-m` (hash mode) is everything: look it up in `hashcat --help | grep -i <type>` or use `hashid`/name-that-hash.
- `-O` (optimized kernel) is much faster but caps password length (~31); drop it for long candidates.
- Rules multiply a wordlist cheaply: `best64`, `OneRuleToRuleThemAll`. Mask attack for known composition; `--increment` to grow length.
- Potfile (`~/.local/share/hashcat/hashcat.potfile`) caches cracks - `--show` reads it; `--potfile-disable` for clean runs.
- Online auth instead of hashes -> [[wiki/tools/hydra]]. Methodology: [[password-cracking]], [[hash-capture-and-cracking]].

## Related techniques
[[password-cracking]], [[hash-capture-and-cracking]], [[kerberos-attacks]], [[cryptography-attacks]]. AD capture via [[netexec]]/[[impacket]].

## Sources
