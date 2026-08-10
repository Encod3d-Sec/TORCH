---
title: "searchsploit (Exploit-DB CLI)"
type: tool
tags: [exploitation, cve, recon, quick-win, exploit-db, methodology]
date_created: 2026-07-21
date_updated: 2026-07-21
sources: []
phase: exploit
---

# searchsploit (Exploit-DB CLI)

Repo: `https://gitlab.com/exploit-database/exploitdb` (the local mirror of `exploit-db.com`)

## Purpose

`searchsploit` is the offline command-line search over the Exploit-DB archive shipped in Kali
(`/usr/share/exploitdb`). The instant a service is fingerprinted to a **product + version**, it tells you
whether a public exploit/PoC already exists, and hands you the code to read or copy. It is half of the
**version -> quick win reflex** (the other half is a [[metasploit]] module search): most boot-to-root
footholds are a ready PoC away once the version is pinned, and hand-rolling before checking is the recurring
time sink. Run BOTH the moment you have a version:

```bash
searchsploit <product> <version>                    # local Exploit-DB
msfconsole -qx "search <product>; exit"             # ready use-able modules
```

## Installation

Preinstalled on Kali/Parrot. Elsewhere:

```bash
sudo apt install -y exploitdb          # Debian/Kali
# or clone the mirror and symlink:
git clone https://gitlab.com/exploit-database/exploitdb
searchsploit -u                        # update the local copy (git pull + refresh)
```

## Usage

```bash
searchsploit blogengine 3.3            # match by product + version (AND of terms)
searchsploit -x 47010                  # READ the exploit (by EDB-ID or path) before running it
searchsploit -m 47010                  # MIRROR (copy) the exploit into the current dir
searchsploit -p 47010                  # print the full path to the exploit file
searchsploit --nmap nmap-svc.xml       # feed an nmap -oX scan; auto-search every detected service
searchsploit -j apache 2.4             # JSON output (scriptable)
searchsploit -w wordpress              # include exploit-db.com URLs in the results
searchsploit -t <term>                 # search TITLES only (fewer false hits than full-text)
searchsploit --exclude="DoS|/dos/"     # drop noise (e.g. denial-of-service entries)
```

## Reflex / notes

1. Fingerprint (`nmap -sCV`, `whatweb`) gives `<product> <version>` -> immediately
   `searchsploit <product> <version>` **and** `msfconsole -qx "search <product>"`.
2. A hit -> `searchsploit -x <id>` (read it, understand what it does + its required auth/preconditions),
   then `-m <id>` to copy. Prefer the documented/ready PoC over writing a fresh one (GATE 1: a canned
   searchsploit/msf exploit for a known version IS the wiki-blessed tool).
3. **CVE/EDB numbers are widely conflated** -- one EDB id can map to a differently-numbered CVE, and one bug
   gets cited under several CVEs. Trust the PoC's actual behaviour + its affected-version string, not the
   label (e.g. BlogEngine.NET's theme-RCE `47010.py` is variously cited as CVE-2019-6714/-10719/-10720).
4. **Read stock PoCs before running** -- many hardcode a proxy (`127.0.0.1:8080`), a fragile regex login
   that drops ASP.NET `__VIEWSTATE`/`__EVENTVALIDATION`, or a wrong endpoint path; fix these locally.
5. `--nmap` on an `-oX` scan turns a full port sweep straight into a candidate-exploit list.

## See also
- [[metasploit]] · [[cve-arsenal]] · [[nday-patch-diffing]] (no public PoC -> patch-diff / n-day research) · [[service-enumeration]]
