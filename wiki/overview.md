---
title: "Overview"
type: overview
date_created: 2026-05-08
date_updated: 2026-07-02
tags: []
sources: []
---

# Overview

*Methodology map and coverage status. Updated after final ingest pass.*

---

## Source corpus

| Course | Files | Ingest scope | Primary value |
|--------|-------|-------------|---------------|
| HackTheBox CPTS | ~237 md + 12 PDFs | All modules (16/16 slugs) | Theory foundation, methodology, tools, network attacks |
| PortSwigger Academy | ~50 md | All modules (11/11 slugs) | Web vuln theory + lab steps |
| TryHackMe | ~365 md total → **~200 effective** | Sections 1,4,5,6,8,10,11,12,13,14 | Real exploitation examples, CVEs, AWS, AD, CMS, advanced web |
| CCDCOE Malware Essentials | 7 md | BOF track (1/1 slug) | x86/x64 Linux BOF, Windows ROP, Windows SEH exploitation |
| HackerOne Paid Reports | ~1,901 reports | 25 vuln categories (bounty > $0) | Real-world exploit patterns, program names, bounty amounts |
| Git: momenbasel/htb-writeups | 54 md | resources/cheatsheets + methodology | HTB machine approach, AD/web/privesc/enumeration cheatsheets, Potato attacks, Certipy ADCS, delegation |
| Research: 0xdf HTB writeups (`raw/research/0xdf-htb`) | ~370 md | 7-wave plan; Waves 1-7 wiki ingest complete (`thm-win-sigma`/hardening still deferred globally) | Enriched tooling pages (`[[netexec]]`, `[[certipy]]`, `[[evil-winrm]]`, … ), AD Kerberos + ADCS pages, Linux web + privesc, Windows AD trilogy, deserialization + container chains, specialty GraphQL/Pollution federation notes, Sink smuggling exemplar |
| Bulk import — InternalAllTheThings | ~170 md in `wiki/techniques/` | Full mirror-style pages with `sources: [InternalAllTheThings]` | Command-oriented reference layered under [[internal-all-the-things]]; curated methodology pages stay canonical where overlap exists |

**Ingested: 96/98 course slugs + 1 git repo slug** — 2 deferred (blue team: `thm-win-sigma`, `thm-win-hardening`)

**THM skipped sections** (duplicate or out of scope): `3. THM CTF` (71% duplicate of topic sections), `9. THM SOC`, `15. THM SOC_SIM`, `2. THM Code`.

---

## Wiki coverage

**~310 markdown notes under `wiki/`** spanning technique pages, 12 domain MOC hubs, tools, cheatsheets, and meta pages. Graph fully connected: navigate via [[moc|Map of Content]]. (~172 technique pages are InternalAllTheThings reference imports under [[internal-all-the-things]].)

### Methodology phases

| Phase | Status | Pages |
|-------|--------|-------|
| Recon & OSINT | Complete | [[wiki/cheatsheets/recon]] cheatsheet, [[wiki/tools/nmap]], [[wiki/tools/ffuf]], [[gobuster]], [[nikto]], [[wiki/tools/rustscan]] |
| Service enumeration | Complete | [[service-enumeration]], [[service-enumeration]] cheatsheet |
| Web exploitation | Complete | 20+ technique pages (see Web section below) |
| Network exploitation | Complete | [[network-service-attacks]], [[network-services]] cheatsheet |
| Password attacks | Complete | [[password-cracking]], [[pass-the-hash]], [[password-attacks]] cheatsheet |
| Post-exploitation | Complete | [[reverse-shells]], [[file-transfer]], [[linux-privesc]], [[linux-privesc]] cheatsheet |
| Active Directory | Complete | [[active-directory]] hub, [[ad-enumeration]], [[ad-lateral-movement]], [[ad-persistence]], [[ad-cheatsheet|Active Directory cheatsheet]] |
| Cloud (AWS) | Complete | [[aws-attacks]], [[cloud-iam-attacks]], [[aws]] cheatsheet |
| Pivoting & Tunneling | Complete | [[pivoting-tunneling]], [[pivoting]] cheatsheet |
| Reporting | Complete | [[vuln-assessment]], [[pentest-methodology]] |

---

## Technique coverage

### Web — Injection
[[sql-injection]] · [[nosql-injection]] · [[os-command-injection]] · [[xxe]] · [[ssti]]

### Web — Server-Side
[[wiki/payloads/ssrf]] · [[file-upload]] · [[path-traversal-lfi]] · [[race-conditions]]

### Web — Authentication & Session
[[authentication-attacks]] · [[access-control]] · [[session-management-attacks]] · [[jwt-attacks]] · [[oauth-attacks]] · [[mfa-bypass]] · [[csrf]]

### Web — Client-Side
[[xss]] · [[dom-attacks]] · [[prototype-pollution]] · [[cors-sop]] · [[http-request-smuggling]]

### Web — Advanced
[[insecure-deserialization]] · [[llm-attacks]] · [[api-security]] · [[api-testing]]

### Active Directory
[[ad-enumeration]] · [[ad-lateral-movement]] · [[ad-persistence]] · [[pass-the-hash]] · [[password-cracking]] · [[uac-bypass]]

### Linux
[[linux-privesc]] · [[docker-attacks]] · [[kubernetes-attacks]] · [[cicd-attacks]] · [[reverse-shells]] · [[file-transfer]] · [[git-exposure]] · [[iot-attacks]]

### Windows
[[applocker-bypass]] · [[seh-exploitation]]

### Network & Services
[[service-enumeration]] · [[network-service-attacks]] · [[pivoting-tunneling]]

### CMS & Apps
[[cms-exploitation]]

### Cloud (AWS / Azure / GCP)
[[aws-attacks]] · [[cloud-iam-attacks]] · [[gcp-attacks]] · [[kubernetes-attacks]] · [[azure-ad-iam]]

### Methodology & Reporting
[[pentest-methodology]] · [[vuln-assessment]] · [[responsible-disclosure]]

### CTF & Specialist
[[cryptography-attacks]] · [[reverse-engineering]] · [[digital-forensics]] · [[steganography]] · [[binary-exploitation]] · [[kernel-exploitation]] · [[memory-safety-bugs]] · [[fuzzing]] · [[nday-patch-diffing]]

### Network Protocols
[[protocol-attacks]] · [[service-enumeration]] · [[network-service-attacks]]

### Mobile & Embedded
[[android-application]] · [[ios-application]] · [[firmware-hardware]] · [[iot-attacks]]

---

## Tools

[[wiki/tools/nmap]] · [[wiki/tools/rustscan]] · [[wiki/tools/ffuf]] · [[gobuster]] · [[nikto]] · [[wiki/tools/httpx]] · [[wiki/tools/nuclei]] · [[hydra]] · [[medusa]] · [[hashcat]] · [[wpscan]] · [[metasploit]] · [[burp-suite]] · [[sqlmap]] · [[netexec]] · [[impacket]] · [[certipy]] · [[evil-winrm]] · [[tshark]] · [[gdb-gef]] · [[radare2]] · [[ghidra]] · [[pwntools]] · [[angr]] · [[volatility]] · [[binwalk]] · [[aflplusplus]] · [[libfuzzer]] · [[semgrep]] · [[codeql]] · [[trivy]] · [[bloodhound]] · [[responder]] · [[subfinder]] · [[gowitness]] · [[ligolo-ng]] · [[frida]] · [[john]] · [[scoutsuite]] · [[pacu]] · [[roadtools]] · [[apktool]] · [[jadx]]

---

## Notable CVEs covered

| CVE | Vulnerability | Page |
|-----|--------------|------|
| CVE-2022-26134 | Confluence OGNL RCE | [[vuln-assessment]] |
| CVE-2021-3156 | sudo heap overflow (Baron Samedit) | [[vuln-assessment]] |
| CVE-2022-0847 | Dirty Pipe kernel privesc | [[linux-privesc]], [[vuln-assessment]] |
| CVE-2023-38408 | OpenSSH agent forwarding RCE | [[vuln-assessment]] |
| CVE-2022-22965 | Spring4Shell RCE | [[vuln-assessment]] |
| CVE-2022-26923 | ADCS ESC1 template abuse | [[uac-bypass]] |
| CVE-2024-21413 | Outlook NTLM leak (MonikerLink) | [[vuln-assessment]] |
| CVE-2023-27350 | PaperCut auth bypass + RCE | [[vuln-assessment]] |
| CVE-2021-29447 | WordPress XXE | [[xxe]] |
| CVE-2021-3493 | OverlayFS Ubuntu privesc | [[linux-privesc]], [[vuln-assessment]] |
| CVE-2019-18634 | sudo pwfeedback overflow | [[vuln-assessment]] |
| CVE-2024-57727 | SimpleHelp path traversal | [[path-traversal-lfi]], [[vuln-assessment]] |
| CVE-2017-0213 | Windows COM elevation | [[uac-bypass]], [[vuln-assessment]] |

---

### HackerOne Paid Reports (added 2026-05-09)
- 1,901 bounty-rewarded reports across 20 categories from H1 Hacktivity API
- All major technique pages now have a "Real-World Examples (HackerOne)" section with real program names, bounties, and attack patterns
- Highest-signal categories: XSS (284), Info Disclosure (184), Access Control (81), CSRF (66), Business Logic (65)
- Re-scrape: `python3 /home/kali/h1-ingest/scrape_hacktivity.py`

## Courses

| Page | Provider | Modules |
|------|----------|---------|
| malware-ccdcoe-essentials-bof | NATO CCDCOE | x86/x64 Linux BOF, Windows ROP, Windows SEH |

---

## Gaps & future work

- **0xdf HTB ingest complete** aside from evergreen maintenance; future passes can mine remaining Insane writeups individually when a technique page needs depth
- **Binary exploitation cheatsheet**: [[binary-exploitation]] is now comprehensive (stack, heap, ROP, SEH, bad chars); a dedicated cheatsheet page would be the logical next step
- **Windows privilege escalation**: now covered, [[windows-privesc]] cheatsheet: Potato attacks, SeBackupPrivilege, service exploitation, UAC bypass, credential harvesting
- **OSINT deep-dive**: [[wiki/cheatsheets/recon]] cheatsheet covers basics; no dedicated OSINT technique page
- **Kubernetes**: [[kubernetes-attacks]] now covers advanced cluster attacks (etcd direct dump, kubelet API, RBAC escalation verbs, node escape)
- **IoT / firmware**: [[iot-attacks]] (MQTT) + [[firmware-hardware]] (binwalk extraction, UART/JTAG/SPI, firmware emulation) now covered
- **CTF + cloud + mobile expansion (2026-06-16)**: added crypto/RE/forensics/stego + GCP + protocol attacks + iOS; hunt skills `hunt-ad`/`hunt-cloud`/`hunt-deserialization` + `ctf-category` router. Remaining: OSINT deep-dive, classical/lattice crypto depth, Azure attack (non-AD) skill
- **Blue team deferred**: Sigma rules (`thm-win-sigma`), Windows hardening (`thm-win-hardening`), add when doing detection engineering work

---

## Active targets

*No targets added yet.*

---

## Platform Coverage

| Platform | Pages | Status | Notes |
|---|---|---|---|
| web | 73 | strong | Injection, auth, client-side, API, advanced |
| active-directory | 94 | strong | ADCS, Kerberos, lateral movement, IATT imports, Azure AD |
| windows | 111 | strong | Post-ex, UAC, AppLocker, WFP, NDIS |
| cloud | 51 | strong | AWS + Azure deep, GCP added, K8s advanced |
| linux | 36 | strong | Privesc, Docker, K8s, kernel, CI/CD |
| network | 26 | strong | Service enum, pivoting, protocol attacks |
| binary | 11 | growing | BOF, heap, fuzzing, crash analysis, RE |
| ctf/specialist | 8 | growing | crypto, reverse-eng, forensics, stego, pwn |
| mobile/embedded | 4 | growing | android, iOS, firmware/hardware, IoT |

Status key: strong (15+ pages), growing (7-14), gap (<7)

*Last updated: 2026-06-16 after CTF + cloud/mobile expansion (see Gaps).*
