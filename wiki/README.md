# TORCH Wiki

A living offensive-security reference: 450+ cross-linked technique pages, payload
arsenals, tool references, and cheatsheets. Built in Obsidian and indexed for
semantic search, so hunt skills consult it before attacking.

Pages cross-link with Obsidian `[[wikilinks]]` and a graph map-of-content, clickable inside
Obsidian. On GitHub, browse via the directory links below.

## Techniques

| Domain | Pages | Domain | Pages |
|---|---|---|---|
| [Active Directory](techniques/active-directory/) | 102 | [Cloud](techniques/cloud/) | 51 |
| [Web](techniques/web/) | 67 | [Exploit Dev](techniques/exploit-dev/) | 18 |
| [Network](techniques/network/) | 17 | [Red Team](techniques/red-team/) | 15 |
| [macOS](techniques/macos/) | 10 | [Methodology](techniques/methodology/) | 10 |
| [OSINT](techniques/osint/) | 7 | [Cracking](techniques/cracking/) | 6 |
| [Linux](techniques/linux/) | 6 | [Mobile / IoT](techniques/mobile-iot/) | 5 |
| [Forensics](techniques/forensics/) | 2 | [Blockchain](techniques/blockchain/) | 1 |

## Arsenal

- [Payloads](payloads/) - per-vulnerability-class payload sets (SQLi, XSS, SSRF, SSTI, XXE, IDOR, deserialization, and more)
- [Tools](tools/) - per-tool references (nmap, ffuf, nuclei, httpx, sqlmap, BloodHound, netexec, ...)
- [Cheatsheets](cheatsheets/) - quick-reference command sheets and default-credential tables

## Recent additions

**HackTricks methodology ingest** (synthesized and attributed, `sources: hacktricks-*`):

- New [macOS](techniques/macos/) area (TCC, Gatekeeper, code-signing, sandbox escape, SIP, dylib injection, keychain, persistence, MDM)
- Deeper [Exploit Dev](techniques/exploit-dev/) (format-string, ROP, ARM64, malware-analysis, heap)
- [Linux](techniques/linux/) privesc plus new D-Bus and container/Kubernetes escape pages
- Android / iOS enrichment, and new [Blockchain / Web3](techniques/blockchain/) and [physical-attacks](techniques/red-team/physical-attacks.md) pages

**2026 CVE research** (from public forks; single-source, verify against vendor advisories):

- [Linux kernel rootkits (LKM / ftrace-hooking)](techniques/linux/linux-rootkits.md) - modern 6.x LKM stealth and detection
- Drupal JSON:API PostgreSQL SQLi (CVE-2026-9082) in [SQL Injection](techniques/web/sql-injection.md)
- 2026 kernel LPEs (futex requeue-PI, netfilter IDLETIMER, IPv6 RPL SRH, pidfd FD-theft) in [Kernel Exploitation](techniques/exploit-dev/kernel-exploitation.md)
- WS2025 local NTLM reflection to SYSTEM (CVE-2026-24294) in [Internal NTLM Relay](techniques/active-directory/internal-ntlm-relay.md)
- Chrome / Firefox renderer RCE plus all the above in the [CVE Arsenal](cheatsheets/cve-arsenal.md)

## License

MIT, see [../LICENSE](../LICENSE).
