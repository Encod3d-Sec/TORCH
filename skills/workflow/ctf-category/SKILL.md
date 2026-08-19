---
name: ctf-category
description: CTF challenge router - fingerprint a challenge (file type / prompt / artifacts) into its category (pwn, rev, crypto, forensics, stego, web, osint, hash) and route to the matching wiki page, tools, and first moves. Wiki-first.
---

# CTF Category Router

Given a challenge file or description, identify the category, then read the matching wiki page and apply its methodology. Always `file` the artifact and read the prompt before choosing.

## Fingerprint -> route

| Signal | Category | Wiki page | First moves / tools |
|---|---|---|---|
| ELF/PE binary + "get a shell" / nc to a port | **pwn** | [[binary-exploitation]] | `checksec`; find offset (`cyclic`); [[pwntools]] template; leak libc |
| Binary + "find the flag" / crackme / no network | **rev** | [[reverse-engineering]] | `file`,`strings`,`checksec`; [[radare2]]/Ghidra; `ltrace`; angr |
| `n,e,c` / .pem / cipher / "encrypt" / base-looking blob | **crypto** | [[cryptography-attacks]], [[crypto-ctf-workflow]] | identify primitive; `RsaCtfTool`; padding/XOR/hash-ext; CyberChef |
| .sol file / ABI+bytecode / contract address / web3 RPC endpoint | **blockchain** | [[smart-contract-web3-attacks]], [[defi-amm-exploitation]] | [[slither]] static analysis; Foundry/Hardhat local fork to reproduce; flash-loan/AMM economic-exploit sims for DeFi |
| .pcap / .raw memory / disk image / .E01 | **forensics** | [[digital-forensics]] | `file`,`binwalk`; [[volatility]] (mem); [[wiki/tools/tshark]]/Wireshark (pcap) |
| Innocuous image/audio / "look closer" | **stego** | [[steganography]] | `exiftool`,`binwalk`,`strings`; `zsteg`/`steghide`/`stegseek`; spectrogram |
| URL / web app | **web** | existing hunt skills | auto-triggers (sqli/xss/ssrf/idor/injection...) via triggers.json |
| Cloud creds/console (Azure TAP+SP, `*.core.windows.net`, AWS keys, GCP) - no ports, only a REST/console surface | **cloud** | [[cloud-moc]], [[cloud-iam-attacks]] | `Skill(hunt-cloud)`: whoami; enumerate storage/SAS/blob + Key Vault (incl. prior secret versions) / IMDS - NOT the network-box driver |
| `$hash` / NTLM / shadow / zip2john | **hash/crack** | [[hash-capture-and-cracking]] | identify (`hashid`); [[wiki/tools/hashcat]] mode; [[password-cracking]] |
| "find the account/person/leak" / no file | **osint** | [[persona-tracing]], [[secret-hunting]], [[web-attack-surface]] | person pivots + photo geolocation; [[git-exposure]] for repos |
| python `>>>` jail / restricted shell / filtered interpreter | **misc/jail** | [[ctf-jail-escapes]] | builtins/mro recovery, format-string pyjail, GTFOBins rbash escape |

## Procedure
1. `file challenge.*`; read the prompt; note the remote (`nc host port`) if any.
2. Match the strongest signal above (multiple may apply -> start with the most specific).
3. `qmd_query "<category> <specific tech>"` -> read the wiki page; apply its methodology + payloads.
4. Re-fingerprint every extracted artifact (stego/forensics nest: image -> zip -> binary).
5. Flag found -> note the technique. Novel trick -> **Wiki Feedback**: update the category page so it is captured.

## Self-heal
If a category page is missing or thin for the technique used, add a `## <technique>` section (or stub the page) before moving on, so the gap fills. Pages: crypto/[[cryptography-attacks]], rev/[[reverse-engineering]], forensics/[[digital-forensics]], stego/[[steganography]], pwn/[[binary-exploitation]] + heap/[[heap-exploitation]], misc-jail/[[ctf-jail-escapes]].

Report: category chosen + flag/blocker + any wiki update.
