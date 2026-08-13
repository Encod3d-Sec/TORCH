---
title: "Digital Forensics"
type: technique
tags: [forensics, ctf, memory, disk, pcap, volatility, incident-response]
phase: post-exploitation
date_created: 2026-06-16
date_updated: 2026-08-13
sources: [pcap-encoded-exfil-reconstruction, cve-2023-32784]
---

## What it is

Recovering evidence and hidden data from disk images, memory dumps, packet captures, and file artifacts. A CTF category and the core skill of incident response / DFIR.

## How it works

Data persists in structure (filesystem metadata, process memory, packet streams) and in slack/deleted regions. Forensics parses these structures and carves data that was deleted, embedded, or in transit.

## Attack phases
Post-exploitation / analysis (CTF forensics; IR; evidence extraction).

## Prerequisites
- The artifact (image/dump/pcap) and its type. For memory: the OS profile/symbols.

## Methodology

### File triage (start here)
```bash
file artifact;  binwalk artifact            # embedded files/signatures ([[binwalk]])
binwalk -e artifact                         # extract; foremost/scalpel for carving
exiftool artifact;  strings -n8 artifact;  xxd artifact | head
```
Wrong/mismatched magic bytes -> fix header. Appended data after EOF -> carve. See [[steganography]] for media-embedded data.

### Memory forensics (Volatility 3)
```bash
vol -f mem.raw windows.info                 # identify build
vol -f mem.raw windows.pslist;  windows.pstree;  windows.cmdline
vol -f mem.raw windows.netscan              # connections
vol -f mem.raw windows.filescan | grep -i flag
vol -f mem.raw windows.dumpfiles --virtaddr 0x...
vol -f mem.raw windows.hashdump;  windows.lsadump;  windows.cachedump
vol -f mem.raw windows.malfind              # injected code
# Linux: linux.pslist / linux.bash (shell history)
```
`bulk_extractor mem.raw -o out` pulls emails, URLs, card numbers, keys.

### Disk forensics
```bash
mmls disk.img;  fls -r -o <offset> disk.img    # sleuthkit: partition + file listing
icat -o <offset> disk.img <inode> > recovered  # extract by inode (incl. deleted)
```
Autopsy GUI for timeline + deleted files. Windows: parse `$MFT`, registry (`regripper`), `NTUSER.dat`, prefetch, `$Recycle.Bin`, browser DBs, event logs (`evtx_dump`).

### Network forensics (pcap)
```bash
tshark -r cap.pcap -q -z io,phs             # protocol hierarchy ([[tshark]])
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri
tcpflow -r cap.pcap;  foremost -i cap.pcap   # reassemble streams / carve files
```
- Wireshark: Follow TCP/HTTP Stream; File > Export Objects (HTTP/SMB/FTP). Credentials in cleartext protocols.
- TLS decrypt: load `SSLKEYLOGFILE`. USB pcap: decode HID keystrokes from `usb.capdata`. ICMP/DNS exfil: reassemble payload bytes.
- **Reassemble a raw TCP exfil stream + reverse its encoding.** A bulk transfer on an odd port is often a staged file (process dump, DB) sent as base64 of XOR'd bytes. Grab the big stream's index from `conv,tcp`, take the client->server direction only, then undo the transform (`0x41` is the example key from one sample; read the dropper for the real key):
```bash
tshark -r cap.pcap -q -z conv,tcp                        # find the largest stream + its index N
tshark -r cap.pcap -q -z follow,tcp,raw,N | grep -E '^[0-9a-f]+$' | tr -d '\n' | xxd -r -p > exfil.b64
python3 -c 'import base64;d=base64.b64decode(open("exfil.b64","rb").read());open("out","wb").write(bytes(b^0x41 for b in d))'
```
- **`[N bytes missing in capture file]` = a truncated/gap-dropped capture, NOT payload.** tshark injects that literal marker into `follow`/`Export` output where bytes were not captured (snaplen or drops). Do not blindly strip it: its text ("bytes missing in capture file") is valid base64 chars, so removing it corrupts and mis-aligns the stream and `base64` silently stops at the first gap (a short, truncated result). Replace each marker with N placeholder chars to preserve length and 4-alignment before decoding:
```bash
python3 -c 'import re,base64;d=open("exfil.b64","rb").read()
d=re.sub(rb"\[(\d+) bytes missing in capture file\]\x00",lambda m:b"A"*int(m.group(1)),d)  # A -> 0x00 filler, keeps offsets
open("out","wb").write(bytes(b^0x41 for b in base64.b64decode(d)))'   # gaps become known filler; captured regions decode intact
```
- **A KeePass process dump (`MDMP` magic) exfiltrated?** Recover the master password with CVE-2023-32784 (all chars but the first, no cracking) then brute the one missing char against the `.kdbx`. See [[password-cracking]] (the dump beats cracking the Argon2 KDF).

### Logs / timeline
`log2timeline.py` + `psort.py` (plaso) for super-timelines; grep auth/access logs for the intrusion path.

## Bypasses and variants
- Corrupted headers: repair PNG/ZIP/PDF magic + CRC (`pngcheck`, `zip -FF`).
- Encrypted volumes: VeraCrypt/BitLocker key in memory dump (`vol ... bitlocker`); ZIP/Office hash -> [[hashcat]].

## Detection and defence
Full-disk encryption, log integrity (append-only/remote), memory-acquisition resistance, secure deletion.

## Tools
`volatility3`, [[binwalk]], Wireshark / [[tshark]], `foremost`, `exiftool`, Autopsy / sleuthkit, `bulk_extractor`, `regripper`, plaso. See [[steganography]], [[encoding-transformations]].

## Sources
