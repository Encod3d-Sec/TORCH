---
title: "Service Enumeration"
type: technique
tags: [enumeration, htb, linux, network, recon, windows]
phase: enumeration
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-footprinting, cpts-nmap]
---

# Service Enumeration

## What It Is

Service enumeration is the process of identifying network services running on target hosts, then extracting version information, configuration details, and accessible data from each service. It bridges initial port scanning with targeted exploitation by revealing exactly what software is running and how it is configured.

## How It Works

Service enumeration proceeds through three mechanisms:

**Banner grabbing** — Most services transmit a plaintext or structured banner on connection that reveals the software name, version, and sometimes OS. Tools like `nc`, `telnet`, and `openssl s_client` capture these directly. Nmap's `-sV` flag automates version detection by sending probes and matching responses against a signatures database.

**Version detection and NSE scripts** — Nmap's Scripting Engine (NSE) runs service-specific Lua scripts that perform structured queries beyond simple banner reading. Scripts like `smtp-commands`, `ms-sql-info`, `oracle-sid-brute`, and `ipmi-version` extract structured data unavailable from banners alone.

**Manual interaction** — For protocols that are text-based (FTP, SMTP, IMAP, POP3), direct interaction with `telnet`, `nc`, or `openssl s_client` allows issuing protocol commands to enumerate users, folders, and capabilities. For encrypted channels, `openssl s_client -connect <target>:<port>` establishes the session before issuing plaintext commands.

## General Methodology

1. **Nmap first pass** — Full port scan with service/version detection on all discovered hosts. Use [[wiki/tools/nmap]] as the foundation.
2. **Service-specific tooling** — Run dedicated tools for each discovered service (rpcclient, smbclient, snmpwalk, odat, etc.).
3. **Manual verification** — Confirm findings by directly connecting to the service and issuing protocol commands.
4. **Cross-reference** — Credentials found in one service (e.g., FTP) may unlock another (e.g., SSH). Check for password reuse. See [[pass-the-hash]] when NTLM hashes are obtained.

---

## Pre-Engagement: Passive Recon

Before touching any live service, passive recon reveals the attack surface.

### Domain and Certificate Transparency

SSL certificates registered with Certificate Transparency logs expose subdomains:

```bash
# Enumerate subdomains via CT logs
curl -s "https://crt.sh/?q=<domain>&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

DNS records expose mail servers, name servers, SPF entries, and third-party services in use:

```bash
dig any <domain>
```

TXT records frequently reveal: Microsoft 365, Google Workspace, Atlassian, LogMeIn, Mailgun — each indicating a potential attack surface or credential reuse vector.

### Company-Hosted Servers

```bash
# Resolve subdomains and extract IPs
for i in $(cat subdomainlist); do host $i | grep "has address" | grep <domain> | cut -d" " -f1,4; done

# Cross-reference IPs with Shodan
for i in $(cat ip-addresses.txt); do shodan host $i; done
```

### Cloud Storage Discovery

Misconfigured cloud storage (S3 buckets, Azure blobs, GCP storage) often contains sensitive files including private SSH keys.

```
# Google dorks
intext:<company> inurl:amazonaws.com
inurl:blob.core.windows.net
```

Search GrayHatWarfare (https://buckets.grayhatwarfare.com/) for public cloud storage buckets.

### Staff OSINT

LinkedIn, Xing, and GitHub profiles reveal:
- Technologies and frameworks in use (from job postings and skills)
- Programming languages and databases
- Hardcoded credentials or JWT tokens in public repositories
- Personal email addresses that can be used for phishing or password spraying

---

## FTP (TCP 21)

FTP transfers files in cleartext. Anonymous login is a frequent misconfiguration. With write access, files can be planted for later execution.

**What it exposes:** File listings and content, server software version, sometimes credential files if misconfigured anonymous access is broad.

**Key files to look for:** Configuration files, scripts, database dumps, SSH keys, password files.

```bash
# Nmap scan with all FTP scripts
sudo nmap -sV -p21 -sC -A <target>

# Nmap script trace (see the full NSE interaction)
sudo nmap -sV -p21 -sC -A <target> --script-trace

# Anonymous download of all available files
wget -m --no-passive ftp://anonymous:anonymous@<target>

# Manual banner grab
nc -nv <target> 21
telnet <target> 21

# Interact with FTPS (FTP over TLS)
openssl s_client -connect <target>:21 -starttls ftp

# Upload a file (from within ftp session)
put testupload.txt
```

---

## SMB (TCP 139, 445)

SMB (Server Message Block) provides file sharing, printer sharing, and named pipe IPC on Windows and Samba (Linux). SMBv1 is deprecated and should be noted. Null session access (no credentials) often exposes share listings and user information.

**What it exposes:** Share names and permissions, OS version, domain/workgroup, usernames via RID cycling, password policy, sometimes open readable shares with sensitive files.

**Key files to look for:** `prep-prod.txt`, config files, password files, scripts in development shares.

```bash
# Nmap SMB scan
sudo nmap <target> -sV -sC -p139,445

# List shares with null session
smbclient -N -L //<target>

# Connect to a specific share
smbclient //<target>/<share>

# Download a file from SMB session
smb: \> get <filename>

# Check SMB status from server side
smbstatus

# Enumerate shares with smbmap (null session)
smbmap -H <target>

# Enumerate with credentials
smbmap -H <target> -u '<user>' -p '<pass>' -r <share>

# Connect with credentials
smbclient //<target>/<share> -U <user>

# CrackMapExec - enumerate shares null session
crackmapexec smb <target> --shares -u '' -p ''

# RPC enumeration (null session)
rpcclient -U "" <target>

# RID brute-force via rpcclient (users 500-1100)
for i in $(seq 500 1100); do rpcclient -N -U "" <target> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""; done

# Impacket samrdump (brute-forces RIDs automatically)
impacket-samrdump <target>

# Enum4linux-ng full enumeration
./enum4linux-ng.py <target> -A
```

Note: SMB credentials enable [[pass-the-hash]] attacks. See also [[sql-injection]] if MSSQL is co-located.

---

## NFS (TCP 111, TCP/UDP 2049)

NFS (Network File System) allows remote filesystem mounts. Misconfigured exports (especially with `no_root_squash`) allow full read/write access as root, and can expose SSH keys and other sensitive files.

**What it exposes:** Exported share paths, file ownership (UIDs/GIDs), contents of mounted shares including SSH private keys.

**Dangerous settings:** `rw`, `insecure`, `nohide`, `no_root_squash` — the last allows root on the client to act as root on the share.

**Default config file:** `/etc/exports`

```bash
# Nmap NFS scan
sudo nmap <target> -p111,2049 -sV -sC

# NSE scripts for NFS
sudo nmap --script nfs* <target> -sV -p111,2049

# Show exported shares
showmount -e <target>

# Mount the NFS share
mkdir target-NFS
sudo mount -t nfs <target>:/ ./target-NFS/ -o nolock
cd target-NFS
tree .

# List with usernames and group names
ls -l mnt/nfs/

# List with UIDs and GUIDs (useful for impersonation)
ls -n mnt/nfs/

# Unmount when done
sudo umount ./target-NFS
```

**Privilege escalation note:** If `no_root_squash` is set, create a binary with the SUID bit of a target user on the NFS share, then execute it via another access vector (e.g., SSH) to read files owned by that user.

---

## DNS (UDP/TCP 53)

DNS is often overlooked as a recon source. Misconfigured zone transfers expose the entire internal network topology.

**DNS record types:**

| Record | Description |
|--------|-------------|
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `MX` | Mail servers |
| `NS` | Name servers |
| `TXT` | SPF, DMARC, DKIM, verification codes |
| `CNAME` | Aliases |
| `PTR` | Reverse lookup |
| `SOA` | Zone authority and admin email |

**Dangerous settings:** `allow-transfer any` permits zone transfers to any host.

```bash
# Query name servers
dig ns <domain> @<dns-server>

# Query DNS version (CHAOS class)
dig CH TXT version.bind <target>

# Query all available records
dig any <domain> @<target>

# Zone transfer (dumps entire zone)
dig axfr <domain> @<target>

# Zone transfer on internal subdomain
dig axfr internal.<domain> @<target>

# Subdomain brute-force (manual loop)
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do
  dig $sub.<domain> @<dns-server> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt
done

# dnsenum automated subdomain enumeration
dnsenum --dnsserver <dns-server> --enum -p 0 -s 0 -o subdomains.txt \
  -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt <domain>
```

Zone transfers revealing internal hostnames (e.g., `dc1.internal.<domain>`, `vpn.internal.<domain>`) provide the internal network map for further targeting.

---

## SMTP (TCP 25, 465, 587)

SMTP handles email transmission. Key attack vectors: user enumeration via `VRFY`/`EXPN`, open relay abuse for spam/spoofing.

**What it exposes:** Valid usernames (via VRFY), relay configuration, mail infrastructure details, internal hostnames in banners.

**Mail flow:** MUA → MSA → MTA (Open Relay) → MDA → Mailbox (POP3/IMAP)

**Dangerous settings:** `mynetworks = 0.0.0.0/0` creates an open relay allowing spoofed email from any source.

```bash
# Nmap SMTP scan (smtp-commands script uses EHLO)
sudo nmap <target> -sC -sV -p25

# Test for open relay (16 different tests)
sudo nmap <target> -p25 --script smtp-open-relay -v

# Manual SMTP interaction
telnet <target> 25

# SMTP commands within telnet session:
# HELO mail1.domain.htb
# EHLO domain.htb
# VRFY root              # enumerate users
# VRFY <username>
# MAIL FROM: <sender@domain.htb>
# RCPT TO: <recipient@domain.htb> NOTIFY=success,failure
# DATA
# <message body>
# .
# QUIT

# Automated user enumeration
smtp-user-enum -M VRFY -U ./footprinting-wordlist.txt -t <target> -m 60 -w 20
```

---

## IMAP / POP3 (TCP 110, 143, 993, 995)

IMAP allows remote email management with folder structures. POP3 downloads locally. Both can transmit credentials in cleartext if not using TLS.

**Ports:** IMAP=143 (plaintext/STARTTLS), IMAP=993 (SSL/TLS); POP3=110 (plaintext), POP3=995 (SSL/TLS)

**What it exposes:** Email contents (including internal communications, credentials, flags), folder structure, usernames, server hostnames in certificates.

**Dangerous settings:** `auth_debug_passwords` logs submitted passwords in plaintext. `auth_anonymous_username` allows anonymous login.

```bash
# Nmap IMAP/POP3 scan
sudo nmap <target> -sV -p110,143,993,995 -sC

# cURL IMAP listing (lists mailboxes)
curl -k 'imaps://<target>' --user <user>:<pass>

# cURL verbose (shows TLS negotiation and capabilities)
curl -k 'imaps://<target>' --user <user>:<pass> -v

# OpenSSL POP3S manual interaction
openssl s_client -connect <target>:pop3s

# OpenSSL IMAPS manual interaction
openssl s_client -connect <target>:imaps
```

**IMAP commands (in openssl/telnet session):**
```
tag0 LOGIN <user> <pass>
tag1 LIST "" "*"
tag2 SELECT INBOX
tag2 SELECT "DEV.DEPARTMENT.INT"
tag3 FETCH 1 (BODY[])
tag4 LOGOUT
```

**POP3 commands:**
```
USER <username>
PASS <password>
STAT
LIST
RETR <id>
DELE <id>
QUIT
```

---

## SNMP (UDP 161, 162)

SNMP manages and monitors network devices. Versions 1 and 2c transmit community strings in plaintext. Community strings act as passwords — `public` (read) and `private` (write) are common defaults.

**What it exposes:** System info (OS, hostname, location, contact), running processes, installed packages, network interfaces, routing tables, user accounts — essentially a full inventory of the managed device.

**OID tree:** Objects addressed hierarchically. `.1.3.6.1.2.1.1` = system info. `.1.3.6.1.2.1.25` = host resources.

**Dangerous settings:** `rwuser noauth` provides full OID tree write access without authentication. `rwcommunity <string> <IP>` allows write from any address.

```bash
# Nmap SNMP scan
sudo nmap -sU -p161 <target> -sC

# SNMPwalk - dump all OIDs with community string "public"
snmpwalk -v2c -c public <target>

# Brute-force community strings
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt <target>

# Brute-force OIDs once community string is known
braa <community-string>@<target>:.1.3.6.*
```

**Default config file:** `/etc/snmp/snmpd.conf`

---

## MySQL (TCP 3306)

MySQL is an open-source relational database frequently exposed externally by misconfiguration. It underpins many web applications (WordPress, Joomla, etc.) and often stores hashed passwords, user records, and application secrets.

**What it exposes:** Database names, table structure, stored user credentials (often hashed), application configuration data.

**Key databases:** `information_schema` (metadata), `sys` (system management), application-specific databases.

**Dangerous settings:** `secure_file_priv` disabled allows reading/writing OS files. Debug settings expose error details for [[sql-injection]] enumeration.

```bash
# Nmap MySQL scan with all mysql scripts
sudo nmap <target> -sV -sC -p3306 --script mysql*

# Connect without password (check for anonymous/root no-pass)
mysql -u root -h <target>

# Connect with credentials
mysql -u root -pP4SSW0rd -h <target>
```

**MySQL enumeration commands (within session):**
```sql
show databases;
use <database>;
show tables;
show columns from <table>;
select * from <table>;
select * from <table> where <column> = "<string>";
```

See [[sql-injection]] for exploitation. Credentials found here enable [[pass-the-hash]] if AD-integrated.

---

## MSSQL (TCP 1433)

Microsoft SQL Server is the Windows counterpart to MySQL, tightly integrated with Active Directory. The `sa` account is the built-in sysadmin — if enabled with a weak/default password, it provides full database and potentially OS access via `xp_cmdshell`.

**What it exposes:** Hostname, database instance name, SQL Server version, named pipe configuration, database contents, Windows authentication integration.

**Default system databases:** `master` (system info), `model` (template), `msdb` (agent jobs/alerts), `tempdb` (temp objects), `resource` (read-only system objects).

**Dangerous settings:** Unencrypted connections, self-signed certificates (spoofable), named pipes enabled, weak `sa` credentials.

```bash
# Nmap MSSQL scan with NSE scripts
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,\
ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
--script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER \
-sV -p1433 <target>

# Metasploit ping/discovery
msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; set rhosts <target>; run; exit"

# Connect with Impacket (Windows auth)
python3 mssqlclient.py Administrator@<target> -windows-auth

# Connect with Impacket (SQL auth)
impacket-mssqlclient <user>@<target>
```

See [[sql-injection]] for T-SQL exploitation paths. MSSQL credentials can be leveraged for [[pass-the-hash]] in AD environments.

---

## Oracle TNS (TCP 1521)

Oracle Transparent Network Substrate is the listener protocol for Oracle databases. The SID (System Identifier) uniquely identifies each database instance and must be known to connect. Oracle 9 has default password `CHANGE_ON_INSTALL`; DBSNMP service uses default `dbsnmp`.

**What it exposes:** Oracle version, SID names, user accounts, password hashes from `sys.user$`, file upload capability via UTL_FILE.

**Key config files:** `$ORACLE_HOME/network/admin/tnsnames.ora` (client-side), `$ORACLE_HOME/network/admin/listener.ora` (server-side).

```bash
# Nmap Oracle TNS scan
sudo nmap -p1521 -sV <target> --open

# SID brute-forcing via Nmap
sudo nmap -p1521 -sV <target> --open --script oracle-sid-brute

# ODAT full enumeration (all modules)
odat all -s <target>

# Connect with sqlplus once SID and creds are known
sqlplus <user>/<pass>@<target>/<SID>

# Connect as sysdba
sqlplus <user>/<pass>@<target>/<SID> as sysdba
```

**Oracle SQL enumeration (within sqlplus session):**
```sql
select table_name from all_tables;
select * from user_role_privs;
select name, password from sys.user$;   -- extract password hashes
```

**File upload via ODAT (for webshell):**
```bash
echo "test" > testing.txt
odat utlfile -s <target> -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

---

## IPMI (UDP 623)

Intelligent Platform Management Interface enables out-of-band management of servers — even when powered off. BMCs (Baseboard Management Controllers) run independently of the OS. Common BMCs: HP iLO, Dell iDRAC, Supermicro IPMI.

**What it exposes:** BMC access (equivalent to physical server access), password hashes via RAKP flaw in IPMI 2.0, default credentials for web console and SSH/Telnet management.

**Critical flaw:** IPMI 2.0 RAKP protocol sends a salted SHA1/MD5 password hash to the client before authentication completes, allowing offline cracking with Hashcat mode 7300.

**Default credentials:**

| Product | Username | Password |
|---------|----------|----------|
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | randomized 8-char (uppercase + digits) |
| Supermicro IPMI | ADMIN | ADMIN |

```bash
# Nmap IPMI version detection
sudo nmap -sU -p623 <target> --script ipmi-version

# Metasploit version detection
msf6 > use auxiliary/scanner/ipmi/ipmi_version
msf6 > set rhosts <target>
msf6 > run

# Metasploit hash dumping (exploits RAKP flaw)
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 > set rhosts <target>
msf6 > run

# Crack IPMI hashes offline
hashcat -m 7300 ipmi.txt /usr/share/wordlists/rockyou.txt

# HP iLO factory default pattern (8 chars, upper+digits)
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

**Note:** Cracked IPMI passwords are frequently reused across other systems in the environment (SSH, Windows admin, VPN). Always try IPMI credentials on other services.

---

## SSH (TCP 22)

Secure Shell is the standard encrypted remote access protocol. SSH-2 only — SSH-1 is vulnerable to MITM. Banner reveals exact OpenSSH version for CVE lookup.

**What it exposes:** Software version (for CVE research), supported authentication methods, supported ciphers and key exchange algorithms (weak algorithms indicate attack surface), host keys.

**Dangerous settings:** `PasswordAuthentication yes` (enables brute-force), `PermitEmptyPasswords yes`, `PermitRootLogin yes`, `Protocol 1` (SSH-1 MITM vulnerability), `X11Forwarding yes` (historically exploitable).

**Authentication methods (in order of interest):**
1. Password authentication
2. Public-key authentication
3. Host-based authentication
4. Keyboard-interactive
5. Challenge-response
6. GSSAPI

```bash
# Audit SSH configuration and ciphers
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py <target>

# Enumerate available authentication methods verbosely
ssh -v <user>@<target>

# Force password authentication (for brute-force)
ssh -v <user>@<target> -o PreferredAuthentications=password

# Connect with a specific private key
ssh -i <key_file> <user>@<target>
```

**Banner interpretation:**
- `SSH-1.99-OpenSSH_3.9p1` → supports both SSH-1 and SSH-2
- `SSH-2.0-OpenSSH_8.2p1` → SSH-2 only

---

## RSYNC (TCP 873)

Rsync is a fast file synchronization tool commonly used for backups. Unauthenticated access to shares can expose sensitive files including SSH keys and configuration files.

**What it exposes:** Share listings, file contents (including `.ssh/` directories, secrets files, YAML configs).

```bash
# Nmap Rsync scan
sudo nmap -sV -p873 <target>

# List available shares (nc probe)
nc -nv <target> 873
# Then type: #list

# List share contents
rsync -av --list-only rsync://<target>/<share>

# Download all files from a share
rsync -av rsync://<target>/<share> ./

# Rsync over SSH (non-standard port)
rsync -av -e "ssh -p 2222" rsync://<target>/<share> ./
```

---

## R-Services (TCP 512, 513, 514)

Legacy Unix remote access suite, replaced by SSH. Still encountered on older commercial Unix systems (Solaris, HP-UX, AIX). Transmits data in cleartext. Trust is controlled by `/etc/hosts.equiv` and per-user `.rhosts` files.

**Ports:**
- 512/tcp — `rexec` (remote execution, requires password)
- 513/tcp — `rlogin` (remote login, trusts `.rhosts`)
- 514/tcp — `rsh` / `rcp` (remote shell and copy, trusts `.rhosts`)

**What it exposes:** Unauthenticated access if trust files are misconfigured (`+` wildcard in `.rhosts`), interactive sessions on the local network via `rwho`/`rusers`.

```bash
# Nmap scan for R-services
sudo nmap -sV -p512,513,514 <target>

# Log in via rlogin (trusts .rhosts)
rlogin <target> -l <username>

# List authenticated users on LAN
rwho

# Detailed user listing
rusers -al <target>
```

**Trust file exploitation:** If `.rhosts` contains `+ +` or `+ <our-ip>`, any connection from our host is trusted without credentials.

---

## RDP (TCP 3389)

Remote Desktop Protocol provides full GUI remote access to Windows systems. RDP uses NLA (Network Level Authentication) in modern configurations; older systems may fall back to weaker encryption.

**What it exposes:** OS version, hostname, domain name, NLA status, encryption negotiation details. NTLM information from the handshake reveals domain/computer name.

```bash
# Nmap RDP scan with NSE scripts
nmap -sV -sC <target> -p3389 --script rdp*

# Packet trace (visible in EDR - use carefully)
nmap -sV -sC <target> -p3389 --packet-trace --disable-arp-ping -n

# RDP security check (unauthenticated)
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl <target>

# Connect via xfreerdp (Linux client)
xfreerdp /u:<user> /p:"<password>" /v:<target>

# Connect ignoring certificate warnings
xfreerdp /u:<user> /p:"<password>" /v:<target> /cert-ignore

# Connect with Pass-the-Hash
xfreerdp /u:<user> /pth:<NTLM-hash> /v:<target>
```

**OPSEC note:** Nmap's RDP scripts use the cookie `mstshash=nmap`, detectable by EDR/IDS. Use `--packet-trace` to verify before use on sensitive engagements.

---

## WinRM (TCP 5985, 5986)

Windows Remote Management uses SOAP over HTTP/HTTPS for remote management. PowerShell remoting and event log merging both use WinRM. Port 5985 is HTTP (plaintext), 5986 is HTTPS.

**What it exposes:** Remote command execution capability once credentials are obtained.

```bash
# Nmap WinRM scan
nmap -sV -sC <target> -p5985,5986 --disable-arp-ping -n

# evil-winrm (Linux WinRM client)
evil-winrm -i <target> -u <user> -p <password>

# evil-winrm with hash (Pass-the-Hash)
evil-winrm -i <target> -u <user> -H <NTLM-hash>

# PowerShell check (from Windows)
Test-WsMan <target>
```

See [[pass-the-hash]] for credential-free access using NTLM hashes.

---

## WMI (TCP 135 + dynamic)

Windows Management Instrumentation provides read/write access to nearly all Windows settings. Commonly accessed via PowerShell, VBScript, or WMIC. Communication initializes on TCP 135, then moves to a dynamic high port.

**What it exposes:** Full system information, process listing, service enumeration, remote command execution capability.

```bash
# wmiexec.py (Impacket) - execute command via WMI
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
  <user>:"<password>"@<target> "hostname"

# Impacket wmiexec shortcut
impacket-wmiexec <user>:"<password>"@<target> "whoami"
```

---

## LDAP (TCP 389, 636)

LDAP (Lightweight Directory Access Protocol) is the backbone of Active Directory. Port 389 is plaintext; 636 is LDAPS (TLS). Anonymous bind is occasionally enabled, leaking user/group/computer objects.

**What it exposes:** User accounts, group memberships, computer objects, OUs, GPO links, password policy, Kerberoastable service accounts (SPNs), AS-REP roastable accounts.

See [[ad-enumeration]] for detailed AD enumeration workflows. For command-style quick reference use [[ad-cheatsheet|Active Directory cheatsheet]]. For initial LDAP checks:

```bash
# Anonymous LDAP query
ldapsearch -x -H ldap://<target> -b "dc=<domain>,dc=<tld>"

# Authenticated LDAP query
ldapsearch -x -H ldap://<target> -D "<user>@<domain>" -w "<pass>" -b "dc=<domain>,dc=<tld>"

# Nmap LDAP scripts
nmap -sV -p389 <target> --script ldap-rootdse,ldap-search
```

---

## Virtual Hosts (VHosts) (TCP 80, 443)

A Virtual Host allows a single IP address to host multiple domain names. Default IP requests often hit a default or generic VHOST, masking hidden functionality.

**Fingerprinting VHOSTs:**
Setting the `Host` header to other known or guessed domains may return completely different applications, status codes, or internal panels.

```bash
# Gobuster VHost discovery
gobuster vhost -u https://example.com -w /path/to/wordlist.txt

# Hakoriginfinder (find origin behind reverse proxy/WAF)
prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo
```

---

## Cross-References

- [[wiki/tools/nmap]] — initial scanning and NSE scripting
- [[sql-injection]] — when MySQL or MSSQL is accessible
- [[pass-the-hash]] — when NTLM hashes are captured (IPMI, MSSQL, SMB)
- [[password-cracking]] — offline cracking of captured hashes (IPMI mode 7300, NTLM mode 5600/1000)
- [[ad-enumeration]] — LDAP-focused domain footprinting
- [[ad-cheatsheet|Active Directory cheatsheet]] — LDAP, SMB, WinRM, and RDP one-liners in AD context
- [[wiki/cheatsheets/recon]] — passive recon techniques that precede service enumeration
