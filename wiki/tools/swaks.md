---
title: "swaks"
type: tool
tags: [smtp, email, network-service, enumeration, testing]
date_created: 2026-07-03
date_updated: 2026-07-03
sources: []
phase: recon
---

## Purpose

**swaks** (Swiss Army Knife for SMTP) scripts and inspects SMTP transactions: test open relay, enumerate users (VRFY/EXPN/RCPT), check AUTH and STARTTLS, and send crafted mail for spoofing/phishing checks.

## Install / setup

```bash
apt install swaks
```

## Core usage

```bash
swaks --to user@target.com --server mail.target.com    # basic delivery test
swaks --to a@ext --from b@ext --server mx.target.com    # open-relay test (ext -> ext)
swaks --to user@t --server mx --quit-after RCPT         # RCPT-based user enum
swaks --to u@t --server mx -tls --auth -au user -ap pass
```

## Common use cases

```bash
# open relay: external sender AND external recipient accepted = misconfig
for u in $(cat users.txt); do swaks --to $u@t --server mx --quit-after RCPT 2>&1 | grep -E '25[05]|550'; done
swaks --to victim@t --from ceo@t --server mx --header 'Subject: test'  # spoof / SPF-DMARC check
```

## Tips and gotchas

- Relay and enum behaviour vary by MTA; read the raw SMTP response codes, do not infer.
- VRFY/EXPN are usually disabled; RCPT-response differencing is the reliable enum path.
- Ties into [[smtp-smuggling]] and [[email-address-parsing-attacks]].
- Prefer swaks over a hand-rolled `/dev/tcp` SMTP loop: cleaner transcript, TLS/AUTH support.

## Related techniques

[[smtp-smuggling]], [[email-address-parsing-attacks]]

## Sources

Vault-resident; swaks docs.
