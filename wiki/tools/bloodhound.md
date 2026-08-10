---
title: "BloodHound"
type: tool
tags: [active-directory, enumeration, attack-path, lateral-movement, privilege-escalation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: postex
---

## Purpose

**BloodHound** maps Active Directory (and Entra/Azure AD) as a graph of principals and the rights between them, then finds the shortest attack path from any foothold to Domain Admin. Collectors gather the data; the BloodHound UI (Neo4j-backed) runs the queries. The single most important AD escalation tool.

## Install / setup

```bash
# BloodHound Community Edition (current)
curl -L https://ghst.ly/getbhce | docker compose -f /dev/stdin up
# collectors:
#   SharpHound.exe (Windows) / SharpHound.ps1
#   bloodhound-python (remote, from Linux)
pipx install bloodhound-ce      # bloodhound-python collector for CE
```

## Core usage

```bash
# Collect from Linux (remote, with creds)
bloodhound-python -u user -p 'pass' -d corp.local -ns <dc-ip> -c All --zip
# or netexec one-liner:
nxc ldap <dc> -u user -p pass --bloodhound -c all --dns-server <dc>
# Windows on-host:
SharpHound.exe -c All --zipfilename loot
```
Then drag the ZIP into the BloodHound UI -> run queries.

## Common use cases

- **Pre-built queries:** "Shortest Paths to Domain Admins", "Find Principals with DCSync Rights", "Kerberoastable users", "Computers where Domain Users are local admin", "Find Unconstrained Delegation".
- **Mark owned** nodes (your current principals) -> "Shortest Path from Owned" to a high-value target.
- **Custom Cypher** for specific edges:
```cypher
// who can write to the target group (-> add yourself / shadow creds)
MATCH p=(n)-[:GenericWrite|GenericAll|WriteDacl|WriteOwner|AddMember]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}) RETURN p
// every ADCS-vulnerable path
MATCH p=()-[:ADCSESC1|ADCSESC3|ADCSESC4]->() RETURN p
```
- Edges drive the next action: `GenericWrite`->shadow creds/targeted Kerberoast, `AddMember`->join the group, `ForceChangePassword`->reset, `AllowedToDelegate`->constrained delegation.

## Tips and gotchas
- CE uses different collectors than legacy BloodHound 4.x - match collector to UI version or the import fails.
- Collect with `-c All` (or `DCOnly` for stealth); large domains: throttle SharpHound (`--jitter`, `--throttle`) to stay quiet.
- The graph is a hypothesis generator - confirm each edge is actually abusable (ACL inheritance, protected groups) before acting.

## Related techniques
[[active-directory]], [[ad-lateral-movement]], [[ad-enumeration]], [[adcs]]. Collected via [[netexec]]; abused with [[impacket]]/[[certipy]]. Drives the `hunt-ad` skill.

## Sources
