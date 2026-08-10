---
title: "Pacu"
type: tool
tags: [cloud, aws, exploitation, privilege-escalation, post-exploitation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: exploit
---

## Purpose

**Pacu** (Rhino Security Labs) is an AWS exploitation framework: a Metasploit-style console with modules for enumeration, IAM privilege escalation, persistence, data exfiltration, and detection evasion. The offensive counterpart to read-only [[scoutsuite]] once you have AWS keys.

## Install / setup

```bash
pipx install pacu
pacu                            # starts the console; create a session, import keys
```

## Core usage

```
Pacu> import_keys default       # pull from ~/.aws/credentials, or set_keys manually
Pacu> whoami                    # current principal + stored data
Pacu> ls                        # list modules
Pacu> run <module> [args]
```

## Common use cases

```
# Enumerate what the key can see/do
Pacu> run iam__enum_permissions
Pacu> run iam__enum_users_roles_policies_groups
Pacu> run ec2__enum

# Privilege escalation (find + exploit IAM paths to admin)
Pacu> run iam__privesc_scan        # detects 20+ known privesc methods, can auto-exploit

# Loot / persistence (RoE-gated)
Pacu> run s3__download_bucket
Pacu> run secrets__enum            # Secrets Manager + SSM params
Pacu> run iam__backdoor_users_keys # persistence: new access key on a user
```

## Tips and gotchas
- `iam__privesc_scan` is the headline module - it maps the key's permissions to known escalation chains (`PassRole`+lambda/ec2, policy version, `CreateAccessKey`, etc.) and can exploit them.
- Every module is an AWS API call - **loud** (CloudTrail/GuardDuty). Respect RoE; some modules create/modify resources (persistence, backdoor) - do not run those without explicit authorization.
- Pairs with [[scoutsuite]] (posture) and the `hunt-cloud` skill (methodology). For Azure/Entra use [[roadtools]].

## Related techniques
[[aws-attacks]], [[cloud-iam-attacks]]. SSRF entry to keys -> [[wiki/payloads/ssrf]] + [[imds-cloud-metadata]]. Driven by the `hunt-cloud` skill.

## Sources
