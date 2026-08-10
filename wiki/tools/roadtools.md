---
title: "ROADtools"
type: tool
tags: [cloud, azure, entra, azure-ad, enumeration, post-exploitation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: postex
---

## Purpose

**ROADtools** (dirkjanm) is the Azure AD / Entra ID exploration framework. **ROADrecon** gathers an entire tenant's directory (users, groups, apps, service principals, roles, devices, CAPs) into a local DB and serves a browsable UI. The Entra counterpart to BloodHound for finding privilege paths in the cloud directory.

## Install / setup

```bash
pipx install roadrecon          # core: roadrecon (gather + GUI)
# roadtools_gui / ROADtools Hub for the newer interface
```

## Core usage

```bash
roadrecon auth -u user@tenant.com -p 'pass'      # or --device-code, or -r <refresh token>
roadrecon gather                                  # dump the tenant -> roadrecon.db
roadrecon gui                                     # browse at http://localhost:5000
```

## Common use cases

```bash
# Auth options (pick what you have)
roadrecon auth --device-code                       # phishing / interactive
roadrecon auth -r <refreshtoken>                   # from a stolen token (e.g. via device-code phish)
roadrecon auth --as-app -c <id> --certificate ...  # service principal

# After gather, in the GUI look for:
#   users with directory roles (Global Admin, Privileged Role Admin)
#   service principals / app registrations with high API permissions (RoleManagement, Directory.ReadWrite.All)
#   Conditional Access Policy gaps; dynamic group rules; owners who can escalate
# plugins:
roadrecon plugin policies                          # dump + analyse CAPs
```

## Tips and gotchas
- ROADrecon reads the directory with normal user tokens - any authenticated user can enumerate a lot of Entra. Pairs with device-code phishing to get the initial token.
- Find escalation via **app/service-principal permissions** (apps with `Directory.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` = path to Global Admin) and **dynamic group** rules you can satisfy.
- Complements [[scoutsuite]] (Azure resource posture) - ROADtools is the *directory/identity* layer (Entra), ScoutSuite the *resource* layer.

## Related techniques
Azure/Entra under [[azure-ad-iam]], [[azure-ad-enumerate]], [[azure-ad-persistence]]. Routed by the `hunt-m365` / `hunt-cloud` skills. AWS counterpart: [[pacu]].

## Sources
