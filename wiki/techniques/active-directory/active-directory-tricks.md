---
title: Active Directory - Tricks
type: technique
tags: [active-directory, lateral-movement, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Tricks

## What it is

In Kerberos, time is used to ensure that tickets are valid. To achieve this, the clocks of all Kerberos clients and servers in a realm must be synchronized to within a certain tolerance. The default clock skew tolerance in Kerberos is `5 minutes`, which means that the difference in time between the clocks of any two Kerberos entities should be no more than 5 minutes.

## How it works

Kerberos enforces a default clock skew tolerance of 5 minutes; attackers operating from a machine whose clock is out of sync with the DC will receive `KRB_AP_ERR_SKEW` errors when requesting or using tickets, requiring clock synchronization before attacks that depend on Kerberos will succeed. Various AD quirks, such as `userPrincipalName` collision, `sAMAccountName` spoofing, and `msDS-AdditionalDnsHostName` manipulation, create edge-case impersonation vectors that are exploited by tools like Certipy and noPac. Understanding these lower-level protocol behaviors is a prerequisite for reliable exploitation in complex or hardened domain configurations.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Kerberos Clock Synchronization

In Kerberos, time is used to ensure that tickets are valid. To achieve this, the clocks of all Kerberos clients and servers in a realm must be synchronized to within a certain tolerance. The default clock skew tolerance in Kerberos is `5 minutes`, which means that the difference in time between the clocks of any two Kerberos entities should be no more than 5 minutes.

* Detect clock skew automatically with `nmap`

```powershell
$ nmap -sV -sC 10.10.10.10
clock-skew: mean: -1998d09h03m04s, deviation: 4h00m00s, median: -1998d11h03m05s
```

* Compute yourself the difference between the clocks

```ps1
nmap -sT 10.10.10.10 -p445 --script smb2-time -vv
```

* Fix #1: Modify your clock

```ps1
sudo date -s "14 APR 2015 18:25:16" # Linux
net time /domain /set # Windows
```

* Fix #2: Fake your clock

```ps1
faketime -f '+8h' date
```

## References

* [BUILDING AND ATTACKING AN ACTIVE DIRECTORY LAB WITH POWERSHELL - @myexploit2600 & @5ub34x](https://1337red.wordpress.com/building-and-attacking-an-active-directory-lab-with-powershell/)
* [Becoming Darth Sidious: Creating a Windows Domain (Active Directory) and hacking it - @chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/building-a-lab/building-a-lab/building-a-small-lab.html)
* [Chump2Trump - AD Privesc talk at WAHCKon 2017 - @l0ss](https://github.com/l0ss/Chump2Trump/blob/master/ChumpToTrump.pdf)
* [How to build a SQL Server Virtual Lab with AutomatedLab in Hyper-V - October 30, 2017 - Craig Porteous](https://www.sqlshack.com/build-sql-server-virtual-lab-automatedlab-hyper-v/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[certipy]]
- [[wiki/tools/nmap]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
