---
title: "Trivy"
type: tool
tags: [sca, dependency-cve, sbom, containers, cve-research, supply-chain]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**Trivy** is an all-in-one scanner for known vulnerabilities (CVEs) in OS packages and language dependencies, plus IaC misconfigurations, secrets, and SBOM generation. The fast way to find **known-CVE-in-a-dependency** on a target - the dependency-review step of source-code and supply-chain research.

## Install / setup

```bash
apt install trivy        # or brew install trivy / docker run aquasec/trivy
```

## Core usage

```bash
trivy fs .                       # scan a project dir (lockfiles -> dep CVEs)
trivy image <name:tag>           # scan a container image
trivy repo https://github.com/org/repo
```

## Common use cases

```bash
# Dependency CVEs from a repo's lockfiles (npm/pip/go/maven/cargo/...)
trivy fs --scanners vuln --severity HIGH,CRITICAL .

# Container image: OS packages + app deps
trivy image --ignore-unfixed myapp:latest

# SBOM in/out
trivy image --format cyclonedx -o sbom.json myapp:latest
trivy sbom sbom.json                        # scan an existing SBOM

# Also: IaC misconfig + secrets
trivy config ./terraform
trivy fs --scanners secret .
```
Alternative: **grype** (`grype dir:.` / `grype <image>`) + **syft** (SBOM) cover the same dependency-CVE job.

## Tips and gotchas
- A reported CVE in a dependency is a **lead, not a finding** - confirm the vulnerable code path is actually reachable from attacker input before claiming it (Trivy reports presence, not reachability).
- `--ignore-unfixed` cuts noise to actionable (patch-available) issues; pin `--severity` on large scans.
- Pairs with deeper source analysis: Trivy finds the known-vulnerable version, [[codeql]]/[[semgrep]] confirm whether your code reaches the bug.

## Related techniques
[[static-code-analysis]], `cicd-attacks` / supply chain. Part of the source-repo and dependency-review path in the `research` skill. Pairs with [[semgrep]], [[codeql]].

## Sources
