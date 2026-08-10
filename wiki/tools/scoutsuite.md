---
title: "ScoutSuite"
type: tool
tags: [cloud, audit, aws, azure, gcp, misconfiguration, enumeration]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: recon
---

## Purpose

**ScoutSuite** (NCC Group) is a multi-cloud security auditing tool: with read-only credentials it enumerates an AWS / Azure / GCP / OCI / Aliyun account and produces an HTML report of misconfigurations (public storage, weak IAM, open security groups, no logging). The fast posture sweep at the start of a cloud engagement.

## Install / setup

```bash
pipx install scoutsuite        # needs read-only creds for the target cloud
```

## Core usage

```bash
scout aws                       # uses your AWS CLI profile/env creds
scout azure --cli              # uses az login session
scout gcp --user-account       # or --service-account key.json
# -> writes scoutsuite-report/<account>.html  (open in a browser)
```

## Common use cases

```bash
# Scope to a profile / subscription / project
scout aws --profile target --report-dir out/
scout azure --subscription-ids <sub-id>
scout gcp --project-id <proj>

# Rule severity triage: open the HTML, sort findings by severity ->
#   public S3/blob/GCS, *:* IAM, 0.0.0.0/0 ingress, unencrypted volumes,
#   no MFA on privileged users, disabled audit logging.
```

## Tips and gotchas
- **Read-only** by design - safe to run, but it makes many API calls (loud in CloudTrail/Activity logs); confirm RoE allows enumeration.
- It reports misconfigurations, not exploitation - feed the findings to the `hunt-cloud` skill / [[pacu]] (AWS) / [[roadtools]] (Entra) to actually escalate.
- Use a dedicated read-only role; large accounts take a while - scope by region/service where supported.

## Related techniques
[[aws-attacks]], [[cloud-iam-attacks]], [[gcp-attacks]], Azure under [[azure-ad-iam]]. Drives the recon phase of the `hunt-cloud` skill. Escalate with [[pacu]] / [[roadtools]].

## Sources
