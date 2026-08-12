---
name: hunt-secrets
description: Exposed-secrets hunting - .git/ dir + history mining, exposed .env/config files, hardcoded keys in JS bundles + source maps, S3/blob exposure, public-repo secret search, CI/CD leakage. Live-validation mandatory. Wiki-first, FIND schema output.
---

# Hunt: Exposed Secrets / Credential Exposure

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "exposed secrets git directory .env config hardcoded API keys JS bundle source maps S3 CI leakage" via wiki-search MCP
```

Hub: [[web-moc]] (live index). Primary page: [[secret-hunting]].
Anchors: [[javascript-source-map-exploitation]], [[supply-chain-attacks]], [[git-exposure]], [[hardcoded-secrets-enumeration]], [[source-code-analysis]], [[aws-service-s3-buckets]], [[aws-access-token-secrets]]. Dorks: [[recon-dorks]].

## Attack surface signals

**Rank before probing** - highest yield first: exposed `.git/` (full source + history) > exposed `.env`/config files > JS bundles + source maps (rebuilt original source) > public repos (org + employee) > CI/CD build logs > S3/blob listings.

Path probes: `/.git/`, `/.env`, `/.env.local`, `/.env.prod`, `/.git-credentials`, `/.aws/credentials`, `/config.json`, `/wp-config.php.bak`, `/.npmrc`, `/.netrc`, `/backup.zip`, `/.DS_Store`
Client-side: inline `<script>`, `main.*.js` bundles, `*.js.map` source maps, webpack chunks, `__NEXT_DATA__`, embedded `firebaseConfig`.
Buckets/blobs: `s3.amazonaws.com/<name>`, `<name>.s3.<region>.amazonaws.com`, `*.blob.core.windows.net`, `storage.googleapis.com/<name>`.
Repos: GitHub/GitLab org + employee personal repos, gists, forks, deleted-but-cached commits.

## Methodology

Route the load-bearing confirming request (the exposed `.git`/`.env` fetch, or a key validity check) through Burp Repeater for operator visibility; quick loops below can stay in the terminal.

1. Probe exposed dotfiles/configs with curl (fixed path list, not an ID sweep):
```bash
for p in .env .env.local .git/HEAD .git-credentials .aws/credentials .npmrc config.json; do
  printf '%s -> ' "$p"; curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/$p"
done
```
2. Exposed `.git/` -> dump full repo, then mine history:
```bash
# /.git/HEAD returning a ref = exposed
curl -s https://target.com/.git/HEAD
git-dumper https://target.com/.git/ ./dump   # or wget -r the .git index
trufflehog filesystem ./dump --only-verified
gitleaks detect --source ./dump --no-banner
```
3. JS bundle + source map extraction:
```bash
# pull bundles, grep for key shapes
curl -s https://target.com/static/js/main.js | grep -Eo \
  '(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{24}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+)'
# rebuild original source from a source map, then trufflehog it
npx source-map-explorer main.js main.js.map 2>/dev/null
trufflehog filesystem ./bundles --only-verified
```
4. S3 / blob enumeration - **list to prove public read; pull at most one benign object as evidence, never bulk-sync real data** (per hunt-core stop conditions):
```bash
aws s3 ls s3://<name> --no-sign-request          # public list = the proof
curl -s "https://storage.googleapis.com/<name>/" # GCS listing
curl -s "https://<name>.blob.core.windows.net/?comp=list"  # Azure blob
# evidence only, one benign object - do NOT `aws s3 sync` the whole bucket
```
5. Public-repo + org search:
```bash
trufflehog github --org=<org> --only-verified
# manual dorks (see [[recon-dorks]]):
#   "target.com" password   filename:.env   org:<org>
gitleaks detect --source ./cloned-repo --no-banner
```
6. CI/CD leakage: check build logs, GitHub Actions artifacts, `pull_request_target` output, exposed `.gitlab-ci.yml` vars, printed env in public job logs.
7. Collect every candidate secret with its type tag (aws/gcp/slack/stripe/github/db-uri) for the validation step.
8. **Distill when confirmed** (reusable exposure vector / extraction trick / key-validation endpoint, GENERIC, no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/osint/secret-hunting.md`

## Confirmation gate

**NOT confirmation:** a high-entropy string; a variable named `API_KEY` / `SECRET`; a scanner or regex match (a trufflehog/gitleaks hit on its own); a key in old git history you have not tested; an `.env.example` placeholder; an already-rotated or invalid key.

**IS confirmation:** the secret **validated against its own service** with a single benign read-only call that returns an authenticated-success signal (an identity, a `200`/`valid`) - live and unrotated. Live-validation is mandatory for this class; a string that merely looks like a key, or scores high on entropy, is never a finding.

**Stop condition:** validate with **ONE** minimal read-only call, observe only the auth-success signal, then stop. Never use the key a second time, never call a data/list endpoint, never write, never exfiltrate data with it. A rotated/invalid key is a Deadend (info-disclosure only if the exposure path itself is the issue).

## Verification / Validation

**One benign call per candidate.** Read the auth-success **signal only** (status code / own identity), never page or read returned records, never chain a second call, never write. A key that authenticates once is proven - stop there.

```bash
# AWS - returns your own identity ARN only
aws sts get-caller-identity
# GitHub token - status only (200 = live)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: token $GH" https://api.github.com/user
# Slack - identity check, not a data pull
curl -s -d "token=$SLACK" https://slack.com/api/auth.test
# Stripe - status only against a no-PII endpoint (NOT /v1/charges, which lists customer data)
curl -s -o /dev/null -w '%{http_code}\n' https://api.stripe.com/v1/balance -u "$SK:"
# Google API key - benign geocode, no customer data
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=$KEY"
```

trufflehog `--only-verified` already performs live checks; still re-confirm scope-impacting creds manually with the single call above.

## Chaining

A validated cloud key (AWS/GCP/Azure) is a foothold, not the finish line: record it and **hand off to `hunt-cloud`** for the (scope-and-billing-aware) privilege and blast-radius assessment. Do not enumerate cloud services with the key yourself here - the confirmation call is where hunt-secrets stops.

## Severity

Rated on what the validated key reaches, not the mechanism.

| Key / scope | Typical |
|---|---|
| Cloud/admin creds, prod-DB URI, org-wide token | critical |
| Scoped prod API key / service token | high |
| Limited-scope or read-only key | medium |
| Low-value key, or rotated/invalid with only the exposure path | low - info |

## Coverage / evasion

Do not stop at the dotfile probe. A single clean `main.js` is not "no client-side secrets" - walk every bundle, webpack chunk, and `*.js.map`, plus inline `<script>` and `__NEXT_DATA__`. Deleted commits frequently survive in fork/gist/cache; a private repo today may have leaked in a public commit yesterday. Log each surface you cleared so `Approach.md`'s 4a table shows the class as actually tested.

## Deadends

```
Append: - [ ] Secret exposure on <host/repo> -- .git absent, configs 404, bundles + source maps clean,
              buckets private, repos dry, candidates invalid/rotated
```

Record what you cleared, not just that it failed, so the next pass knows the boundary.
