---
name: ctf-box
description: Boot-to-root methodology for a full machine (THM/HTB/PG/CTF box, "get user.txt+root.txt", "root the box", "foothold to root"). Enforces basic-tool recon (nmap, nc, ffuf, nuclei, dig) before anything custom, wiki-first lookups, and ALWAYS pspy + linpeas/winpeas for privesc. Use when handed a box/IP to own end-to-end.
---

# CTF / Boot-to-Root Box

Own a whole machine: recon -> service triage -> foothold -> user.txt -> privesc -> root.txt.
**Run everything from the engagement tooling host (e.g. Kali in tmux), capture into `targets/<eng>/`.**

Track progress in `targets/<eng>/Approach.md` -- work the current phase's open items, mark `[x]` as each
lands; honor GATE 1 (no hand-rolled exploit before its wiki item is `[x]`), GATE 2 (no exploit step `[x]`
without a `poc/` image), GATE 3 (exhausted vector -> `[!]` + one `Deadends.md` line, never re-run it).

## Standing mandate: Wiki-first, tools-before-scripts (GATE 1, all phases)

This mandate stands over every phase below. Before writing ANY custom script or recalling an exploit from memory:
1. `qmd_query "<tech/version> exploit"` and `qmd_query "<service> privilege escalation"` via wiki-search MCP. Read matches. If the MCP is down (it drops mid-session), run `bash scripts/wiki-query.sh "<tech> exploit"` (same qmd index; `-k` for an exact CVE) - do NOT skip wiki-first or fall back to grep.
2. Pull payloads from `wiki/payloads/` and chains from `wiki/cheatsheets/attack-chains.md` + `wiki/cheatsheets/cve-arsenal.md`, or `Skill(arsenal)` to resolve the exact file.
3. Privesc reference: `wiki/techniques/linux/linux-privesc.md` / `wiki/cheatsheets/linux-privesc.md` (or windows-privesc).
Only after the wiki has nothing do you write a custom PoC. Do not reinvent what the wiki already documents.

**Tooling home:** check `/opt/arsenal` first for pspy/linpeas/shot/capture. pspy64/linpeas/winPEAS live in `/opt/arsenal`, seeded by `vm-provision.sh` from their GitHub releases; our own helpers (`shot.py`, `capture.sh`) are pushed on demand by `bash scripts/vm-sync.sh <name>` from the vault.

**Version-pinned tooling -> a THROWAWAY docker container, never mutate the VM's runtime.** A tool that needs a specific/older interpreter or an abandoned dependency (e.g. `h2csmuggler` pins the deprecated `hyper` lib and only runs on Python <=3.11; a legacy exploit needs `node:16`) should run inside a disposable container matched to that version, NOT via a host downgrade or a fragile venv that leaves the Kali VM in a broken state for the next box. `docker run -it --rm -v $(pwd):/app python:3.11 bash` (swap the tag: `python:3.9`, `node:16`, ...); `--rm` deletes it the moment you exit, so nothing persists and nothing on the VM breaks. Keep the VM's system python/tooling pristine.

**Anti-pattern:** a raw one-shot `bash /root/vm.sh '<exploit>'` (or an inline `node -e`/`python3 -c` payload through it) for a listener, shell, or chained exploit is the smell this mandate exists to catch -- it skips wiki-first and leaves no session to capture. Run persistent/interactive steps in their own named tmux tab instead: `scripts/vm-scan.sh <eng> <target> '<cmd>'`.

## Phase 1 Recon: basic tools only (in this order)

Use the standard toolkit. Do NOT hand-roll recon scripts.

**Preflight (every engagement, before scanning): prune the tooling VM's `/etc/hosts` and `/etc/krb5.conf` of PRIOR-box entries.** The VM persists across boxes, so a stale `<ip> <domain>/<realm>` line (or a stale `default_realm`) silently mis-resolves this box while nxc/certipy (explicit IP) look fine; impacket Kerberos hangs on a dead KDC instead. `bash /root/vm.sh 'grep -vE "^#|^127\.|^::1|^$" /etc/hosts'`, delete any line not for this box, add only this target; `bash /root/vm.sh 'grep -i default_realm /etc/krb5.conf'`, blank/reset it.

Tooling-first: rustscan/nmap/feroxbuster/ffuf/nuclei/nxc, never a hand-rolled `/dev/tcp` or curl fuzz loop (skips the fingerprint router). **feroxbuster is the DEFAULT web content-discovery tool** (recursive, faster than ffuf/big.txt); launch it the moment nmap shows a web port; ffuf is for param-mining + vhosts.

**Card EVERY scan tab AS it finishes, not at the end:** `scripts/capture.sh recon <eng> <slug> <tab>` renders the tmux tab into `recon/`, rustscan, nmap, feroxbuster, ffuf, nuclei, whatweb (its own tab). Even an empty result gets a card. `status.py` surfaces the recon-card count.

**ONE tmux session per engagement, one WINDOW per parallel scan.** `bash scripts/vm-scan.sh <eng> <target> '<scan>'` for the first, then `--win nuclei`/`--win ferox`/`--win whatweb` for the rest on the same host; never bump the session name to dodge a collision. Screenshot a tab with `Skill(screenshot) --tmux <eng>:<tab>`.

**`vm.sh` drops long foreground commands (exit 255, no output) past ~2 min.** Run scans/cracks/sprays DETACHED (a tmux tab via `vm-scan.sh`, or `nohup <cmd> >/tmp/out 2>&1 &` + poll for a DONE marker), never blocking one `vm.sh` call. Stdin is not forwarded through `vm.sh`; push files via base64 (`echo <b64> | base64 -d > ~/file`), write+run in one call.

**Never `pkill -f <pattern>` with a pattern that also matches your OWN driver/ssh command** - it kills your own tooling (a pattern on the target IP can match the ssh session carrying it).

```bash
T=<ip>
rustscan -a $T --ulimit 5000 -g                        # fast full-port sweep -> open-port CSV
nmap -p<found> -sCV -Pn $T -oN nmap-svc.txt            # version/script scan on rustscan's hits
nmap -p- --min-rate 2000 -T4 -Pn $T -oN nmap-all.txt   # full-TCP confirm (own tmux tab)
nc -nv $T <port>                 # manual banner / custom-proto services
dig any @$T <domain>; dig axfr @$T <domain>   # DNS if 53 open / vhost hints
nxc smb $T -u '' -p '' --shares                 # SMB: netexec first (fingerprint router), not smbclient
nxc smb $T -u 'guest' -p '' --shares --rid-brute   # guest fallback + RID-cycle user enum
smbclient -N //$T/<share> -c 'recurse;ls'       # smbclient only to pull a specific file/share
# --- web ports found: feroxbuster (primary) + nuclei + whatweb IN PARALLEL, own tmux tab each ---
feroxbuster -u http://$T -w /tmp/harness-paths.txt -x php,txt,log,sql,bak,zip,env,old,conf -d 2 --no-state -o ferox.txt   # our high-signal list first
feroxbuster -u http://$T -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,log,bak -d 2 --no-state   # then the big list
bash scripts/backup-sweep.sh http://$T ferox.txt    # full-filename backup suffixes (.bak/~/.old/...) ferox -x misses; BURP_PROXY=127.0.0.1:8080 to route via Burp
ffuf -c -u "http://$T/?FUZZ=x" -w scripts/wordlists/harness-params.txt -fs <baseline>   # param mining
ffuf -c -u http://$T/ -H "Host: FUZZ.$T" -w <vhost-wordlist> -mc all -o vh.json         # vhosts: diff redirect Location, don't filter by code (a decoy vhost 302s the same place; the real one differs)
ffuf -c -u "http://$T/~FUZZ/" -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -mc 200,301,403   # Apache userdir (~name) - no dir wordlist carries these, fuzz explicitly
nuclei -u http://$T -o nuclei.txt
whatweb -a3 http://$T ; curl -s -I http://$T    # own tmux tab so it gets a recon card
wpscan -u http://$T                              # if WordPress
```

**Missing `-w` wordlist = ffuf prints help text and silently finds NOTHING** (a false "no hidden endpoints"). Preflight every fuzz (`ls "$W" || W=/usr/share/wordlists/dirb/big.txt`); seclists may be absent on the VM, push harness lists over via base64 first.

**Slow vs worker-starved, don't conflate them.** Fast HTTP 000 under concurrency (ffuf/sqlmap/parallel scans) = the box is WORKER-STARVED: back off to serial, one request per call, drop fuzzers, let it drain. A request that just never returns = the box is SLOW, not dead: raise the timeout to 120s+ and be patient (a heavy CMS/backend page can take 60-90s). Tell: nmap shows "filtered" but a single `nc`/`curl` connection succeeds = it drops fast-scan probes, switch to gentle serial mode rather than declaring it dead.

**On any TLS host, dump the cert SANs early**; a hidden vhost that decoy services and ffuf/feroxbuster never surface can be listed only in the Subject Alternative Name, see [[cdn-waf-bypass]].

**On any web surface, before moving to exploitation, all of this, in parallel where possible:**
- **Capture it as-is first**: `capture.sh web <eng> <slug> http://T:PORT/` (browser shot) + `curl -s http://T:PORT/ > poc/<slug>-source.html` (raw source), for EVERY distinct surface (login, dashboards, OSINT/social apps) as you open it.
- **Read full, not grep.** Fetch a file/response (source, config, HLS manifest, JS bundle) and read it END-TO-END; the vuln hides in the line a narrow `grep` skips. Never pipe an exploit/lead response through `head`/`grep` before reading it whole.
- **Exploit requests -> Burp.** curl is fine for quick loops; push every load-bearing request (SSRF/LFI/SQLi/BFLA/deser/flag-returning) into Repeater via `Skill(hunt-burp)`, card with `capture.sh burp`.
- **Source-read primitive first.** The moment you can read files (LFI/.git/backup), read ALL the app source before brute-forcing a login/DB; the vuln is usually in source you can already read.
- **Read the client JS and snippet what it reveals.** Grep bundles for `fetch(`/`axios`/`/api`/`token`/`secret`/`admin`; a JS/SPA's POST-only JSON API is invisible to feroxbuster/ffuf (they GET, a bare `/api` 404s so recursion never descends). The moment source reveals something load-bearing, capture it: `scripts/capture.sh snippet <eng> <slug> <url-or-file> '<pattern>' '<what it reveals>'` -> paste the fenced block into walkthrough.md Recon.
- **Launch scanners in parallel the moment a web port appears**, feroxbuster + nuclei + whatweb, one tmux tab each, don't wait serially; card each on finish. Never conclude "no web vuln" until both feroxbuster and nuclei have run AND been read.

Fingerprint the exact app + version. **`Skill(arsenal)` FIRST** on any fingerprinted surface (maps it to `wiki/tools/` automation), then INVOKE `Skill(hunt-<class>)` for each fingerprinted vuln class; actually load and follow it, not just the router's advisory nudge (a routed-but-never-invoked hunt skill is drift in eval.md). Record HOW each vuln was discovered, not just the exploit; screenshot findings as they land. **OT/ICS ports (502/102/44818/1880, an HMI web app) -> `Skill(hunt-ics)`.** A web surface -> `scripts/recon-web.sh <eng> <url>` (fans out feroxbuster+nuclei+whatweb+backup-sweep); re-run per new vhost/path, nothing auto-launches it.

## Phase 2 Weaponize: pick the exploit

- **Version-known -> [[wiki/tools/searchsploit]] AND [[metasploit]] FIRST (the quick-win reflex).** The instant a service is fingerprinted to a version, run BOTH before hand-rolling or deep-diving a CVE: `searchsploit <app> <ver>` (local Exploit-DB; `-m <id>` to copy a PoC, `-x` to read it) and `msfconsole -qx "search <app>; exit"` (a ready `use`-able module = often an instant shell). A matching msf module or a copy-pasteable searchsploit PoC beats writing your own. Cross-check with the wiki CVE lookup ([[cve-arsenal]] · [[metasploit]]); prefer the documented/ready PoC over a fresh one. (GATE 1 still holds: the wiki item for the tech is `[x]` before a hand-rolled PoC - but a canned searchsploit/msf exploit for a known version IS the wiki-blessed tool, use it.)
- Pick the payload set from `wiki/payloads/` for the fingerprinted class (GATE 1: the wiki item is `[x]` before you hand-roll a PoC).
- Stage the chosen exploit/PoC into `targets/<eng>/poc/scripts/` before firing, so the code and the run are captured together.
- **A fingerprinted service can expose SEVERAL vuln classes - do not tunnel on the first.** One plugin/app often has an SQLi AND a file-read AND an authed RCE; the intended door is usually the CHEAPEST (a source/config read), not the loudest (a blind SQLi you grind for hours). Two mechanical tells that the vector you picked is the WRONG one - switch it, do not tune the tooling (see [[hunt-core]] Stop conditions): (1) **the box starves under your own exploit loop** (repeated `000`/timeout/empty-reply) - a vector that DoSes a lab box is almost never intended; (2) **two verified hashes in a row fail the wordlist** - the passwords are delivered out-of-band (email/note/KeePass/config), so stop cracking and read the app's OTHER surfaces (LFI/source, a second vhost, mail) for where creds are handed out. Re-fingerprint the asset for untested classes (`coverage` / `campaign.py board`) before extracting a third hash.

## Phase 3 Deliver: land a shell

- Deliver the staged payload/exploit against the target; prefer the documented PoC over a fresh one.
- **Stabilize EVERY Linux shell the moment it lands** (a raw `nc` shell has no job control, no arrow keys, no tab-complete, and Ctrl-C kills it). Full TTY-upgrade dance, in order: `python3 -c 'import pty;pty.spawn("/bin/bash")'` (fall back to `python`/`python2` if `python3` is absent; `script -qc /bin/bash /dev/null` if no python) -> `Ctrl+Z` to background -> `stty raw -echo; fg` (hands your terminal's raw mode to the shell; press Enter twice) -> `export TERM=xterm` (fixes clear/less/vim). Then set `stty rows <R> cols <C>` to your local `stty size` if editors wrap. Or better, drop your SSH key into a writable user's `~/.ssh/authorized_keys` for a resilient, already-interactive session. (Windows shells: no PTY dance; grab a proper shell via a C2/`ConPtyShell` or just RDP/WinRM once you have creds.)
- **Prefer a real handler over a raw `nc` listener for the reverse shell.** A raw `nc` PTY has the footgun that `Ctrl-C` kills the LISTENER (dropping the shell back to your own prompt - the false-RCE trap) and needs quoting gymnastics to drive. Reach instead for `pwncat-cs` (auto PTY-stabilization, session persistence, built-in up/download; `pip install pwncat-cs` if absent) or a metasploit `multi/handler` -> meterpreter. Meterpreter also gives `autoroute`/`portfwd`/`socks` to reach internal-only ports - use that before hand-rolling SSH `-L` forwards. `msfconsole`/`msfvenom` are on the VM; pwncat is a pip install.
- **Drive commands into the landed shell (reverse shell or tmux tab) with `scripts/vm-rsh.sh <eng> '<cmd>'`** - it base64-wraps the command so any metachars survive the vm.sh -> ssh -> tmux bridge and returns clean output. NEVER hand-quote `tmux send-keys` + `capture-pane`, or `/dev/tcp` file-transfers, to run commands; that quoting hell is a known repeat drift.
- **On FIRST foothold, stand up ONE persistent multiplexed channel and reuse it.** SSH `ControlMaster`/`ControlPersist` (plus `-L` forwards for internal-only ports), or a reverse shell that survives home-perm resets. Opening a fresh SSH per command through an unstable VPN tunnel was the dominant wall-clock sink on a recent box. See [[pivoting]].
- **Cred-reuse FIRST.** Capture creds to `targets/<eng>/loot.md` immediately; try reuse (su / ssh / other services) BEFORE hunting new ones. DB/web creds are very often **reused for SSH**.
  - **Spray EVERY secret you hold against EVERY user x surface, not just the newest one.** The drift: a cred gets written to loot.md, one obvious target is tried, and the rest of the matrix is never run while a fresh privesc vector is ground for half an hour. Re-run the FULL matrix each time a new secret lands. `su` and SSH are NOT equivalent - `PermitRootLogin no` makes `ssh root@` fail while `su root` with the same password succeeds, so a "root: []" SSH result is NOT a negative for root (needs a PTY: `pty.spawn`/`script -qc`).
  - **The leaked config is not the live secret.** An app that does `load_dotenv()` / `os.environ.get(...)` keeps its REAL password in a `.env` beside the source, not in the seeded `.sql`. Read every config the app actually loads, and diff it against what the leak gave you.
  - **Crack the hashes you ALREADY hold before hunting a new vector.** A DB account with `ALL PRIVILEGES` lets you read the DBMS's own account table; a second, otherwise-invisible account there is a deliberate lead. MySQL 8 `caching_sha2_password` (`$A$005$...`) is hashcat `-m 7401` (see [[password-cracking]], [[mysql]]) - convert `$A$<iter>$<20-byte salt><43-byte digest>` to `$mysql$A$005*<salt-hex>*<digest-hex>`. A DBMS password is a prime candidate for OS-account reuse.

## Phase 4 Exploit: finish the foothold, then privesc

**RCE-first (impact-first).** When more than one vector is open, take the one that yields code-exec
first - an RCE foothold is the attack vector that carries impact. Grind XSS/IDOR/enum only after
code-exec is ruled out or the objective specifically needs them (the driver now ranks code-exec
classes ahead of access/enum rows).

**Web foothold = STAY in Burp (anti-drift).** If the foothold is an HTTP primitive (RCE/LFI/SSRF/authed
API), the recurring failure is abandoning Burp the instant it lands and scripting the ENTIRE
post-exploitation over raw `curl`/`vm.sh`/urllib - so the operator, who is watching Burp, loses all
visual on the exploitation. Keep the load-bearing follow-ups (the injection that reads user.txt, the
authed call that leaks config, each privesc-relevant fetch) in **Burp Repeater** (native `mcp__burp__*`
first, CLI bridge fallback; `Skill(hunt-burp)`). Quick throwaway enumeration loops over the bridge are
fine; the requests you'd screenshot are not throwaway. See CLAUDE.md "Burp-first does NOT stop at foothold".

**STOP-and-think the moment ANY shell lands (before reaching for a shortcut).** The recurring
failure is following the FASTEST path instead of the INTENDED one, then going off the rails. Pause and:
1. Read the box's THEME/name + any notes/creds/files you already have - CTF boxes telegraph the
   intended vector (a module lesson, a service left on, a labelled secret). `qmd_query` the wiki for
   that theme + the exact fingerprinted tech before acting.
2. Enumerate the INTENDED escalation surface FIRST: `sudo -l`, writable configs/cron/timers/scripts
   you own, group memberships, service creds - the deliberate path is almost always one of these and
   `pspy`/`linpeas` surface it in seconds. **When a user is in `sudo`/`wheel` but the password is
   nowhere findable AND cron/writable/SUID/group vectors dead-end, READ `/etc/pam.d/{sudo,su}` and
   `/etc/sudoers.d/*` (not a grep) - a `pam_ssh_agent_auth` (hijack a forwarded agent socket in
   `/tmp/ssh-*/agent.*` -> passwordless sudo), `pam_exec`, or bare `NOPASSWD` line IS the vector; a
   user conspicuously in `lxd`/`docker` that's unreachable is often a DECOY (see [[linux-privesc]]).**
   Read linpeas output WHOLE - the pam/sudoers tell is there but a keyword grep skips it.
3. **Kernel-LPE arsenal (dirtyfrag/copyfail/PwnKit/...) is a LABELLED FALLBACK, not the opening move.**
   We DO carry instant-escalation payloads for old kernels ([[privesc-exploit-arsenal]], [[dirty-frag]]) -
   note the `uname -r` band as a fallback, but VERIFY the intended path is genuinely absent AND verify
   the CVE precondition (userns/module/patch-band) before firing. A shortcut that works is fine; taking
   it BEFORE checking the taught vector is the drift. Once you have full root, look back at what was
   INTENDED and record it (walkthrough + Deadends), so the fast win still teaches the lesson.

Finish the foothold first (leftover Rule 2 techniques, if the shell landed mid-app):
- **Consistent escalation primitive:** if a box exposes the SAME pivot at each stage (a Docker socket/TLS pivot per level, an SSRF each hop), verify/exhaust that intended vector end-to-end BEFORE an opportunistic shortcut (raw device mount, a memory CVE). A shortcut that relies on `--privileged`/a loose cap can mask that a hardened config would block it, and it is less reproducible/auditable. Getting the flag via a shortcut is fine; SKIPPING the taught vector without testing it is the miss.
- Web SQLi: in-band (UNION/error) before blind; test EVERY quote context (`'` `"` numeric) and second-order (a stored value used unsafely on another page). If the app hashes the password inside the query, read plaintext from `information_schema.PROCESSLIST`. Load `Skill(hunt-sqli)` / see [[sql-injection]].
- Recovered unsalted MD5/SHA1: **online lookup first** (CrackStation/hashes.com) before hashcat/john. A hash that resists everything on a hard box may be a deliberate decoy; pivot, don't grind.

Then privesc = pspy ALWAYS + linpeas/winpeas, then manual. **Run a long tool reliably with
`bash scripts/vm-bg.sh <eng> <win> '<tool>'`** - it stages the tool to `/dev/shm`, runs it inside the
stabilized tmux shell (line-buffered to a `/dev/shm/*.log`), and you `--read` / `--wait 120` the
logfile. Never hand-roll a backgrounded watcher over the one-shot SSH bridge (it gets reaped / `tee`
buffers), and never retry a broken tool-execution pattern >2x - switch method (vm-bg) or
`Skill(redteamlead)`. See [[pspy]] / [[linpeas]].

**Always run pspy first** to catch root-run background jobs/cron/timers that static checks miss:
```bash
# upload pspy64 (host it on the tooling box, curl/wget it down) and watch >=60s
./pspy64 -pf -i 1000     # see every exec + file event as root; reveals per-minute cron/systemd timers
```
Then the automated sweep:
```bash
./linpeas.sh         # linux   (winpeas.exe / winpeas.bat on windows)
# AVOID `-a` (deep/thorough) on small boxes (<=1-2 GB RAM, most THM VMs): the full scan can
# OOM-thrash the target until every service (ssh/http/db) times out - looks exactly like the box
# crashed. Use the default scan, or throttle: `nice -n19 ionice -c3 ./linpeas.sh`. If it does hang
# the box, `pkill -9 -f linpeas` (kill it as the user that launched it) and load drains in seconds.
```
Capture linpeas/pspy TWO ways: a `--term` screenshot of the highlighted findings (Skill(screenshot),
the colored hits survive) AND the FULL text log - redirect the tool to a file, then
`scripts/capture.sh log <eng> <slug> /tmp/linpeas.txt` pulls the whole scan (ANSI stripped) into
`poc/NN-<slug>.md`. The screenshot is unreadable past one screen; the `.md` keeps every line so you
(and the operator) can grep it later. Do this for full nmap output too when it is long.

**Read-whole is not just for recon: grep is NOT the read for PAYLOAD RESULTS or pspy/linpeas output either.** A UNION/echo dump can reflect in an unexpected phrasing (singular "1 word" vs plural "N words"), and a root cron hides in the full pspy stream; read the whole result block, not a keyword grep.

Then walk the manual checklist (do not skip any; the box's intended path is usually ONE of these):

| Check | Command | Win = |
|---|---|---|
| sudo rights | `sudo -l` | NOPASSWD/GTFObin -> root |
| SUID/SGID | `find / -perm -4000 -o -perm -2000 2>/dev/null` | GTFObins |
| Capabilities | `getcap -r / 2>/dev/null` | cap_setuid etc. |
| Cron | `cat /etc/crontab /etc/cron.d/*; ls -la /etc/cron.*` + pspy | writable/relative-path script |
| **systemd timers** | `systemctl list-timers --all` + `systemctl cat <svc>` | **writable ExecStart script run as root** (e.g. THM Ollie `feedme.timer`) |
| Writable root files | writable scripts/units root executes; `/etc/passwd` writable | inject payload, wait for trigger |
| Groups | `id` (docker/lxd/disk/adm/shadow) | group->root GTFO |
| Creds | configs, history, DB, `.ssh`, backups | reuse / su |
| Kernel/pkg CVE | `uname -r`; pkg versions (pkexec/polkit, sudo, dbus) | **LAST resort** - check the patch level first ([[linux-privesc]]) |

Box-specific chains now live in wiki (see the technique pages linked per class in `approach-notes.json` REFS).

**Don't assume the flag path** (e.g. `/root/root.txt`); once you have exec, `find` it - the root flag can live at a non-standard path.

## Capture (engagement discipline)

After each phase, write to `targets/<eng>/`: hosts/access -> `state.md`, creds -> `loot.md`, chain -> `state.md`'s `## Chain` section, vulns -> `Vuln-index.md`, dead-ends -> `Deadends.md`, narrative -> `walkthrough.md` (at close-out). Flags go in the writeup, never in `session/*` or `wiki/`.

**Board hygiene, live (GATE 3).** `state.md`'s `## Chain` section and `Deadends.md` rot under momentum while other state.md prose absorbs the narrative instead; the instant a vector (a potato variant, a kernel CVE, a cred spray) is exhausted, append ONE `Deadends.md` line + set its status in `state.md`'s `## Chain` BEFORE trying the next. `status.py` shows board phase + deadend count to spot the drift.

**Live-capture machinery; evidence is never backfilled at close-out:**
- **Auto-card is a backstop, not primary.** The Stop hook (`scripts/autocard.sh`, capped `AUTOCARD_MAX=2`/run) renders any finished scan tmux tab into `recon/`; hand-carding as you go (Phase 1: `capture.sh recon <eng> <slug> <tab>`) stays PRIMARY. 0 cards while tabs finished = VM down / `timeout` missing; hand-card now.
- **Hand-card exploit-state shots** (the flag, the RCE firing, an authed panel) the moment they land; persist to `state.md`/`loot.md` immediately, never deferred.
- **A PoC card is ONE human-authored command**, concrete values, full paths, NO `export`/`$VAR`, NO `;`/`&&`-chains, NO echo banners, NO base64/pty wrappers. Re-run the clean single command for the capture even if a messy pipeline was needed to work the box (that stays in `poc/scripts/`).

**`walkthrough.md` (assembled at close-out) is the narrative** and the clean human version (concrete one-liners, no `$VAR`s); the messy automation (base64 wrappers, pty helpers) stays in `poc/scripts/`.

**Read UI/source hints literally before fuzzing.** A placeholder, button label, or leaked source usually states the intended input format directly; do not default to injection-fuzzing a field that already told you its format.

**Locally-substituted payloads = false-positive RCE.** `$(...)`/backticks/`$VAR` sent through the VM bridge or any local shell get substituted LOCALLY before reaching the target, and the tooling VM runs as root; a reflected `uid=0` may be YOUR box. Always single-quote or base64 injection payloads; confirm execution with a target-only marker (hostname, a file only it has) before claiming RCE.

**Preserve exploit scripts and source reads.** Copy any exploit script or read target source into `targets/<eng>/poc/scripts/`, saved as `<name>.md` with a fenced code block (`sh`/`js`/`py`/`html`), NOT a bare `.sh`/`.js`/`.py`, since Obsidian only previews `.md`/images. `capture.sh snippet <eng> <slug> <url-or-file> '<pattern>' '<reveals>'` for a targeted excerpt.

**Video/media -> mp4 into `poc/` early.** `ffmpeg -i <in> -c copy poc/<slug>.mp4`, then hand it to the operator; a visual puzzle (shoulder-surf, on-screen code) is far cheaper read by a human than brute-analyzed frame-by-frame; frame extraction/OCR is the fallback, not the opening move.

**Screenshot every successful step live, not at the end.** No auto-capture net exists; `scripts/capture.sh` (`ev`/`req`/`tmux`/`burp`) captures straight into `poc/` the moment a step lands. `capture.sh ev <eng> <slug> "<url>" "<cmd-label>"` for a one-call output+request card; `capture.sh req <eng> <slug> -- <curl-args>` for a full request/response card; `capture.sh tmux` for a session card; `capture.sh burp` for a Repeater PoC. `Skill(screenshot)` covers authed/exploited GUI states. Never hand-write a `--term` card (fabricated evidence); `tee` real output into the pane if it was redirected to a file. `python3 scripts/build-walkthrough.py <eng>` auto-populates the `## Evidence` gallery from every `poc/` card.

**Grow the harness wordlist.** A non-obvious route/param that cracked the box -> `python3 scripts/wordlist-suggest.py` (leak-safe) then `scripts/wl-add.sh paths <token>` / `wl-add.sh params <name>`, generic methodology names only, never client branding.

## Context tools

<!-- auto-wired: documented tools to reach for; do not hand-roll -->
- [[wiki/tools/nmap]]
- [[wiki/tools/rustscan]]
- [[naabu]]
- [[wiki/tools/ffuf]]
- [[feroxbuster]]
- [[gobuster]]
- [[wiki/tools/nuclei]]
- [[nikto]]
- [[wiki/tools/whatweb]]
- [[arjun]]
- [[dalfox]]
- [[swaks]]
- [[wiki/cheatsheets/recon]]
- [[nuclei-arsenal]]
- [[wordlists]]
- [[network-services]]
- [[linux-enumeration]]
- [[windows-enumeration]]
- [[windows-privesc]]
- [[password-attacks]]
- [[sqlmap]]
- [[pivoting]]
- [[web-client-attacks]]
- [[metasploit]]
