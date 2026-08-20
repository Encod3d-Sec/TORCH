---
title: "Medusa"
type: tool
tags: [brute-force, htb, linux, network, tool, windows]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-brute-forcing]
phase: crack
---

## Purpose

Medusa is a fast, massively parallel, modular login brute-forcer designed to support a wide array of remote authentication services through a plugin-based module system.

## Install / Setup

```bash
sudo apt-get -y update
sudo apt-get -y install medusa
```

## Core Usage

```bash
medusa [target_options] [credential_options] -M module [module_options]
```

### Core Flags

| Flag             | Description                                                          |
|------------------|----------------------------------------------------------------------|
| `-h HOST`        | Single target hostname or IP                                         |
| `-H FILE`        | File containing target hosts (one per line)                          |
| `-u USERNAME`    | Single username                                                      |
| `-U FILE`        | Username wordlist file                                               |
| `-p PASSWORD`    | Single password                                                      |
| `-P FILE`        | Password wordlist file                                               |
| `-M MODULE`      | Module to use (e.g., `ssh`, `ftp`, `http`, `rdp`)                   |
| `-m "OPTIONS"`   | Module-specific options (quoted string)                              |
| `-t N`           | Number of parallel login attempts per host                           |
| `-T N`           | Total concurrent hosts to attack simultaneously                       |
| `-f`             | Stop after first success on current host                             |
| `-F`             | Stop after first success on any host                                 |
| `-n PORT`        | Non-default port                                                     |
| `-v LEVEL`       | Verbosity (0–6; higher = more output)                                |
| `-e ns`          | Additional checks: `n` = empty password, `s` = password = username  |

## Modules

| Module      | Protocol              | Example                                                              |
|-------------|----------------------|----------------------------------------------------------------------|
| `ssh`       | SSH                   | `medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt`            |
| `ftp`       | FTP                   | `medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt`           |
| `http`      | HTTP (GET/POST)       | `medusa -M http -h example.com -U users.txt -P passwords.txt -m GET` |
| `web-form`  | HTML login form       | `medusa -M web-form -h example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"` |
| `rdp`       | Remote Desktop        | `medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt`           |
| `mysql`     | MySQL                 | `medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt`          |
| `pop3`      | POP3 Email            | `medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt`   |
| `imap`      | IMAP Email            | `medusa -M imap -h mail.example.com -U users.txt -P passwords.txt`   |
| `vnc`       | VNC                   | `medusa -M vnc -h 192.168.1.100 -P passwords.txt`                    |
| `telnet`    | Telnet                | `medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt`        |
| `svn`       | Subversion            | `medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt`           |

## Common Use Cases

### SSH Brute Force

```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

With specific port and thread limit:

```bash
medusa -h 10.10.10.1 -n 2222 -u sshuser -P passwords.txt -M ssh -t 3
```

### FTP with Known Username

If you've identified a likely FTP username from `/home` directory listings:

```bash
medusa -h 127.0.0.1 -u ftpuser -P passwords.txt -M ftp -t 5
```

### Multiple Web Servers — HTTP Basic Auth

```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

### Check for Empty or Default Passwords

```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M ssh
```

- `-e n` — try empty password for each username
- `-e s` — try the username itself as the password

### Web Login Form

```bash
medusa -M http -h www.example.com -U users.txt -P passwords.txt \
       -m DIR:/login.php \
       -m FORM:"username=^USER^&password=^PASS^:F=Invalid"
```

## Medusa vs Hydra

| Feature                      | Medusa                          | Hydra                           |
|------------------------------|---------------------------------|---------------------------------|
| Architecture                 | Module-based plugins            | Service-based modules           |
| Multi-host parallelism       | Yes (`-T` flag)                 | Yes (`-M` flag for host lists)  |
| HTTP form support            | Yes (`web-form` module)         | Yes (`http-post-form`)          |
| RDP support                  | Yes                             | Yes                             |
| Overall speed                | Very fast (multi-host)          | Very fast (multi-thread)        |
| Protocol coverage            | Broad but fewer than Hydra      | Very broad                      |
| Active maintenance           | Less actively maintained        | More actively maintained        |

Hydra has slightly broader protocol support and is more commonly used. Medusa's `-T` flag makes it slightly better for simultaneous multi-host attacks.

## Tips and Gotchas

- **`-e ns`** is a quick win — always check for empty passwords and username-as-password before launching a full dictionary attack.
- **`-f` vs `-F`**: Use `-f` when you want to stop on the first success per host. Use `-F` when scanning multiple hosts and you want to stop globally on the first credential found anywhere.
- **Web form module**: The `FORM:` string format is similar to Hydra's `http-post-form`. Inspect the form HTML and use browser dev tools to get the exact field names.
- **Thread count**: Keep `-t` low (3–5) for SSH to avoid rate limiting and lockouts. Higher values are safer for HTTP.
- **Verbosity**: Use `-v 6` for maximum detail when debugging why a module isn't matching correctly.

## Related Techniques

- [[wiki/tools/hydra]] — More widely used alternative with similar capabilities and broader protocol support
- [[wiki/cheatsheets/recon]] — Identify login interfaces before brute forcing

## Sources

- CPTS Login Brute Forcing — Medusa (`4. Medusa/1. Medusa.md`)
