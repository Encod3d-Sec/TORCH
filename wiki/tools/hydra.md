---
title: "Hydra"
type: tool
tags: [brute-force, htb, linux, network, tool, web, windows]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-brute-forcing]
phase: crack
---

## Purpose

Hydra is a fast, parallelised network login brute-forcer that supports a wide range of protocols including SSH, FTP, HTTP, RDP, MySQL, SMTP, and many more.

## Install / Setup

Pre-installed on Kali. Install on Debian-based systems:

```bash
sudo apt-get -y update
sudo apt-get -y install hydra
```

## Core Usage

```bash
hydra [login_options] [password_options] [attack_options] [service_options]
```

### Core Flags

| Flag              | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| `-l LOGIN`        | Single username                                                    |
| `-L FILE`         | Username wordlist file                                             |
| `-p PASS`         | Single password                                                    |
| `-P FILE`         | Password wordlist file                                             |
| `-t N`            | Number of parallel tasks/threads (default 16)                     |
| `-f`              | Stop after first successful login                                  |
| `-s PORT`         | Non-default port                                                   |
| `-v`              | Verbose output                                                     |
| `-V`              | Very verbose — show each login attempt                            |
| `-M FILE`         | File containing multiple target hosts (one per line)              |
| `-x min:max:charset` | Generate passwords on the fly (brute force, not dict)          |

### Service Syntax

```bash
hydra <service>://<target>
# or
hydra <options> <target> <service>
```

## Supported Services

| Service       | Protocol          | Example Command                                                                                  |
|---------------|-------------------|--------------------------------------------------------------------------------------------------|
| `ssh`         | SSH               | `hydra -l root -P passwords.txt ssh://192.168.1.100`                                             |
| `ftp`         | FTP               | `hydra -L users.txt -P passwords.txt ftp://192.168.1.100`                                        |
| `http-get`    | HTTP Basic Auth   | `hydra -L users.txt -P passwords.txt www.example.com http-get`                                   |
| `http-post-form` | HTML Login Form | `hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"` |
| `rdp`         | Remote Desktop    | `hydra -l admin -P passwords.txt rdp://192.168.1.100`                                            |
| `smb`         | SMB               | `hydra -L users.txt -P passwords.txt smb://192.168.1.100`                                        |
| `mysql`       | MySQL             | `hydra -l root -P passwords.txt mysql://192.168.1.100`                                           |
| `mssql`       | SQL Server        | `hydra -l sa -P passwords.txt mssql://192.168.1.100`                                             |
| `smtp`        | Email (SMTP)      | `hydra -l admin -P passwords.txt smtp://mail.server.com`                                         |
| `pop3`        | Email (POP3)      | `hydra -l user@example.com -P passwords.txt pop3://mail.server.com`                              |
| `imap`        | Email (IMAP)      | `hydra -l user@example.com -P passwords.txt imap://mail.server.com`                              |
| `vnc`         | VNC               | `hydra -P passwords.txt vnc://192.168.1.100`                                                     |

## Common Use Cases

### HTTP Basic Authentication

```bash
hydra -l basic-auth-user -P /usr/share/wordlists/rockyou.txt 10.10.10.1 http-get / -s 81
```

### FTP on non-standard port

```bash
hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp
```

### SSH brute force

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100
```

### SSH against multiple targets

```bash
hydra -l root -p toor -M targets.txt ssh
```

### HTTP POST form login

First, determine the form parameters using browser dev tools (F12 → Network tab) or Burp Suite. Then:

```bash
hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt \
     -f 10.10.10.1 -s 5000 \
     http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

The `http-post-form` argument format is:

```
"path:params:condition_string"
```

- **`path`** — URL path where the form POSTs to (e.g., `/` or `/login`)
- **`params`** — Form field names with `^USER^` and `^PASS^` placeholders
- **`condition_string`** — Either a failure string (`F=<text>`) or success string (`S=<text>` or `S=302`)

#### Condition String Examples

| Pattern                          | Meaning                                                          |
|----------------------------------|------------------------------------------------------------------|
| `F=Invalid credentials`          | Fail if response body contains "Invalid credentials"             |
| `F=Login failed`                 | Fail if response body contains "Login failed"                    |
| `S=302`                          | Succeed if server returns HTTP 302 redirect                      |
| `S=Dashboard`                    | Succeed if response body contains "Dashboard"                    |
| `S=Welcome`                      | Succeed if response body contains "Welcome"                      |

#### Full form login example

```bash
hydra -l admin -P passwords.txt www.example.com \
     http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

### RDP with generated passwords

```bash
hydra -l administrator \
     -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \
     192.168.1.100 rdp
```

The `-x min:max:charset` flag generates all combinations from length `min` to `max` using the given charset.

## Wordlist Selection

| Wordlist                            | Use Case                                |
|-------------------------------------|-----------------------------------------|
| `/usr/share/wordlists/rockyou.txt`  | General password brute force            |
| `SecLists: top-usernames-shortlist.txt` | Quick username attempts             |
| `SecLists: xato-net-10-million-usernames.txt` | Thorough username brute force |
| `SecLists: 2023-200_most_used_passwords.txt` | Common passwords (fast)      |
| `SecLists: Default-Credentials/default-passwords.txt` | Default creds for devices |

## Custom Wordlists

Use **Username Anarchy** for targeted username generation:

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

Use **CUPP** for target-aware password lists:

```bash
sudo apt install cupp -y
cupp -i   # interactive mode; answer questions about the target
```

Filter CUPP output to match a specific password policy:

```bash
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | \
     grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

## Tips and Gotchas

- **`-f` is your friend**: Stop at first success to avoid unnecessary noise and potential account lockout triggers.
- **`-t` threads**: More threads = faster but noisier. For SSH/RDP, keep threads low (4–8) to avoid lockouts. For HTTP, 16–64 is reasonable.
- **Inspect the login form carefully**: Incorrect `params` strings are the most common cause of Hydra failures. Use browser dev tools (F12 → Network) or Burp Suite to capture the exact POST request, then replicate the field names exactly.
- **CSRF tokens**: If the login form uses CSRF tokens that change per request, `http-post-form` alone cannot handle them. Use Burp Suite's Intruder or a custom script instead.
- **Success vs failure detection**: Use failure strings (`F=`) when the error message is consistent. Use success strings (`S=`) when the success state (e.g., redirect code, dashboard content) is more reliable.
- **HTTP Basic Auth vs form login**: `http-get` is for Basic Auth (the browser pop-up). `http-post-form` is for HTML form-based logins.
- **VNC**: Typically only requires a password, not a username — use `-P` without `-l`/`-L`.
- **Rate limiting**: Many services throttle login attempts. Use `--wait N` or reduce threads with `-t 4`.

## Related Techniques

- [[medusa]] — Alternative parallel brute-forcer with module-based design
- [[wiki/tools/ffuf]] — Can also brute-force web form passwords via POST fuzzing
- [[wiki/cheatsheets/recon]] — Identify login forms and authentication endpoints before brute forcing

## Sources

- CPTS Login Brute Forcing — Hydra (`1. Hydra.md`, `2. Login Forms.md`)
- CPTS Login Brute Forcing — Custom Wordlists (`1. Custom WordLists.md`)
- CPTS Login Brute Forcing — Brute Force Attacks (`1. Intaractive Brute Force attacks.md`)
