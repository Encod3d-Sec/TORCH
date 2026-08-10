# The Kali attack VM and `vm.sh`

Claude Code runs in WSL, which has **no VPN route** to targets and no offensive
tooling. A separate **Kali VM** holds the VPN, the tools (nmap/ffuf/nuclei/nxc,
linpeas, chromium), and is reached over SSH by a one-line driver, `vm.sh`.

```
Claude (WSL) --ssh (vm.sh)--> Kali VM --VPN--> targets
```

## Configure it: one file, `/root/creds.txt`

IP, username, and password all live in `/root/creds.txt` (git-ignored, device-local).
Edit the value on the line under each header:

```
# IP
192.168.1.1
# Username
kali
# Password
your-password
```

`vm.sh` reads all three from here and hardcodes nothing. To point at a new VM, edit
this file only. The script lives at `/root/vm.sh` (device-local, one copy per machine).

## Use it

```bash
bash /root/vm.sh '<remote bash command>'   # runs as root on the VM, output streamed back
bash /root/vm.sh 'nmap -sV -Pn TARGET'
```

## Gotchas

- **No stdin is forwarded.** `local-cmd | vm.sh 'cat > f'` writes an EMPTY file. Push a
  file by base64-ing it INTO the command:
  `B64=$(base64 -w0 f); bash /root/vm.sh "echo $B64 | base64 -d > /tmp/f"`.
  Pull one back: `bash /root/vm.sh 'base64 -w0 /tmp/f' | base64 -d > local`.
- **No persistent state.** Each call is a fresh SSH session; `cd` and vars do not carry.
  Chain steps with `;` / `&&` in one call.
- **Long FOREGROUND commands get dropped (exit 255, no output).** A single `vm.sh '<cmd>'`
  running more than ~2 min (scan / crack / spray / brute) has its SSH cut mid-run. Detach and
  poll a file instead: a tmux tab (`scripts/vm-scan.sh <eng> <target> '<cmd>'`), or
  `nohup <cmd> >/tmp/out 2>&1 &` then poll `for i in $(seq 1 60); do grep -q DONE /tmp/out && break; sleep 3; done`.
  When pushing a script then running it, do BOTH in one call (write races the run otherwise).
- **Runs as root**, `ConnectTimeout=10` (fails fast). A `Permission denied` means
  `/root/creds.txt` is stale.

## Running scans in tmux + capturing the desktop

Scans run in a root tmux session on the VM (persistent across `vm.sh` calls), one named
tab per target: `bash scripts/vm-scan.sh <eng> <target> '<scan>'`. Capture a tab as a
terminal card with `shot.py --tmux <eng>:<target>`; capture a GUI app / the desktop with
`shot.py --window "Name"` / `--screen`. Capture by the `window=@NN` id (or the sanitized
tab name) that `vm-scan.sh` prints, not the raw dotted target (a dot in the target
collides with tmux's `session:window.pane` syntax).

### tmux for interactive sessions (shell + msfconsole)

tmux is NOT for scan parallelism (one-shots + the `capture-poc` hook cover that). It is reserved
for landing a PERSISTENT INTERACTIVE session so it survives the agent's one-shot command boundaries
and is `tmux attach`-able for manual operator work. Same `--win` mechanism, split by session type:

- **Reverse shell:** `vm-scan.sh --win shell <eng> <target> 'nc -lvnp <port>'` holds the listener; the
  shell lands in `<eng>:shell`. Drive it one command at a time with `vm-rsh.sh --win shell <eng> '<cmd>'`
  (base64 + marker wrapped, clean output).
- **msfconsole / meterpreter:** `vm-scan.sh --win msf <eng> <target> "msfconsole -q -x 'use <mod>; set
  RHOSTS ...; run'"` lands msfconsole in `<eng>:msf`, persistent + attachable. Drive msf itself by
  **operator attach** (`tmux attach -t <eng>`); for agent-driven post-ex, drop to a system shell inside
  the session and use `vm-rsh.sh --win msf` there. `vm-rsh`'s wrapper is bash (`... | base64 -d | bash`),
  so it frames a shell, not the raw `msf6 >` REPL.
- **Operator takeover:** `tmux attach -t <eng>` on the VM, select the `shell`/`msf` window.

The campaign driver records the foothold window (`campaign.py foothold <asset> --win <win>`, or
`done ... --win <win>` on the closing find). After that, `campaign.py next` routes post-foothold tool
commands for that asset through `vm-rsh --win <win>` and prints the `tmux attach` hint, keeping the
persistent session and operator visibility past foothold.

GUI grabs need the desktop's X session: shot.py resolves the seat user/display from `who`,
unlocks via `loginctl unlock-session`, wakes with `xset dpms force on`, and grabs as that
user with `XAUTHORITY` (a bare `scrot` as root-over-SSH fails with "Can't open X display").
Install the deps once with `bash scripts/vm-provision.sh` (also run by `setup/bootstrap.sh`).
This installs the screenshot/tmux capture deps AND the recon + test toolchain the
fingerprint router routes to (apt-first; `bash scripts/vm-provision.sh --list` prints the set,
and the final line prints a verify one-liner). It is per-package tolerant, so a name that is not
in your Kali release's repo is reported `MISS` rather than aborting the run.

## Driving a live browser (chrome-devtools MCP)

`bash scripts/browser.sh start` runs chromium on the VM (headless, in the `browser:cdp` tmux
window) and forwards its DevTools port to `127.0.0.1:9222` here over SSH, so the
`chrome-devtools` MCP can drive it: navigate, click, read the DOM/accessibility tree, inspect
network traffic, run JS in the page. `status` / `stop` manage it; `--headed` keeps a visible
window when the VM has a desktop.

Chromium runs on the VM for the same reason `shot.py` does: **that is where the VPN route to
in-scope targets is**. A browser on Windows or in WSL cannot reach them.

The DevTools port is **unauthenticated total control of the browser** - any page it has open,
every cookie and session in it. So it is bound to `127.0.0.1` on the VM and reached only
through `ssh -L` loopback-to-loopback; it is never offered to a network. If it ever seems
unreachable, fix the tunnel - do not "fix" it with `--remote-debugging-address=0.0.0.0`.
`tests/test_browser.py` guards against that flag reappearing.

`--host windows` drives Windows Chrome instead (interactive: you can solve a login or MFA
prompt by hand mid-flow), but needs WSL mirrored networking (`networkingMode=mirrored` in
`.wslconfig` + `wsl --shutdown`); under default NAT the script refuses rather than exposing
the port. Mirrored mode changes WSL networking broadly - do not flip it mid-engagement with
Ligolo tunnels up.

## `/opt/arsenal` (canonical on-VM tool/script home)

`/opt/arsenal` is the canonical home on the VM for OUR helpers and fetched offensive tools -
`shot.py`, `capture.sh`, harness wordlists, and privesc binaries (`pspy64`, `linpeas.sh`,
`winPEASx64.exe`). `vm-provision.sh` creates it (world-writable) and seeds it: it fetches the
privesc tools from their GitHub releases on the VM, and base64-pushes `shot.py` + `capture.sh` +
`scripts/wordlists/harness-*.txt` from the vault.

On a box, reach for a helper from `/opt/arsenal` first (e.g. `/opt/arsenal/pspy64`,
`/opt/arsenal/linpeas.sh`). If a script you need is not there yet, push it from the vault on
demand:

```
bash scripts/vm-sync.sh <name>     # pushes scripts/<name> -> /opt/arsenal/<name> if missing
```

`vm-sync.sh` is idempotent (skips when the file is already present) and base64-pushes over the
`vm.sh` bridge (which forwards no stdin). It fails open with a clear message when the VM is
unreachable.

## Secrets boundary

The VM IP and password live only in `/root/creds.txt` (device-local). Never write them
into `docs/`, `wiki/`, `session/`, scripts, or commits. Target specifics stay under
`targets/<eng>/`.
