#!/usr/bin/env bash
# browser-win.sh - drive the WINDOWS Chrome from WSL over CDP, under DEFAULT NAT networking.
#
#   bash scripts/browser-win.sh start     # launch debuggable Chrome + bridge it to WSL 127.0.0.1:9222
#   bash scripts/browser-win.sh status
#   bash scripts/browser-win.sh stop
#
# WHY THIS EXISTS (and how it differs from browser.sh):
#   scripts/browser.sh drives chromium ON KALI (it holds the VPN route to targets) and its
#   `--host windows` mode REFUSES to run without WSL mirrored networking - correctly, because the
#   only NAT-mode alternative it knew was binding the DevTools port to 0.0.0.0, which hands
#   unauthenticated control of the browser (and every logged-in session in it) to the whole LAN.
#   This script gets there safely instead: it relays through the HOST-ONLY WSL interface
#   (the default gateway, e.g. 172.26.192.1), which is reachable from WSL but NOT from the LAN.
#   Use this one when a human must log in interactively (national eID / bank / SSO), which is
#   impractical in headless chromium on the VM.
#
# THE CHAIN:
#   WSL 127.0.0.1:9222  --(python fwd, this script)-->  <gw>:9224
#                       --(PowerShell relay on Windows)-->  127.0.0.1:9333  (Chrome CDP)
#   The last hop lands on Windows loopback, so Chrome sees a sane Host header. The MCP is
#   configured with `--browserUrl http://127.0.0.1:9222`, so it needs no reconfiguration.
#
# HARD-WON GOTCHAS (each of these cost real time - do not re-derive them):
#   1. An ALREADY-RUNNING Chrome is almost never debuggable. Chrome only opens the CDP port when
#      it is STARTED with --remote-debugging-port. A normal Chrome may still be *listening* on
#      9222 for unrelated reasons and answer /json/version with 404 - that is not CDP.
#      Verify with: Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" | % { $_.CommandLine }
#   2. Chrome will NOT enable debugging on an existing profile that is already open. This script
#      therefore launches a SECOND instance on its own --user-data-dir, leaving the user's main
#      browser and sessions untouched. The human logs in inside that second window.
#   3. `netsh interface portproxy` needs Administrator (UAC). The userland PowerShell TcpListener
#      relay used here does not.
#   4. Bind the relay to the gateway IP ONLY. Never 0.0.0.0.
#   5. The relay does not survive a Windows reboot; re-run `start`.
set -uo pipefail

WIN_PORT=9333                       # Chrome CDP on Windows loopback
RELAY_PORT=9224                     # host-only relay port on the WSL-facing interface
WSL_PORT=9222                       # what the MCP connects to, inside WSL
PROFILE='C:\Temp\cdp-profile'
RELAY_PS1_WIN='C:\Temp\cdp-relay-win.ps1'
RELAY_PS1_WSL='/mnt/c/Temp/cdp-relay-win.ps1'
FWD_PY="${TMPDIR:-/tmp}/cdp-fwd-win.py"
PS_EXE='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
CHROME_WIN='C:\Program Files\Google\Chrome\Application\chrome.exe'

GW="$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')"

die() { echo "browser-win.sh: $*" >&2; exit 1; }
have_interop() { [ -x "$PS_EXE" ]; }

write_relay() {
  mkdir -p /mnt/c/Temp 2>/dev/null
  cat > "$RELAY_PS1_WSL" <<PS1
\$src = @"
using System; using System.Net; using System.Net.Sockets; using System.Threading;
public class CdpRelayWin {
  public static void Start(string bindIp, int listenPort, string dstIp, int dstPort) {
    var l = new TcpListener(IPAddress.Parse(bindIp), listenPort);
    l.Start();
    while (true) {
      var c = l.AcceptTcpClient();
      var t = new Thread(delegate() { Handle(c, dstIp, dstPort); });
      t.IsBackground = true; t.Start();
    }
  }
  static void Handle(TcpClient c, string dstIp, int dstPort) {
    try {
      using (c) using (var d = new TcpClient(dstIp, dstPort)) {
        var cs = c.GetStream(); var ds = d.GetStream();
        var t1 = new Thread(delegate() { try { cs.CopyTo(ds); } catch {} });
        t1.IsBackground = true; t1.Start();
        try { ds.CopyTo(cs); } catch {}
      }
    } catch {}
  }
}
"@
Add-Type -TypeDefinition \$src -Language CSharp
[CdpRelayWin]::Start('$GW', $RELAY_PORT, '127.0.0.1', $WIN_PORT)
PS1
}

write_fwd() {
  cat > "$FWD_PY" <<PY
import socket, threading, sys
GW, RELAY, LOCAL = "$GW", $RELAY_PORT, $WSL_PORT
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except Exception: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            try: s.close()
            except Exception: pass
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", LOCAL)); srv.listen(64)
while True:
    c, _ = srv.accept()
    try:
        u = socket.create_connection((GW, RELAY), timeout=10)
    except Exception:
        c.close(); continue
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c), daemon=True).start()
PY
}

cdp_ok() { curl -fsS --max-time 5 "http://127.0.0.1:$WSL_PORT/json/version" >/dev/null 2>&1; }

cmd_start() {
  have_interop || die "no WSL interop ($PS_EXE missing). Is this WSL with interop enabled?"
  [ -n "$GW" ] || die "could not determine the WSL default gateway"
  echo "gateway (host-only, WSL-facing): $GW"

  # 1. Chrome with CDP. Launch unconditionally on its own profile: a second instance is harmless,
  #    and an already-open Chrome cannot be retrofitted with a debugging port (gotcha 1 + 2).
  if "$PS_EXE" -NoProfile -Command "try { (Invoke-WebRequest -Uri 'http://127.0.0.1:$WIN_PORT/json/version' -UseBasicParsing -TimeoutSec 4) | Out-Null; exit 0 } catch { exit 1 }" 2>/dev/null; then
    echo "chrome:  already debuggable on 127.0.0.1:$WIN_PORT"
  else
    "$PS_EXE" -NoProfile -Command "Start-Process '$CHROME_WIN' -ArgumentList '--remote-debugging-port=$WIN_PORT','--user-data-dir=$PROFILE','--no-first-run','--no-default-browser-check','about:blank'" >/dev/null 2>&1
    for _ in $(seq 1 15); do
      "$PS_EXE" -NoProfile -Command "try { (Invoke-WebRequest -Uri 'http://127.0.0.1:$WIN_PORT/json/version' -UseBasicParsing -TimeoutSec 3) | Out-Null; exit 0 } catch { exit 1 }" 2>/dev/null && break
      sleep 1
    done
    echo "chrome:  launched on 127.0.0.1:$WIN_PORT (profile $PROFILE)"
  fi

  # 2. Host-only relay on Windows.
  write_relay
  if ! curl -fsS --max-time 4 "http://$GW:$RELAY_PORT/json/version" >/dev/null 2>&1; then
    "$PS_EXE" -NoProfile -Command "Start-Process powershell -ArgumentList '-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File','$RELAY_PS1_WIN' -WindowStyle Hidden" >/dev/null 2>&1
    sleep 3
  fi
  curl -fsS --max-time 4 "http://$GW:$RELAY_PORT/json/version" >/dev/null 2>&1 \
    && echo "relay:   $GW:$RELAY_PORT -> 127.0.0.1:$WIN_PORT (host-only, NOT LAN-exposed)" \
    || die "relay did not come up on $GW:$RELAY_PORT"

  # 3. WSL-side forwarder. setsid so it outlives this shell.
  write_fwd
  if ! cdp_ok; then
    pkill -f "$(basename "$FWD_PY")" 2>/dev/null
    setsid nohup python3 "$FWD_PY" >/tmp/cdp-fwd-win.log 2>&1 < /dev/null &
    sleep 2
  fi
  cdp_ok && echo "CDP:     http://127.0.0.1:$WSL_PORT  (chrome-devtools MCP needs no reconfiguration)" \
         || die "forwarder failed; see /tmp/cdp-fwd-win.log"
  echo
  echo "Log in interactively in the Chrome window that opened; the MCP drives that same browser."
}

cmd_status() {
  echo "gateway: ${GW:-unknown}"
  if cdp_ok; then
    echo "UP    http://127.0.0.1:$WSL_PORT"
    curl -fsS --max-time 5 "http://127.0.0.1:$WSL_PORT/json/version" 2>/dev/null | head -4
    echo "--- pages ---"
    curl -fsS --max-time 5 "http://127.0.0.1:$WSL_PORT/json/list" 2>/dev/null \
      | python3 -c "import json,sys
try:
    for t in json.load(sys.stdin):
        if t.get('type')=='page': print(' -', (t.get('title') or '')[:44], '|', (t.get('url') or '')[:58])
except Exception: pass" 2>/dev/null | head -10
  else
    echo "DOWN  nothing answering on 127.0.0.1:$WSL_PORT   (run: $0 start)"
  fi
}

cmd_stop() {
  pkill -f "$(basename "$FWD_PY")" 2>/dev/null && echo "wsl forwarder stopped" || echo "wsl forwarder not running"
  if have_interop; then
    "$PS_EXE" -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { \$_.CommandLine -like '*cdp-relay-win.ps1*' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force }" >/dev/null 2>&1 \
      && echo "windows relay stopped"
    echo "NOTE: the debuggable Chrome window is left open on purpose (it may hold a login you still need)."
    echo "      Close it yourself, or: powershell -Command \"Get-CimInstance Win32_Process -Filter \\\"Name='chrome.exe'\\\" | Where-Object { \\\$_.CommandLine -like '*remote-debugging-port=$WIN_PORT*' } | ForEach-Object { Stop-Process -Id \\\$_.ProcessId -Force }\""
  fi
}

case "${1:-status}" in
  start)  cmd_start ;;
  status) cmd_status ;;
  stop)   cmd_stop ;;
  -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command '${1}'. Use: start | status | stop" ;;
esac
