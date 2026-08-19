#!/usr/bin/env bash
# browser-visible.sh - bring up a VISIBLE, interactive chromium on the Kali VM's real
# desktop (:0) with a debuggable CDP port, so the OPERATOR can complete a manual login
# (Smart-ID / Mobile-ID / any MFA) while the agent drives + observes it via the
# chrome-devtools MCP. Companion to scripts/browser.sh (which only does headless + the
# CDP tunnel). Encodes the failures.md recipe: seat-user + :0 + XAUTHORITY, tmux-persisted,
# dedicated profile, deliberate port-free + stale-lock clear, verify-visible.
#
#   bash scripts/browser-visible.sh <url> [--profile NAME] [--port 9222] [--session cdpbrowser]
#   bash scripts/browser-visible.sh https://target.example/login --profile bbtest-<eng>
#
# After it prints "VISIBLE on :0", point chrome-devtools MCP at http://127.0.0.1:<port>,
# then hand the window to the operator to log in (stay off the browser during credential entry).
set -uo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
VM_SH="${VM_SH:-/root/vm.sh}"
PORT=9222
PROFILE="cdp-visible"
SESSION="cdpbrowser"
URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:?}"; shift 2;;
    --profile) PROFILE="${2:?}"; shift 2;;
    --session) SESSION="${2:?}"; shift 2;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    -*) echo "browser-visible.sh: unknown arg '$1'" >&2; exit 2;;
    *) URL="$1"; shift;;
  esac
done
[ -n "$URL" ] || { echo "browser-visible.sh: need a <url>" >&2; exit 2; }
[ -r "$VM_SH" ] || { echo "browser-visible.sh: no vm.sh at $VM_SH" >&2; exit 2; }

# 1. Resolve the VM seat session ONCE (user + :N display from `who`, like shot.py x_session).
#    Resolving locally keeps the launch/verify commands simple (plain interpolation, no remote-var
#    escaping). No (:N) line -> the VM has no desktop; caller should use scripts/browser.sh headless.
seat="$(bash "$VM_SH" 'who | grep -E "\(:[0-9]+\)" | head -1' 2>/dev/null || true)"
user="$(printf '%s' "$seat" | awk '{print $1}')"
disp="$(printf '%s' "$seat" | grep -oE '\(:[0-9]+\)' | tr -d '()')"
if [ -z "$user" ] || [ -z "$disp" ]; then
  echo "browser-visible.sh: no (:N) desktop session on the VM (who: '${seat:-empty}') - use scripts/browser.sh for headless" >&2
  exit 3
fi
home="/home/$user"; xauth="$home/.Xauthority"; prof="$home/$PROFILE"
echo "VM seat: $user on $disp ; profile=$PROFILE port=$PORT"

# 2. Cleanup then launch, as TWO simple ssh calls. Bundling cleanup + a GUI launch into one
#    multi-line ssh command drops the channel before chromium starts; separate single-purpose
#    calls are reliable. We ignore output/exit (a tmux GUI launch swallows its own output) and
#    verify separately (step 3).
#  2a. unlock/wake the seat; free the CDP port + any same-profile chromium; WIPE the profile (a
#      leftover SingletonLock makes a new chromium attach-and-exit instead of opening a debug port -
#      the #1 failure; nothing to preserve for a fresh login browser).
bash "$VM_SH" "
sid=\$(loginctl list-sessions --no-legend 2>/dev/null | awk '/seat0/{print \$1; exit}'); [ -n \"\$sid\" ] && loginctl unlock-session \"\$sid\" 2>/dev/null || true
sudo -u $user env DISPLAY=$disp XAUTHORITY=$xauth xset dpms force on 2>/dev/null || true
pkill -9 -f 'remote-debugging-port=$PORT' 2>/dev/null; pkill -9 -f 'user-data-dir=$prof' 2>/dev/null
sleep 2; rm -rf '$prof' 2>/dev/null; tmux kill-session -t $SESSION 2>/dev/null
true" >/dev/null 2>&1 || true
#  2b. launch chromium AS THE SEAT USER on :0 in a named tmux session (single-line; stdio to
#      /dev/null so tmux cannot hold the SSH channel).
bash "$VM_SH" "tmux new-session -d -s $SESSION -c '$home' \"sudo -u $user env HOME=$home DISPLAY=$disp XAUTHORITY=$xauth chromium --remote-debugging-port=$PORT --remote-debugging-address=127.0.0.1 --user-data-dir=$prof --no-first-run --no-default-browser-check '$URL'\" </dev/null >/dev/null 2>&1" >/dev/null 2>&1 || true
echo "launched; verifying the CDP port + on-screen window..."

# 3. Poll-verify via SEPARATE short calls (each a fresh ssh -> reliable output).
up=""
for _ in $(seq 1 20); do
  sleep 2
  if [ -n "$(bash "$VM_SH" "ss -ltn 2>/dev/null | grep -o 127.0.0.1:$PORT | head -1" 2>/dev/null || true)" ]; then up=1; break; fi
done
[ -n "$up" ] || { echo "browser-visible.sh: chromium did not open the CDP port on the VM (check the VM console; a stuck chromium on this profile?)" >&2; exit 4; }
win="$(bash "$VM_SH" "sudo -u $user env DISPLAY=$disp XAUTHORITY=$xauth xdotool search --onlyvisible --class chromium getwindowname 2>/dev/null | head -1" 2>/dev/null || true)"
if [ -n "$win" ]; then echo "VISIBLE on $disp: $win"; else echo "port up but no on-screen window (check the VM console)"; fi

# 4. Reuse browser.sh for the loopback->loopback CDP forward (it detects the already-listening
#    chromium and only sets up the ssh -L tunnel - no second browser launched).
echo "forwarding CDP to this host via scripts/browser.sh ..."
bash "$VAULT/scripts/browser.sh" start --port "$PORT" 2>&1 | grep -iE "CDP:|already|forward|FAIL" || true
echo "READY: point chrome-devtools MCP at http://127.0.0.1:$PORT ; hand the window to the operator to log in."
