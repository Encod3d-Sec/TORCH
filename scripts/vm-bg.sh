#!/usr/bin/env bash
# Reliable long-running remote tool exec: stage the tool in /dev/shm, run it INSIDE the engagement's
# stabilized tmux window redirected (line-buffered) to /dev/shm/<win>.log, return immediately. Read
# the LOGFILE (never a flaky pane capture). Fixes pspy/linpeas dying over the one-shot SSH bridge.
#   vm-bg.sh <eng> <win> '<remote cmd>'      launch, log -> /dev/shm/<win>.log
#   vm-bg.sh --read  <eng> <win>             cat the log
#   vm-bg.sh --wait  <eng> <win> [secs=120]  sleep then cat the log
#   vm-bg.sh --dry-run <eng> <win> '<cmd>'   print the plan, run nothing
set -uo pipefail
VM_SH="${VM_SH:-/root/vm.sh}"
DRY=0; MODE=launch
case "${1:-}" in
  --dry-run) DRY=1; shift;;
  --read)    MODE=read; shift;;
  --wait)    MODE=wait; shift;;
esac
ENG="${1:?need <eng>}"; WIN="${2:?need <win>}"; CMD="${3:-}"
SESSION="$ENG"; LOG="/dev/shm/${WIN}.log"
if [ "$MODE" = read ]; then
  bash "$VM_SH" "cat '$LOG' 2>/dev/null || echo '(no log yet: $LOG)'"; exit 0
fi
if [ "$MODE" = wait ]; then
  SECS="${3:-120}"; bash "$VM_SH" "sleep $SECS; cat '$LOG' 2>/dev/null || echo '(no log: $LOG)'"; exit 0
fi
# launch: run CMD inside the tmux window, line-buffered, to the /dev/shm log
REMOTE="tmux has-session -t '$SESSION' 2>/dev/null || tmux new-session -d -s '$SESSION'; \
tmux list-windows -t '$SESSION' -F '#{window_name}' | grep -qx '$WIN' || tmux new-window -t '$SESSION' -n '$WIN'; \
tmux send-keys -t '$SESSION:$WIN' \"stdbuf -oL -eL $CMD > $LOG 2>&1\" Enter; echo 'launched -> $LOG (read: vm-bg.sh --read $ENG $WIN)'"
if [ "$DRY" = 1 ]; then
  printf 'DRY-RUN plan:\n  log: %s\n  stage: run in tmux %s:%s via stdbuf, redirect to /dev/shm\n  remote: %s\n' "$LOG" "$SESSION" "$WIN" "$REMOTE"
  exit 0
fi
bash "$VM_SH" "$REMOTE"
