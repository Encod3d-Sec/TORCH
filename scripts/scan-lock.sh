#!/usr/bin/env bash
# scan-lock.sh - run ONE heavy scanner at a time on the Kali VM.
#
# The VM is 4-core and CPU-bound. On 2026-08-03 a single `feroxbuster -t 20` run
# pegged it to 100%, sshd stopped answering ("Connection timed out during banner
# exchange"), and the operator had to hard-reset the box -- losing every tmux
# session on it. Two concurrent scanners are worse. So: every nuclei/ffuf/
# feroxbuster invocation goes through here, and flock serializes them VM-wide.
#
#   bash scripts/scan-lock.sh '<remote scanner command>'
#
# The command is shipped base64-encoded rather than quoted inline: the VM's login
# shell is zsh, and hand-quoting a command containing & or ' through the ssh
# bridge has already produced `zsh: parse error near &` and a mangled tmux
# send-keys today. base64 sidesteps all shell-quoting layers.
#
# Waits up to 30 minutes for the lock, then gives up rather than piling on.
set -uo pipefail

CMD="${1:?usage: scan-lock.sh '<remote scanner command>'}"
VM_SH="${VM_SH:-/root/vm.sh}"

B64="$(printf '%s' "$CMD" | base64 -w0)"
TAG="$(date +%s)$$"

exec bash "$VM_SH" "echo $B64 | base64 -d > /tmp/.scan-$TAG.sh
flock -w 1800 /tmp/.scanlock sh /tmp/.scan-$TAG.sh
rc=\$?
rm -f /tmp/.scan-$TAG.sh
exit \$rc"
