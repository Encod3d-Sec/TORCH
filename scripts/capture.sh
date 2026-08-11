#!/usr/bin/env bash
# capture.sh <mode> <eng> <slug> [args] - unified live PoC-evidence capture on the Kali VM.
# Merges the former ev/req/tmux/burp shot scripts into one entrypoint. Every mode renders a
# PNG on the VM (via shot.py) and pulls it into targets/<eng>/poc/NN-<slug>.png (auto-numbered),
# then prints the walkthrough `md:` ref. Call it the MOMENT a step LANDS, not at the end.
#
# HUMAN-COMMAND RULE: what you capture goes in front of a technical team. Card ONE standalone,
# human-authored command with concrete values + FULL paths - no `export VAR=`/`$VAR`, no `;`/`&&`
# multi-step chains, no `echo "-- label --"` banners, no base64/pty wrappers. Needed a merged
# pipeline to work the box? Re-run the clean single command for the card. Inline any env var on the
# one command (`KRB5CCNAME=/tmp/x.ccache impacket-... `), never a separate `export`.
#
# CARD MODE RULE (2026-08-03): `cli` is the DEFAULT AND ONLY mode for a finding's PoC card.
# `tmux` is RETIRED for PoC cards - it renders window chrome (title bar, traffic lights) and it
# takes a SCRIPT, which invites the two failures that produced a bad FIND-011 card: a wrapper
# invocation (`clear; bash /tmp/poc_xxx.sh`) standing in for the real command, and a hand-written
# pseudo-command that was never run. `cli` takes a cmdfile of REAL commands, types each at a live
# `$ ` prompt, and skips `#` lines entirely - so a card can only ever show commands that actually
# executed. Reserve `tmux` for `recon` scan panes, never for a finding's evidence.
#
# Modes:
#   ev   <eng> <slug> <request-url> <cmd-label> [logfile]   terminal card (cmd + url) from a tee'd log
#   req  <eng> <slug> [--] <curl-args...>                   real `curl -iv` request/response card
#   cli  <eng> <slug> <cmdfile>                             USE THIS FOR EVERY POC CARD: run each
#                                                           command at a real `$ ` prompt, no chrome
#   tmux <eng> <slug> <local-script.sh>                     RETIRED for PoC cards (chrome + wrapper
#                                                           risk); scan panes only
#   web  <eng> <slug> <url> [--no-bar] [width height]        render a LIVE page via chromium (address-bar frame)
#   recon <eng> <slug> <tmux-tab> [session=<eng>]            card a scan tmux tab (nmap/ffuf/...) into recon/
#   log  <eng> <slug> <remote-logfile>                      save a long text log (linpeas/pspy) to poc/NN.md
#   raw  <eng> <slug> <remote-file>                         pull RAW scan output verbatim -> recon/raw/<slug>
#   snippet <eng> <slug> <url-or-file> [grep-pattern] [note] fenced source excerpt (app.js/HTML) -> poc/NN-<slug>-snippet.md
#   burp <eng> <slug> <host> <port> <https> <method> <path> [bodyfile] [tabname]
#                                                           Burp Repeater request/response grab (via MCP)
#
# The VM bridge is $VM_SH (default /root/vm.sh); files cross it base64-in-command (no stdin).
set -euo pipefail

VAULT="${VAULT:-$(cd "$(dirname "$0")/.." && pwd)}"
VM_SH="${VM_SH:-/root/vm.sh}"

usage() {
  cat >&2 <<'U'
usage: capture.sh <mode> <eng> <slug> [args]
  ev   <eng> <slug> <request-url> <cmd-label> [logfile]
  req  <eng> <slug> [--] <curl-args...>
  cli  <eng> <slug> <cmdfile>            (preferred: clean `$ cmd` transcript, no chrome)
  tmux <eng> <slug> <local-script.sh>
  web  <eng> <slug> <url> [--no-bar] [width height]
  recon <eng> <slug> <tmux-tab> [session=<eng>]
  log  <eng> <slug> <remote-logfile>
  raw  <eng> <slug> <remote-file>
  snippet <eng> <slug> <url-or-file> [grep-pattern] [reveals-note]
  burp <eng> <slug> <host> <port> <https> <method> <path> [bodyfile] [tabname]
U
  exit 2
}

# Sets POC + NN + PNG globals: the next NN index for <eng>'s poc/ dir, for <slug>.
# 10# forces base-10 (08->09, not octal); empty poc/ -> 01.
_poc_target() {   # $1=eng $2=slug
  POC="$VAULT/targets/$1/poc"; mkdir -p "$POC"
  local last; last=$(ls "$POC" 2>/dev/null | grep -oE '^[0-9]{2}' | sort -n | tail -1 || true)
  NN=$(printf "%02d" $(( 10#${last:-00} + 1 ))); PNG="$NN-$2.png"
}

# Pull a rendered PNG off the VM into poc/ (base64 through the pipe, not the caller's context)
# and print the saved path + walkthrough ref. $ENG/$POC/$PNG are set by the caller.
_pull_and_report() {   # $1=remote-png-path $2=caption
  # `|| true` so a failed pull (pipefail/set -e) does NOT abort before the empty-file cleanup below,
  # which would leave a 0-byte PNG on disk (a broken image the operator then sees in poc/).
  { bash "$VM_SH" "base64 -w0 '$1' 2>/dev/null" | base64 -d > "$POC/$PNG"; } 2>/dev/null || true
  if [ -s "$POC/$PNG" ]; then
    echo "saved targets/$ENG/poc/$PNG"
    echo "md: ![$2](poc/$PNG)"
  else
    rm -f "$POC/$PNG"
    echo "capture($MODE): no PNG produced (VM unreachable? tee the step output first?)" >&2
    exit 1
  fi
}

# ev: terminal card showing BOTH the command and the request URL, from a log you tee'd on the VM.
# --reqresp colorizes the log like a real shell (`$ ` bold cyan, `> ` request cyan, `< ` response
# blue, `# ` comment green). Pass an EMPTY cmd-label to leave the title bar as dots only, and put
# the `$ command` line in the log itself -- that renders coloured instead of flat title-bar text.
mode_ev() {
  [ $# -ge 4 ] || { echo "usage: capture.sh ev <eng> <slug> <request-url> <cmd-label> [logfile]" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" URL="$3" CMD="$4" LOG="${5:-/tmp/poc/$2.log}"
  _poc_target "$ENG" "$SLUG"
  local B64; B64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "mkdir -p /tmp/poc; echo '$B64' | base64 -d > /tmp/shot.py
python3 /tmp/shot.py --term '$LOG' --reqresp --cmd \"$CMD\" --url-bar \"$URL\" -o /tmp/poc/$PNG" >&2
  _pull_and_report "/tmp/poc/$PNG" "$CMD"
}

# req: curl request+response card, rendered like a real shell (dots-only title bar; `$ ` command
# bold cyan, `> ` request cyan, `< ` response blue via --reqresp).
#
# Uses `curl -v`, NOT `-iv`: -v already prints the `< ` response headers, so -i printed the whole
# header block a SECOND time in the body. The TLS handshake, certificate chain and HTTP/2 framing
# are filtered out too -- they are never the evidence and they buried the payload (a real card went
# from 2794px to 858px). Set CAPTURE_FULL=1 to keep -iv and the unfiltered transcript.
# base64-wraps the remote script so a forged body (+ / = / & / quotes) survives SSH transport.
mode_req() {
  [ $# -ge 3 ] || { echo "usage: capture.sh req <eng> <slug> [--] <curl-args...>" >&2; exit 2; }
  ENG="$1"; local SLUG="$2"; shift 2
  [ "${1:-}" = "--" ] && shift
  [ $# -ge 1 ] || { echo "capture(req): no curl args given" >&2; exit 2; }
  _poc_target "$ENG" "$SLUG"
  local LOG="/tmp/poc/$SLUG.reqresp" a
  local CURL="curl -sS -v" NOISE='^\*|^\{ \[|^\} \[|^  '
  [ -n "${CAPTURE_FULL:-}" ] && { CURL="curl -sS -iv"; NOISE='^$a^'; }   # never matches
  for a in "$@"; do CURL+=" $(printf '%q' "$a")"; done
  local REMOTE; REMOTE=$(cat <<EOF
mkdir -p /tmp/poc
{ echo "\$ $CURL"; $CURL 2>&1 | grep -vE '$NOISE' ; } > "$LOG" 2>&1 || true
EOF
)
  local RB64 SHOT_B64
  RB64=$(printf '%s' "$REMOTE" | base64 -w0)
  SHOT_B64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "echo '$SHOT_B64' | base64 -d > /tmp/shot.py
echo '$RB64' | base64 -d > /tmp/reqshot_cmd.sh
bash /tmp/reqshot_cmd.sh
python3 /tmp/shot.py --term '$LOG' --reqresp --cmd '' --maxlines 600 -o /tmp/poc/$PNG" >&2
  _pull_and_report "/tmp/poc/$PNG" "curl request+response - $SLUG"
}

# tmux: run a command-script in a real Kali tmux pane and grab the pane, so the evidence is an
# ACTUAL session (real commands + output). The script should echo `# comments`/`$ cmds`, run
# them, and end with `echo POC-DONE`.
mode_tmux() {
  [ $# -ge 3 ] || { echo "usage: capture.sh tmux <eng> <slug> <local-script.sh>" >&2; exit 2; }
  _mode_tmux_body "$@"
}

# cli: the CLEAN evidence card. Runs each command in a real shell at a real `$ ` prompt and
# renders with NO window chrome, so the image reads exactly like a Linux terminal transcript:
#   $ dig +short A www.example.com
#   93.184.216.34
# Prefer this over `tmux` for anything a reviewer will read. `tmux` runs a WRAPPER SCRIPT, so its
# card is headed by `bash /tmp/poc_<slug>.sh` plus a decorative title bar -- the reviewer sees a
# script name instead of the commands, which is exactly the noise this mode removes.
# <cmdfile> is one shell command per line; blank lines and `#` comments are skipped.
mode_cli() {
  [ $# -ge 3 ] || { echo "usage: capture.sh cli <eng> <slug> <cmdfile>" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" CMDFILE="$3"
  [ -f "$CMDFILE" ] || { echo "capture(cli): no such cmdfile $CMDFILE" >&2; exit 2; }
  _poc_target "$ENG" "$SLUG"
  local SESS="poc_${SLUG//[^a-zA-Z0-9]/_}" CB64 SHOTB64 RUNNER RB64
  CB64=$(base64 -w0 "$CMDFILE")
  SHOTB64=$(base64 -w0 "$VAULT/scripts/shot.py")
  # Built locally then shipped base64 so no quoting survives the SSH hop to be mangled.
  RUNNER=$(mktemp)
  cat > "$RUNNER" <<'RUNNER_EOS'
set -u
SESS="__SESS__"; PNG="__PNG__"
mkdir -p /tmp/poc
tmux kill-session -t "$SESS" 2>/dev/null || true
tmux new-session -d -s "$SESS" -x 200 -y 200
tmux set-option -t "$SESS" window-size manual 2>/dev/null || true
tmux resize-window -t "$SESS" -x 200 -y 200 2>/dev/null || true
# A bare `$ ` prompt, then clear, so the card opens on the first real command.
tmux send-keys -t "$SESS" "PS1='$ '" C-m; sleep 1
tmux send-keys -t "$SESS" clear C-m; sleep 1
# Drop the PS1/clear setup from the scrollback so the card opens on the first real command.
tmux clear-history -t "$SESS" 2>/dev/null || true
while IFS= read -r c || [ -n "$c" ]; do
  case "$c" in ""|\#*) continue ;; esac
  tmux send-keys -t "$SESS" "$c" C-m
  # Wait for the prompt to come back (command finished) rather than a blind sleep.
  for _ in $(seq 1 180); do
    sleep 1
    [ "$(tmux capture-pane -p -t "$SESS" | grep -v '^[[:space:]]*$' | tail -1)" = '$' ] && break
  done
done < /tmp/"$SESS".cmds
python3 /tmp/shot.py --tmux "$SESS" --plain --history --maxlines 100000 -o "/tmp/poc/$PNG" >/dev/null 2>&1
tmux kill-session -t "$SESS" 2>/dev/null || true
RUNNER_EOS
  sed -i "s|__SESS__|$SESS|g; s|__PNG__|$PNG|g" "$RUNNER"
  RB64=$(base64 -w0 "$RUNNER"); rm -f "$RUNNER"
  bash "$VM_SH" "echo '$SHOTB64' | base64 -d > /tmp/shot.py
echo '$CB64' | base64 -d > /tmp/$SESS.cmds
echo '$RB64' | base64 -d > /tmp/$SESS.run.sh
bash /tmp/$SESS.run.sh" >&2
  _pull_and_report "/tmp/poc/$PNG" "$SLUG"
}

_mode_tmux_body() {
  ENG="$1"; local SLUG="$2" SCRIPT="$3"
  [ -f "$SCRIPT" ] || { echo "capture(tmux): no such script $SCRIPT" >&2; exit 2; }
  _poc_target "$ENG" "$SLUG"
  local SESS="poc_${SLUG//[^a-zA-Z0-9]/_}" SB64 SHOTB64
  SB64=$(base64 -w0 "$SCRIPT")
  SHOTB64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "echo '$SHOTB64' | base64 -d > /tmp/shot.py
mkdir -p /tmp/poc; echo '$SB64' | base64 -d > /tmp/$SESS.sh; chmod +x /tmp/$SESS.sh
tmux kill-session -t $SESS 2>/dev/null || true
tmux new-session -d -s $SESS -x 200 -y 200
tmux set-option -t $SESS window-size manual 2>/dev/null || true
tmux resize-window -t $SESS -x 200 -y 200 2>/dev/null || true
tmux send-keys -t $SESS 'clear; bash /tmp/$SESS.sh' C-m
for i in \$(seq 1 60); do tmux capture-pane -p -t $SESS 2>/dev/null | grep -q POC-DONE && break; sleep 1; done
python3 /tmp/shot.py --tmux $SESS --reqresp --history --maxlines 100000 -o /tmp/poc/$PNG >/dev/null 2>&1
tmux kill-session -t $SESS 2>/dev/null || true" >&2
  _pull_and_report "/tmp/poc/$PNG" "$SLUG"
}

# web: render a LIVE target URL through chromium (browser-chrome frame + address bar) into poc/.
# The operator-legible shot: the page as a browser shows it. Use `req` for a request/response card,
# `web` for the rendered page. Runs on the VM (chromium there has the VPN path to the target). URL is
# %q-quoted so query strings (?a=1&b=2) survive the SSH hop; a dead target makes shot.py exit non-zero
# (net::ERR) so set -e aborts before an error-page PNG is pulled.
mode_web() {
  [ $# -ge 3 ] || { echo "usage: capture.sh web <eng> <slug> <url> [--no-bar] [width height]" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" URL="$3"; shift 3
  local BAR=""
  [ "${1:-}" = "--no-bar" ] && { BAR="--no-bar"; shift; }
  local W="${1:-1440}" H="${2:-900}"
  _poc_target "$ENG" "$SLUG"
  local SHOT_B64; SHOT_B64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "echo '$SHOT_B64' | base64 -d > /tmp/shot.py; mkdir -p /tmp/poc
python3 /tmp/shot.py $(printf '%q' "$URL") $BAR --width $W --height $H -o /tmp/poc/$PNG" >&2
  _pull_and_report "/tmp/poc/$PNG" "$SLUG"
  # also save the raw page source next to the render, as .md in an ```html fence so Obsidian
  # actually renders it in the GUI (a bare .html attachment does not preview).
  local SRC="${PNG%.png}-source.md"
  { printf '# source: %s\n\n```html\n' "$URL"
    bash "$VM_SH" "curl -sk -L --max-time 12 $(printf '%q' "$URL") 2>/dev/null | head -c 300000"
    printf '\n```\n'; } > "$POC/$SRC" 2>/dev/null || true
  [ -s "$POC/$SRC" ] && echo "saved targets/$ENG/poc/$SRC (page source)"
}

# webauth: render an AUTHENTICATED page into poc/. `web` (live URL, no cookie) shoots whatever an
# anonymous browser sees -- for a page behind login that is the LOGIN REDIRECT, not the authed
# state, so a flag/dashboard shot fires prematurely on the wrong page (observed real miss). This
# mode curls the URL WITH the session cookie (+ a browser UA, since UA-WAF boxes need it), saves the
# authed HTML, and renders it via `shot.py --html` (assets loaded from --base origin, address bar =
# the real URL). Use for any post-login dashboard / flag page / authed panel.
mode_webauth() {
  [ $# -ge 4 ] || { echo "usage: capture.sh webauth <eng> <slug> <url> <cookie e.g. 'PHPSESSID=..'> [user-agent]" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" URL="$3" COOKIE="$4"; shift 4
  local UA="${1:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36}"
  local ORIGIN; ORIGIN=$(printf '%s' "$URL" | sed -E 's,^(https?://[^/]+).*,\1,')
  _poc_target "$ENG" "$SLUG"
  local HTML="/tmp/poc/${SLUG//[^a-zA-Z0-9]/_}-authed.html"
  local SHOT_B64; SHOT_B64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "echo '$SHOT_B64' | base64 -d > /tmp/shot.py; mkdir -p /tmp/poc
curl -sk -L --max-time 15 -A $(printf '%q' "$UA") -b $(printf '%q' "$COOKIE") $(printf '%q' "$URL") -o $(printf '%q' "$HTML")
python3 /tmp/shot.py --html $(printf '%q' "$HTML") --base $(printf '%q' "$ORIGIN") --url-bar $(printf '%q' "$URL") -o /tmp/poc/$PNG" >&2
  _pull_and_report "/tmp/poc/$PNG" "$SLUG"
}

# recon: card a running/finished scan tmux TAB (nmap/ffuf/nuclei/rustscan) into recon/ (NOT poc/).
# Run per-tool AS each scan finishes, before exploiting - EVERY tool gets a card, even an empty
# result, so the operator can see what ran. <tab> = the sanitized name or @id vm-scan.sh printed;
# a bare name is qualified with <session> (default <eng>). recon/ is auto-numbered separately from poc/.
mode_recon() {
  [ $# -ge 3 ] || { echo "usage: capture.sh recon <eng> <slug> <tmux-tab> [session=<eng>]" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" TAB="$3" SESS="${4:-$1}"
  # must match vm-scan.sh's sanitize EXACTLY, or we address a session tmux never created
  SESS="$(printf '%s' "$SESS" | tr './: ' '----')"
  local RECON="$VAULT/targets/$ENG/recon"; mkdir -p "$RECON"
  local last NN; last=$(ls "$RECON" 2>/dev/null | grep -oE '^[0-9]{2}' | sort -n | tail -1 || true)
  NN=$(printf "%02d" $(( 10#${last:-00} + 1 ))); PNG="$NN-$SLUG.png"
  local TGT="$TAB"; case "$TAB" in @*|*:*) ;; *) TGT="$SESS:$TAB";; esac
  local RPNG="/tmp/recon-${SLUG//[^a-zA-Z0-9]/_}.png" SHOT_B64
  SHOT_B64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "echo '$SHOT_B64' | base64 -d > /tmp/shot.py; rm -f '$RPNG'
python3 /tmp/shot.py --tmux '$TGT' --history -o '$RPNG' >/dev/null 2>&1 || true" >&2
  # `|| true`: don't let a failed pull abort before the empty-file cleanup (avoids 0-byte broken PNGs).
  { bash "$VM_SH" "base64 -w0 '$RPNG' 2>/dev/null" | base64 -d > "$RECON/$PNG"; } 2>/dev/null || true
  if [ -s "$RECON/$PNG" ]; then
    echo "saved targets/$ENG/recon/$PNG"
    echo "md: ![$SLUG](recon/$PNG)"
  else
    rm -f "$RECON/$PNG"
    echo "capture(recon): no PNG (tab '$TGT' wrong? use the @id or sanitized name vm-scan.sh printed)" >&2
    exit 1
  fi
}

# log: save a long TEXT log (linpeas/pspy/full nmap) from the VM into poc/NN-<slug>.md as fenced
# text, NOT a screenshot -- linpeas is hundreds of colored lines, unreadable and un-scrollable as an
# image. ANSI stripped on pull; the full scan is kept so the operator can grep/read it later.
mode_log() {
  [ $# -ge 3 ] || { echo "usage: capture.sh log <eng> <slug> <remote-logfile>" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" RLOG="$3"
  _poc_target "$ENG" "$SLUG"
  local MD="$NN-$SLUG.md" BODY
  BODY=$(bash "$VM_SH" "base64 -w0 '$RLOG' 2>/dev/null" | base64 -d 2>/dev/null | sed -r 's/\x1B\[[0-9;]*[mGKHhl]//g' || true)
  if [ -z "$BODY" ]; then
    echo "capture(log): '$RLOG' empty/unreachable on the VM (redirect the tool to a file first)" >&2
    exit 1
  fi
  printf '# %s\n\nSource: `%s` (full text log captured on the VM, ANSI stripped).\n\n```text\n%s\n```\n' \
    "$SLUG" "$RLOG" "$BODY" > "$POC/$MD"
  echo "saved targets/$ENG/poc/$MD ($(wc -l < "$POC/$MD") lines)"
  echo "md: [$SLUG](poc/$MD)"
}

# raw: pull a scan's RAW output off the VM verbatim into targets/<eng>/recon/raw/<slug>. Unlike `log`
# (one file rendered into poc/ as fenced markdown, ANSI stripped) this preserves the MACHINE-readable
# artifact -- nmap -oN/-oX, ffuf -of json, nuclei -je, httpx -json -- so hits can be walked one at a
# time with jq and a scan can be traced back to exactly one host. <slug> IS the filename: keep the real
# extension (ffuf.json, nmap-svc.txt) so downstream tooling can still parse it. Pair it with the
# `recon` mode: `recon` gives the operator the visual card, `raw` gives the reusable data.
mode_raw() {
  [ $# -ge 3 ] || { echo "usage: capture.sh raw <eng> <slug> <remote-file>" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" RFILE="$3"
  local RAW="$VAULT/targets/$ENG/recon/raw"; mkdir -p "$RAW"
  # Written as .md with the payload FENCED: Obsidian only previews .md and images in the GUI, so a
  # bare .json/.txt in the vault is unreadable there. Content is preserved verbatim inside the fence
  # (extract with: sed '1,/^```/d; /^```$/,$d' <file>.md).
  local BASE="${SLUG%.*}" EXT="${SLUG##*.}" DEST LANG BODY
  case "$EXT" in json) LANG=json ;; xml) LANG=xml ;; sh) LANG=sh ;; *) LANG=text ;; esac
  DEST="$RAW/$BASE.md"
  BODY=$(bash "$VM_SH" "base64 -w0 '$RFILE' 2>/dev/null" | base64 -d 2>/dev/null | sed -r 's/\x1B\[[0-9;]*[mGKHhl]//g' || true)
  if [ -z "$BODY" ]; then
    echo "capture(raw): '$RFILE' empty/unreachable on the VM (redirect the tool to a file first)" >&2
    exit 1
  fi
  printf '# %s\n\nRaw scan output. Source on the VM: `%s`\n\n```%s\n%s\n```\n' \
    "$SLUG" "$RFILE" "$LANG" "$BODY" > "$DEST"
  echo "saved targets/$ENG/recon/raw/$BASE.md ($(wc -c < "$DEST") bytes)"
}

# snippet: extract the LOAD-BEARING lines of a website source (app.js, an inline script, a source map,
# an HTML/JSON/config) into poc/NN-<slug>-snippet.md as a fenced block + a `reveals:` note. Fire the
# MOMENT reading source hands you something that shapes the attack - API endpoints, a secret/key, a
# hidden route, client-side validation/logic - so the walkthrough cites the exact code, not just
# "app.js revealed the API". <source> is an http(s) URL (fetched via curl on the VM) OR a file already
# on disk (a poc/ copy, an absolute path, or a vault-relative path). Optional grep -E pattern keeps
# only the matching lines (with their line numbers). PASTE the fenced block inline into walkthrough Recon.
mode_snippet() {
  [ $# -ge 3 ] || { echo "usage: capture.sh snippet <eng> <slug> <url-or-file> [grep-pattern] [reveals-note]" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" SRC="$3" PAT="${4:-}" NOTE="${5:-}"
  _poc_target "$ENG" "$SLUG"
  local MD="$NN-$SLUG-snippet.md" BODY LANG
  case "${SRC%%\?*}" in
    *.js|*.mjs) LANG=js ;;
    *.json)     LANG=json ;;
    *.css)      LANG=css ;;
    *.htm|*.html) LANG=html ;;
    *) LANG=text ;;
  esac
  case "$SRC" in
    http://*|https://*)
      BODY=$(bash "$VM_SH" "curl -sk -L --max-time 12 $(printf '%q' "$SRC") 2>/dev/null | head -c 200000" 2>/dev/null || true) ;;
    *)
      local F="$SRC"; [ -f "$F" ] || F="$VAULT/$SRC"
      [ -f "$F" ] || { echo "capture(snippet): '$SRC' is neither an http(s) URL nor an existing file" >&2; exit 1; }
      BODY=$(head -c 200000 "$F" 2>/dev/null || true) ;;
  esac
  [ -n "$BODY" ] || { echo "capture(snippet): source '$SRC' empty/unreachable" >&2; exit 1; }
  if [ -n "$PAT" ]; then
    local HITS; HITS=$(printf '%s\n' "$BODY" | grep -nE -- "$PAT" || true)
    [ -n "$HITS" ] || { echo "capture(snippet): pattern '$PAT' matched nothing in '$SRC'" >&2; exit 1; }
    BODY="$HITS"
  fi
  { printf '# snippet: %s\n\nSource: `%s`' "$SLUG" "$SRC"
    [ -n "$PAT" ] && printf ' · filter: `%s`' "$PAT"
    printf '\n\n```%s\n%s\n```\n\n_reveals: %s_\n' "$LANG" "$BODY" \
      "${NOTE:-TODO: what this gave you (endpoints / secret / hidden route / logic)}"
  } > "$POC/$MD"
  echo "saved targets/$ENG/poc/$MD ($(wc -l < "$POC/$MD") lines)"
  echo "md: paste the fenced block into walkthrough.md Recon; file ref: [$SLUG](poc/$MD)"
}

# burp: drive Burp (via the MCP) to replay a request in Repeater, then screenshot the
# request+response panes. Grabs as the SEAT user (Burp draws on the seat X session).
mode_burp() {
  [ $# -ge 7 ] || { echo "usage: capture.sh burp <eng> <slug> <host> <port> <https> <method> <path> [bodyfile] [tabname]" >&2; exit 2; }
  ENG=$1; local SLUG=$2 HOST=$3 PORT=$4 HTTPS=$5 METHOD=$6 RPATH=$7 BODYFILE=${8:-} TABNAME=${9:-$2}
  _poc_target "$ENG" "$SLUG"
  local RPNG="/tmp/burpshot_${SLUG//[^a-zA-Z0-9]/_}.png"

  # --- VM-side helper 1: build the raw request (CRLF) + create the Repeater tab via the MCP ---
  local TABPY GRABSH
  read -r -d '' TABPY <<'PY' || true
import json, os, subprocess, sys
cli = os.path.expanduser("~/burp-mcp-cli.py")
host, port, https, method, path, tab = sys.argv[1:7]
bf = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] else ""
lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s:%s" % (host, port), "Accept: */*", "Connection: close"]
body = ""
if bf:
    body = open(bf).read().strip()
    lines += ["Content-Type: application/x-www-form-urlencoded;charset=UTF-8", "Content-Length: %d" % len(body)]
req = "\r\n".join(lines + ["", body])
args = json.dumps({"content": req, "targetHostname": host, "targetPort": int(port),
                   "usesHttps": https == "true", "tabName": tab})
try:
    p = subprocess.run(["python3", cli, "call", "create_repeater_tab", args],
                       capture_output=True, text=True, timeout=45)
    print("TAB_OK" if "Executed" in p.stdout else "TAB_FAIL " + (p.stdout.strip() or p.stderr.strip()[-140:]))
except Exception as e:
    print("TAB_FAIL " + str(e))
PY

  # --- VM-side helper 2: send in the GUI (as the seat user) + grab the window ---
  read -r -d '' GRABSH <<PY || true
set -e
U=\$(who | awk '/\\(:[0-9]/{print \$1; exit}'); U=\${U:-\$(who | awk 'NR==1{print \$1}')}
D=\$(who | grep -oE '\\(:[0-9]+' | head -1 | tr -d '('); D=\${D:-:0}
XA=/home/\$U/.Xauthority
r(){ sudo -u "\$U" env DISPLAY="\$D" XAUTHORITY="\$XA" "\$@"; }
WID=\$(r xdotool search --name "Burp Suite Professional" | head -1)
[ -n "\$WID" ] || { echo "GRAB_FAIL no Burp window on \$D"; exit 0; }
# unlock + wake the seat FIRST: a screen LOCK on seat0 routes synthetic input to the locker (getmouselocation
# reports window:0) so keys never reach Burp. loginctl unlock-session (root) dismisses the lock; xset wakes the
# display + disables the blanker. Without this a locked/idle VM silently fails the interactivity precheck below.
SID=\$(loginctl list-sessions --no-legend 2>/dev/null | awk '/seat0/{print \$1; exit}')
[ -n "\$SID" ] && loginctl unlock-session "\$SID" 2>/dev/null || true
r xset dpms force on 2>/dev/null || true; r xset s off 2>/dev/null || true; sleep 0.4
r xdotool windowactivate --sync "\$WID"; r xdotool windowraise "\$WID"; sleep 0.7
# window client origin, for coord mapping (screen = window + origin)
GEO=\$(r xdotool getwindowgeometry "\$WID"); WX=\$(echo "\$GEO" | awk -F'[ ,]+' '/Position/{print \$3}'); WY=\$(echo "\$GEO" | awk -F'[ ,]+' '/Position/{print \$4}'); WX=\${WX:-0}; WY=\${WY:-0}
# interactivity precheck: a headless/unmapped X still lets 'import' grab the window PIXMAP but routes
# INPUT to root, so clicks/keys never reach Burp (getmouselocation over Burp reports window:0). Fail loud.
UW=\$(r xdotool mousemove \$((WX+600)) \$((WY+300)) getmouselocation 2>/dev/null | grep -oE 'window:[0-9]+' | cut -d: -f2)
if [ "\${UW:-0}" = "0" ]; then echo "GRAB_FAIL Burp window not interactive (input routes to root - headless/unmapped display). Foreground Burp on the VM desktop or restart the X session, then retry."; exit 0; fi
# Java/Swing IGNORES synthetic --window (XSendEvent) input -> drive via XTEST (no --window flag). Keys reach
# Burp once the window is activated (synthetic mouse clicks are still swallowed by Swing, so never rely on them).
r xdotool key ctrl+shift+r; sleep 1.2                                   # -> Repeater tool
# SELECT the just-created tab. create_repeater_tab appends it RIGHTMOST but does NOT focus it, and Ctrl+=
# (go_to_next_tab) WRAPS, so step tab-by-tab until get_active_editor_contents shows OUR request line. A
# built-in VERIFY: Send/grab happens ONLY after the intended tab is confirmed focused (retires stale-tab PoCs).
MARKER="$METHOD $RPATH"
SELECTED=0
for i in \$(seq 1 16); do
  CUR=\$(timeout 10 python3 ~/burp-mcp-cli.py call get_active_editor_contents "{}" 2>/dev/null | head -1)
  if printf '%s' "\$CUR" | grep -Fq "\$MARKER"; then SELECTED=1; break; fi
  r xdotool key ctrl+equal; sleep 0.5                                  # go_to_next_tab (wraps)
done
[ "\$SELECTED" = 1 ] || { echo "GRAB_FAIL could not select the tab for '\$MARKER' after 16 steps (MCP up? scripts/burp/burp-transport.sh)"; exit 0; }
r xdotool key --clearmodifiers ctrl+space; sleep 4                      # Burp Repeater "Send"
r import -window "\$WID" "$RPNG"; chmod 644 "$RPNG" 2>/dev/null || true
echo "GRAB_OK \$WID (verified tab: \$MARKER)"
PY

  local TABPY_B64 GRABSH_B64 CLI_B64
  TABPY_B64=$(printf '%s' "$TABPY" | base64 -w0)
  GRABSH_B64=$(printf '%s' "$GRABSH" | base64 -w0)
  CLI_B64=$(base64 -w0 "$VAULT/scripts/burp/burp-mcp-cli.py")

  # 1) create the Repeater tab
  local RES
  RES=$(bash "$VM_SH" "echo '$CLI_B64' | base64 -d > ~/burp-mcp-cli.py
echo '$TABPY_B64' | base64 -d > /tmp/burpshot_tab.py
python3 /tmp/burpshot_tab.py '$HOST' '$PORT' '$HTTPS' '$METHOD' '$RPATH' '$TABNAME' '${BODYFILE}'" 2>&1 || true)
  if ! echo "$RES" | grep -q TAB_OK; then
    echo "capture(burp): create_repeater_tab failed -> $RES" >&2
    echo "  The Burp MCP server did not accept create_repeater_tab. Confirm it is up: scripts/burp/burp-transport.sh" >&2
    echo "  (expect 'bridge' or 'native'; 'down' -> start Burp + the MCP Server BApp on the VM), or route the" >&2
    echo "  request via the proxy (curl -x 127.0.0.1:8080 ...) and grab Proxy history instead." >&2
    exit 1
  fi

  # 2) send + grab (seat user)
  bash "$VM_SH" "echo '$GRABSH_B64' | base64 -d > /tmp/burpshot_grab.sh; bash /tmp/burpshot_grab.sh" >&2

  # 3) pull the PNG into the vault poc/
  _pull_and_report "$RPNG" "$SLUG (Burp)"
}

MODE="${1:-}"; [ -n "$MODE" ] || usage
shift || true
case "$MODE" in
  ev)   mode_ev "$@" ;;
  cli)  mode_cli "$@" ;;
  req)  mode_req "$@" ;;
  tmux) mode_tmux "$@" ;;
  web)  mode_web "$@" ;;
  webauth) mode_webauth "$@" ;;
  recon) mode_recon "$@" ;;
  log)  mode_log "$@" ;;
  raw)  mode_raw "$@" ;;
  snippet) mode_snippet "$@" ;;
  burp) mode_burp "$@" ;;
  -h|--help|help) usage ;;
  *)    echo "capture: unknown mode '$MODE'" >&2; usage ;;
esac
