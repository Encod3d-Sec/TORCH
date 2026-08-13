#!/usr/bin/env bash
# Create a new engagement from a type template and set it active, or rename one.
#
#   bash setup/new-engagement.sh <name> <pentest|bugbounty|ctf> [--with-oob] [--scope <host>]...
#   bash setup/new-engagement.sh --rename <old> <new>
#
# Scaffolds targets/<name>/ with the type-aware file set + ingest/ poc/ dirs,
# and points targets/active.md at it. Engagement data stays under targets/ (private).
#   - pentest/bugbounty: full set (adds oob.md, Vuln-index.md, identities/source-ledger/
#     write-ledger campaign-driver files).
#   - ctf: lean set (state,loot,Approach,scope,Deadends); Killchain.md/log.md are
#     pentest/bugbounty-only (a ctf's live chain lives in state.md's ## Chain/## Status
#     sections instead); walkthrough.md/eval.md self-create on demand at their trigger
#     (close-out.py / Skill(learn)) for every type, same as decisions.md (/redteamlead);
#     oob is opt-in via --with-oob; the severity Vuln-index is skipped (a slim ctf
#     findings list is created on demand by ensure_optional_file). Per-asset coverage
#     lives in the Approach.md 4a table for all types.
#   - --scope <host> (repeatable): seed scope.md's "## In scope" bullets at creation
#     time, so scope-gated evidence auto-capture is live immediately instead of
#     waiting on a hand-edit. Validated against a conservative host/CIDR charset;
#     an invalid value is skipped (creation still succeeds), never written to disk.
# Vulns/ is NOT created here; it is made lazily on the first FIND (pentest/bugbounty).
# Keep the file set in sync with SHARED_CORE/SHARED_FULL/STATE_DIRS in
# skills/hooks/_engagement.py, which self-heals the same set at SessionStart.
set -euo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"

sub() { sed -e "s/{{ENGAGEMENT}}/$2/g" -e "s/{{DATE}}/$3/g" "$1" > "$4"; }

# --rename OLD NEW: move an engagement dir and re-run the sed substitution so no
# managed file keeps the old name in its title:/engagement: frontmatter or its H1
# heading (fixes the stale-title leak seen after a copy/rename).
if [ "${1:-}" = "--rename" ]; then
  OLD_RAW="${2:-}"
  # Reject traversal/empty BEFORE OLD ever touches a path or sed pattern: raw OLD
  # used verbatim in SRC="$VAULT/targets/$OLD" let "../setup/templates" (or "..")
  # resolve outside targets/ entirely, and any "/" broke the sed delimiter below.
  case "$OLD_RAW" in
    "") echo "error: --rename OLD must not be empty" >&2; exit 1 ;;
    .|..) echo "error: --rename OLD must not be '.' or '..'" >&2; exit 1 ;;
    */*) echo "error: --rename OLD must not contain '/'" >&2; exit 1 ;;
  esac
  # Defense-in-depth: same sanitizer NEW already gets, so OLD can't inject sed metachars.
  OLD="$(printf '%s' "$OLD_RAW" | tr ' /' '--' | tr -cd 'A-Za-z0-9._-')"
  NEW="$(printf '%s' "${3:-}" | tr ' /' '--' | tr -cd 'A-Za-z0-9._-')"
  # Re-validate the SANITIZED OLD against the same forbidden set: a raw value
  # like ".!." is not literally "."/".."/empty and has no "/", so it passes the
  # raw-input case above, but tr -cd strips the "!" and collapses it to "..",
  # and SRC is built from THIS value, not the raw one. Validate-then-mutate
  # bugs check the wrong variable; re-check what's actually used. Sanitized OLD
  # can never contain "/" (tr -cd already stripped it), so only empty/./ ..
  # remain possible here.
  case "$OLD" in
    "") echo "error: --rename OLD sanitizes to empty; refusing" >&2; exit 1 ;;
    .|..) echo "error: --rename OLD sanitizes to '.' or '..' (collapsed from \"$OLD_RAW\"); refusing" >&2; exit 1 ;;
  esac
  [ -n "$OLD" ] && [ -n "$NEW" ] || { echo "usage: new-engagement.sh --rename <old> <new>"; exit 1; }
  SRC="$VAULT/targets/$OLD"
  DST="$VAULT/targets/$NEW"
  [ -d "$SRC" ] || { echo "no such engagement: $SRC"; exit 1; }
  [ -e "$DST" ] && { echo "already exists: $DST"; exit 1; }
  mv "$SRC" "$DST"
  for f in "$DST"/*.md; do
    [ -f "$f" ] || continue
    sed -i -E \
      -e "s/(^title:.*[[:space:]])${OLD}(\"?)[[:space:]]*\$/\1${NEW}\2/" \
      -e "s/(^engagement:[[:space:]]*)${OLD}[[:space:]]*\$/\1${NEW}/" \
      -e "s/(^#[[:space:]].*[[:space:]])${OLD}[[:space:]]*\$/\1${NEW}/" "$f"
  done
  printf '%s\n' "$NEW" > "$VAULT/targets/active.md"
  echo "renamed engagement: $OLD -> $NEW (titles re-substituted, active set to $NEW)"
  exit 0
fi

NAME="${1:-}"
NAME="$(printf '%s' "$NAME" | tr ' /' '--' | tr -cd 'A-Za-z0-9._-')"   # sanitize before it reaches sed/paths
TYPE="${2:-pentest}"
[ -n "$NAME" ] || { echo "usage: new-engagement.sh <name> <pentest|bugbounty|ctf> [--with-oob] [--scope <host>]..."; exit 1; }
case "$TYPE" in pentest|bugbounty|ctf) ;; *) echo "type must be pentest|bugbounty|ctf"; exit 1;; esac

WITH_OOB=0
SCOPE_HOSTS=()
ARGS=("${@:3}")
i=0
while [ "$i" -lt "${#ARGS[@]}" ]; do
  arg="${ARGS[$i]}"
  case "$arg" in
    --with-oob) WITH_OOB=1 ;;
    --scope)
      i=$((i + 1))
      val="${ARGS[$i]:-}"
      case "$val" in
        "") echo "error: --scope requires a value; skipping" >&2 ;;
        *[!A-Za-z0-9._:/-]*) echo "error: --scope value '$val' has invalid characters; skipping" >&2 ;;
        *) SCOPE_HOSTS+=("$val") ;;
      esac
      ;;
    *) echo "unknown flag: $arg"; exit 1 ;;
  esac
  i=$((i + 1))
done
# pentest/bugbounty always carry the full severity/OOB machinery.
if [ "$TYPE" != "ctf" ]; then WITH_OOB=1; fi

TPL="$VAULT/setup/templates/$TYPE"
DEST="$VAULT/targets/$NAME"
TODAY="$(date +%F)"

[ -d "$TPL" ] || { echo "template missing: $TPL"; exit 1; }
[ -e "$DEST" ] && { echo "already exists: $DEST"; exit 1; }

# poc/ is scaffolded for ALL types (curated exploit/PoC/flag shots); ingest/ = raw
# tool output. Vulns/ is created lazily on the first FIND.
mkdir -p "$DEST/ingest" "$DEST/poc"

# state/loot/Approach (+ Killchain for pentest/bugbounty) from the type's own template
# dir (per-type columns). Keep in sync with state_files() in skills/hooks/_engagement.py.
CORE_FILES="state loot Approach"
[ "$TYPE" != "ctf" ] && CORE_FILES="state loot Killchain Approach"
for f in $CORE_FILES; do
  sub "$TPL/$f.md" "$NAME" "$TODAY" "$DEST/$f.md"
done
# shared core: ctf gets only scope (log/walkthrough/eval self-create at their own
# trigger); pentest/bugbounty keep the full shared core (SHARED_CORE in _engagement.py).
if [ "$TYPE" != "ctf" ]; then
  for f in log scope walkthrough eval; do
    sub "$VAULT/setup/templates/_$f.md" "$NAME" "$TODAY" "$DEST/$f.md"
  done
else
  sub "$VAULT/setup/templates/_scope.md" "$NAME" "$TODAY" "$DEST/scope.md"
fi

# stamp the precise box start time for the metrics/eval system (engagement-init back-fills
# this for boxes created before telemetry; here we record the real creation instant).
printf '{\n  "started_at": "%s"\n}\n' "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)" > "$DEST/.metrics.json"

# seed scope.md's "## In scope" bullet list from --scope, if any were given;
# replaces the template's lone empty "-" bullet with one "- <host>" per value,
# in the order given. Unrecognized/invalid values were already skipped above,
# so SCOPE_HOSTS only ever holds validated, sanitized values here.
if [ "${#SCOPE_HOSTS[@]}" -gt 0 ]; then
  SCOPE_LIST="$(printf '%s\n' "${SCOPE_HOSTS[@]}")"
  awk -v hosts="$SCOPE_LIST" '
    BEGIN { n = split(hosts, arr, "\n") }
    $0 == "## In scope" { print; in_scope = 1; next }
    in_scope == 1 && $0 == "-" {
      for (i = 1; i <= n; i++) print "- " arr[i]
      in_scope = 0
      next
    }
    { print }
  ' "$DEST/scope.md" > "$DEST/scope.md.tmp" && mv "$DEST/scope.md.tmp" "$DEST/scope.md"
fi

sub "$VAULT/setup/templates/_deadends.md" "$NAME" "$TODAY" "$DEST/Deadends.md"
# full-set extras (SHARED_FULL): default for pentest/bugbounty, opt-in for ctf
[ "$WITH_OOB" = 1 ] && sub "$VAULT/setup/templates/_oob.md" "$NAME" "$TODAY" "$DEST/oob.md"
[ "$TYPE" != "ctf" ] && sub "$VAULT/setup/templates/_vuln-index.md" "$NAME" "$TODAY" "$DEST/Vuln-index.md"
# campaign-driver working files: identities/source-ledger/write-ledger are pentest/
# bugbounty-only (bug-bounty spray-identity + OSINT-provenance + write-budget machinery
# a ctf box never touches). decisions.md is on-demand for EVERY type: /redteamlead (RTL)
# creates it from setup/templates/_decisions.md the first time it (or `campaign.py done
# --park`) writes to it; see skills/hooks/_engagement.py's ensure_optional_file().
if [ "$TYPE" != "ctf" ]; then
  for f in identities source-ledger write-ledger; do
    sub "$VAULT/setup/templates/_$f.md" "$NAME" "$TODAY" "$DEST/$f.md"
  done
fi

printf '%s\n' "$NAME" > "$VAULT/targets/active.md"

if [ "$TYPE" != "ctf" ]; then
  FILES="state, loot, Killchain, Approach, log, scope, walkthrough, eval, Deadends"
else
  FILES="state, loot, Approach, scope, Deadends"
fi
[ "$WITH_OOB" = 1 ] && FILES="$FILES, oob"
[ "$TYPE" != "ctf" ] && FILES="$FILES, Vuln-index"
echo "created $TYPE engagement: targets/$NAME/ ($FILES, ingest/, poc/)"
echo "fill targets/$NAME/scope.md with in/out-of-scope + RoE before testing (or pass --scope <host> next time)."
echo "active engagement set to: $NAME"
echo "drop raw recon output into targets/$NAME/ingest/ then run the ingest skill."
