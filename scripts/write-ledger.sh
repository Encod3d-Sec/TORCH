#!/usr/bin/env bash
# write-ledger.sh - append a state-changing request+response to an engagement's write ledger.
#
# Purpose is DISCLOSURE, not restriction. When a run operates under a full-exploitation
# envelope against live production systems, anything an agent alters has to be reportable
# to the client so it can be reverted -- and that is only possible if every state-changing
# request was recorded verbatim as it went out. Inference after the fact is not enough.
#
#   bash scripts/write-ledger.sh <label> <request-file> <response-file> [engagement]
#
# `engagement` defaults to the active engagement in targets/active.md, so the common case
# needs only the label and the two files. Pass it explicitly when several engagements are
# in flight and the ledger must not follow whatever active.md currently points at.
#
# The ledger lives at targets/<engagement>/write-ledger.md -- git-ignored, like all
# engagement data. Created on first use. Never edit a past entry.
set -uo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
LABEL="${1:?usage: write-ledger.sh <label> <request-file> <response-file> [engagement]}"
REQ="${2:?need <request-file>}"
RES="${3:?need <response-file>}"
ENG="${4:-}"

if [ -z "$ENG" ]; then
  ENG="$(tr -d '[:space:]' < "$VAULT/targets/active.md" 2>/dev/null)"
  [ -n "$ENG" ] || { echo "write-ledger: no engagement given and targets/active.md is empty" >&2; exit 2; }
fi

DIR="$VAULT/targets/$ENG"
[ -d "$DIR" ] || { echo "write-ledger: no engagement folder at targets/$ENG" >&2; exit 2; }
[ -r "$REQ" ] || { echo "write-ledger: cannot read request file '$REQ'" >&2; exit 2; }
[ -r "$RES" ] || { echo "write-ledger: cannot read response file '$RES'" >&2; exit 2; }

LEDGER="$DIR/write-ledger.md"
if [ ! -f "$LEDGER" ]; then
  cat > "$LEDGER" <<EOF
---
title: "Write ledger"
type: engagement-write-ledger
tags: [engagement, write-ledger, disclosure]
date_created: "$(date -u +%Y-%m-%d)"
---

# Write ledger

Every state-changing request this engagement sent to a live system, verbatim, in order.
Kept so anything altered on a production system can be disclosed to the client and
reverted. One section per request. Never edit a past entry.

EOF
fi

{
  printf '\n## %s -- %s\n\n### Request\n```http\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LABEL"
  cat "$REQ"
  printf '\n```\n\n### Response\n```http\n'
  head -c 4000 "$RES"
  printf '\n```\n'
} >> "$LEDGER"

echo "ledger: appended '$LABEL' to targets/$ENG/write-ledger.md"
