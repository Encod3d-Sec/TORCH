#!/usr/bin/env bash
# Deterministic wordlist selector: (surface [fingerprint] [ctf|pt|bb]) -> ordered
# absolute wordlist paths + profile-tuned flags. Reads wordlist-map.json (sibling).
# Resolves the seclists base from the map; installs seclists if none is present.
# The skill (skills/workflow/fuzz) calls this for WHAT to run; judgment stays in the skill.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAP="$HERE/wordlist-map.json"
surface="${1:-}"; fp="${2:-}"; etype="${3:-ctf}"

if [ -z "$surface" ] || ! python3 -c "import json,sys
sys.exit(0 if '$surface' in json.load(open('$MAP'))['surfaces'] else 1)" 2>/dev/null; then
  echo "usage: wl-pick.sh <content|files|vhost|api|params|artifacts> [fingerprint] [ctf|pt|bb]" >&2
  exit 2
fi

# --- resolve seclists base (first existing candidate; else install) ---
base="$(python3 -c "import json,os,sys
m=json.load(open('$MAP'))
for b in m['seclists_bases']:
    if os.path.isdir(b): print(b); sys.exit(0)
sys.exit(1)" 2>/dev/null || true)"
if [ -z "$base" ]; then
  echo "# seclists not found -> installing" >&2
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y seclists >/dev/null 2>&1 || true
  fi
  base="$(python3 -c "import json,os,sys
m=json.load(open('$MAP'))
for b in m['seclists_bases']:
    if os.path.isdir(b): print(b); sys.exit(0)" 2>/dev/null || true)"
  [ -n "$base" ] || { echo "seclists unavailable and install failed" >&2; exit 3; }
fi

# --- emit header lines (base, flags); surface already validated above ---
python3 - "$MAP" "$base" "$surface" "$fp" "$etype" "$HERE" <<'PY'
import json, os, sys
mapf, base, surface, fp, etype, here = sys.argv[1:7]
m = json.load(open(mapf))
prof = m["profiles"].get(etype) or m["profiles"]["ctf"]
print("# seclists: %s" % base)
print("# flags: threads=%s rate=%s recursion=%s jitter=%s (profile=%s)"
      % (prof["threads"], prof["rate"], prof["recursion"], prof["jitter"], etype))
out = []
# T0 harness first (repo-relative -> absolute under scripts/)
hf = m.get("harness_first", {}).get(surface)
if hf:
    p = os.path.join(here, hf)
    if os.path.exists(p):
        out.append(p)
# T3 fingerprint jump (only if the fp matches a known key)
for name, paths in m.get("fingerprints", {}).items():
    if fp and name.lower() == fp.strip().lower():
        out += [os.path.join(base, r) for r in paths]
        break
# T1 surface lists, size-ordered
out += [os.path.join(base, r) for r in m["surfaces"][surface]]
# dedup preserving order
seen = set()
for p in out:
    if p not in seen:
        seen.add(p); print(p)
PY
