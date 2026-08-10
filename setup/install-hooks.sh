#!/usr/bin/env bash
# Per-device installer for the engagement-state automation.
# settings.json and the ~/.claude/vault-hooks symlink are machine-local and do
# NOT sync. Run this once on each device after the vault code is present.
#
#   bash setup/install-hooks.sh
#
# Idempotent: safe to re-run. Self-locating: works on any user/path.
set -euo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
HOOKS_SRC="$VAULT/skills/hooks"
LINK="$HOME/.claude/vault-hooks"
SETTINGS="$HOME/.claude/settings.json"

echo "Vault:    $VAULT"
echo "Hooks:    $HOOKS_SRC"
echo "Symlink:  $LINK"
echo "Settings: $SETTINGS"

[ -d "$HOOKS_SRC" ] || { echo "ERROR: $HOOKS_SRC missing (vault code not synced here?)"; exit 1; }

# 1. symlink ~/.claude/vault-hooks -> vault skills/hooks
# A pre-existing REAL directory at $LINK makes `ln -sfn` drop the link INSIDE it
# ($LINK/hooks) instead of replacing it, which leaves every hook command in
# settings.json pointing at a missing file -- and a PreToolUse hook that cannot
# start exits 2, which BLOCKS Bash/Write/Edit. Clear any non-symlink first, then
# prove the link resolves before claiming success.
mkdir -p "$HOME/.claude"
if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
  rm -rf "$LINK"
  echo "removed stale non-symlink $LINK"
fi
ln -sfn "$HOOKS_SRC" "$LINK"
[ -f "$LINK/scope-guard.py" ] || { echo "ERROR: $LINK does not resolve to $HOOKS_SRC"; exit 1; }
echo "symlink ok"

# 2. register hooks in this machine's settings.json (idempotent)
# Canonical expected-hook list lives in scripts/check-hooks.py (EXPECTED_HOOKS),
# which SessionStart uses to detect drift. When you add a hook below, add it
# there too so both stay in sync.
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"
cp "$SETTINGS" "$SETTINGS.bak-$(date +%s)"

python3 - "$SETTINGS" "$HOOKS_SRC" <<'PY'
import json, os, sys
p = sys.argv[1]
hooks_src = sys.argv[2]
d = json.load(open(p))
h = d.setdefault("hooks", {})

# 2a. PRUNE hooks whose script no longer exists.
# This installer only ever ADDED, so a hook DELETED upstream stayed registered
# on every already-provisioned device -- pointing at a file the next `git pull`
# removed. That is not silent: a PostToolUse entry then errors on every matching
# tool call, and a PreToolUse one exits 2 and BLOCKS Bash/Write/Edit. Prune by
# existence, so removing a hook needs no list kept in sync here.
present = set(os.listdir(hooks_src))

def _dead(hk):
    cmd = hk.get("command", "") if isinstance(hk, dict) else ""
    return any("vault-hooks/" in t and t.rsplit("/", 1)[-1] not in present
               for t in cmd.split())

for event in list(h):
    groups = []
    for g in h.get(event, []):
        dead = [hk for hk in g.get("hooks", []) if _dead(hk)]
        for hk in dead:
            print("pruned %s %s (script no longer in skills/hooks)"
                  % (event, hk.get("command", "").rsplit("/", 1)[-1]))
            g["hooks"].remove(hk)
        if g.get("hooks"):          # drop a group left with no hooks
            groups.append(g)
    if groups:
        h[event] = groups
    else:
        del h[event]

def has(event, needle, matcher=None):
    for g in h.get(event, []):
        if matcher is not None and g.get("matcher") != matcher:
            continue
        for hk in g.get("hooks", []):
            if needle in hk.get("command", ""):
                return True
    return False

def add(event, group):
    h.setdefault(event, []).append(group)

if not has("UserPromptSubmit", "hunt-trigger.py"):
    add("UserPromptSubmit", {"hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/hunt-trigger.py", "timeout": 10}]})
    print("added UserPromptSubmit hunt-trigger")
if not has("SessionStart", "engagement-init.py"):
    add("SessionStart", {"hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/engagement-init.py", "timeout": 40}]})
    print("added SessionStart engagement-init")
# idempotent: ensure engagement-init timeout >= 40 (cold /mnt/c upkeep can exceed 25s and get killed)
for g in h.get("SessionStart", []):
    for hk in g.get("hooks", []):
        if "engagement-init.py" in hk.get("command", "") and hk.get("timeout", 0) < 40:
            hk["timeout"] = 40
            print("bumped engagement-init timeout -> 40")
if not has("PostToolUse", "recon-capture.py"):
    add("PostToolUse", {"matcher": "Bash", "hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/recon-capture.py", "timeout": 30}]})
    print("added PostToolUse recon-capture")
# idempotent: ensure recon-capture timeout >= 30 (the fingerprint router + OOB correlation
# work needs headroom over the old 10s default)
for g in h.get("PostToolUse", []):
    for hk in g.get("hooks", []):
        if "recon-capture.py" in hk.get("command", "") and hk.get("timeout", 0) < 30:
            hk["timeout"] = 30
            print("bumped recon-capture timeout -> 30")
if not has("PostToolUse", "tool-telemetry.py"):
    add("PostToolUse", {"matcher": "*", "hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/tool-telemetry.py", "timeout": 10}]})
    print("added PostToolUse tool-telemetry")
if not has("PostToolUse", "wiki-reindex.py"):
    add("PostToolUse", {"matcher": "Write|Edit", "hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/wiki-reindex.py", "timeout": 10}]})
    print("added PostToolUse wiki-reindex")
if not has("PreToolUse", "scope-guard.py"):
    add("PreToolUse", {"matcher": "Bash", "hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/scope-guard.py", "timeout": 10}]})
    print("added PreToolUse scope-guard")
if not has("PreToolUse", "session-guard.py"):
    add("PreToolUse", {"matcher": "Write|Edit", "hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/session-guard.py", "timeout": 10}]})
    print("added PreToolUse session-guard")
if not has("PreToolUse", "drift-guard.py"):
    add("PreToolUse", {"matcher": "Bash", "hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/drift-guard.py", "timeout": 10}]})
    print("added PreToolUse drift-guard")
if not has("SessionStart", "session-start.sh"):
    add("SessionStart", {"hooks": [{"type": "command",
        "command": "bash ~/.claude/vault-hooks/session-start.sh"}]})
    print("added SessionStart session-start")
if not has("PreCompact", "pre-compact.sh"):
    add("PreCompact", {"hooks": [{"type": "command",
        "command": "bash ~/.claude/vault-hooks/pre-compact.sh"}]})
    print("added PreCompact pre-compact")
if not has("Stop", "close-out.py"):
    add("Stop", {"hooks": [{"type": "command",
        "command": "python3 ~/.claude/vault-hooks/close-out.py", "timeout": 10}]})
    print("added Stop close-out")

json.dump(d, open(p, "w"), indent=1)
json.load(open(p))  # validate
print("settings.json valid")
PY

echo "Done. Restart Claude Code (or start a new session) to load the hooks."
