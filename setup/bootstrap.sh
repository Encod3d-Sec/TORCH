#!/usr/bin/env bash
# TORCH vault bootstrap -- run once per machine from the vault root.
# Usage: bash setup/bootstrap.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULT="$(bash "$SCRIPT_DIR/vault-path.sh")"

if [ -z "$VAULT" ]; then
  echo "ERROR: could not resolve vault path. Set OBSIDIAN_VAULT env var or add path to setup/vault-path.sh" >&2
  exit 1
fi

echo "Vault: $VAULT"
echo "Machine: $(hostname)"

# 1. Create ~/.claude/CLAUDE.md include
CLAUDE_DIR="$HOME/.claude"
mkdir -p "$CLAUDE_DIR"
echo "@$VAULT/CLAUDE.md" > "$CLAUDE_DIR/CLAUDE.md"
echo "[ok] Created $CLAUDE_DIR/CLAUDE.md -> $VAULT/CLAUDE.md"

# 2. Symlink vault hooks into ~/.claude/vault-hooks
# Owned by install-hooks.sh (step 3b): it clears a stale REAL directory at the
# link path first. A bare `ln -sf` here would nest the link inside such a
# directory instead of replacing it, leaving every hook command dead.
echo "[..] vault-hooks symlink: handled by install-hooks.sh below"

# 3b. Register hooks in settings.json + expose vault skills to /skills
bash "$SCRIPT_DIR/install-hooks.sh"  || echo "[warn] install-hooks.sh failed (run it manually)"
bash "$SCRIPT_DIR/install-skills.sh" || echo "[warn] install-skills.sh failed (run it manually)"
echo "[ok] Hooks registered in settings.json + vault skills linked into ~/.claude/skills"

# 3. Install qmd if missing
if ! command -v qmd >/dev/null 2>&1; then
  echo "Installing bun + qmd..."
  curl -fsSL https://bun.sh/install | bash
  export PATH="$HOME/.bun/bin:$PATH"
  bun install -g @qmd/cli
  echo "[ok] qmd installed"
else
  echo "[ok] qmd already installed: $(qmd --version 2>/dev/null || echo 'version unknown')"
fi

# 4. Install official Claude plugins
if command -v claude >/dev/null 2>&1; then
  echo "Installing official plugins..."
  for plugin in code-review frontend-design skill-creator claude-md-management; do
    claude plugins install "${plugin}@claude-plugins-official" 2>/dev/null && \
      echo "  [ok] ${plugin}" || echo "  [ok] ${plugin} (already installed)"
  done
else
  echo "[warn] claude CLI not found -- install plugins manually after Claude Code is set up:"
  echo "  claude plugins install code-review@claude-plugins-official"
  echo "  claude plugins install frontend-design@claude-plugins-official"
  echo "  claude plugins install skill-creator@claude-plugins-official"
  echo "  claude plugins install claude-md-management@claude-plugins-official"
fi

# 5b. Install ponytail (lazy-code discipline plugin -- separate marketplace)
if command -v claude >/dev/null 2>&1; then
  echo "Installing ponytail..."
  claude plugins marketplace add DietrichGebert/ponytail 2>/dev/null || true
  claude plugins install ponytail@ponytail 2>/dev/null && \
    echo "  [ok] ponytail" || echo "  [ok] ponytail (already installed)"
else
  echo "[warn] claude CLI not found -- install ponytail manually:"
  echo "  claude plugins marketplace add DietrichGebert/ponytail"
  echo "  claude plugins install ponytail@ponytail"
fi

# 5. Install caveman (output compression skill -- required on all machines)
NODE_MAJOR=$(node -e "process.stdout.write(process.version.split('.')[0].replace('v',''))" 2>/dev/null || echo "0")
if [ "$NODE_MAJOR" -ge 18 ]; then
  echo "Installing caveman..."
  curl -fsSL https://raw.githubusercontent.com/JuliusBrussee/caveman/main/install.sh | bash
  echo "[ok] caveman installed"
else
  echo "[warn] Node >=18 required for caveman -- install Node first, then run:"
  echo "  curl -fsSL https://raw.githubusercontent.com/JuliusBrussee/caveman/main/install.sh | bash"
fi

# 6. Register MCP servers (wiki-search + caveman-shrink wrapper)
if command -v claude >/dev/null 2>&1; then
  echo "Registering MCP servers..."

  # wiki-search: semantic + keyword search over the vault wiki
  if claude mcp get wiki-search >/dev/null 2>&1; then
    echo "  [ok] wiki-search already registered"
  else
    claude mcp add wiki-search -s user \
      -e "QMD_VAULT=$VAULT" \
      -- qmd mcp
    echo "  [ok] wiki-search registered (QMD_VAULT=$VAULT)"
  fi

  # caveman-shrink: same wiki-search upstream, tool descriptions compressed
  if claude mcp get caveman-shrink >/dev/null 2>&1; then
    echo "  [ok] caveman-shrink already registered"
  else
    claude mcp add caveman-shrink -s user \
      -e "QMD_VAULT=$VAULT" \
      -- npx -y caveman-shrink qmd mcp
    echo "  [ok] caveman-shrink registered (QMD_VAULT=$VAULT)"
  fi
else
  echo "[warn] claude CLI not found -- register MCPs manually after Claude Code is set up:"
  echo "  claude mcp add wiki-search -s user -e QMD_VAULT=$VAULT -- qmd mcp"
  echo "  claude mcp add caveman-shrink -s user -e QMD_VAULT=$VAULT -- npx -y caveman-shrink qmd mcp"
fi

# Kali VM capture deps (screenshot + tmux scan-runner). Best-effort; needs the VM configured.
if [ -f /root/vm.sh ] && [ -f /root/creds.txt ]; then
  echo "[..] provisioning Kali VM capture deps"
  bash "$VAULT/scripts/vm-provision.sh" || echo "[warn] vm-provision failed; run scripts/vm-provision.sh later"
else
  echo "[note] Kali VM not configured; after setup run: bash scripts/vm-provision.sh (see docs/virtual-machine.md)"
fi

echo ""
echo "Done. Restart Claude Code, then run: qmd update"
