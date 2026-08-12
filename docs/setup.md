# Vault Setup

**New machine:** run `bash setup/bootstrap.sh` from the vault root. This creates the `~/.claude/CLAUDE.md` include, copies obsidian skills, installs bun + qmd, installs the four official Claude plugins (code-review, frontend-design, skill-creator, claude-md-management), installs caveman and ponytail, and registers the `wiki-search` and `caveman-shrink` MCP servers. After setup, restart Claude Code and run `qmd update` to build the local search index.

**Caveman (both machines):** Output compression skill -- cuts ~65% of Claude output tokens with no accuracy loss. Requires Node >=18. Bootstrap handles install automatically; to install manually: `curl -fsSL https://raw.githubusercontent.com/JuliusBrussee/caveman/main/install.sh | bash`. Trigger per session with `/caveman`, or say "talk like caveman". Source: https://github.com/JuliusBrussee/caveman

**Ponytail (both machines):** "lazy senior dev" engineering-discipline plugin -- pushes for the simplest working solution (YAGNI, stdlib/native before dependencies, shortest diff). Governs what you build, not prose (pairs with caveman for terse output). Auto-activates at SessionStart (level `full`); switch with `/ponytail lite|full|ultra`. Install: `claude plugins marketplace add DietrichGebert/ponytail && claude plugins install ponytail@ponytail`. Source: https://github.com/DietrichGebert/ponytail

**caveman-shrink MCP (both machines):** MCP proxy that wraps `wiki-search` (qmd.mcp_server) and compresses tool descriptions before Claude reads them, reducing context token usage. Bootstrap registers it automatically at user scope with the correct `QMD_VAULT` for each machine. To register manually: `claude mcp add caveman-shrink -s user -e QMD_VAULT=<vault-path> -- npx -y caveman-shrink qmd mcp`. Both `wiki-search` (raw) and `caveman-shrink` (compressed descriptions) run as separate MCP entries; they share the same underlying data.

**qmd / `wiki-search` index:** Aim the markdown collection (`wiki`, or whichever name your MCP uses) only at **`$(vault-root)/wiki`**. Set `QMD_VAULT` to your vault root (no trailing slash). Remove stale collections that still reference old absolute paths before `qmd update` so indexing never scans the wrong directory.

**Vault file reads:** Use the `Read` tool with the vault path directly. The `obsidian-vault` MCP (`mcp-obsidian`) was removed -- it required the Obsidian app running and offered no advantage over `Read`. See `skills/skills-setup.md` for details.

**Hook symlink (wiki session hooks):** `bootstrap.sh` creates this automatically. To create it manually:

```bash
VAULT="<vault-root>"   # e.g. /mnt/c/Users/<you>/Documents/ObsidianVaults/ClaudeBrain
ln -sf "$VAULT/skills/hooks" ~/.claude/vault-hooks
```

Then register the vault hook set in `~/.claude/settings.json` (`bash setup/install-hooks.sh` does this for you; the canonical set spans 6 events -- see below). On a new machine, re-running `bash setup/bootstrap.sh` handles both steps automatically.

## Engagement-state automation (both machines)

**Transport is Obsidian Sync** for everything: the markdown knowledge base AND the automation code (`.py`, `.json`, `.sh`). There is no git push; a local git repo may exist per-device as offline history only (Obsidian does not sync `.git`).

**Hard requirement:** Obsidian Sync must be set to carry non-markdown files, or the hook code never reaches the other device and automation is dead there. In Obsidian: **Settings -> Sync -> turn ON "Sync all other file types"**, and confirm **Selective Sync** is not excluding `skills/`, `scripts/`, or `setup/`. By default Obsidian also skips dotfiles, but nothing runtime-critical is a dotfile (the engagement pointer is `targets/active.md`, not `.active`), so that exclusion is harmless.

**Device-2 / new-device procedure:**

```bash
# 1. let Obsidian Sync finish pulling the vault (incl. skills/, scripts/, setup/)
# 2. then, once per device:
cd <vault-root>
bash setup/install-hooks.sh    # symlinks ~/.claude/vault-hooks + registers the vault hook set
# 3. restart Claude Code
```

`install-hooks.sh` is self-locating (works on any user/path/spelling) and idempotent. It registers the canonical set (mirrored in `scripts/check-hooks.py` `EXPECTED_HOOKS`; `engagement-init` warns at SessionStart if any is unregistered) -- 12 hook commands across 6 events:
- **SessionStart** -- `session-start.sh` (skill auto-register + hot.md cache), `engagement-init.py` (self-heals the `state/loot/Killchain/Approach/...` set, injects the state summary + plan board status + top next-moves + one compact `harness:` maintenance line).
- **UserPromptSubmit** -- `hunt-trigger.py` (fires hunt skills from `skills/hunt/triggers.json`).
- **PreToolUse (Bash)** -- `scope-guard.py` (ENFORCES: denies out-of-scope host/IP (IPv4+IPv6, CIDR-aware; query-param/fragment values exempt) or RoE-forbidden tooling; fail-open + `skills/hooks/.enforce-off` escape hatch; also logs each block as a drift signal).
- **PreToolUse (Write)** -- `session-guard.py` (client-marker leak guard: session/* AND git-tracked framework trees; targets/ + docs/superpowers/ exempt; logs a boundary-drift signal).
- **PreToolUse (Bash)** -- `drift-guard.py` (makes the campaign driver non-optional: on an off-board exploit-shaped command during an active campaign at pass>=5 -- a NET_BINS/handroll call whose binary the driver never emitted, board non-empty -- escalates an `off_board_streak` in `.campaign.json`: 1-2 injects a "run campaign.py next" warning, >=3 DENIES; a `campaign.py next|board|done` call resets it. Fail-open; shares the `.enforce-off` escape hatch).
- **PostToolUse (Bash)** -- `recon-capture.py` (fingerprint router + OOB callback correlation + a once-per-engagement GATE-1 wiki-first nudge; a framework-meta guard suppresses false fires; advisory).
- **PostToolUse (all)** -- `tool-telemetry.py` (per-box telemetry: appends every tool/skill call to `targets/<eng>/.events.jsonl`, stamps `started_at`, records the session `transcript_path`; feeds `scripts/eval_metrics.py`. Silent, fail-open).
- **PostToolUse (Write/Edit)** -- `wiki-reindex.py` (auto-reindex: a Write/Edit to `wiki/**/*.md` fires a debounced background `qmd update` so the change is searchable without a manual reindex; off the blocking path, fail-open).
- **PreCompact** -- `pre-compact.sh` (persist state before compaction).
- **Stop** -- `close-out.py` (close-out reflex: when the engagement is SOLVED but its walkthrough is unassembled / the learn harvest is due, nudges Skill(walkthrough) then Skill(learn); advisory, self-clearing).

**Hooks self-locate the vault** via `realpath(__file__)` through the `~/.claude/vault-hooks` symlink -- no hardcoded paths, so the same code runs unmodified on every device.

**Active engagement pointer:** `targets/active.md` (one line: engagement dir name). It is markdown, so it syncs via Obsidian to both devices. Engagement files: `targets/<eng>/{state,loot,Killchain,log}.md` + `ingest/`, scaffolded from `setup/templates/<type>/` via `bash setup/new-engagement.sh <name> <pentest|bugbounty|ctf>`.

**`settings.json` and the symlink never sync** (machine-local by design). Always run `install-hooks.sh` once per device after the first git pull.

## Burp GUI automation: the Kali seat must stay UNLOCKED (gotcha)

`capture.sh burp` (burpshot) and any xdotool driving of Burp inject **synthetic input** into the Kali
desktop. A screen LOCK (xfce4-screensaver on seat0) or a blanked display routes that input to the locker,
not to Burp: `import -window` still grabs the window pixmap, but keys/clicks never land, so a grab silently
shows the WRONG Repeater tab. Symptom: `capture.sh burp` prints `GRAB_FAIL ... not interactive` even though
Burp is clearly on screen, and `getmouselocation` over Burp reports `window:0`.

- **Per-run (automatic):** `capture.sh burp` self-heals, it runs `loginctl unlock-session <seat0-sid>` +
  `xset` wake before the precheck, so a transient lock no longer blocks it.
- **Permanent (once per Kali box):** `sudo bash setup/burp/disable-lock.sh` disables the xfce4-screensaver
  saver + lock, removes its autostart, and kills DPMS/blanking (xfconf + `~/.xprofile` + an autostart
  override). Re-run after a box rebuild. Detail: `setup/burp/README.md`.
- **`wmctrl -lG` is NOT a reliable interactivity check** here, it reports "no managed windows" on this
  no-WM seat even when input lands (false negative). Use the pointer test (`getmouselocation` == the app
  WID), which is what `capture.sh burp` uses.

Burp MCP install (the "MCP Server" BApp, native vs `scripts/burp/burp-mcp-cli.py` bridge,
`burp-transport.sh`, the BApp loadout) lives in `wiki/tools/burp-mcp.md`. Driver scripts are in
`scripts/burp/`, skills in `skills/burp/` (`hunt-burp`, `screenshot-burp`), host setup in `setup/burp/`.
