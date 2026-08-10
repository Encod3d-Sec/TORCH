#!/usr/bin/env python3
"""Canonical expected vault-hook set + drift detector (hooks AND skills).

Single source of truth for which vault hooks SHOULD be registered in this
machine's ~/.claude/settings.json. settings.json is machine-local and does not
sync across devices, so a hook can silently go unregistered on one machine
(hooks fail open + silent, so the omission is invisible). This module lets the
SessionStart hook surface that drift as one advisory line.

When you add a new vault hook to setup/install-hooks.sh, also add it to
EXPECTED_HOOKS below so the drift check stays accurate on every device.

missing_hooks() returns the script basenames that the expected set requires but
that are absent from settings.json. It fails open: an unreadable or missing
settings.json returns [] (we cannot assert drift without the file).

missing_skills() does the parallel check for skills: setup/install-skills.sh
symlinks every SKILL.md-bearing dir under skills/ into ~/.claude/skills so the
Skill tool + /skills picker can load it. That dest is also machine-local and the
installer is only re-run by hand, so a newly added vault skill can sit
unregistered (Skill(<name>) -> "Unknown skill") while triggers.json still routes
to it. No EXPECTED list to maintain: the SKILL.md walk IS the source of truth,
identical to the installer's `find skills -name SKILL.md`.
"""
import json
import os
import sys

# (event, script_basename) pairs the per-device installer registers.
# Match this to setup/install-hooks.sh.
EXPECTED_HOOKS = [
    ("SessionStart", "session-start.sh"),
    ("SessionStart", "engagement-init.py"),
    ("UserPromptSubmit", "hunt-trigger.py"),
    ("PostToolUse", "recon-capture.py"),
    ("PostToolUse", "tool-telemetry.py"),
    ("PostToolUse", "wiki-reindex.py"),
    ("PreToolUse", "scope-guard.py"),
    ("PreToolUse", "session-guard.py"),
    ("PreToolUse", "drift-guard.py"),
    ("PreCompact", "pre-compact.sh"),
    ("Stop", "close-out.py"),
]


def default_settings_path():
    return os.path.expanduser("~/.claude/settings.json")


def _registered_commands(settings):
    """Yield every hook command string across all events in settings."""
    for groups in settings.get("hooks", {}).values():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for hk in group.get("hooks", []):
                if isinstance(hk, dict):
                    cmd = hk.get("command", "")
                    if isinstance(cmd, str):
                        yield cmd


def missing_hooks(settings_path=None):
    """Return expected script basenames absent from settings.json.

    Match is by the script basename appearing anywhere in a registered hook
    command string (commands use ~/.claude/vault-hooks/<name> or
    `python3 ... <name>`). Fails open: unreadable/missing settings -> [].
    """
    if settings_path is None:
        settings_path = default_settings_path()
    try:
        with open(settings_path, encoding="utf-8") as f:
            settings = json.load(f)
    except Exception:
        return []  # fail open: cannot assert drift without the file

    commands = list(_registered_commands(settings))
    missing = []
    for _event, basename in EXPECTED_HOOKS:
        if not any(basename in cmd for cmd in commands):
            missing.append(basename)
    return missing


def vault_root():
    """Repo root: scripts/check-hooks.py -> its grandparent dir."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def stale_hooks(settings_path=None, hooks_root=None):
    """Return registered vault-hook scripts that no longer exist in skills/hooks.

    The mirror image of missing_hooks(). settings.json is machine-local and the
    installer only ADDS, so a hook DELETED upstream stays registered on every
    already-provisioned device, pointing at a file the next `git pull` removed.
    That is not silent: the hook cannot start, so a PostToolUse entry errors on
    every matching tool call (and a PreToolUse one exits 2, which BLOCKS
    Bash/Write/Edit). Detect by name, not by an EXPECTED list, so a removal
    needs no bookkeeping. Fails open: unreadable settings/hooks dir -> [].
    """
    if settings_path is None:
        settings_path = default_settings_path()
    if hooks_root is None:
        hooks_root = os.path.join(vault_root(), "skills", "hooks")
    try:
        with open(settings_path, encoding="utf-8") as f:
            settings = json.load(f)
        present = set(os.listdir(hooks_root))
    except Exception:
        return []  # fail open: cannot assert drift without both sides

    stale = []
    for cmd in _registered_commands(settings):
        for token in cmd.split():
            name = token.rsplit("/", 1)[-1]
            if "vault-hooks/" in token and name not in present:
                stale.append(name)
    return sorted(set(stale))


def default_skills_dest():
    return os.path.expanduser("~/.claude/skills")


def _vault_skill_names(skills_root):
    """Basenames of every dir under skills_root holding a SKILL.md.

    Mirrors setup/install-skills.sh's `find skills -name SKILL.md` -> the exact
    set that installer symlinks into ~/.claude/skills. os.walk over a missing
    tree yields nothing, so an absent skills/ naturally returns [] (fail open).
    """
    names = set()
    try:
        for dirpath, _dirs, files in os.walk(skills_root):
            if "SKILL.md" in files:
                names.add(os.path.basename(dirpath))
    except Exception:
        return set()
    return names


def missing_skills(skills_root=None, dest=None):
    """Return vault skill names not symlinked into ~/.claude/skills.

    A vault skill is unregistered when the installer has not been re-run since
    it was added: triggers.json routes to it but Skill(<name>) fails. We flag by
    presence-of-name only (os.path.lexists, so a broken symlink still counts as
    'present' - that is a different drift). Fails open: an unreadable skills/
    tree returns [] (cannot assert drift without the source).
    """
    if skills_root is None:
        skills_root = os.path.join(vault_root(), "skills")
    if dest is None:
        dest = default_skills_dest()
    names = _vault_skill_names(skills_root)
    missing = [n for n in names if not os.path.lexists(os.path.join(dest, n))]
    return sorted(missing)


def main():
    rc = 0
    miss_h = missing_hooks()
    if miss_h:
        print("Missing vault hooks: " + ", ".join(miss_h))
        print("Run: bash setup/install-hooks.sh")
        rc = 1
    else:
        print("all %d vault hooks registered" % len(EXPECTED_HOOKS))
    stale_h = stale_hooks()
    if stale_h:
        print("Stale vault hooks (script deleted upstream, still registered): "
              + ", ".join(stale_h))
        print("Run: bash setup/install-hooks.sh")
        rc = 1
    miss_s = missing_skills()
    if miss_s:
        print("Unregistered vault skills: " + ", ".join(miss_s))
        print("Run: bash setup/install-skills.sh")
        rc = 1
    else:
        print("all vault skills registered")
    return rc


if __name__ == "__main__":
    sys.exit(main())
