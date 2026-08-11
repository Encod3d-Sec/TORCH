# Sharing TORCH (client-data boundary)

TORCH mixes shareable methodology with private client data. The split is enforced by git.

## The boundary

| Surface | Contains | Shareable? | Mechanism |
|---------|----------|-----------|-----------|
| git repo | CLAUDE.md, `skills/`, `scripts/`, `setup/`, `docs/`, `wiki/`* | **yes** | what you publish |
| Obsidian vault (full folder) | the above **plus** `targets/`, `session/`, `raw/` | **no** | private working copy |

`targets/`, `session/`, `raw/` are git-ignored (see `.gitignore`). They never enter the repo.

\* `wiki/` is also git-ignored (Obsidian owns the markdown corpus). If you want to publish the wiki too, track it deliberately, but run the leak check first.

## How to share

**Share the git repo, never the Obsidian vault folder.**

```bash
bash scripts/check-leaks.sh        # must print "clean"
git archive --format=tar.gz -o /tmp/torch-share.tar.gz HEAD
# or push the repo to a (private first, then public) remote
```

Copying the vault directory (zip, cloud folder, Obsidian Sync to a shared vault) **leaks `targets/`**. Don't.

## Leak check

`scripts/check-leaks.sh` greps every git-tracked file against the private term list `targets/scrub-terms.txt` (itself git-ignored, so it never ships). It fails if a client name, hostname, or IP appears in a shareable file.

- Add each engagement's markers (client name, internal hostnames, domains, IP ranges) to `targets/scrub-terms.txt` when you start.
- Run the check before every push / archive / handoff.

## Rules going forward

- **Code stays client-agnostic.** Hooks/scripts self-locate and read `targets/active.md`; no hardcoded client names or IPs. Keep it that way.
- **Docs/specs use placeholders** (`acme-internal`, `10.0.0.0/24`, `host1`), never real client data.
- **Commit messages** describe mechanism, not client specifics. Git history is hard to scrub; keep it clean from the start.
- **All client engagement data lives only under `targets/<engagement>/`** (state, loot, paths, ingest, findings, scope, poc).
