---
name: coverage
description: Show per-asset vuln-class coverage gaps for the active engagement so nothing in scope is skipped. Use when asked "coverage", "what haven't we tested", "test gaps", "are we thorough", or before calling an engagement done.
---

# Coverage

Systematic thoroughness: which phase items and applicable vuln classes have NOT been done.
Coverage now lives in the plan board (`targets/<eng>/Approach.md`), not a separate file.

## Read the board
```
cat targets/<active>/Approach.md
python3 scripts/next_move.py      # ranks [gap] test moves from the 4a table + findings + Deadends
```
- Phase items still `[ ]` (todo) or `[~]` (doing) are the open work, in kill-chain order.
- The `### 4a` table is the per-asset coverage matrix: one row per (asset, vuln class); a row
  counts as tested when its `status` cell is `[x]`/done. Any applicable class with no done row
  on an in-scope asset is a gap. `next_move.py` surfaces these as `[gap]` moves.

## Then (model)
1. For each asset, the untested applicable classes ARE the to-do. Prioritise by impact + the
   `[gap]`/`[now]` moves from `next_move.py` (fingerprint-targeted).
2. Pull payloads from `wiki/payloads/<class>` for each untested class (or `Skill(arsenal)`).
3. After testing a class on an asset, **add a `### 4a` row to `Approach.md`** with the class,
   the tool/payload, `status` `[x]`, and the `poc/` image (GATE 2). Otherwise the gap recurs.
4. A phase is done only when every applicable item is `[x]` or `[-]` (n/a) or `[!]` (deadend).

## Discipline
- Respect scope: out-of-scope assets are excluded by `next_move.py`.
- "Done" means tested, not necessarily clean - record findings separately as FINDs.
- Don't mark a row `[x]` without actually testing it and capturing a `poc/` image; this
  checklist only helps if honest.
