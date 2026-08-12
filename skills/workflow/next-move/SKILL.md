---
name: next-move
description: Ranked next offensive moves from engagement state. Reads state/loot/Killchain, runs the deterministic analyzer, elaborates the top move. Use when asked "what next", "where to focus", "prioritize", or at the start of an engagement session.
---

# Next Move (deprecated - now an input to /redteamlead)

`next-move` no longer runs standalone. Its ranked output is now one INPUT that
`/redteamlead` reads before giving a wiki-grounded direction.

For "where do I go next", call `Skill(redteamlead)` instead of this skill directly.

The deterministic ranker stays and is unchanged:
```
python3 scripts/next_move.py --json
```
RTL reads this `--json` output (plus state/loot/Killchain/log and the wiki) to produce
its ranked directions. Nothing else in this file is load-bearing anymore.
