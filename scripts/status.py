#!/usr/bin/env python3
"""On-demand engagement status dashboard -- one consolidated glance for operator observability.

Composes the active engagement's counts (_engagement.summary), kill-chain phase (the board),
evidence actually captured (poc/ + recon/ shots), recent dead-ends, and the ranked next moves
(ranking stays in scripts/next_move.py -- not duplicated here). Read-only; never edits the
engagement. Run any time:

    python3 scripts/status.py
    python3 scripts/status.py --coverage   # full uncapped asset x vuln-class coverage matrix

The same render is surfaced compactly at SessionStart by engagement-init; this is the full
on-demand view (evidence + dead-ends included) the operator can pull mid-engagement. The
--coverage flag prints the per-asset coverage grid (Skill(coverage)) instead of the dashboard.
"""
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))


def evidence_counts(d):
    """(poc_shots, recon_cards): deliberate PoC images under poc/ (recursive) + auto recon cards."""
    poc = len(glob.glob(os.path.join(d, "poc", "**", "*.png"), recursive=True))
    recon = len(glob.glob(os.path.join(d, "recon", "*.png")))
    return poc, recon


def deadend_lines(d, limit=3):
    """The most recent Dead-ends.md bullet lines (skip headers/frontmatter/blank)."""
    p = os.path.join(d, "Deadends.md")
    if not os.path.isfile(p):
        return []
    out = []
    for line in open(p, encoding="utf-8", errors="ignore"):
        s = line.strip()
        if s.startswith("- ") and len(s) > 2:
            body = s[2:].strip()
            # skip template placeholders: a bare/empty checkbox line carries no dead-end
            if body and not re.fullmatch(r"\[[ x!~-]?\]", body):
                out.append(body)
    return out[-limit:]


def board_phase(d):
    """(where, open_n, dead_n) from Approach.md: highest-numbered phase with an open item,
    or the explicit `current_phase` frontmatter field when set and in-scope (see
    _engagement.phase_explicit). Mirrors engagement-init.board_status; kept here so
    status.py has no hook dependency."""
    import _engagement
    p = os.path.join(d, "Approach.md")
    if not os.path.isfile(p):
        return None
    open_n = dead_n = 0
    phase = cur = None
    for line in open(p, encoding="utf-8", errors="ignore"):
        s = line.rstrip()
        hm = re.match(r"##\s+(\d+)\.\s+([^(]+)", s)
        if hm:
            phase = (int(hm.group(1)), hm.group(2).strip())
            continue
        if "[ ]" in s or "[~]" in s:
            open_n += 1
            if phase and (cur is None or phase[0] >= cur[0]):
                cur = phase
        elif "[!]" in s:
            dead_n += 1
    where = _engagement.phase_explicit(d) or (("Phase %d %s" % cur) if cur else "complete")
    return where, open_n, dead_n


def render_coverage(base, assets, tested_by_asset):
    """Pure formatter -> the full asset x vuln-class coverage grid (x=tested . =untested),
    UNCAPPED (unlike next_move's top-5 per-asset shortlist), so the coverage skill sees every
    in-scope asset against every base class instead of eyeballing Approach.md. `tested_by_asset`
    maps an asset name -> its set of tested class names (lowercased). Deterministic."""
    if not base or not assets:
        return "coverage: no in-scope assets or no class checklist for this engagement type."
    lines = ["coverage matrix (x=tested . =untested), %d classes:" % len(base)]
    for a in assets:
        tested = tested_by_asset.get(a, set())
        cells = " ".join("x" if c.lower() in tested else "." for c in base)
        n = sum(1 for c in base if c.lower() in tested)
        lines.append("  %-22s %s  (%d/%d)" % (a[:22], cells, n, len(base)))
    lines.append("  class order: " + " ".join(base))
    return "\n".join(lines)


def coverage_data(d, etype):
    """Gather (base_classes, in_scope_assets, {asset: tested_set}) for render_coverage.
    Read-only; reuses the exact helpers next_move.py consumes (in_scope_assets +
    _engagement.tested_classes) so the uncapped matrix and the ranked [gap] moves agree.
    Any missing piece degrades to empty. Import is lazy so module load stays dependency-light."""
    import json
    import _engagement
    import next_move
    try:
        base = json.load(open(os.path.join(VAULT, "scripts", "coverage-classes.json"),
                              encoding="utf-8")).get(etype, [])
    except Exception:
        base = []
    if not base:
        return base, [], {}
    sc = _engagement.scope(d)
    state = _engagement._parse_table(os.path.join(d, "state.md"))
    assets = next_move.in_scope_assets(state, etype, sc)
    glob_l, norm = next_move.tested_lookup(d, etype, base)
    tested_by_asset = {a: next_move.tested_for_asset(a, glob_l, norm) for a in assets}
    return base, assets, tested_by_asset


def render(name, etype, solved, summ, board, poc, recon, deads, moves_text):
    """Pure formatter -> the dashboard string. All inputs are precomputed (testable)."""
    head = "=== %s (%s)%s ===" % (name, etype, "  STATUS: SOLVED" if solved else "")
    lines = [head]
    if summ:
        lines.append("hosts %d (owned %d) | creds %d | open paths %d"
                     % (summ["hosts"], summ["owned"], summ["creds"], summ["open_paths"]))
    if board:
        where, open_n, dead_n = board
        lines.append("board: %s | %d open | %d deadends" % (where, open_n, dead_n))
    lines.append("evidence: %d poc shot(s), %d recon card(s)" % (poc, recon))
    if deads:
        lines.append("recent deadends:")
        lines += ["  - " + x for x in deads]
    if moves_text.strip():
        lines.append(moves_text.strip())
    return "\n".join(lines)


def main():
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        d = None
    if not d:
        print("No active engagement (targets/active.md).")
        return 0
    name = os.path.basename(d)
    etype = _engagement.engagement_type(d)
    if "--coverage" in sys.argv:   # full uncapped asset x class matrix (Skill(coverage))
        print(render_coverage(*coverage_data(d, etype)))
        return 0
    solved = _engagement.is_solved(d)
    summ = _engagement.summary()
    board = board_phase(d)
    poc, recon = evidence_counts(d)
    deads = deadend_lines(d)
    moves_text = ""
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "next_move.py")],
                           capture_output=True, text=True, timeout=25)
        moves_text = r.stdout or ""
    except Exception:
        pass
    print(render(name, etype, solved, summ, board, poc, recon, deads, moves_text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
