#!/usr/bin/env python3
"""SessionStart hook: self-heal engagement state + inject summary + board + gap report.

- Creates any missing files from the active engagement's per-type core set (state/loot/
  Approach/...; Killchain only for pentest/bugbounty) from templates (self-heal; never
  overwrites).
- Injects the active-engagement summary, scope, OOB HITs, and the kill-chain board
  status (current phase + open/deadend counts) so you re-orient to the board.
- Collapses the per-item maintenance nags (wordlist / wiki-candidate / hook-drift /
  skill-drift / wiki-freshness / md-tables) into one compact `harness:` line, silent at zero.
- Keeps wiki/index.md fresh (scripts/gen_index.py, idempotent) only when the wiki
  actually changed since last session.
- Surfaces the active research project's loop state (scripts/research_status.py).

Plain stdout is added to context, alongside the other SessionStart hooks
(hot.md). Non-fatal: any error exits 0 silent.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _run_script(name, *args, timeout=40):
    """Run scripts/<name> from the vault; return CompletedProcess or None."""
    try:
        import _engagement
        script = os.path.join(_engagement.VAULT, "scripts", name)
        return subprocess.run(
            ["python3", script, *args],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return None


def regen_index():
    """Keep wiki/index.md current (writes only when stale; no churn when fresh)."""
    _run_script("gen_index.py", timeout=30)


def board_status():
    """One-line kill-chain board summary for the active engagement, or None.
    Names the highest-numbered phase that still has an open ([ ] / [~]) item and
    counts total open items + deadends ([!]). Best-effort; None when no board or
    nothing is open/dead (so it stays silent on a fresh or finished board)."""
    try:
        import _engagement
        d = _engagement.active_dir()
        if not d:
            return None
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
        if open_n == 0 and dead_n == 0:
            return None
        where = _engagement.phase_explicit(d) or (("Phase %d %s" % cur) if cur else "complete")
        return "Board: %s, %d open, %d deadends" % (where, open_n, dead_n)
    except Exception:
        return None


def harness_maintenance():
    """Compact list of pending harness-maintenance tags -- replaces the old stack of
    per-item SessionStart nags (wordlist / wiki-candidate / hook-drift / skill-drift).
    Each is best-effort + silent-at-zero; returns [] when nothing pends."""
    tags = []
    try:
        wc = wordlist_candidates()
        if wc and (wc[0] + wc[1]) > 0:
            tags.append("wordlist %d+%d (wl-add.sh)" % wc)
    except Exception:
        pass
    try:
        wcc = wiki_candidate_count()
        if wcc:
            tags.append("wiki-candidates:%d (wiki-promote.py --list)" % wcc)
    except Exception:
        pass
    try:
        import importlib.util
        import _engagement
        _ch_path = os.path.join(_engagement.VAULT, "scripts", "check-hooks.py")
        _spec = importlib.util.spec_from_file_location("check_hooks", _ch_path)
        _ch = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_ch)
        miss = _ch.missing_hooks()
        if miss:
            tags.append("hook-drift: " + ",".join(miss) + " (install-hooks.sh)")
        stale = _ch.stale_hooks()
        if stale:
            tags.append("stale-hook: " + ",".join(stale) + " (install-hooks.sh)")
        if _ch.missing_skills():
            tags.append("skill-drift (install-skills.sh)")
    except Exception:
        pass
    try:
        import importlib.util
        import _engagement
        _lmt_path = os.path.join(_engagement.VAULT, "scripts", "lint-md-tables.py")
        _spec = importlib.util.spec_from_file_location("lint_md_tables", _lmt_path)
        _lmt = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_lmt)
        d = _engagement.active_dir()
        if d:
            broken = _lmt.lint_paths([d])
            if broken:
                tags.append("md-tables:%d broken (lint-md-tables.py %s)"
                            % (len(broken), os.path.basename(d.rstrip("/"))))
    except Exception:
        pass
    return tags


def wordlist_candidates():
    """(paths, params) count of NEW generic wordlist tokens minable from targets/, or None."""
    r = _run_script("wordlist-suggest.py", "--count", timeout=20)
    if r is None:
        return None
    try:
        p, q = r.stdout.split()
        return (int(p), int(q))
    except Exception:
        return None


def wiki_candidate_count():
    """Pending candidates in the active engagement's wiki-candidates/ inbox, or 0.
    Silent-at-zero surfacer, same shape as the wordlist nag. Best-effort.

    Detects pending by PARSING frontmatter via _engagement._frontmatter (the same
    tolerant parser wiki-promote.py's pending-detection uses), not a raw
    "status: pending" substring - a raw substring misses e.g. 'status:  pending'
    (extra spacing), silently undercounting a candidate that IS promotable."""
    try:
        import _engagement
        d = _engagement.active_dir()
        if not d:
            return 0
        inbox = os.path.join(d, "wiki-candidates")
        if not os.path.isdir(inbox):
            return 0
        n = 0
        for f in os.listdir(inbox):
            if not f.endswith(".md") or f.startswith("_"):
                continue
            text = open(os.path.join(inbox, f), encoding="utf-8", errors="ignore").read()
            fm = _engagement._frontmatter(text)
            if fm.get("status", "").strip().lower() == "pending":
                n += 1
        return n
    except Exception:
        return 0


def research_status_text():
    """Full status block for the active research project, or None if none set."""
    r = _run_script("research_status.py", timeout=15)
    if r is None:
        return None
    out = r.stdout.strip()
    return out if out and "No active research project" not in out else None


def _stamp_path():
    import _engagement
    return os.path.join(_engagement.VAULT, ".wiki-stamp")


def wiki_fingerprint():
    """Cheap max-mtime over wiki/ + triggers.json + playbook.json (stat only, no reads).
    Detects any page add/remove/edit so the heavy walks run only when needed."""
    import _engagement
    mx = 0.0
    stack = [os.path.join(_engagement.VAULT, "wiki")]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    else:
                        m = e.stat(follow_symlinks=False).st_mtime
                        if m > mx:
                            mx = m
        except OSError:
            pass
    for f in ("skills/hunt/triggers.json", "scripts/playbook.json"):
        try:
            m = os.stat(os.path.join(_engagement.VAULT, f)).st_mtime
            if m > mx:
                mx = m
        except OSError:
            pass
    return f"{mx:.3f}"


def wiki_changed():
    """(changed, fingerprint). True if wiki/triggers/playbook changed since last stamp."""
    fp = wiki_fingerprint()
    try:
        old = open(_stamp_path(), encoding="utf-8").read().strip()
    except OSError:
        old = ""
    return (fp != old, fp)


def write_stamp(fp):
    try:
        open(_stamp_path(), "w", encoding="utf-8").write(fp)
    except OSError:
        pass


def main():
    try:
        import _engagement
    except Exception:
        return

    out = []
    created = _engagement.ensure_state_files()
    if created:
        out.append("Self-heal: created " + ", ".join(created) + " from template.")

    # telemetry: back-fill the box start time on first sight (new-engagement.sh stamps the precise
    # start; this covers pre-existing boxes) and record the session-start hook fire.
    try:
        import _telemetry
        _d = _engagement.active_dir()
        if _d:
            _telemetry.stamp_once("started_at", _telemetry.now_iso(), d=_d)
            _telemetry.hook("engagement-init", d=_d, action="session-start")
    except Exception:
        pass

    summ = _engagement.summary_text()
    if summ:
        out.append(summ)

    sc = _engagement.scope_text()
    if sc:
        out.append(sc)

    # tunnel_safe is an affirmation, not a forbidden flag, so scope_text (RoE-forbidden
    # list) omits it. Surface it explicitly so the model knows curl+nc is the intended
    # tool here (scanners exhaust the pivot's conntrack). Silent when unset.
    try:
        if _engagement.scope().get("tunnel_safe"):
            out.append("tunnel_safe: curl+nc only (scanners kill the pivot)")
    except Exception:
        pass

    # OOB callback HITs land the highest: a confirmed blind-bug callback should be
    # turned into a FIND immediately. Surfaced above next-moves.
    try:
        hits = _engagement.oob_hits()
        if hits:
            sinks = "; ".join((h.get("sink") or h.get("token") or "?") for h in hits[:4])
            out.append(f"OOB HIT: {len(hits)} callback(s) landed ({sinks}) -> scaffold + "
                       "validate the FIND(s), then mark the oob.md row 'actioned'.")
    except Exception:
        pass

    # kill-chain board: current phase + open/deadend counts, so you re-orient to the
    # board rather than re-running the last thing. Silent when no board / nothing open.
    try:
        bs = board_status()
        if bs:
            out.append(bs)
    except Exception:
        pass

    # evidence captured (observability): a multi-finding box with few deliberate shots is a
    # capture gap the operator should see at a glance. Silent at zero. Full view: scripts/status.py.
    try:
        import glob as _glob
        _d = _engagement.active_dir()
        if _d:
            _poc = len(_glob.glob(os.path.join(_d, "poc", "**", "*.png"), recursive=True))
            _rec = len(_glob.glob(os.path.join(_d, "recon", "*.png")))
            if _poc or _rec:
                out.append("evidence: %d poc shot(s), %d recon card(s) "
                           "(scripts/status.py = full status)" % (_poc, _rec))
    except Exception:
        pass

    # ranked next-moves from the analyzer (top 3)
    try:
        sys.path.insert(0, os.path.join(_engagement.VAULT, "scripts"))
        import next_move
        for m in next_move.suggest(limit=3):
            out.append("  next: " + m)
    except Exception:
        pass

    # One compact harness-maintenance line replaces the old stack of per-item nags
    # (wordlist / wiki-candidate / hook-drift / skill-drift). Silent at zero.
    try:
        maint = harness_maintenance()
        if maint:
            out.append("harness: " + "; ".join(maint))
    except Exception:
        pass

    # Wiki upkeep runs ONLY when wiki/triggers/playbook actually changed since the
    # last session (a cheap stat-only fingerprint vs a stamp) - the main SessionStart
    # speedup on the slow Windows mount. Refresh index.md silently, fold a freshness
    # count into one note, and nudge a qmd reindex. The gaps/lint checks are on-demand
    # scripts now (scripts/wiki-gaps.py, scripts/lint-wiki.py), not SessionStart nags.
    changed, _ = wiki_changed()
    if changed:
        regen_index()  # keep index.md fresh (idempotent)
        note = "Wiki changed since last session -> run `qmd update` to refresh the search index."
        try:
            import freshness
            fr = freshness.stale()
            if fr:
                note += "  [%d reuse page(s) stale -> scripts/freshness.py]" % len(fr)
        except Exception:
            pass
        out.append(note)
        write_stamp(wiki_fingerprint())   # recompute AFTER regen_index bumped index.md, else next session re-fires

    if out:
        print("=== Engagement state ===")
        print("\n".join(out))

    # client narrative loads from the private per-engagement log.md, NOT session/
    # (session/hot.md stays generic/framework-only). log.md = the per-engagement audit;
    # its newest block is the continuity cache surfaced here.
    try:
        rl = _engagement.recent_log()
        if rl:
            print("=== Recent engagement log ===")
            print(rl)
    except Exception:
        pass

    # active research project (raw/research/active.md) surfaces its loop state
    rs = research_status_text()
    if rs:
        print(rs)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
