#!/usr/bin/env python3
"""Stop hook: close-out reflex. When the active engagement is marked SOLVED but its
web evidence is incomplete (a web box with no recon cards or no saved render+source) --
or the walkthrough is not assembled -- or the walkthrough is done but the learn harvest is
still due -- surface a one-line nudge to run the close-out steps. The web-evidence gate
fires FIRST: you cannot have a complete walkthrough without the evidence, and it is the
thing skipped under momentum (recon cards, site render+source).

This is the reflex the de-bloat left unwired: deleting loop-driver removed the Stop-gate,
and _engagement.is_solved / walkthrough_stale / learn_pending had no caller, so a SOLVED box
produced no reminder (observed live: a solved box whose walkthrough + learn were never
invoked). Advisory + fail-open: never blocks the Stop, prints nothing on any
error, and self-clears the moment the walkthrough is assembled and Skill(learn) writes
.learn-done.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def main():
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        return
    if not d:
        return
    # Always-on live capture: card any scan tmux tab that FINISHED since last turn into recon/.
    # Run it SYNCHRONOUSLY but BOUNDED (autocard caps itself to AUTOCARD_MAX tabs/run + per-SSH
    # timeout, so a run finishes in a few seconds, inside the hook's 10s budget). A detached spawn
    # was unreliable over the WSL/remote-VM SSH bridge - the grandchild often never ran, so cards
    # only showed up in one late batch at close-out instead of trickling in live. In-hook + capped
    # trades a couple of seconds at turn-end for deterministic live cards. Hard-bounded by timeout
    # so a dead VM can never hang the hook.
    try:
        import subprocess
        sc = os.path.join(_engagement.VAULT, "scripts", "autocard.sh")
        if os.path.isfile(sc):
            env = dict(os.environ, AUTOCARD_MAX=os.environ.get("AUTOCARD_MAX", "2"))
            # total budget 8s (> autocard's 5s per-SSH cap, < the harness 10s hook timeout);
            # the fast nudge logic below needs only sub-second, so it is never starved.
            subprocess.run(["bash", sc, os.path.basename(d)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, env=env, timeout=8)
    except Exception:
        pass
    if not _engagement.is_solved(d):
        # During the box: state-discipline reflex. Loot captured but Killchain.md has no chain
        # rows -> nudge to write the attack path now, not at close-out. Deduped on the loot
        # row-count (a marker) so it re-fires only when a NEW finding lands, never every Stop.
        gap = _engagement.paths_write_gap(d)
        if gap:
            marker = os.path.join(d, ".paths-nudged")
            last = 0
            try:
                last = int((open(marker).read().strip() or "0"))
            except Exception:
                last = 0
            if gap > last:
                print("State-discipline: loot.md has %d finding(s) but Killchain.md has no chain "
                      "rows. Write the attack path NOW (one row per hop: what -> stage -> "
                      "status) so the chain persists across sessions -- do not defer it to "
                      "close-out." % gap)
                try:
                    open(marker, "w").write(str(gap))
                    import _telemetry
                    _telemetry.drift("close-out", "loot captured but Killchain.md empty (state discipline)")
                    _telemetry.hook("close-out", action="paths-nudge")
                except Exception:
                    pass
        # Cred-reuse reflex: several credentials captured, box not rooted, and no spray/reuse
        # line in Deadends.md -> a captured password is sitting unused. Deduped on the cred
        # row-count so it re-fires only when a NEW credential lands.
        creds = _engagement.unsprayed_cred_gap(d)
        if creds:
            cmarker = os.path.join(d, ".cred-spray-nudged")
            clast = 0
            try:
                clast = int((open(cmarker).read().strip() or "0"))
            except Exception:
                clast = 0
            if creds > clast:
                print("Cred-reuse: loot.md holds %d credential(s) and the box is not rooted, but "
                      "Deadends.md records no spray/reuse attempt. Try EVERY captured secret "
                      "against EVERY auth surface (ssh, su, the DB, the web login) BEFORE hunting "
                      "a new privesc vector -- and crack any hash you already hold. Log the "
                      "result to Deadends.md either way." % creds)
                try:
                    open(cmarker, "w").write(str(creds))
                    import _telemetry
                    _telemetry.drift("close-out", "credentials captured but never sprayed")
                    _telemetry.hook("close-out", action="cred-spray-nudge")
                except Exception:
                    pass
        return
    # box is SOLVED: stamp the finish time once (the far end of the start->finish delta)
    try:
        import _telemetry
        _telemetry.stamp_once("finished_at", _telemetry.now_iso(), d=d)
    except Exception:
        pass
    # fire the auto eval-metrics block once at close-out. Previously ONLY Skill(learn) Phase 0d ran
    # eval_metrics, so a light close-out that skipped learn produced no eval (observed live). Bounded
    # subprocess, fail-open, once per engagement (.eval-written marker); learn still re-runs it later.
    try:
        import subprocess
        em_marker = os.path.join(d, ".eval-written")
        em = os.path.join(_engagement.VAULT, "scripts", "eval_metrics.py")
        if not os.path.exists(em_marker) and os.path.isfile(em):
            subprocess.run(["python3", em, os.path.basename(d), "--write"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, timeout=15)
            open(em_marker, "w").close()
    except Exception:
        pass
    # Flag-accounting reflex (ctf only): SOLVED but fewer flags recorded than flags_expected,
    # or flags_expected unset -> nudge the full-FS flag sweep. Prints first but does NOT return,
    # so the evidence/walkthrough/learn chain below still surfaces. Fires each Stop while unsatisfied
    # (same as the walkthrough/learn nudges); resolves the moment the flags are recorded.
    fg = _engagement.flag_accounting_gap(d)
    if fg:
        print("Flag accounting: " + fg)
        try:
            import _telemetry
            _telemetry.drift("close-out", "flags under-counted / flags_expected unset at SOLVED")
            _telemetry.hook("close-out", action="flag-accounting-nudge")
        except Exception:
            pass
    gaps = _engagement.web_evidence_gaps(d)
    if gaps:
        print("Close-out INCOMPLETE (web box marked SOLVED but evidence missing): "
              + "; ".join(gaps) + ". Capture these NOW so the operator can see/verify what was "
              "found -- do not consider the box done until status.py shows recon-card + source "
              "evidence.")
        return
    # Auto-build the walkthrough scaffold + Evidence gallery (idempotent, no-clobber: only the
    # ## Evidence section is refreshed, narrative bytes preserved). Same bounded/fail-open pattern
    # as the eval_metrics call above. This does the mechanical assembly so a SOLVED box always has
    # a started walkthrough.md; the narrative stubs remain, so walkthrough_stale below stays True
    # and the "draft the narrative" nudge still fires. Runs each SOLVED Stop (build is idempotent).
    try:
        import subprocess
        bw = os.path.join(_engagement.VAULT, "scripts", "build-walkthrough.py")
        if os.path.isfile(bw):
            subprocess.run(["python3", bw, os.path.basename(d)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, timeout=15)
    except Exception:
        pass
    if _engagement.walkthrough_stale(d):
        print("Close-out: engagement is SOLVED but walkthrough.md is not assembled (scaffold + "
              "Evidence gallery auto-built). Run Skill(walkthrough) to draft the narrative, then "
              "Skill(learn).")
    elif _engagement.learn_pending(d):
        print("Close-out: walkthrough assembled, learn harvest still due. Run Skill(learn) "
              "to harvest generic lessons into wiki/ + do the harness retrospective.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
