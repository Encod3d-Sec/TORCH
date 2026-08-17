#!/usr/bin/env python3
"""campaign-doctor.py [--verbose] - health check for the bb/pt/ctf workflow subsystem.

The vault syncs across machines; ~/.claude (hook registration, skill symlinks, deps) does NOT. So
"it works here" does not mean "it works there". This verifies BOTH halves so every machine runs the
same driver:

  A. vault content is internally consistent (scripts present, JSON valid, routing wired, 69 tool
     pages carry phase:, the tool index resolves, the hook edits are in place)
  B. this machine is wired (the 3 skills are symlinked, hooks are registered, python imports work)
  C. a live smoke test: init -> board -> next against a throwaway copy of the fixture

Exit 0 = all green; 1 = at least one FAIL. WARN never fails the run. Fix what FAILs before relying on
the driver on this machine.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
FIX = os.path.join(VAULT, "tests", "fixtures", "campaign")

RESULTS = []


def check(name, ok, detail="", warn=False):
    RESULTS.append((name, "WARN" if (warn and not ok) else ("PASS" if ok else "FAIL"), detail))
    return ok


# --------------------------------------------------------------------------- A. vault content

def _a_files():
    need = ["campaign.py", "campaign.json", "behaviours.json", "surface-seeds.json", "handroll.py",
            "check-engagement.py", "playbook.json", "chains.json", "coverage-classes.json",
            "tool-phase-backfill.py"]
    for f in need:
        check("script present: " + f, os.path.isfile(os.path.join(HERE, f)))
    check("triggers.json present",
          os.path.isfile(os.path.join(VAULT, "skills", "hunt", "triggers.json")))
    check("drift-guard hook present",
          os.path.isfile(os.path.join(VAULT, "skills", "hooks", "drift-guard.py")))
    check("vm-bg.sh present+exec",
          os.access(os.path.join(HERE, "vm-bg.sh"), os.X_OK))


def _a_json():
    for f in ("campaign.json", "behaviours.json", "playbook.json", "chains.json",
              "coverage-classes.json"):
        p = os.path.join(HERE, f)
        try:
            json.load(open(p, encoding="utf-8"))
            check("valid JSON: " + f, True)
        except Exception as e:
            check("valid JSON: " + f, False, str(e)[:80])
    # campaign approaches must exist in playbook + coverage-classes
    try:
        cfg = json.load(open(os.path.join(HERE, "campaign.json")))
        pb = json.load(open(os.path.join(HERE, "playbook.json")))["fingerprints"]
        pb_appr = {a for v in pb.values() for a in (v.get("approach") or [])}
        cc = json.load(open(os.path.join(HERE, "coverage-classes.json")))
        for t in ("bb", "pt", "ctf"):
            appr = cfg[t]["approach"]
            check("approach '%s' in playbook" % appr, appr in pb_appr)
            check("approach '%s' in coverage-classes" % appr, appr in cc)
    except Exception as e:
        check("campaign.json cross-refs", False, str(e)[:80])


def _a_hook_edits():
    """The two hook edits that must be present for G2/G8 and tool routing (they live in the vault,
    so a stale sync is caught here, not at runtime)."""
    rc = os.path.join(VAULT, "skills", "hooks", "recon-capture.py")
    tt = os.path.join(VAULT, "skills", "hooks", "tool-telemetry.py")
    try:
        check("recon-capture emits spec['tools']",
              'spec.get("tools")' in open(rc, encoding="utf-8").read())
    except Exception as e:
        check("recon-capture readable", False, str(e)[:60])
    try:
        t = open(tt, encoding="utf-8").read()
        check("tool-telemetry logs binaries", "_binaries" in t and '"bins"' in t or "bins=" in t)
    except Exception as e:
        check("tool-telemetry readable", False, str(e)[:60])
    dg = os.path.join(VAULT, "skills", "hooks", "drift-guard.py")
    try:
        d = open(dg, encoding="utf-8").read()
        # advisory-only (declawed): _scanner_cap stays, but drift-guard never denies and no longer
        # carries the time-based auto-RTL nudge (RTL reflex now lives in campaign.py _tells_stop +
        # recon-capture's vector-doubt nudges).
        check("drift-guard has _scanner_cap, advisory-only (no deny)",
              "_scanner_cap" in d and "permissionDecision" not in d)
    except Exception as e:
        check("drift-guard readable", False, str(e)[:60])
    try:
        r = open(rc, encoding="utf-8").read()
        check("recon-capture has _readwhole_nudge", "_readwhole_nudge" in r)
    except Exception as e:
        check("recon-capture readable (readwhole)", False, str(e)[:60])


def _a_tool_index():
    sys.path.insert(0, HERE)
    try:
        import campaign
        idx = campaign.tool_index()
        miss = [s for s, m in idx.items() if not m["invocation"]]
        check("tool index resolves all invocations", not miss,
              "missing: " + ", ".join(miss) if miss else "")
        # every wiki/tools page carries phase:
        tdir = os.path.join(VAULT, "wiki", "tools")
        nopf = [f for f in os.listdir(tdir) if f.endswith(".md")
                and not re.search(r"^phase:\s*\S", open(os.path.join(tdir, f),
                                  encoding="utf-8", errors="ignore").read(), re.M)]
        check("all wiki/tools pages carry phase:", not nopf, "missing: " + ", ".join(nopf))
    except Exception as e:
        check("campaign.tool_index importable", False, str(e)[:80])


# --------------------------------------------------------------------------- B. machine wiring

def _b_skills():
    dest = os.path.expanduser("~/.claude/skills")
    for s in ("bb-workflow", "pt-workflow", "ctf-workflow"):
        src = os.path.join(VAULT, "skills", "workflow", s, "SKILL.md")
        check("skill authored: " + s, os.path.isfile(src))
        link = os.path.join(dest, s)
        check("skill installed (symlink): " + s, os.path.islink(link) or os.path.isdir(link),
              "run setup/install-skills.sh", warn=True)


def _b_hooks():
    """Delegate to the canonical hook checker if present."""
    ch = os.path.join(HERE, "check-hooks.py")
    if not os.path.isfile(ch):
        check("check-hooks.py present", False, warn=True)
        return
    try:
        r = subprocess.run([sys.executable, ch], capture_output=True, text=True, timeout=30)
        check("hooks registered (check-hooks.py)", r.returncode == 0,
              (r.stdout + r.stderr).strip().splitlines()[-1][:80] if (r.stdout or r.stderr) else "",
              warn=True)
    except Exception as e:
        check("check-hooks.py runs", False, str(e)[:60], warn=True)


def _b_imports():
    sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
    try:
        import _engagement  # noqa
        check("import _engagement", True)
        check("_engagement has touch_direction + seconds_since_direction",
              hasattr(_engagement, "touch_direction") and hasattr(_engagement, "seconds_since_direction"))
    except Exception as e:
        check("import _engagement", False, str(e)[:80])


# --------------------------------------------------------------------------- C. live smoke test

def _c_smoke():
    if not os.path.isdir(FIX):
        check("fixture present for smoke test", False)
        return
    tmp = tempfile.mkdtemp(prefix="campaign-doctor-")
    try:
        eng = os.path.join(tmp, "eng")
        shutil.copytree(FIX, eng)

        def C(*a):
            return subprocess.run([sys.executable, os.path.join(HERE, "campaign.py"),
                                   "--eng", eng, *a], capture_output=True, text=True)
        r = C("init", "--type", "bb")
        check("smoke: init", r.returncode == 0, r.stderr.strip()[:80])
        r = C("board")
        check("smoke: board writes rows", r.returncode == 0 and "+"
              in r.stdout, r.stderr.strip()[:80])
        r = C("next")
        check("smoke: next prints a block", r.returncode == 0 and "PASS" in r.stdout,
              r.stderr.strip()[:80])
        check("smoke: next withholds exploit at G1 (arsenal empty)", "wiki-arsenal" in r.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    verbose = "--verbose" in argv or "-v" in argv
    _a_files(); _a_json(); _a_hook_edits(); _a_tool_index()
    _b_skills(); _b_hooks(); _b_imports()
    _c_smoke()

    fails = [r for r in RESULTS if r[1] == "FAIL"]
    warns = [r for r in RESULTS if r[1] == "WARN"]
    for name, status, detail in RESULTS:
        if status == "PASS" and not verbose:
            continue
        print("%-5s %s%s" % (status, name, ("  - " + detail) if detail else ""))
    print("\ncampaign-doctor: %d checks, %d PASS, %d WARN, %d FAIL"
          % (len(RESULTS), sum(1 for r in RESULTS if r[1] == "PASS"), len(warns), len(fails)))
    if fails:
        print("FAIL -> the driver will not run correctly on this machine. Fix the above.")
    elif warns:
        print("OK with warnings (machine wiring - run the named setup script).")
    else:
        print("ALL GREEN - the campaign subsystem is consistent and wired on this machine.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
