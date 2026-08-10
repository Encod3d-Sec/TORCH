#!/usr/bin/env python3
"""tool-phase-backfill.py [--write]

Add a `phase:` frontmatter line to every wiki/tools/*.md, derived from its existing `tags:`, from
the controlled vocabulary recon|fuzz|scan|exploit|crack|postex|pivot|aux. gen_index.py already emits
an (empty) Phase column for tools, so filling this populates wiki/index.md with no code change, and
campaign.py's tool index (Task 14) reads it.

Idempotent: a page that already has `phase:` is left alone. Dry-run by default; --write applies.
Prints one line per page so the mapping can be eyeballed before writing.
"""
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(VAULT, "wiki", "tools")

# tag -> phase, in priority order (first matching tag wins). A tool is placed by its most
# offensively-specific tag: exploitation beats recon, so sqlmap (exploitation, scanner, web) -> exploit.
PRIORITY = [
    ("exploit", {"exploitation", "exploit"}),
    ("crack", {"cracking", "password-cracking", "brute-force"}),
    ("postex", {"post-exploitation", "privilege-escalation", "lateral-movement", "credential-access"}),
    ("pivot", {"pivoting", "tunneling", "tunnel", "c2"}),
    ("scan", {"scanner", "scanning", "vulnerability", "automation"}),
    ("fuzz", {"fuzzing", "content-discovery"}),
    ("aux", {"reverse-engineering", "binary", "forensics", "cve-research", "exploit-dev",
             "stego", "crypto", "mobile"}),
    ("recon", {"recon", "osint", "attack-surface", "enumeration", "subdomain"}),
]
FALLBACK = "aux"
VOCAB = {"recon", "fuzz", "scan", "exploit", "crack", "postex", "pivot", "aux"}

# Explicit overrides where the tag heuristic misplaces a tool. Content-discovery fuzzers carry
# 'enumeration'/'brute-force' tags that resolve to recon/crack, but their campaign role is fuzz;
# a secret scanner runs in recon; wpscan is a scanner not a password cracker.
OVERRIDE = {
    "ffuf": "fuzz", "feroxbuster": "fuzz", "gobuster": "fuzz", "dirb": "fuzz",
    "wpscan": "scan", "netexec": "postex", "trufflehog": "recon", "arjun": "recon",
    "kerbrute": "recon", "gowitness": "recon", "cewl": "recon",
}


def _tags(fm_text):
    m = re.search(r"^tags:\s*\[(.*?)\]", fm_text, re.M)
    if not m:
        return []
    return [t.strip().strip('"').strip("'").lower() for t in m.group(1).split(",") if t.strip()]


def _phase_for(tags):
    tset = set(tags)
    for phase, keys in PRIORITY:
        if tset & keys:
            return phase
    return FALLBACK


def main(argv):
    write = "--write" in argv
    changed = 0
    for fn in sorted(os.listdir(TOOLS)):
        if not fn.endswith(".md"):
            continue
        p = os.path.join(TOOLS, fn)
        text = open(p, encoding="utf-8", errors="ignore").read()
        m = re.match(r"(---\s*\n)(.*?)(\n---\s*\n)", text, re.S)
        if not m:
            print("SKIP (no frontmatter): " + fn)
            continue
        fm = m.group(2)
        slug = fn[:-3]
        existing = re.search(r"^phase:\s*(\S+)", fm, re.M)
        if existing and existing.group(1) in VOCAB and slug not in OVERRIDE:
            print("have  %-28s %s" % (fn, existing.group(1)))
            continue
        phase = OVERRIDE.get(slug) or _phase_for(_tags(fm))
        if existing:                                    # normalise an out-of-vocab / overridden value
            print("fix   %-28s %-8s (was %s)" % (fn, phase, existing.group(1)))
            if write:
                text = re.sub(r"^phase:\s*\S+", "phase: " + phase, text, count=1, flags=re.M)
                open(p, "w", encoding="utf-8").write(text)
                changed += 1
            continue
        print("set   %-28s %-8s tags=%s" % (fn, phase, _tags(fm)))
        if write:
            new_fm = fm.rstrip("\n") + "\nphase: " + phase
            text = text[:m.start(2)] + new_fm + text[m.end(2):]
            open(p, "w", encoding="utf-8").write(text)
            changed += 1
    print("\n%s: %d pages %s" % ("WROTE" if write else "DRY-RUN", changed,
                                 "updated" if write else "would change (pass --write)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
