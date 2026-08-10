#!/usr/bin/env python3
"""playbook-tools-backfill.py [--write]

Add a `tools` array to playbook.json fingerprints that have `skills` but no `tools`, so G8 routes a
real tool instead of falling back to a phase default. LINE-BASED so the file's one-object-per-line
formatting, inline comments and regex escaping are preserved byte-for-byte (a json.load/dump round
trip would destroy them).

Conservative skill -> tools map: only tools that have a wiki/tools/ page, and only where the tool is
genuinely the right automation for that class. Entries whose class has no clean automated tool are
left alone (the driver's phase-default covers them). Dry-run by default; --write applies.
"""
import json
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PB = os.path.join(VAULT, "scripts", "playbook.json")
TOOLS_DIR = os.path.join(VAULT, "wiki", "tools")

# skill -> the automated tool(s) to run for it. Only tools with a wiki/tools page (verified below).
SKILL_TOOLS = {
    "hunt-sqli": ["sqlmap"],
    "hunt-xss": ["dalfox"],
    "hunt-secrets": ["trufflehog"],
    "hunt-ad": ["netexec"],
    "hunt-cloud": ["scoutsuite"],
    "hunt-api": ["nuclei"],          # introspection/misconfig sweep before manual BOLA work
    "hunt-vpn": ["nuclei"],
    "hunt-federation": ["jwt_tool"],
}


def _tool_pages():
    return {f[:-3] for f in os.listdir(TOOLS_DIR) if f.endswith(".md")}


def main(argv):
    write = "--write" in argv
    pages = _tool_pages()
    # sanity: every tool we would add must have a page
    bad = {t for tools in SKILL_TOOLS.values() for t in tools if t not in pages}
    if bad:
        print("ERROR: mapped tools with no wiki/tools page: %s" % ", ".join(sorted(bad)),
              file=sys.stderr)
        return 1

    lines = open(PB, encoding="utf-8").readlines()
    changed = 0
    for i, line in enumerate(lines):
        s = line.strip()
        # a fingerprint entry line looks like:  "<pattern>": { ... },
        if not (s.startswith('"') and '"skills"' in s and '"tools"' not in s):
            continue
        # which skills does this entry name?
        m = re.search(r'"skills"\s*:\s*\[([^\]]*)\]', s)
        if not m:
            continue
        skills = [x.strip().strip('"') for x in m.group(1).split(",") if x.strip()]
        tools = []
        for sk in skills:
            for t in SKILL_TOOLS.get(sk, []):
                if t not in tools:
                    tools.append(t)
        if not tools:
            continue
        # insert  "tools": [...]  before the closing brace of this one-line object
        toolstr = '"tools": [%s]' % ", ".join('"%s"' % t for t in tools)
        # find the last '}' on the line and insert before it (with a comma separator)
        idx = line.rstrip().rfind("}")
        if idx < 0:
            continue
        head = line[:idx].rstrip()
        sep = ", " if not head.endswith("{") else " "
        newline = head + sep + toolstr + " " + line[idx:]
        label = s.split('"')[1][:40]
        print("%s  %-42s +tools %s" % ("set " if write else "would", label, tools))
        if write:
            lines[i] = newline
        changed += 1

    if write:
        open(PB, "w", encoding="utf-8").write("".join(lines))
        json.load(open(PB, encoding="utf-8"))   # validate it still parses
        print("\nWROTE %d entries; playbook.json still valid JSON." % changed)
    else:
        print("\nDRY-RUN: %d entries would change (pass --write)." % changed)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
