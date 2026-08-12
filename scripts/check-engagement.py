#!/usr/bin/env python3
"""check-engagement.py [<eng>] [--type bb|pt|ctf] [--repair]

Verify an engagement's declared type is consistent everywhere, and that its `state.md` table
schema matches that type.

Why this exists: a bug-bounty engagement carried `engagement_type: pentest`. That one value
selects the Approach template, the self-heal set, the playbook `approach` filter and the
coverage-classes list -- so the whole campaign was ranked against the 9-class pentest checklist
instead of the 27-class bugbounty one. It also gave that engagement the pentest `state.md`
schema (host/ip/os/services/signing/winrm/smbv1) on a web target, where recon output
(url, endpoint, param, tech) has NO column to land in.

  --type    the authoritative type. Given -> everything is compared and repaired to it.
            Omitted -> state.md's own value is the reference and only internal consistency
            is checked (which cannot catch a wrong-but-consistent declaration).
  --repair  rewrite mismatched `engagement_type:` values, and swap the `state.md` header row
            when that table is still empty. A populated table is never rewritten -- that needs
            a data migration, so it is reported instead.

Exit 0 = consistent (or fully repaired), 2 = mismatches remain.
"""
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))

TYPES = ("bugbounty", "pentest", "ctf")
ALIASES = {"bb": "bugbounty", "bugbounty": "bugbounty",
           "pt": "pentest", "pentest": "pentest", "ctf": "ctf"}


def _fm_type(path):
    """The `engagement_type:` value in a file's frontmatter, or None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except Exception:
        return None
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    t = re.search(r"^engagement_type:\s*['\"]?([\w-]+)", m.group(1), re.M)
    return t.group(1) if t else None


def _header_row(path):
    """First markdown table header row in a file, normalised, or None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("| ") and "---" not in line:
                    cells = [c.strip().lower() for c in line.strip().strip("|").split("|")]
                    return [c for c in cells if c]
    except Exception:
        pass
    return None


def _table_is_empty(path):
    """True when the state table has a header but no data rows (safe to re-schema)."""
    seen_sep = False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("|") and "---" in line:
                    seen_sep = True
                    continue
                if seen_sep and line.startswith("|") and line.strip().strip("|").strip():
                    return False
    except Exception:
        return False
    return True


def _resolve(arg):
    if arg:
        p = arg if os.path.isdir(arg) else os.path.join(VAULT, "targets", arg)
        return p if os.path.isdir(p) else None
    try:
        import _engagement
        return _engagement.active_dir()
    except Exception:
        return None


def main(argv):
    repair = "--repair" in argv
    want = None
    if "--type" in argv:
        i = argv.index("--type")
        want = ALIASES.get(argv[i + 1].lower()) if i + 1 < len(argv) else None
        if not want:
            print("check-engagement: --type must be one of bb|pt|ctf", file=sys.stderr)
            return 2
        del argv[i:i + 2]
    positional = [a for a in argv if not a.startswith("--")]
    d = _resolve(positional[0] if positional else None)
    if not d:
        print("check-engagement: no engagement (pass a name or set targets/active.md)",
              file=sys.stderr)
        return 2

    name = os.path.basename(d.rstrip(os.sep))
    state = os.path.join(d, "state.md")
    declared = _fm_type(state)
    ref = want or declared
    if not ref:
        print(f"check-engagement: {name}: state.md has no engagement_type and no --type given",
              file=sys.stderr)
        return 2
    if ref not in TYPES:
        print(f"check-engagement: {name}: unknown engagement_type '{ref}'", file=sys.stderr)
        return 2

    problems, fixed = [], []

    # 1. every sibling that declares a type must agree with the reference
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".md"):
            continue
        p = os.path.join(d, fn)
        got = _fm_type(p)
        if got is None or got == ref:
            continue
        if repair:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            text = re.sub(r"^engagement_type:.*$", f"engagement_type: {ref}", text,
                          count=1, flags=re.M)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
            fixed.append(f"{fn}: engagement_type {got} -> {ref}")
        else:
            problems.append(f"{fn}: engagement_type is '{got}', expected '{ref}'")

    # 2. state.md table schema must match the type's template
    tmpl = os.path.join(VAULT, "setup", "templates", ref, "state.md")
    want_hdr, got_hdr = _header_row(tmpl), _header_row(state)
    if want_hdr and got_hdr and want_hdr != got_hdr:
        detail = (f"state.md schema is {got_hdr}, expected {want_hdr} for '{ref}'")
        if repair and _table_is_empty(state):
            with open(state, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            bar = "|" + "|".join("-" * (len(c) + 2) for c in want_hdr) + "|"
            text = re.sub(r"^\|.*\n\|[-| ]+\|\s*$",
                          "| " + " | ".join(want_hdr) + " |\n" + bar,
                          text, count=1, flags=re.M)
            with open(state, "w", encoding="utf-8") as fh:
                fh.write(text)
            fixed.append(f"state.md: schema -> {ref} (table was empty)")
        else:
            problems.append(detail + ("  [table has rows: needs a data migration]"
                                      if repair else ""))

    for f in fixed:
        print(f"repaired  {name}/{f}")
    for p in problems:
        print(f"MISMATCH  {name}/{p}", file=sys.stderr)
    if not problems and not fixed:
        print(f"check-engagement: {name} consistent ({ref})")
    return 2 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
