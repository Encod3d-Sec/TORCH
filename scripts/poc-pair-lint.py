#!/usr/bin/env python3
"""poc-pair-lint.py -- report PoC evidence that is not a PAIR.

Every capture must land as BOTH `NN-slug.png` (the image) and `NN-slug-source.md` (the verbatim
request/response or source snippet). Before capture.sh paired centrally, only `mode_web` wrote the
card, so evidence completeness was mode-dependent and only surfaced at submission time -- which is
an RoE 3.1.8 rejection risk, not a tidiness issue.

Usage: poc-pair-lint.py <poc-dir> [<poc-dir>...]
Exit 1 if any unpaired file is found, 0 when clean. A missing directory is clean, not an error.
"""
import os
import sys

IMAGE_EXTS = (".png", ".jpg", ".jpeg")
CARD_SUFFIX = "-source.md"


def lint_dir(poc_dir):
    """Return [(filename, reason)] for every unpaired evidence file, sorted by filename."""
    poc_dir = str(poc_dir)
    if not os.path.isdir(poc_dir):
        return []
    names = os.listdir(poc_dir)
    stems = {n[: -len(CARD_SUFFIX)] for n in names if n.endswith(CARD_SUFFIX)}
    images = {os.path.splitext(n)[0]: n for n in names if n.lower().endswith(IMAGE_EXTS)}
    issues = []
    for stem, fname in images.items():
        if stem not in stems:
            issues.append((fname, "no source card (expected %s%s)" % (stem, CARD_SUFFIX)))
    for stem in stems:
        if stem not in images:
            issues.append((stem + CARD_SUFFIX, "no image (expected %s.png)" % stem))
    return sorted(issues)


def main(argv):
    if not argv:
        print("usage: poc-pair-lint.py <poc-dir> [<poc-dir>...]", file=sys.stderr)
        return 2
    found = 0
    for d in argv:
        for fname, reason in lint_dir(d):
            print("%s/%s: %s" % (d.rstrip("/"), fname, reason))
            found += 1
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
