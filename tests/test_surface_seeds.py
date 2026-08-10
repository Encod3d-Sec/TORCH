#!/usr/bin/env python3
"""Self-check for derive_surface_rows: the board is never empty on generic tech, and RoE flags gate.

The failure this guards: playbook.json (tech fingerprint) and behaviours.json (endpoint semantics)
BOTH yield 0 rows on a plain Apache/SSH/FTP host, leaving an empty board and `next` with no action.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))
import campaign as C  # noqa: E402

_STATE = """---
engagement_type: ctf
---
| target | service | port | foothold | access | flag | notes |
|--------|---------|------|----------|--------|------|-------|
| box | Apache httpd 2.4.49 | 80 | | port-open | | |
| box | OpenSSH 8.2p1 | 22 | | port-open | | |
| box | vsftpd 3.0.3 | 21 | | port-open | | |
"""

_SCOPE = """---
autonomy: full
no_bruteforce: {nb}
no_dos: false
passive_only: {po}
---

## In scope
- box
"""


def _mk(nb="false", po="false"):
    d = tempfile.mkdtemp()
    open(os.path.join(d, "state.md"), "w").write(_STATE)
    open(os.path.join(d, "scope.md"), "w").write(_SCOPE.format(nb=nb, po=po))
    return d


def _pairs(d):
    return {(a, c) for a, c, _s, _t, _r in C.derive_surface_rows(d)}


def demo():
    # generic host -> never empty; web+version+ssh+ftp all seed rows
    p = _pairs(_mk())
    assert p, "generic host produced an empty surface-seed board"
    assert ("box", "content-discovery") in p
    assert ("box", "vhost-fuzz") in p
    assert ("box", "cve-check") in p          # version regex on "2.4.49" / "8.2p1" / "3.0.3"
    assert ("box", "ssh-enum") in p
    assert ("box", "ftp-enum") in p

    # no_bruteforce gates the brute-shaped rows, leaves read-only enum
    p = _pairs(_mk(nb="true"))
    assert ("box", "content-discovery") not in p
    assert ("box", "vhost-fuzz") not in p
    assert ("box", "ssh-enum") not in p
    assert ("box", "cve-check") in p          # not a brute
    assert ("box", "ftp-enum") in p

    # passive_only gates every active enum row -> back to empty (correct: nothing active allowed)
    assert not _pairs(_mk(po="true"))

    print("ok: surface-seed never-empty on generic tech, RoE flags gate")


if __name__ == "__main__":
    demo()
