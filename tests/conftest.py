"""Shared pytest fixtures. Adds the hook + script dirs to sys.path and builds an
isolated fixture vault so tests never touch real engagement data."""
import os
import shutil
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "hooks"))
sys.path.insert(0, os.path.join(REPO, "scripts"))

# Force a nonexistent VM_SH for the whole test session: recon-capture.py's live lead
# render (and loop-driver.py's drains) shell out to $VM_SH, and a real device may have
# a real /root/vm.sh configured (a real SSH bridge). Tests must never dial that out --
# this makes every hook subprocess fail open (os.path.exists(vm) is False) instantly
# instead of attempting a real network connection. A test that wants a FAKE vm.sh stub
# still works: it sets "VM_SH" explicitly in its own env dict, which always wins over
# whatever is inherited from this process-wide os.environ default.
os.environ["VM_SH"] = os.path.join(REPO, ".nonexistent-test-vm.sh")


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


@pytest.fixture
def vault(tmp_path, monkeypatch):
    """A minimal isolated vault: real templates + triggers, a pentest engagement
    with populated tables. Points _engagement at it via env + module globals."""
    root = tmp_path / "vault"
    # real framework files
    shutil.copytree(os.path.join(REPO, "setup", "templates"), root / "setup" / "templates")
    os.makedirs(root / "skills" / "hunt", exist_ok=True)
    shutil.copy(os.path.join(REPO, "skills", "hunt", "triggers.json"),
                root / "skills" / "hunt" / "triggers.json")

    eng = root / "targets" / "acme"
    _write(str(root / "targets" / "active.md"), "acme\n")
    _write(str(eng / "state.md"),
           "---\ntype: engagement-state\nengagement_type: pentest\n---\n\n# State\n\n"
           "| host | ip | os | services | signing | winrm | smbv1 | access | owned | notes |\n"
           "|------|----|----|----------|---------|-------|-------|--------|-------|-------|\n"
           "| WS1 | 10.0.0.5 | Win10 | SMB | False | open | - | port-open | no | x |\n"
           "| DC1 | 10.0.0.1 | Win2019 | - | - | - | - | none | no | filtered |\n")
    _write(str(eng / "loot.md"),
           "---\ntype: engagement-loot\nengagement_type: pentest\n---\n\n# Loot\n\n"
           "| cred | type | source | valid-where | reused-where | status |\n"
           "|------|------|--------|-------------|--------------|--------|\n")
    _write(str(eng / "Killchain.md"),
           "---\ntype: engagement-killchain\nengagement_type: pentest\n---\n\n# Paths\n\n"
           "| path | stage | status | blocker | next-move |\n"
           "|------|-------|--------|---------|-----------|\n"
           "| coerce->relay->DC | relay | open | - | relay to DC |\n"
           "| old->dead | x | dead | n/a | n/a |\n")
    _write(str(eng / "log.md"),
           "---\ntype: engagement-log\n---\n\n# Log - acme\n\nintro\n\n---\n\n"
           "## [2026-06-04] entry one\n- did a thing\n")

    # Import _engagement BEFORE setting the tmp CLAUDEBRAIN_VAULT env. A sibling test may have
    # purged _engagement from sys.modules; if the env were tmp at import time, the fresh module's
    # VAULT would be the tmp path and monkeypatch would "revert" to tmp (not the real vault),
    # leaking a bad _engagement.VAULT to every later test. Importing first captures the real VAULT.
    import _engagement
    monkeypatch.setenv("CLAUDEBRAIN_VAULT", str(root))
    monkeypatch.setattr(_engagement, "VAULT", str(root))
    monkeypatch.setattr(_engagement, "TARGETS", str(root / "targets"))
    monkeypatch.setattr(_engagement, "TEMPLATES", str(root / "setup" / "templates"))
    return root
