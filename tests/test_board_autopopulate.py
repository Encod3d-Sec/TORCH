"""Board auto-populate: state.md fills itself from recon so `campaign.py board` just works.

Covers the three pieces: the shared state.md row-appender (_engagement.append_state_asset), the
recon hook's nmap/rustscan parser (_extract_assets), and campaign's scope-host seeder
(_scope_hosts). This is the fix for the drift where an empty state.md dead-ended `board`, which
made the board easy to bypass.
"""
import importlib.util
import os
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, relpath):
    os.environ.setdefault("CLAUDEBRAIN_VAULT", ROOT)
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


STATE_TEMPLATE = """# State - test

| target | service | port | foothold | access | flag | notes |
|--------|---------|------|----------|--------|------|-------|
"""

SCOPE_TEMPLATE = """# Scope

## In scope
- 10.9.9.9
- shop.example.thm   some annotation

## Out of scope
-
"""


def test_append_and_dedup():
    E = _load("eng", "skills/hooks/_engagement.py")
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "state.md"), "w").write(STATE_TEMPLATE)
        assert E.append_state_asset(d, "10.1.1.1", service="http", port="80")
        assert E.append_state_asset(d, "10.1.1.1", service="ssh", port="22")
        # dup target+port -> no add
        assert not E.append_state_asset(d, "10.1.1.1", service="http", port="80")
        # bare seed skipped because the target already has rows
        assert not E.append_state_asset(d, "10.1.1.1")
        rows = E._parse_table(os.path.join(d, "state.md"))
        ports = sorted(r["port"] for r in rows)
        assert ports == ["22", "80"], ports
        assert all(r["access"] == "port-open" for r in rows)


def test_seed_then_real_ports():
    E = _load("eng2", "skills/hooks/_engagement.py")
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "state.md"), "w").write(STATE_TEMPLATE)
        assert E.append_state_asset(d, "box.example.thm")            # bare seed
        assert E.append_state_asset(d, "box.example.thm", service="http", port="80")  # real port still adds
        rows = E._parse_table(os.path.join(d, "state.md"))
        assert len(rows) == 2


def test_extract_assets_nmap_and_rustscan():
    rc = _load("rc", "skills/hooks/recon-capture.py")
    nmap = "Nmap scan report for 10.10.10.10\n22/tcp open  ssh     OpenSSH 8.2p1\n80/tcp open  http    Apache httpd 2.4.41\n"
    got = rc._extract_assets("bash /root/vm.sh 'nmap -sCV 10.10.10.10'", nmap)
    assert ("10.10.10.10", "22", "ssh") in got and ("10.10.10.10", "80", "http") in got
    rust = "10.10.10.10 -> [22,80,8080]"
    gr = rc._extract_assets("rustscan -a 10.10.10.10 -g", rust)
    assert {p for _, p, _ in gr} == {"22", "80", "8080"}
    # a non-scan command with an incidental 'open' line must NOT extract
    assert rc._extract_assets("cat notes.txt", "80/tcp open http") == []


def test_scope_hosts():
    camp = _load("camp", "scripts/campaign.py")
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "scope.md"), "w").write(SCOPE_TEMPLATE)
        hosts = camp._scope_hosts(d)
        assert hosts == ["10.9.9.9", "shop.example.thm"], hosts
