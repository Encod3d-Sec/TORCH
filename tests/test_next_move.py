"""Tests for next_move.suggest heuristics across engagement types."""
import _engagement
import next_move


def _scope(**kw):
    base = {"in_scope": [], "out_of_scope": [], "allowed_tooling": [], "roe": [],
            "no_bruteforce": False, "no_dos": False, "passive_only": False}
    base.update(kw)
    return base


def _patch(monkeypatch, etype, state, loot, paths, scope=None, killchain=None):
    monkeypatch.setattr(_engagement, "active_dir", lambda: "/fake")
    monkeypatch.setattr(_engagement, "engagement_type", lambda d=None: etype)
    monkeypatch.setattr(_engagement, "scope", lambda d=None: scope or _scope())
    tables = {"state.md": state, "loot.md": loot, "Killchain.md": paths,
              "Approach.md": killchain or []}
    monkeypatch.setattr(_engagement, "_parse_table",
                        lambda p: tables.get(p.rsplit("/", 1)[-1], []))


def test_empty(monkeypatch):
    _patch(monkeypatch, "pentest", [], [], [])
    assert next_move.suggest() == ["No open moves. Recon more hosts or capture a cred."]


def test_open_path_ranks_first(monkeypatch):
    _patch(monkeypatch, "pentest", [], [],
           [{"path": "a->b", "status": "open", "next-move": "go"}])
    out = next_move.suggest()
    assert out[0].startswith("[now] a->b")


def test_dead_path_excluded(monkeypatch):
    _patch(monkeypatch, "pentest", [], [],
           [{"path": "x", "status": "dead", "next-move": "n"}])
    assert next_move.suggest() == ["No open moves. Recon more hosts or capture a cred."]


def test_pentest_spray_excludes_reused_host(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "PC1", "access": "port-open"}, {"host": "PC2", "access": "creds"}],
           [{"cred": "u:p", "status": "active", "reused-where": "PC2"}], [])
    # PC2 is already sprayed -> it must not be a spray target (it legitimately still
    # appears as an in-scope per-asset coverage [gap] target, which is a different move).
    spray = [s for s in next_move.suggest(limit=99) if "spray" in s]
    assert spray == ["[now] spray u:p at PC1"]


def test_pentest_relay_blocked_without_cred(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "H", "access": "port-open", "signing": "False"}], [], [])
    out = " ".join(next_move.suggest())
    assert "relay blocked" in out


def test_acquisition_capped_at_three(monkeypatch):
    state = [{"host": f"H{i}", "access": "port-open", "services": "smb"} for i in range(6)]
    _patch(monkeypatch, "pentest", state, [], [])
    acq = [s for s in next_move.suggest(limit=99) if s.startswith("[acquire]")]
    assert len(acq) == 3


def test_bugbounty_uses_test_verb(monkeypatch):
    _patch(monkeypatch, "bugbounty",
           [{"asset": "api.x", "access": "tested", "tech": "Node"}], [],
           [{"path": "ssrf->ato", "status": "open", "next-move": "oob"}])
    out = next_move.suggest()
    assert any(s.startswith("[now] ssrf->ato") for s in out)
    assert any("test: api.x" in s for s in out)


def test_ctf_uses_foothold_verb(monkeypatch):
    _patch(monkeypatch, "ctf",
           [{"target": "box1", "service": "http", "access": "port-open"}], [], [])
    out = " ".join(next_move.suggest())
    assert "get foothold: box1" in out


def test_bugbounty_no_pentest_relay(monkeypatch):
    # signing column absent for bugbounty; relay logic must not fire
    _patch(monkeypatch, "bugbounty", [{"asset": "a", "access": "recon"}], [], [])
    out = " ".join(next_move.suggest())
    assert "relay" not in out


def test_out_of_scope_host_filtered(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "ws1", "access": "port-open", "services": "smb"},
            {"host": "prod-db", "access": "port-open", "services": "smb"}],
           [], [], scope=_scope(out_of_scope=["prod-db"]))
    out = " ".join(next_move.suggest())
    assert "ws1" in out and "prod-db" not in out


def test_no_bruteforce_suppresses_spray(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "PC1", "access": "port-open", "signing": "False"}],
           [{"cred": "u:p", "status": "active", "reused-where": ""}], [],
           scope=_scope(no_bruteforce=True))
    out = " ".join(next_move.suggest())
    assert "spray" not in out and "relay-ready" not in out


def test_fingerprint_emits_test_move(monkeypatch):
    _patch(monkeypatch, "bugbounty",
           [{"asset": "api.x", "tech": "GraphQL Apollo", "access": "tested"}], [], [])
    out = next_move.suggest()
    assert any(s.startswith("[test] api.x") and "introspection" in s
               and "hunt-injection" in s for s in out)


def test_suggest_json_parity_and_shape(monkeypatch):
    _patch(monkeypatch, "pentest", [], [],
           [{"path": "a->b", "status": "open", "next-move": "go"}])
    sj = next_move.suggest_json()
    assert sj and isinstance(sj[0], dict)
    assert set(sj[0]) == {"score", "tag", "text"}
    # parity: the string contract reflects the same ranked tuples
    assert next_move.suggest()[0] == f"[{sj[0]['tag']}] {sj[0]['text']}"


def test_suggest_json_empty_no_engagement(monkeypatch):
    monkeypatch.setattr(_engagement, "active_dir", lambda: None)
    assert next_move.suggest_json() == [] and next_move.suggest() == []


def test_fingerprint_priority_survives_truncation(monkeypatch):
    # one asset matching 6 fingerprints incl a prio-3 (ofbiz) + prio-1s (ldap/swagger).
    # tests[:4] must keep the critical and drop the info-level ones (the flat-85 bug).
    _patch(monkeypatch, "bugbounty",
           [{"asset": "host.x", "tech": "ldap swagger jenkins graphql redis ofbiz",
             "access": "tested"}], [], [])
    out = " ".join(next_move.suggest(limit=99))
    assert "CVE-2023-51467" in out          # prio-3 ofbiz survived the cap
    assert "anon bind" not in out           # prio-1 ldap truncated below it


def test_fingerprint_low_confidence_flagged(monkeypatch):
    # tech named only in free-text notes -> low-confidence flag, not a structured match
    _patch(monkeypatch, "bugbounty",
           [{"asset": "host.y", "notes": "banner suggests graphql", "access": "tested"}], [], [])
    out = " ".join(next_move.suggest())
    assert "low-confidence" in out


def test_fingerprint_suppressed_when_passive(monkeypatch):
    _patch(monkeypatch, "bugbounty",
           [{"asset": "api.x", "tech": "GraphQL", "access": "tested"}], [], [],
           scope=_scope(passive_only=True))
    out = " ".join(next_move.suggest())
    assert "[test]" not in out


def test_fingerprint_respects_scope(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "prod-db", "services": "mssql", "access": "port-open"}], [], [],
           scope=_scope(out_of_scope=["prod-db"]))
    out = " ".join(next_move.suggest())
    assert "prod-db" not in out


def test_passive_only_suppresses_acquisition(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "PC1", "access": "port-open", "services": "smb"}], [],
           [{"path": "recon->lead", "status": "open", "next-move": "watch"}],
           scope=_scope(passive_only=True))
    out = next_move.suggest()
    assert any(s.startswith("[now] recon->lead") for s in out)
    assert not any(s.startswith("[acquire]") for s in out)


# --- coverage-gap floor moves -------------------------------------------------

def test_coverage_gap_surfaces_untested(monkeypatch):
    # in-scope asset, no Approach.md 4a rows -> untested base classes enter the
    # shortlist as [gap] moves, highest-severity (list order) first.
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [])
    gaps = [s for s in next_move.suggest(limit=99) if s.startswith("[gap]")]
    assert gaps, "expected coverage-gap moves"
    assert "rce" in gaps[0]            # rce is first in the reordered bugbounty checklist


def test_coverage_gap_excludes_tested(monkeypatch):
    # Approach.md 4a rows credit a class as tested when its status cell is done.
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [],
           killchain=[{"asset": "api.x", "vuln class": "rce", "status": "[x]"},
                      {"asset": "api.x", "vuln class": "sqli", "status": "[x]"}])
    gaps = " ".join(s for s in next_move.suggest(limit=99) if s.startswith("[gap]"))
    assert "rce" not in gaps and "sqli" not in gaps   # tested -> not a gap
    assert "ssrf" in gaps                              # still untested


def test_coverage_gap_capped_at_five(monkeypatch):
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [])
    gaps = [s for s in next_move.suggest(limit=99) if s.startswith("[gap]")]
    assert len(gaps) <= 5


def test_coverage_gap_ranks_below_concrete_moves(monkeypatch):
    # a gap floor move must never outrank an open path
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [],
           [{"path": "p", "status": "open", "next-move": "go"}])
    out = next_move.suggest(limit=99)
    assert out[0].startswith("[now]")
    now_i = next(i for i, s in enumerate(out) if s.startswith("[now]"))
    gap_i = next(i for i, s in enumerate(out) if s.startswith("[gap]"))
    assert now_i < gap_i


def test_coverage_gap_suppressed_when_passive(monkeypatch):
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [],
           scope=_scope(passive_only=True))
    assert not any(s.startswith("[gap]") for s in next_move.suggest(limit=99))


def test_coverage_gap_none_without_assets(monkeypatch):
    # no in-scope assets -> no gap moves (breadth is per-target, not free-floating)
    _patch(monkeypatch, "bugbounty", [], [], [])
    assert not any(s.startswith("[gap]") for s in next_move.suggest(limit=99))


def test_coverage_gap_per_asset_not_flattened(monkeypatch):
    # THE completeness property: rce tested on A only must NOT suppress the rce gap on B.
    # (single-asset test_coverage_gap_excludes_tested cannot catch the old flatten bug.)
    _patch(monkeypatch, "bugbounty",
           [{"asset": "a.x", "access": "recon"}, {"asset": "b.x", "access": "recon"}],
           [], [],
           killchain=[{"asset": "a.x", "vuln class": "rce", "status": "[x]"}])
    gaps = [s for s in next_move.suggest(limit=99) if s.startswith("[gap]")]
    a_gaps = " ".join(g for g in gaps if "a.x:" in g)
    b_gaps = " ".join(g for g in gaps if "b.x:" in g)
    assert "rce" not in a_gaps       # tested on A -> not a gap on A
    assert "rce" in b_gaps           # untested on B -> STILL a gap on B


def test_fingerprint_suppressed_after_tested(monkeypatch):
    # graphql marked [x] on api.x in Approach 4a -> its re-ranked [test] move disappears.
    _patch(monkeypatch, "bugbounty",
           [{"asset": "api.x", "tech": "GraphQL Apollo", "access": "tested"}], [], [],
           killchain=[{"asset": "api.x", "vuln class": "graphql", "status": "[x]"}])
    out = next_move.suggest(limit=99)
    assert not any(s.startswith("[test] api.x") and "introspection" in s for s in out)


def test_allowlist_gate_drops_unlisted_host(monkeypatch):
    # 1.2: with a non-empty in-scope allowlist, a host in neither list is dropped.
    _patch(monkeypatch, "pentest",
           [{"host": "app.example.com", "access": "port-open", "services": "smb"},
            {"host": "stray.other.com", "access": "port-open", "services": "smb"}],
           [], [], scope=_scope(in_scope=["app.example.com"]))
    out = " ".join(next_move.suggest(limit=99))
    assert "app.example.com" in out
    assert "stray.other.com" not in out


def test_allowlist_cidr_matches_host_by_ip_column(monkeypatch):
    # HIGH regression: a pentest host tracked by HOSTNAME whose ip falls inside an in-scope
    # CIDR must NOT be dropped. The gate checks every identifier column (host AND ip), not
    # just the displayed hostname (a hostname never matches a CIDR). This is the standard
    # internal-pentest scoping; the old single-entity gate silenced the entire ranker.
    _patch(monkeypatch, "pentest",
           [{"host": "dc01", "ip": "10.10.10.5", "access": "port-open", "services": "smb ldap"}],
           [], [], scope=_scope(in_scope=["10.10.10.0/24"]))
    out = next_move.suggest(limit=99)
    assert out != ["No open moves. Recon more hosts or capture a cred."]
    assert any("dc01" in s for s in out)   # in-scope via its ip column, still ranked


def test_tested_credit_matches_across_url_host_drift(monkeypatch):
    # MED regression: an Approach 4a cell written as a URL must still credit a state asset
    # tracked by bare host (host-normalized join). Otherwise scheme/path drift orphans the
    # credit and a cleared class wrongly regresses to a [gap].
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [],
           killchain=[{"asset": "https://api.x/graphql", "vuln class": "rce", "status": "[x]"}])
    gaps = " ".join(s for s in next_move.suggest(limit=99) if s.startswith("[gap]"))
    assert "rce" not in gaps


_EDGE = {
    "ssrf": {"then": [{"move": "hit metadata from {asset}", "to_class": "rce", "to_phase": 4,
                       "gain": 2, "cost": "cheap", "likelihood": 0.5, "gate": "oob",
                       "skill": "hunt-ssrf"}]},
}


def _chain_patch(monkeypatch, findings, scope=None, killchain=None):
    _patch(monkeypatch, "bugbounty", [], [], [], scope=scope, killchain=killchain)
    monkeypatch.setattr(next_move, "CHAINS", _EDGE)
    monkeypatch.setattr(_engagement, "confirmed_findings", lambda d: findings)


def test_chain_candidate_emitted_and_scored(monkeypatch):
    _chain_patch(monkeypatch, [{"class": "ssrf", "asset": "web01", "severity": "HIGH",
                                "status": "confirmed"}])
    sj = next_move.suggest_json(limit=99)
    chain = [c for c in sj if c["tag"] == "chain"]
    assert len(chain) == 1
    assert chain[0]["score"] == 96                      # 80 + 6*2 + round(8*0.5) - 0
    assert "web01: ssrf->rce" in chain[0]["text"]
    assert "OOB-gate: confirm callback first" in chain[0]["text"]
    assert "[hunt-ssrf]" in chain[0]["text"]


def test_chain_suppressed_when_dest_class_tested(monkeypatch):
    # Approach 4a marks rce [x] on web01 -> the ssrf->rce pivot is already covered there
    _chain_patch(monkeypatch,
                 [{"class": "ssrf", "asset": "web01", "severity": "HIGH", "status": "confirmed"}],
                 killchain=[{"asset": "web01", "vuln class": "rce", "status": "[x]"}])
    assert not any(c["tag"] == "chain" for c in next_move.suggest_json(limit=99))


def test_chain_out_of_scope_asset_filtered(monkeypatch):
    _chain_patch(monkeypatch,
                 [{"class": "ssrf", "asset": "web01", "severity": "HIGH", "status": "confirmed"}],
                 scope=_scope(out_of_scope=["web01"]))
    assert not any(c["tag"] == "chain" for c in next_move.suggest_json(limit=99))


def test_chain_no_edge_no_move(monkeypatch):
    _chain_patch(monkeypatch, [{"class": "xxe", "asset": "web01", "severity": "LOW",
                                "status": "confirmed"}])
    assert not any(c["tag"] == "chain" for c in next_move.suggest_json(limit=99))
