import os
HERE = os.path.dirname(os.path.abspath(__file__)); VAULT = os.path.dirname(HERE)


def test_killchain_templates_have_confirmed_chain_header():
    for t in ("ctf", "pentest", "bugbounty"):
        txt = open(os.path.join(VAULT, "setup", "templates", t, "Killchain.md")).read()
        assert "## Confirmed chain so far" in txt


def test_decisions_template_has_decision_log():
    txt = open(os.path.join(VAULT, "setup", "templates", "_decisions.md")).read()
    assert "## Decision log" in txt
