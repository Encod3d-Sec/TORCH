import os
HERE = os.path.dirname(os.path.abspath(__file__)); VAULT = os.path.dirname(HERE)


def test_killchain_templates_have_confirmed_chain_header():
    # ctf has no Killchain.md template (pentest/bugbounty-only per the ctf scaffold trim;
    # a ctf's live chain lives in state.md's ## Chain/## Status sections instead).
    for t in ("pentest", "bugbounty"):
        txt = open(os.path.join(VAULT, "setup", "templates", t, "Killchain.md")).read()
        assert "## Confirmed chain so far" in txt
    assert not os.path.exists(os.path.join(VAULT, "setup", "templates", "ctf", "Killchain.md"))


def test_decisions_template_has_decision_log():
    txt = open(os.path.join(VAULT, "setup", "templates", "_decisions.md")).read()
    assert "## Decision log" in txt
