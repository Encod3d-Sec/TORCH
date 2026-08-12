import os
HERE = os.path.dirname(os.path.abspath(__file__)); VAULT = os.path.dirname(HERE)
SKILL = os.path.join(VAULT, "skills", "workflow", "redteamlead", "SKILL.md")


def test_skill_exists_with_frontmatter():
    txt = open(SKILL).read()
    assert txt.startswith("---") and "name: redteamlead" in txt and "description:" in txt


def test_skill_references_the_new_schema_and_resilient_wiki():
    txt = open(SKILL).read()
    for token in ("Approach.md", "Killchain.md", "decisions.md", "scripts/wiki-query.sh",
                  "next_move.py", "targets/active.md", "model: opus", "STOP", "DECISION"):
        assert token in txt, token
    # must NOT resurrect the old names
    assert "killchain.md" not in txt and "paths.md" not in txt


def test_skill_documents_decisions_on_demand_creation():
    txt = open(SKILL).read()
    assert "ensure_optional_file" in txt
