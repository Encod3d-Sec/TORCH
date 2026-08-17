# tests/test_new_skills.py
import os, re
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)

def _skill(name):
    return os.path.join(VAULT, "skills", "workflow", name, "SKILL.md")

def _frontmatter_ok(path):
    txt = open(path, encoding="utf-8").read()
    return txt.startswith("---") and "\nname:" in txt[:400] and "\ndescription:" in txt[:1200]

def _refs_resolve(path):
    """Every [[wiki]] and Skill(x) ref in the file resolves to an existing wiki page or skill dir."""
    txt = open(path, encoding="utf-8").read()
    missing = []
    for m in re.findall(r"\[\[([^\]|#]+)", txt):
        slug = m.strip().split("/")[-1]
        hits = []
        for root, _, files in os.walk(os.path.join(VAULT, "wiki")):
            if slug + ".md" in files:
                hits.append(root)
        if not hits:
            missing.append("[[%s]]" % m)
    for m in set(re.findall(r"Skill\(([a-z0-9-]+)\)", txt)):
        found = any(os.path.isfile(os.path.join(VAULT, "skills", sub, m, "SKILL.md"))
                    for sub in ("workflow", "hunt", "burp", ""))
        if not found:
            missing.append("Skill(%s)" % m)
    return missing

def test_delegate_frontmatter():
    assert _frontmatter_ok(_skill("delegate"))

def test_delegate_refs_resolve():
    assert _refs_resolve(_skill("delegate")) == []

def test_metasploit_frontmatter():
    assert _frontmatter_ok(_skill("metasploit"))

def test_metasploit_refs_resolve():
    assert _refs_resolve(_skill("metasploit")) == []

def test_delegate_and_metasploit_interlock_resolves():
    # now that both exist, the whole set resolves
    assert _refs_resolve(_skill("delegate")) == []
    assert _refs_resolve(_skill("metasploit")) == []
