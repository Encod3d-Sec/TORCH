# tests/test_new_skills.py
import os, re
import json
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

def test_triggers_route_new_skills():
    d = json.load(open(os.path.join(VAULT, "skills", "hunt", "triggers.json")))
    t = d["triggers"]
    # both regexes compile and map to the new skills
    for k in t:
        re.compile(k)
    # a value may be a str or a list (multi-skill trigger, e.g. broken access control ->
    # [hunt-idor, hunt-api]); flatten before building the set so that legitimate
    # list-valued entries don't blow up set(t.values()) with an unhashable type.
    vals = set()
    for v in t.values():
        vals.update(v) if isinstance(v, list) else vals.add(v)
    assert "metasploit" in vals and "delegate" in vals

def test_playbook_wires_metasploit_and_parses():
    d = json.load(open(os.path.join(VAULT, "scripts", "playbook.json")))
    fps = d["fingerprints"]
    hits = [k for k, v in fps.items() if "metasploit" in (v.get("skills") or [])]
    assert hits, "no fingerprint routes to metasploit"
    # not blanket-applied
    assert len(hits) < len(fps), "metasploit added to every fingerprint (should be msf-strong only)"

def test_fuzz_frontmatter():
    assert _frontmatter_ok(_skill("fuzz"))

def test_fuzz_refs_resolve():
    assert _refs_resolve(_skill("fuzz")) == []

def test_fuzz_calls_selector():
    txt = open(_skill("fuzz"), encoding="utf-8").read()
    assert "wl-pick.sh" in txt, "fuzz skill must call the deterministic selector"
