#!/usr/bin/env python3
"""campaign.py - deterministic driver for the bb/pt/ctf workflow skills.

The routing mandate that hooks and skill-prose failed to enforce lives here instead, as tool
output printed fresh every turn. The three workflow skills are thin: run `next`, do exactly what
it prints, `done`, repeat.

  init  --type bb|pt|ctf     validate scope + envelope, write .campaign.json
  board                      (re)generate killchain 4a rows from state.md x playbook.json
  next                       print the one required-action block for the current row
  note  <row> --arsenal S    fill a row's arsenal cell (G1 release), verifying the card
  done  <row> ...            close/kill/park a row, enforcing G2/G3
  pass-done                  advance the pass when its exit condition is met
  ledger                     budget + command + drift ledger

Reuses skills/hooks/_engagement (table parse, frontmatter, active dir, class vocab) and
scripts/playbook.json + triggers.json + chains.json for routing. It sequences; it does not judge.

Fail open, except the gates: a malformed file warns and is skipped; only the init validations and
G1/G2/G3 refuse (exit 2). No code path emits a question (G7).
"""
import argparse
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
import _engagement as E  # noqa: E402

CFG = os.path.join(HERE, "campaign.json")
BOARD_COLS = ["id", "asset", "vuln class", "arsenal", "skill", "tool", "status", "poc", "poc_kind"]
ENVELOPE_KEYS = ["autonomy", "enum_cap", "write_policy", "oob_allowed", "scanners",
                 "budget_requests", "rate_per_host", "target_severity"]
PASS_LABELS = ["osint", "crawl", "fingerprint", "cve-sweep", "board",
               "low-hanging", "class-hunt", "wall-break", "fuzz", "chain"]
# Blind classes whose confirmation is an out-of-band callback (Task 20c). Serving one without a
# live listener produces silence that reads as "not vulnerable" - a confident false negative.
OOB_CLASSES = {"ssrf", "ssti", "xxe", "rce", "deserialization", "blind-sqli", "cmdi"}
# Classes whose proof needs two accounts (hunt-core's two-account rule). Serving one without a
# second identity produces a claim that can't distinguish "cross-user access" from "own data".
TWO_ACCOUNT_CLASSES = {"idor", "bola", "business-logic"}
# Network-touching binaries: the pre-filter for drift (Task 12a) and G6. 46% of Bash calls
# touch no network, so counting all of them as drift would be noise.
NET_BINS = {"curl", "wget", "nmap", "rustscan", "dnsx", "httpx", "nc", "ncat", "ffuf",
            "feroxbuster", "gobuster", "sqlmap", "nuclei", "nxc", "netexec", "katana",
            "gau", "subfinder", "amass", "nikto", "wpscan", "dig", "openssl", "hydra"}
TYPE_ALIASES = {"bb": "bb", "bugbounty": "bb", "pt": "pt", "pentest": "pt", "ctf": "ctf"}
TYPE_TO_APPROACH = {"bb": "bugbounty", "pt": "pentest", "ctf": "ctf"}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "exceptional": 5}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _now_dt():
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt):
    """Force a tz on a naive datetime (assume UTC) so deadline math never mixes naive+aware."""
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def _load_cfg():
    return json.load(open(CFG, encoding="utf-8"))


def _resolve(name):
    if name:
        p = name if os.path.isdir(name) else os.path.join(E.TARGETS, name)
        return p if os.path.isdir(p) else None
    return E.active_dir()


def _state_path(d):
    return os.path.join(d, ".campaign.json")


def _load_state(d):
    try:
        return json.load(open(_state_path(d), encoding="utf-8"))
    except Exception:
        return None


def _save_state(d, st):
    with open(_state_path(d), "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=1)


def _warn(msg):
    print("campaign: " + msg, file=sys.stderr)


def _die(msg, code=2):
    _warn(msg)
    sys.exit(code)


# --------------------------------------------------------------------------- scope / envelope

def _scope_fm(d):
    p = os.path.join(d, "scope.md")
    try:
        return E._frontmatter(open(p, encoding="utf-8", errors="ignore").read())
    except Exception:
        return {}


def _budget(d):
    """budget_requests as an int, tolerating commas / junk / absence (fail-open, never crash)."""
    v = str(_scope_fm(d).get("budget_requests") or "0").replace(",", "").strip()
    m = re.match(r"\d+", v)
    return int(m.group(0)) if m else 0


def _flag(d, key, default):
    """A boolean envelope flag, case-insensitive, honoring the absent-field default.
    _frontmatter yields raw strings, so `True`/`FALSE`/`no`/`yes` would otherwise miscompare."""
    v = _scope_fm(d).get(key)
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes", "on")


def _in_scope_nonempty(d):
    """True when scope.md's '## In scope' section has at least one bullet that is not a
    placeholder dash."""
    p = os.path.join(d, "scope.md")
    try:
        text = open(p, encoding="utf-8", errors="ignore").read()
    except Exception:
        return False
    m = re.search(r"^##\s*In scope\s*$(.*?)(^##\s|\Z)", text, re.S | re.M | re.I)
    if not m:
        return False
    for line in m.group(1).splitlines():
        s = line.strip()
        if s.startswith(("-", "*")) and s.lstrip("-* ").strip():
            return True
    return False


def _scope_hosts(d):
    """First token of each non-placeholder bullet under scope.md '## In scope' (host/IP/domain)."""
    p = os.path.join(d, "scope.md")
    try:
        text = open(p, encoding="utf-8", errors="ignore").read()
    except Exception:
        return []
    m = re.search(r"^##\s*In scope\s*$(.*?)(^##\s|\Z)", text, re.S | re.M | re.I)
    if not m:
        return []
    out = []
    for line in m.group(1).splitlines():
        s = line.strip()
        if not s.startswith(("-", "*")):
            continue
        v = s.lstrip("-* ").strip()
        if not v or v == "-":
            continue
        tok = v.split()[0].split(",")[0].strip()          # first token; drop inline annotations
        if tok and not tok.startswith(("<", "#", "(")):
            out.append(tok)
    return out


def _seed_assets_from_scope(d):
    """Ensure state.md has >=1 asset by seeding the in-scope host(s), so `board` never dead-ends on
    an empty inventory (the friction that made the board bypassable). Returns count added. A later
    nmap/rustscan run (parsed by the recon hook) adds the real per-port service rows on top."""
    n = 0
    for h in _scope_hosts(d):
        if E.append_state_asset(d, h, notes="auto: scope seed (re-run board after nmap for services)"):
            n += 1
    return n


# --------------------------------------------------------------------------- board table io

def _needs_migration(d):
    """True when killchain.md has a 4a table in the OLD schema (a `vuln class` header but no `id`
    column). Detected by the HEADER, not the rows, so an EMPTY old board is caught too - otherwise
    write_board's `| id |` regex misses it and appends a duplicate table. A fresh board from the
    current template already has the `id` header, so this only fires on pre-overhaul engagements."""
    p = os.path.join(d, "killchain.md")
    if not os.path.isfile(p):
        return False
    try:
        text = open(p, encoding="utf-8", errors="ignore").read()
    except Exception:
        return False
    # a 4a table exists (some header line names 'vuln class') but the new-schema section (id-first
    # header) is not found -> old schema, empty or not.
    has_4a = re.search(r"^\|[^\n]*\bvuln class\b[^\n]*\n", text, re.M | re.I)
    return bool(has_4a) and _board_section(text) is None


def _board_section(text):
    """(pre, header_line, sep_line, rows_text, post) for the 4a table, or None.

    The separator row is OPTIONAL and no group may cross a newline, so a hand-edited board with a
    missing/odd separator is still matched and rewritten in place rather than growing a duplicate
    table, and the blank line after the table is never swallowed into the body."""
    m = re.search(r"(^\|\s*id\s*\|[^\n]*\n)(\|[-:| ]+\|[^\n]*\n)?((?:\|[^\n]*\n?)*)", text, re.M)
    if not m:
        return None
    return text[:m.start(1)], m.group(1), m.group(2) or "", m.group(3), text[m.end():]


def read_board(d):
    """List of row dicts (lowercased keys) from killchain.md 4a. [] if none."""
    return E._parse_table(os.path.join(d, "killchain.md"))


def _fmt_row(r):
    return "| " + " | ".join(str(r.get(c, "") or "") for c in BOARD_COLS) + " |"


def write_board(d, rows):
    """Replace the 4a table body with `rows`, preserving everything else in killchain.md."""
    p = os.path.join(d, "killchain.md")
    text = open(p, encoding="utf-8", errors="ignore").read()
    sec = _board_section(text)
    header = "| " + " | ".join(BOARD_COLS) + " |\n"
    sep = "|" + "|".join("-" * (len(c) + 2) for c in BOARD_COLS) + "|\n"
    body = "".join(_fmt_row(r) + "\n" for r in rows)
    if sec:
        pre, _h, _s, _rows, post = sec
        new = pre + header + sep + body + post
    else:
        new = text.rstrip() + "\n\n### 4a. Foothold\n\n" + header + sep + body
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(new)


# --------------------------------------------------------------------------- routing

def _playbook():
    try:
        return json.load(open(os.path.join(HERE, "playbook.json"), encoding="utf-8"))["fingerprints"]
    except Exception:
        return {}


def _triggers():
    try:
        return json.load(open(os.path.join(VAULT, "skills", "hunt", "triggers.json"),
                              encoding="utf-8")).get("triggers", {})
    except Exception:
        return {}


def _chains():
    try:
        return json.load(open(os.path.join(HERE, "chains.json"), encoding="utf-8")).get("edges", {})
    except Exception:
        return {}


def _skill_for_class(cls, triggers):
    """triggers.json fallback: first vuln-type regex whose match hits the class token."""
    for pat, skill in triggers.items():
        try:
            if re.search(pat, cls, re.I):
                return skill if isinstance(skill, str) else (skill[0] if skill else "")
        except re.error:
            continue
    return ""


def _tool_for_class(cls, cfg):
    """phase_default_tools fallback when the fingerprint names no tool."""
    pdt = cfg.get("phase_default_tools", {})
    if cls in ("sqli", "idor", "graphql", "nosql"):
        return (pdt.get("param-endpoint") or ["sqlmap"])[0]
    # Known-CVE / RCE exploitation: prefer a vetted Metasploit module (msfconsole -q -x 'search ...;
    # use ...; set RHOSTS/LHOST; run -z; exit') over a hand-rolled exploit - faster, more reliable,
    # and keeps the operator on a tool instead of bespoke exploit code.
    if cls in ("rce", "cve-check", "deserialization", "cmdi", "ssti"):
        return (pdt.get("exploit") or ["msfconsole"])[0]
    return (pdt.get("web-fuzz") or ["ffuf"])[0]


_TOOL_INDEX = None
# 66/69 tool pages use `## Core usage`; the rest use `## Usage`. Priority order: a usage heading
# always beats an install heading, which is why we search by this list, not by document position
# (## Install typically precedes ## Core usage on the page).
_USAGE_HEADINGS = ("core usage", "usage", "syntax", "commands", "install the extension", "install")


def tool_index():
    """{slug: {phase, tags, invocation, page}} built from wiki/tools/*.md frontmatter + the first
    fenced command under a usage heading. Cached. Task 14: generated, never a hand-written file."""
    global _TOOL_INDEX
    if _TOOL_INDEX is not None:
        return _TOOL_INDEX
    idx = {}
    tdir = os.path.join(VAULT, "wiki", "tools")
    for fn in sorted(os.listdir(tdir)) if os.path.isdir(tdir) else []:
        if not fn.endswith(".md"):
            continue
        slug = fn[:-3]
        text = open(os.path.join(tdir, fn), encoding="utf-8", errors="ignore").read()
        fm = E._frontmatter(text)
        phase = (fm.get("phase") or "").strip()
        tags = fm.get("tags")
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.strip("[]").split(",") if t.strip()]
        inv = _first_usage_fence(text)
        idx[slug] = {"phase": phase, "tags": tags or [], "invocation": inv,
                     "page": "wiki/tools/%s.md" % slug}
    _TOOL_INDEX = idx
    return idx


def _fence_after(lines, start):
    """First non-empty line inside the first fenced block at or after index `start`, or ''."""
    for j in range(start, len(lines)):
        if lines[j].startswith("```"):
            for k in range(j + 1, len(lines)):
                if lines[k].startswith("```"):
                    return ""
                if lines[k].strip():
                    return lines[k].strip()
    return ""


def _first_usage_fence(text):
    """First fenced command under a usage heading, searched by heading PRIORITY (a usage heading
    beats an install heading even when install appears first on the page)."""
    lines = text.splitlines()
    heads = [(i, ln.strip().lower().lstrip("#").strip())
             for i, ln in enumerate(lines) if ln.startswith("#")]
    for want in _USAGE_HEADINGS:
        for i, h in heads:
            if h.startswith(want):
                cmd = _fence_after(lines, i + 1)
                if cmd:
                    return cmd
    # no usage heading matched: fall back to the first fenced block anywhere
    return _fence_after(lines, 0)


def _behaviours():
    try:
        b = json.load(open(os.path.join(HERE, "behaviours.json"), encoding="utf-8"))
        return {k: v for k, v in b.items() if not k.startswith("_")}
    except Exception:
        return {}


def derive_behavioural_rows(d):
    """(asset, class, skill, tool, requires) implied by state.md endpoint/param SEMANTICS rather
    than tech (Task 31). Fixes the board-thinness case: a /redeem endpoint or an ?id= param has no
    tech fingerprint, so the playbook path never routes it."""
    beh = _behaviours()
    out, seen = [], set()
    for r in E._parse_table(os.path.join(d, "state.md")):
        asset = (r.get("asset") or r.get("host") or r.get("target") or "").strip()
        if not asset or asset == "?":
            continue
        endp = " ".join(str(r.get(k, "")) for k in ("endpoint", "url", "notes")).lower()
        param = " ".join(str(r.get(k, "")) for k in ("param", "params")).lower()
        for cls, spec in beh.items():
            hit = any(p.lower() in endp for p in spec.get("endpoint_patterns", []))
            if not hit and param:
                hit = any(re.search(r"\b" + re.escape(p.lower()) + r"\b", param)
                          for p in spec.get("param_patterns", []))
            if not hit:
                continue
            key = (asset.lower(), cls)
            if key in seen:
                continue
            seen.add(key)
            out.append((asset, cls, spec.get("skill", ""), spec.get("tool", ""),
                        spec.get("requires", {})))
    return out


def _surface_seeds():
    try:
        s = json.load(open(os.path.join(HERE, "surface-seeds.json"), encoding="utf-8"))
        return {k: v for k, v in s.items() if not k.startswith("_")}
    except Exception:
        return {}


def derive_surface_rows(d):
    """(asset, class, skill, tool, requires) seeded by an OBSERVED SURFACE (service/port/tech) rather
    than a tech fingerprint (playbook.json) or endpoint semantics (behaviours.json). On a generic host
    both of those yield 0 rows -> empty board -> `next` has no action to return to (Observation 1);
    this third source guarantees a never-empty board by seeding high-value ENUMERATION rows off the
    surface itself. surface-seeds.json maps a surface -> 1-3 rows; a row naming an RoE flag that is set
    in scope.md (no_bruteforce/no_dos/passive_only) is skipped here so the board never carries a row
    the envelope forbids. Modeled on derive_behavioural_rows; requires is {} (read-only enum)."""
    seeds = _surface_seeds()
    out, seen = [], set()
    for r in E._parse_table(os.path.join(d, "state.md")):
        asset = (r.get("asset") or r.get("host") or r.get("target") or "").strip()
        if not asset or asset == "?":
            continue
        hay = " ".join(str(r.get(k, "")) for k in
                       ("service", "services", "port", "tech", "os", "notes")).lower()
        for _surf, spec in seeds.items():
            hit = any(re.search(r"\b" + re.escape(m.lower()) + r"\b", hay)
                      for m in spec.get("match", []))
            if not hit and spec.get("match_regex"):
                try:
                    hit = bool(re.search(spec["match_regex"], hay, re.I))
                except re.error:
                    hit = False
            if not hit:
                continue
            for row in spec.get("rows", []):
                roe = row.get("roe") or []
                if isinstance(roe, str):
                    roe = [roe]
                if any(_flag(d, f, False) for f in roe):
                    continue
                cls = row.get("class", "")
                key = (asset.lower(), cls)
                if key in seen:
                    continue
                seen.add(key)
                out.append((asset, cls, row.get("skill", ""), row.get("tool", ""), {}))
    return out


def _deadend_pairs(d):
    """{(asset_lower, class_lower)} from the Deadends.md table (G4)."""
    out = set()
    for r in E._parse_table(os.path.join(d, "Deadends.md")):
        a = (r.get("asset") or "").strip().lower()
        c = (r.get("class") or "").strip().lower()
        if a and c:
            out.add((a, c))
    return out


def derive_rows(d, approach):
    """(asset, class, skill, tool, score) tuples implied by state.md x playbook.json,
    filtered to `approach`, ranked. Reuses next_move.py's exact scoring."""
    base = E._class_vocab()
    pb = _playbook()
    triggers = _triggers()
    cfg = _load_cfg()
    # class(es) each fingerprint implies, via the same alias vocab _engagement credits with
    fp_cls, fp_meta = {}, {}
    for pat, info in pb.items():
        txt = pat + " " + " ".join(info.get("tests", [])) + " " + " ".join(info.get("skills", []))
        fp_cls[pat] = {c.lower() for c in E._match_classes(txt, base)}
        fp_meta[pat] = info
    out, seen = [], set()
    for r in E._parse_table(os.path.join(d, "state.md")):
        asset = (r.get("asset") or r.get("host") or r.get("target") or "").strip()
        if not asset or asset == "?":
            continue
        structured = " ".join(str(r.get(k, "")) for k in ("tech", "services", "service")).lower()
        freetext = " ".join(str(r.get(k, "")) for k in ("os", "notes")).lower()
        for pat, info in pb.items():
            try:
                hi = bool(re.search(pat, structured, re.I))
                lo = bool(re.search(pat, freetext, re.I))
            except re.error:
                continue
            if not (hi or lo):
                continue
            try:
                prio = max(1, min(3, int(info.get("prio", 2))))
            except (TypeError, ValueError):
                prio = 2
            score = 80 + prio * 5
            appr = info.get("approach")
            if appr:
                score += 6 if approach in appr else -4
            skills = info.get("skills") or []
            tools = info.get("tools") or []
            implied = fp_cls.get(pat) or set()
            for cls in implied:
                key = (asset.lower(), cls)
                if key in seen:
                    continue
                seen.add(key)
                # Route skill PER CLASS: a fingerprint implying >1 class (e.g. ssti+rce) must not
                # send every class to skills[0]. Prefer the class-specific hunt (triggers), fall
                # back to the fingerprint's own first skill.
                sk = _skill_for_class(cls, triggers) or (skills[0] if skills else "")
                tool = tools[0] if tools else _tool_for_class(cls, cfg)
                out.append((asset, cls, sk, tool, score))
    out.sort(key=lambda t: -t[4])
    return out


# --------------------------------------------------------------------------- telemetry read

def _events(d):
    p = os.path.join(d, ".events.jsonl")
    if not os.path.isfile(p):
        return None                       # missing -> G2 fails open
    rows = []
    for line in open(p, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def _skill_fired_since(d, skill, since_iso):
    """(fired, oracle_present). oracle_present=False means .events.jsonl is missing (G2 warns,
    allows). fired=True means a Skill(<skill>) event exists dated at/after since_iso."""
    ev = _events(d)
    if ev is None:
        return False, False
    for e in ev:
        if e.get("kind") == "tool" and e.get("tool") == "Skill" and e.get("skill") == skill:
            if not since_iso or (e.get("ts") or "") >= since_iso:
                return True, True
    return False, True


def _req_count(d):
    """Request-issuing tool invocations in .events.jsonl (the budget unit - NOT literal HTTP
    requests; a single ffuf/nuclei/Intruder run issues thousands). Counts network-touching Bash
    events AND the non-Bash request paths this framework mandates - Burp (mcp__burp__send*,
    send_to_intruder), WebFetch, chrome-devtools navigations - which the last audit found were
    invisible, so a Burp-first campaign blew its budget silently. The driver runs between the
    agent's actions and cannot count requests itself; the telemetry hook that logs every call can."""
    ev = _events(d) or []
    n = 0
    for e in ev:
        if e.get("kind") != "tool":
            continue
        tool = e.get("tool") or ""
        if tool == "Bash" and any(b in NET_BINS for b in (e.get("bins") or [])):
            n += 1
        elif tool == "WebFetch" or "burp" in tool.lower() or tool.startswith(
                "mcp__plugin_chrome-devtools"):
            n += 1
    return n


def _row_effort(d, st, rid):
    """Tool calls since the row went [~] (Task 12c anti-grind). Uses row_started[rid], stamped by
    `note`/`done` when a row becomes active; falls back to row_created."""
    since = (st.get("row_started", {}) or {}).get(rid) or (st.get("row_created", {}) or {}).get(rid)
    if not since:
        return 0
    ev = _events(d) or []
    return sum(1 for e in ev if e.get("kind") == "tool"
               and e.get("tool") in ("Bash", "Skill") and (e.get("ts") or "") >= since)


def _drift(d, st):
    """Network-touching binaries that ran but were never emitted by `next` (Task 12a)."""
    ev = _events(d) or []
    emitted = set(st.get("emitted_bins") or [])
    n = 0
    for e in ev:
        if e.get("kind") != "tool" or e.get("tool") != "Bash":
            continue
        for b in (e.get("bins") or []):
            if b in NET_BINS and b not in emitted:
                n += 1
                break
    return n


# --------------------------------------------------------------------------- status helpers

_ST = {"todo": "[ ]", "doing": "[~]", "done": "[x]", "na": "[-]", "dead": "[!]", "park": "[?]"}


def _status_of(r):
    return (r.get("status") or "").strip() or "[ ]"


def _counts(rows):
    c = {"[x]": 0, "[!]": 0, "[?]": 0, "open": 0}
    for r in rows:
        s = _status_of(r)
        if s in ("[x]", "[!]", "[?]"):
            c[s] += 1
        else:
            c["open"] += 1
    return c


def _row_by_id(rows, rid):
    for r in rows:
        if (r.get("id") or "").strip() == rid:
            return r
    return None


# =========================================================================== commands

def cmd_init(a):
    d = _resolve(a.eng)
    if not d:
        _die("no engagement (pass a name or set targets/active.md)")
    t = TYPE_ALIASES.get((a.type or "").lower())
    if not t:
        _die("--type must be one of bb|pt|ctf")
    # Task 3 validator with --repair (the driver owns the repair decision, Task 30)
    approach = TYPE_TO_APPROACH[t]
    try:
        import subprocess
        subprocess.run([sys.executable, os.path.join(HERE, "check-engagement.py"),
                        d, "--type", t, "--repair"], check=False)
    except Exception as e:
        _warn("check-engagement skipped: %s" % e)
    # envelope
    fm = _scope_fm(d)
    missing = [k for k in ENVELOPE_KEYS if k not in fm or fm.get(k) in ("", None)]
    # target_severity may legitimately be blank only if the programme has no tiers; still require key
    if "target_severity" in missing and "target_severity" in fm:
        missing.remove("target_severity")
    if not _in_scope_nonempty(d):
        missing.append("(## In scope block is empty)")
    if missing:
        _die("scope.md is missing required envelope keys: " + ", ".join(missing))
    # RESUME, don't clobber: init is also the "validate + repair on re-open" entry point, so an
    # existing in-progress campaign keeps its pass/cursor/lenses/paused state. Only the type is
    # reconciled (it was just repaired above). A fresh engagement gets a fresh state.
    existing = _load_state(d)
    if existing and existing.get("pass", 0) >= 0 and os.path.isfile(_state_path(d)) \
            and (existing.get("pass", 0) > 0 or existing.get("row_created")):
        existing["type"], existing["approach"] = t, approach
        _save_state(d, existing)
        print("campaign init: resumed %s at pass %d (existing progress kept)."
              % (os.path.basename(d), existing.get("pass", 0)))
        return 0
    # req_count and per-row effort are DERIVED from .events.jsonl telemetry, not stored (the driver
    # runs between the agent's actions and cannot self-count); emitted_bins feeds the drift diff.
    st = {"type": t, "approach": approach, "pass": 0, "asset_cursor": None,
          "dry_streak": 0, "dry_rounds": 0, "lenses_used": [],
          "row_created": {}, "row_started": {}, "emitted_bins": [], "mode": "normal",
          "started_at": _now()}
    _save_state(d, st)
    de = os.path.join(d, "Deadends.md")
    sz = os.path.getsize(de) if os.path.isfile(de) else 0
    print("campaign init: %s type=%s. Deadends.md is %d bytes (read it before selecting a host)."
          % (os.path.basename(d), t, sz))
    if t == "ctf":
        print("reminder: set `flags_expected` in state.md from the room's answer boxes "
              "(base+user+root...) so the close-out flag-sweep reflex can verify completeness.")
    print("next: campaign.py board  (after passes 1-3 have fed state.md)")
    return 0


def cmd_board(a):
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign (run: campaign.py init --type ...)")
    if _needs_migration(d):
        _die("this engagement's board is the pre-overhaul format - run: campaign.py migrate")
    def _assets():
        return [r for r in E._parse_table(os.path.join(d, "state.md"))
                if (r.get("asset") or r.get("host") or r.get("target") or "").strip() not in ("", "?")]
    assets = _assets()
    if not assets:
        # auto-populate from recon instead of dead-ending: seed the in-scope host(s) so the board
        # always builds (the recon hook fills in per-port service rows from nmap/rustscan on top).
        seeded = _seed_assets_from_scope(d)
        assets = _assets()
        if seeded:
            print("campaign board: auto-seeded %d asset(s) from scope.md (re-run board after nmap "
                  "to add per-port services)." % seeded)
    if not assets:
        _die("state.md has no assets and scope.md '## In scope' is empty - add the target host to "
             "scope.md, then re-run board")
    # board is the pass-4 deliverable and hands off to driving, so honor the pass-1 read gate here
    # too (a board built while source is unread skips read-whole). Only in the pre-board window;
    # a mid-campaign re-board (pass>=5) is unaffected.
    if st.get("pass", 0) < 5:
        unread = _unread_artifacts(d)
        if unread:
            _die("cannot build the board with %d unread source artifact(s) in source-ledger.md "
                 "(%s) - read each WHOLE first [Task 19]" % (len(unread), ", ".join(unread[:5])))
    existing = read_board(d)
    have = {((r.get("asset") or "").lower(), (r.get("vuln class") or "").lower()) for r in existing}
    dead = _deadend_pairs(d)
    maxid = 0
    for r in existing:
        m = re.match(r"4a:(\d+)", (r.get("id") or "").strip())
        if m:
            maxid = max(maxid, int(m.group(1)))
    added = 0
    parked = 0
    rows = list(existing)
    write_policy = str(_scope_fm(d).get("write_policy") or "none").strip()

    def _add(asset, cls, skill, tool, requires=None):
        nonlocal added, parked, maxid
        key = (asset.lower(), cls)
        if key in have or key in dead:
            return
        have.add(key)
        maxid += 1
        rid = "4a:%d" % maxid
        status = "[ ]"
        # Task 31c: a row whose behaviour requires a write the envelope forbids is born parked,
        # not attempted-and-failed-silently. A race is a write by definition.
        req = requires or {}
        wp_ok = req.get("write_policy")
        if wp_ok and write_policy not in wp_ok:
            status = "[?]"
            parked += 1
            dec = os.path.join(d, "decisions.md")
            if not os.path.isfile(dec):
                _append_line(dec, "# Decisions - park queue\n\n| # | row | question | kind | asked | answer |\n|---|-----|----------|------|-------|--------|")
            _append_line(dec, "| - | %s | %s x %s needs write_policy %s (envelope=%s) | out-of-envelope | %s | |"
                         % (rid, asset, cls, "/".join(wp_ok), write_policy, _now()[:10]))
        rows.append({"id": rid, "asset": asset, "vuln class": cls, "arsenal": "",
                     "skill": skill, "tool": tool, "status": status, "poc": "", "poc_kind": ""})
        st.setdefault("row_created", {})[rid] = _now()
        added += 1

    for asset, cls, skill, tool, _score in derive_rows(d, st["approach"]):
        _add(asset, cls, skill, tool)
    for asset, cls, skill, tool, requires in derive_behavioural_rows(d):
        _add(asset, cls, skill, tool, requires)
    # Third source (surface-seed): guarantees a never-empty board on generic tech, so `next` always
    # has a real action. Runs LAST so its enum rows never displace a tech/endpoint row (_add dedups
    # against `have`); RoE-forbidden seeds are already dropped inside derive_surface_rows.
    for asset, cls, skill, tool, requires in derive_surface_rows(d):
        _add(asset, cls, skill, tool, requires)
    write_board(d, rows)
    # Building the board IS the pass-4 deliverable and hands off to driving; advance to pass 5 so
    # `next` drives the board instead of repeating pre-board recon guidance.
    st["pass"] = max(st.get("pass", 0), 5)
    _save_state(d, st)
    print("campaign board: +%d rows (%d total, %d parked by envelope, %d suppressed by Deadends)."
          % (added, len(rows), parked, len(dead)))
    return 0


def _coverage_classes(approach):
    """The per-type vuln-class checklist (coverage-classes.json), used by the off-playbook lens."""
    try:
        cc = json.load(open(os.path.join(HERE, "coverage-classes.json"), encoding="utf-8"))
        return [c.lower() for c in (cc.get(approach) or [])]
    except Exception:
        return []


def _found_target(d, st):
    """True when a finding at/above the envelope's target_severity has been recorded."""
    target = str(_scope_fm(d).get("target_severity") or "").strip().lower()
    if not target or target not in SEV_RANK:
        return False
    return st.get("max_sev_rank", -1) >= SEV_RANK[target]


def _board_exhausted(rows):
    return not any(_status_of(r) in ("[ ]", "[~]") for r in rows)


def _oob_ready(d):
    """True when oob.md registers at least one live listener token (Task 20c)."""
    for r in E._parse_table(os.path.join(d, "oob.md")):
        if (r.get("token") or "").strip() and (r.get("status") or "").lower() in ("waiting", "hit"):
            return True
    return False


def _account_count(d):
    """Number of usable account identities in identities.md (Task 20b two-account rule)."""
    n = 0
    for r in E._parse_table(os.path.join(d, "identities.md")):
        t = (r.get("type") or "").lower()
        who = (r.get("who/scope") or r.get("who") or "").strip()
        if "account" in t and who:
            n += 1
    return n


def _lens_rows(d, st, lens, have):
    """(asset, class, skill, tool) rows a reframe lens contributes, deduped against `have` (every
    pair ever on the board - rows are never deleted, so the board IS the full history). Two lenses
    generate rows directly; the narrative lenses emit no rows here and rely on the agent having fed
    new state, which board() then picks up - a dry lens correctly yields nothing."""
    triggers = _triggers()
    cfg = _load_cfg()
    assets = [(r.get("asset") or r.get("host") or r.get("target") or "").strip()
              for r in E._parse_table(os.path.join(d, "state.md"))]
    assets = [a for a in assets if a and a != "?"]
    out = []
    if lens == "off-playbook":
        onboard = {}
        for a, c in have:
            onboard.setdefault(a, set()).add(c)
        for a in assets:
            for cls in _coverage_classes(st["approach"]):
                if cls in onboard.get(a.lower(), set()):
                    continue
                out.append((a, cls, _skill_for_class(cls, triggers), _tool_for_class(cls, cfg)))
    elif lens == "chain-first":
        edges = _chains()
        # pivot from every confirmed class already on the board
        for r in read_board(d):
            if _status_of(r) != "[x]":
                continue
            for e in edges.get((r.get("vuln class") or "").lower(), {}).get("then", []):
                to = (e.get("to_class") or "").lower()
                asset = (r.get("asset") or "").strip()
                if to and asset:
                    out.append((asset, to, _skill_for_class(to, triggers),
                                _tool_for_class(to, cfg)))
    # second-order / deprioritised / historical / version-recheck: no direct generation; the agent
    # feeds new state, board() picks it up. Returning [] means "dry unless state changed."
    return out


def _host_of(asset):
    """Bare host of an asset string (strip scheme/path/port), for ban matching. Case-insensitive
    scheme strip so HTTPS://Host also normalises."""
    return re.sub(r"^[a-z]+://", "", (asset or "").strip(), flags=re.I).split("/")[0].split(":")[0].lower()


def _open_assets(rows, paused=()):
    """Assets (board order, deduped) that still have a [ ]/[~] row, excluding paused hosts (Task
    20d ban detection - a banned host measures the ban, not the app, so we skip it)."""
    pset = {p.lower() for p in (paused or ())}
    seen, out = set(), []
    for r in rows:
        a = (r.get("asset") or "").strip()
        if _host_of(a) in pset:
            continue
        if _status_of(r) in ("[ ]", "[~]") and a and a not in seen:
            seen.add(a)
            out.append(a)
    return out


def _cursor_asset(rows, st):
    """Depth-first (G5), STICKY: finish the asset already in progress before moving to the next.
    A [~] row's asset wins; else the stored asset_cursor if it still has an open row; else the
    first open asset in board order. Score-sorting + appended behavioural rows interleave one
    asset's rows, so without stickiness the cursor would jump assets and break G5."""
    paused = (st or {}).get("paused_hosts", [])
    for r in rows:
        if _status_of(r) == "[~]" and _host_of(r.get("asset")) not in {p.lower() for p in paused}:
            return (r.get("asset") or "").strip()
    open_a = _open_assets(rows, paused)
    cur = (st or {}).get("asset_cursor")
    if cur and cur in open_a:
        return cur
    return open_a[0] if open_a else None


def _active_row(rows, asset):
    """The [~] row FOR THIS ASSET if any (one-open-at-a-time), else the top open row for `asset`.
    Restricting the [~] check to `asset` keeps it consistent with the sticky cursor."""
    for r in rows:
        if _status_of(r) == "[~]" and (r.get("asset") or "").strip() == asset:
            return r
    for r in rows:
        if (r.get("asset") or "").strip() == asset and _status_of(r) == "[ ]":
            return r
    return None


# Classes worth chasing when the clock is short: high-impact / target-severity-reachable. Used only
# to rank OPEN rows under a deadline crunch, never to gate.
HIGH_VALUE_CLASSES = {"rce", "sqli", "ssrf", "auth", "idor", "bola", "deserialization", "xxe",
                      "ssti", "cmdi", "file-upload", "business-logic", "default-creds", "lfi"}


def _deadline_info(d, st):
    """(remaining_min, total_min, frac_left) from scope.md `deadline`, or None when unset/bad.
    `deadline` is either an integer count of MINUTES from started_at, or an absolute ISO timestamp.
    Fail-open: any parse problem returns None so the clock simply does not exist."""
    raw = str(_scope_fm(d).get("deadline") or "").strip()
    if not raw:
        return None
    try:
        start = _aware(datetime.datetime.fromisoformat(st.get("started_at")))
    except Exception:
        return None
    if re.fullmatch(r"\d+", raw):
        total = float(raw)
        end = start + datetime.timedelta(minutes=total)
    else:
        try:
            end = _aware(datetime.datetime.fromisoformat(raw))
        except Exception:
            return None
        total = (end - start).total_seconds() / 60.0
    remaining = (end - _now_dt()).total_seconds() / 60.0
    frac = (remaining / total) if total > 0 else 0.0
    return remaining, total, frac


def _row_value(r):
    """Rough worth of an OPEN row under clock crunch: high-impact class + progress already sunk.
    ponytail: a 3-signal heuristic, not a persisted score - board rows never stored one."""
    v = 2 if (r.get("vuln class") or "").strip().lower() in HIGH_VALUE_CLASSES else 1
    if _status_of(r) == "[~]":        # already in progress -> finishing it is cheapest
        v += 2
    if (r.get("arsenal") or "").strip():  # arsenal loaded -> one step from a close
        v += 1
    return v


def _crunch_serve(d, st, rows, dl):
    """Under <25% of the wall-clock budget, return (asset, row) for the single highest-value open
    row across the WHOLE board (depth-first abandoned) and print the crunch banner; else None.
    Rows are re-ranked, never deleted - low-value ones are flagged for the agent to --dead, so the
    board stays a full audit trail. Fail-open: no deadline / no open rows -> None (cursor drives)."""
    if dl is None or dl[2] >= 0.25:
        return None
    paused = {p.lower() for p in st.get("paused_hosts", [])}
    open_rows = [r for r in rows if _status_of(r) in ("[ ]", "[~]")
                 and _host_of(r.get("asset")) not in paused]
    if not open_rows:
        return None
    open_rows.sort(key=lambda r: -_row_value(r))
    print("CLOCK CRUNCH: %.0fm of %.0fm left (<25%%) - depth-first OFF, chasing highest value:"
          % (dl[0], dl[1]))
    for r in open_rows[:3]:
        print("  %s  %s x %s   value %d" % (r.get("id"), (r.get("asset") or "").strip(),
                                            r.get("vuln class"), _row_value(r)))
    extra = len(open_rows) - 3
    if extra > 0:
        print("  ... %d lower-value open row(s) - `done <id> --dead 'clock'` unless quick." % extra)
    top = open_rows[0]
    st["asset_cursor"] = (top.get("asset") or "").strip()
    _save_state(d, st)
    return (top.get("asset") or "").strip(), top


def cmd_next(a):
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign (run: campaign.py init --type ...)")
    if _needs_migration(d):
        _die("this engagement's board is the pre-overhaul format - run: campaign.py migrate "
             "(a silent misread of an old board is how a whole campaign ran the wrong checklist)")
    cfg = _load_cfg()
    tconf = cfg[st["type"]]
    rows = read_board(d)
    counts = _counts(rows)
    budget = _budget(d)
    req = _req_count(d)
    drift = _drift(d, st)
    ceiling = tconf["row_effort_ceiling"]

    if budget and req >= budget:
        st["mode"] = "report-only"
        _save_state(d, st)

    dl = _deadline_info(d, st)
    clock = ""
    if dl is not None:
        clock = "   clock %.0fm/%.0fm left" % (dl[0], dl[1]) + (" [CRUNCH]" if dl[2] < 0.25 else "")
    header = ("PASS %d/9  %s      rows %d[x] %d[!] %d[?] %d open   req %s/%s   drift %d%s"
              % (st["pass"], PASS_LABELS[min(st["pass"], 9)], counts["[x]"], counts["[!]"],
                 counts["[?]"], counts["open"], req, budget or "-", drift, clock))
    print(header)
    if st.get("paused_hosts"):
        print("PAUSED (banned/rate-walled, rows skipped): %s" % ", ".join(st["paused_hosts"]))

    if st.get("mode") == "report-only":
        print("MODE report-only (budget spent): finish write-ups only.")
        print("REQUIRED, in order:")
        for i, s in enumerate(tconf["closeout"], 1):
            print("  %d. Skill(%s)" % (i, s))
        return 0

    # Passes 0-4 are pre-board recon: feed state.md, then build the board. Only from pass 5 on does
    # the board drive (and an exhausted board reframes). Without this an empty board at pass 0 would
    # be read as "exhausted" and dump reframe rows onto nothing.
    if st["pass"] < 5:
        return _pre_board_next(d, st, tconf, rows)

    if _board_exhausted(rows):
        return _reframe_or_closeout(d, st, rows, tconf)
    # Wall-clock crunch (deadline envelope): under 25% of the budget left, abandon depth-first and
    # serve the single highest-value open row across the board. Reuses `dl` from the header.
    crunch = _crunch_serve(d, st, rows, dl)
    if crunch:
        asset, row = crunch
    else:
        asset = _cursor_asset(rows, st)
        if asset is None:
            # Board is NOT exhausted (checked above) yet no asset is servable -> every open row is on
            # a paused host. That is a ban wall, not real exhaustion: do NOT reframe/close-out (which
            # would abandon unexhausted work). Wait for a resume.
            print("all remaining open rows are on PAUSED hosts (%s) - resume one to continue:"
                  % ", ".join(st.get("paused_hosts", [])))
            print("  campaign.py pause-host <host> --resume")
            return 0
        st["asset_cursor"] = asset
        _save_state(d, st)
        row = _active_row(rows, asset)
    aset_rows = [r for r in rows if (r.get("asset") or "").strip() == asset]
    closed = sum(1 for r in aset_rows if _status_of(r) in ("[x]", "[!]", "[?]"))
    print("ASSET     %s  (%d/%d rows closed, depth-first)" % (asset, closed, len(aset_rows)))
    if not row:
        print("no open row for %s -> pass-done." % asset)
        return 0

    rid = (row.get("id") or "").strip()
    # start the effort clock the first time this row is served (Task 12c anti-grind)
    if rid and rid not in (st.get("row_started") or {}):
        st.setdefault("row_started", {})[rid] = _now()
        _save_state(d, st)
    effort = _row_effort(d, st, rid)
    print("ROW       %s  %s x %s        (%d/%d effort)"
          % (rid, row.get("asset"), row.get("vuln class"), effort, ceiling))
    win = (st.get("footholds") or {}).get(asset)
    eng = os.path.basename(os.path.normpath(d))
    if win:
        print("FOOTHOLD  session live in tmux window '%s' -> operator can: tmux attach -t %s"
              % (win, eng))
    print("")
    print("REQUIRED, in order:")

    if effort >= ceiling:
        print("  effort ceiling reached -> resolve this row:")
        print("  - campaign.py done %s --dead <reason>   (or --park <question>)" % rid)
        return 0

    n = 1
    if not (row.get("arsenal") or "").strip():
        surface = (row.get("vuln class") or "").strip()
        print("  %d. Skill(wiki-arsenal) %s        [G1: arsenal cell empty -> exploit "
              "actions withheld]" % (n, surface))
        return 0
    rowcls = (row.get("vuln class") or "").strip().lower()
    # Two-account readiness (Task 20b): an IDOR/BOLA proof needs a second identity to tell
    # cross-user access from own-data. Guide registering one before serving the exploit.
    if rowcls in TWO_ACCOUNT_CLASSES and _account_count(d) < 2:
        print("  %d. register a SECOND test account in identities.md (type=account) "
              "[20b: %s needs two identities to prove cross-user access]" % (n, rowcls))
        print("     a one-account result cannot distinguish cross-tenant access from your own data.")
        return 0
    # OOB readiness (Task 20c): a blind class needs a live listener or its silence is a false
    # negative. If OOB is forbidden by the envelope the row cannot be proven -> park; if allowed
    # but no listener is up, set one up first (withheld like G1).
    if rowcls in OOB_CLASSES and not _oob_ready(d):
        if not _flag(d, "oob_allowed", True):
            print("  blind class + oob_allowed=false -> this row cannot be proven; parking it:")
            print("  - campaign.py done %s --park 'blind %s, OOB disabled by envelope'"
                  % (rid, row.get("vuln class")))
            return 0
        print("  %d. start an OOB listener and register the token in oob.md   [20c: blind "
              "class, no live callback -> exploit withheld]" % n)
        print("     e.g. interactsh-client -v  ; add its domain as a `waiting` row in oob.md")
        return 0
    fired, oracle = _skill_fired_since(d, row.get("skill"),
                                       st.get("row_created", {}).get(rid, st.get("started_at")))
    if row.get("skill") and not fired:
        note = "" if oracle else " (telemetry file absent - G2 fails open)"
        print("  %d. Skill(%s)              [G2: skill unfired in .events.jsonl%s]"
              % (n, row.get("skill"), note))
        n += 1
    tool = (row.get("tool") or "").strip()
    if tool:
        inv = tool_index().get(tool, {}).get("invocation") or (tool + " <target>")
        if win:
            # post-foothold: keep the persistent session + operator visibility (route through the
            # known driver primitive, which fixes the drift-guard's post-foothold blind spot).
            print("  %d. run: bash scripts/vm-rsh.sh --win %s %s '%s'   [post-foothold: persistent "
                  "session; G8]" % (n, win, eng, inv))
        else:
            print("  %d. run: %s          [G8: tool-first]" % (n, inv))
        st.setdefault("emitted_bins", [])
        if tool not in st["emitted_bins"]:
            st["emitted_bins"].append(tool)
        n += 1
    print("  %d. capture.sh req <request>   (load-bearing exploit reqs -> Skill(hunt-burp) "
          "if Burp reachable)" % n)
    if not (row.get("poc") or "").strip():
        print("CANNOT CLOSE: no evidence for %s    [G3]" % rid)
    _save_state(d, st)
    return 0


def _unread_artifacts(d):
    """source-ledger.md rows whose `read` cell is not yes/y/x (Task 19d)."""
    out = []
    for r in E._parse_table(os.path.join(d, "source-ledger.md")):
        art = (r.get("artifact") or "").strip()
        rd = (r.get("read") or "").strip().lower()
        if art and rd not in ("yes", "y", "x", "[x]", "done"):
            out.append(art)
    return out


def _pre_board_next(d, st, tconf, rows):
    """Passes 0-4: guide recon that feeds state.md, then build the board. The board does not drive
    yet (it may be empty), so this never serves a row or reframes."""
    p = st["pass"]
    recon = ", ".join(tconf.get("recon_tools", []))
    osint_on = tconf.get("osint", True)
    guidance = {
        0: ("OSINT / Wayback - old endpoints, leftover paths, leaked creds. Feed finds into state.md."
            if osint_on else "OSINT is OFF for this type - skip (pass-done). Invoke with 'osint' to enable."),
        1: ("Crawl every in-scope host (%s). Inventory every JS bundle / .js.map / handler / inline "
            "script into source-ledger.md, then READ each WHOLE (source-map -> drop vendor -> "
            "beautify -> read) and flip its `read` cell to yes; never grep-as-read. Write one "
            "state.md row per discovered asset (url/endpoint/param/tech). %d artifact(s) unread."
            % (recon, len(_unread_artifacts(d)))),
        2: "Fingerprint exact versions into each state.md row's tech column; pull vendor advisories.",
        3: "CVE / n-day sweep: searchsploit per exact version; record confirmed CVEs as findings.",
        4: ("board built (%d rows) -> campaign.py pass-done to start working it" % len(rows))
           if rows else "Build the board: campaign.py board  (4a rows from state.md x playbook + behaviours).",
    }
    print("PRE-BOARD pass %d/4 (%s)" % (p, PASS_LABELS[min(p, 9)]))
    print("REQUIRED:")
    print("  - " + guidance.get(p, "advance: campaign.py pass-done"))
    if p < 4:
        print("  then: campaign.py pass-done")
    assets = [r for r in E._parse_table(os.path.join(d, "state.md"))
              if (r.get("asset") or r.get("host") or r.get("target") or "").strip() not in ("", "?")]
    print("state.md assets so far: %d" % len(assets))
    return 0


def _closeout(d, st, tconf, why):
    st["mode"] = "done"
    _save_state(d, st)
    print("CAMPAIGN COMPLETE (%s). Close-out chain:" % why)
    for i, s in enumerate(tconf["closeout"], 1):
        print("  %d. Skill(%s)" % (i, s))
    return 0


def _reframe_or_closeout(d, st, rows, tconf):
    """Board exhausted (Task 21/33). Reframe while budget remains and no target-severity finding
    exists; otherwise hand off to close-out. Two consecutive zero-new-row rounds terminate."""
    budget = _budget(d)
    if budget and _req_count(d) >= budget:
        return _closeout(d, st, tconf, "budget spent")
    if _found_target(d, st):
        return _closeout(d, st, tconf, "target-severity finding confirmed")
    lenses = _load_cfg().get("reframe_lenses", [])
    used = st.get("lenses_used", [])
    if st.get("dry_rounds", 0) >= 2 or len(used) >= len(lenses):
        return _closeout(d, st, tconf, "reframe exhausted (2 dry rounds)")

    lens = lenses[len(used)]
    have = {((r.get("asset") or "").lower(), (r.get("vuln class") or "").lower()) for r in rows}
    dead = _deadend_pairs(d)
    maxid = max([int(re.match(r"4a:(\d+)", (r.get("id") or "").strip()).group(1))
                 for r in rows if re.match(r"4a:(\d+)", (r.get("id") or "").strip())] or [0])
    added = 0
    newrows = list(rows)
    for asset, cls, skill, tool in _lens_rows(d, st, lens, have):
        key = (asset.lower(), cls)
        if key in have or key in dead:
            continue
        have.add(key)
        maxid += 1
        rid = "4a:%d" % maxid
        newrows.append({"id": rid, "asset": asset, "vuln class": cls, "arsenal": "",
                        "skill": skill, "tool": tool, "status": "[ ]", "poc": "", "poc_kind": ""})
        st.setdefault("row_created", {})[rid] = _now()
        added += 1
    write_board(d, newrows)
    st.setdefault("lenses_used", []).append(lens)
    st["dry_rounds"] = 0 if added else st.get("dry_rounds", 0) + 1
    st["pass"] = 5
    _save_state(d, st)
    _append_line(os.path.join(d, "killchain.md"),
                 "<!-- reframe lens '%s': +%d rows (dry_rounds=%d) -->" % (lens, added, st["dry_rounds"]))
    print("REFRAME lens '%s': +%d new rows (dry_rounds=%d). Run `next` to work them."
          % (lens, added, st["dry_rounds"]))
    if not added:
        print("  (this lens needs recon the driver cannot do alone - feed new state.md rows for "
              "%s, then `board`, or `next` again to advance to the next lens.)" % lens)
    return 0


def cmd_note(a):
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign")
    slug = a.arsenal
    card = os.path.join(d, "arsenal", slug + ".md")
    if not os.path.isfile(card):
        _die("arsenal card not found: arsenal/%s.md (run Skill(wiki-arsenal) first)" % slug)
    text = open(card, encoding="utf-8", errors="ignore").read()
    for sect in ("Techniques", "Payloads", "Tools", "Cheatsheets"):
        m = re.search(r"^#{1,4}\s*" + sect + r"\s*$(.*?)(^#{1,4}\s|\Z)", text, re.S | re.M | re.I)
        body = (m.group(1).strip() if m else "")
        if not body:
            _die("arsenal card %s has an empty '%s' section - one filled cell is not four "
                 "consulted areas" % (slug, sect))
    rows = read_board(d)
    row = _row_by_id(rows, a.row)
    if not row:
        _die("no such row: %s" % a.row)
    row["arsenal"] = slug
    if _status_of(row) == "[ ]":
        row["status"] = "[~]"
    write_board(d, rows)
    print("campaign note: %s arsenal=%s (G1 released; row [~])" % (a.row, slug))
    return 0


def _append_line(path, line):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line.rstrip() + "\n")


def _append_pivot_rows(d, st, asset, cls):
    """Grow the board with chains.json pivots off a just-CONFIRMED class (done --find): each edge
    becomes a real `[ ]` row (asset x to_class, the edge's skill + a class-default tool), deduped
    against every pair already on the board and against Deadends (G4). Mirrors cmd_board._add's id
    allocation. gate:oob edges are added like any other row; next() withholds their exploit until
    oob.md has a live listener (OOB_CLASSES gate) - current oob edges all target OOB classes, so no
    separate per-edge gate is needed here. Mutates st.row_created; caller saves. Returns (added,
    skipped)."""
    edges = _chains().get(cls, {}).get("then", [])
    if not edges:
        return 0, 0
    rows = read_board(d)
    have = {((r.get("asset") or "").lower(), (r.get("vuln class") or "").lower()) for r in rows}
    dead = _deadend_pairs(d)
    maxid = 0
    for r in rows:
        m = re.match(r"4a:(\d+)", (r.get("id") or "").strip())
        if m:
            maxid = max(maxid, int(m.group(1)))
    triggers = _triggers()
    cfg = _load_cfg()
    added = skipped = 0
    for e in edges:
        to = (e.get("to_class") or "").strip().lower()
        if not to:
            continue
        key = (asset.lower(), to)
        if key in have or key in dead:
            skipped += 1
            continue
        have.add(key)
        maxid += 1
        rid = "4a:%d" % maxid
        skill = (e.get("skill") or "").strip() or _skill_for_class(to, triggers)
        rows.append({"id": rid, "asset": asset, "vuln class": to, "arsenal": "",
                     "skill": skill, "tool": _tool_for_class(to, cfg),
                     "status": "[ ]", "poc": "", "poc_kind": ""})
        st.setdefault("row_created", {})[rid] = _now()
        added += 1
    if added:
        write_board(d, rows)
    return added, skipped


def _set_state_access(d, asset, win, access="foothold"):
    """Flip the state.md inventory row whose key cell == `asset` to access=`access` and note the
    tmux window. Line-based (mirrors E._parse_table's header/separator handling) so it rewrites one
    cell in place without a table library. Returns True if a row matched. Fail-soft on any IO."""
    p = os.path.join(d, "state.md")
    try:
        lines = open(p, encoding="utf-8", errors="ignore").read().split("\n")
    except Exception:
        return False
    header = None
    for i, line in enumerate(lines):
        s = line.strip()
        if not s.startswith("|"):
            if header is not None:
                break  # table ended
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue  # separator
        if header is None:
            header = [c.lower() for c in cells]
            continue
        if not cells or cells[0] != asset:
            continue
        ai = header.index("access") if "access" in header else None
        ni = header.index("notes") if "notes" in header else None
        changed = False
        if ai is not None and ai < len(cells):
            cells[ai] = access
            changed = True
        note = "tmux:%s" % win
        if ni is not None and ni < len(cells) and note not in cells[ni]:
            cells[ni] = (cells[ni] + "; " + note) if cells[ni] else note
            changed = True
        if changed:
            lines[i] = "| " + " | ".join(cells) + " |"
            open(p, "w", encoding="utf-8").write("\n".join(lines))
        return True
    return False


def _record_foothold(d, st, asset, win):
    """Mark an asset's foothold: store the tmux window in state.json and flip its state.md row to
    access=foothold. next() then routes post-ex tool commands for this asset through
    `vm-rsh --win <win>`, keeping the persistent session and operator visibility (the drift-guard's
    post-foothold blind spot). Mutates st; caller saves. Returns True if a state.md row matched."""
    if not asset or not win:
        return False
    st.setdefault("footholds", {})[asset] = win
    return _set_state_access(d, asset, win)


def cmd_foothold(a):
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign")
    asset = a.asset or st.get("asset_cursor")
    if not asset:
        _die("foothold needs an <asset> (or a cursor asset from a prior `next`)")
    matched = _record_foothold(d, st, asset, a.win)
    _save_state(d, st)
    eng = os.path.basename(os.path.normpath(d))
    print("campaign foothold: %s -> tmux window '%s'%s"
          % (asset, a.win, "" if matched else " (no state.md row matched; recorded anyway)"))
    print("  post-ex for %s now routes through: bash scripts/vm-rsh.sh --win %s %s '<cmd>'"
          % (asset, a.win, eng))
    print("  operator can: tmux attach -t %s" % eng)
    return 0


def cmd_done(a):
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign")
    rows = read_board(d)
    row = _row_by_id(rows, a.row)
    if not row:
        _die("no such row: %s" % a.row)
    modes = [m for m in (a.poc, a.dead, a.park, a.find) if m]
    if not modes:
        _die("done needs one of --poc P --kind K | --dead REASON | --park QUESTION | --find F "
             "[G3: a row never closes without evidence, a dead-end reason, or a park]")
    # G3: --find records a CONFIRMED finding, so it MUST carry evidence. Without this, `done --find`
    # closes [x] with empty poc cells AND writes a CONFIRMED row - and if its severity meets the
    # target, trips a premature close-out. Requiring --poc routes it through the --kind gate below.
    if a.find and not a.poc:
        _die("--find records a CONFIRMED finding and requires --poc P --kind K [G3]")
    cls = (row.get("vuln class") or "").strip().lower()

    if a.park:
        row["status"] = "[?]"
        write_board(d, rows)
        dec = os.path.join(d, "decisions.md")
        if not os.path.isfile(dec):
            _append_line(dec, "# Decisions - park queue\n\n| # | row | question | kind | asked | answer |\n|---|-----|----------|------|-------|--------|")
        _append_line(dec, "| - | %s | %s | out-of-envelope | %s | |" % (a.row, a.park, _now()[:10]))
        print("campaign done: %s parked [?] -> decisions.md (loop advances)" % a.row)
        return 0

    if a.dead:
        row["status"] = "[!]"
        write_board(d, rows)
        de = os.path.join(d, "Deadends.md")
        _append_line(de, "| %s | %s | %s | %s | %s | |"
                     % (row.get("asset"), cls, a.dead, "exhausted", _now()[:10]))
        st["dry_streak"] = st.get("dry_streak", 0) + 1
        _save_state(d, st)
        print("campaign done: %s dead [!] (dry_streak=%d) -> Deadends.md"
              % (a.row, st["dry_streak"]))
        return 0

    # --poc / --find both close [x] and both require evidence gates
    if a.poc:
        if not a.kind:
            _die("--poc requires --kind req|burp|web [G3]")
        if a.kind == "web" and cls not in set(_load_cfg().get("visual_evidence_classes", [])):
            _die("a 'web' render is not evidence for class '%s' - it is indistinguishable from any "
                 "visitor's screenshot. Use capture.sh req [G3]" % cls)
    # G2: the mapped skill must have fired
    fired, oracle = _skill_fired_since(d, row.get("skill"),
                                       st.get("row_created", {}).get(a.row, st.get("started_at")))
    if row.get("skill") and not fired:
        if oracle:
            _die("cannot close %s: Skill(%s) never fired since the row was created "
                 "[G2 skill-first]" % (a.row, row.get("skill")))
        _warn("G2: .events.jsonl absent, cannot verify Skill(%s) fired - allowing (fail-open)"
              % row.get("skill"))

    # G8 (Task 15): the mapped tool SHOULD have run. Warn, never refuse - a tool can be
    # genuinely unavailable (not installed, missing wordlist, barred by scope/RoE). A refusal
    # would strand the row. Skip silently when scope bars the tool class.
    tool = (row.get("tool") or "").strip()
    if tool:
        sc = _scope_fm(d)
        barred = _flag(d, "passive_only", False) or _flag(d, "no_bruteforce", False)
        ev = _events(d)
        ran = ev is not None and any(
            e.get("kind") == "tool" and tool in (e.get("bins") or []) for e in ev)
        if not ran and not barred and ev is not None:
            _warn("G8: mapped tool '%s' never appears in .events.jsonl for %s - closing anyway "
                  "(is it installed / reachable?)" % (tool, a.row))

    row["status"] = "[x]"
    if a.poc:
        row["poc"] = a.poc
        row["poc_kind"] = a.kind
    st["dry_streak"] = 0
    _save_state(d, st)
    write_board(d, rows)
    print("campaign done: %s closed [x]" % a.row)

    if getattr(a, "win", None):
        _record_foothold(d, st, (row.get("asset") or "").strip(), a.win)
        _save_state(d, st)
        eng = os.path.basename(os.path.normpath(d))
        print("foothold recorded: %s access=foothold, tmux window '%s' -> post-ex routes through "
              "vm-rsh --win %s ; operator can: tmux attach -t %s"
              % (row.get("asset"), a.win, a.win, eng))

    if a.find:
        # track the max severity found, for the reframe/close-out decision (Task 21)
        m = re.search(r"FIND-\d+-([A-Za-z]+)", a.find)
        if m:
            rank = SEV_RANK.get(m.group(1).lower())
            if rank is not None and rank > st.get("max_sev_rank", -1):
                st["max_sev_rank"] = rank
                _save_state(d, st)
        # refuter (the only subagent), then chains.json pivots -> paths.md + Vuln-index.md
        print("REFUTER (spawn one adversarial verifier before recording CONFIRMED):")
        print("  Agent: %s" % _load_cfg().get("refuter_prompt", "")[:120] + " ...")
        edges = _chains().get(cls, {}).get("then", [])
        if edges:
            pth = os.path.join(d, "paths.md")
            for e in edges:
                mv = (e.get("move") or "").replace("{asset}", row.get("asset") or "")
                _append_line(pth, "| %s->%s | 4 | open | | %s |"
                             % (cls, e.get("to_class", "?"), mv))
            # ...AND grow the board itself, so a confirmed finding turns into servable next-rows
            # instead of a note the driver never re-serves.
            addn, skipn = _append_pivot_rows(d, st, row.get("asset") or "", cls)
            _save_state(d, st)
            print("PATHS: +%d pivot row(s) -> paths.md ; BOARD: +%d pivot row(s) [ ]%s"
                  % (len(edges), addn,
                     (", %d dup/dead skipped" % skipn) if skipn else ""))
        _append_line(os.path.join(d, "Vuln-index.md"),
                     "<!-- %s | %s | %s | CONFIRMED -->" % (a.find, row.get("asset"), cls))
    return 0


def cmd_pass_done(a):
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign")
    p = st["pass"]
    rows = read_board(d)
    # Task 12d exit conditions
    if p == 1:
        # Task 19d: pass 1 (crawl/read) cannot end while any source-ledger artifact is unread.
        unread = _unread_artifacts(d)
        if unread:
            _die("pass 1 cannot end: %d source artifact(s) still `read: no` in source-ledger.md "
                 "(%s) - read each WHOLE (source-map -> drop vendor -> beautify -> read), never "
                 "grep-as-read [Task 19]" % (len(unread), ", ".join(unread[:5])))
    if p == 2:
        assets = [r for r in E._parse_table(os.path.join(d, "state.md"))
                  if (r.get("asset") or r.get("host") or r.get("target") or "").strip() not in ("", "?")]
        if not assets:
            _die("pass 2 cannot end: no asset has a state.md row yet [state-feed gate]")
    if p == 4 and not rows:
        _die("pass 4 cannot end with an empty board - run campaign.py board")
    if p >= 5:
        # per-asset: advance the cursor when its rows are resolved
        asset = st.get("asset_cursor")
        if asset:
            aset = [r for r in rows if (r.get("asset") or "").strip() == asset]
            openc = [r for r in aset if _status_of(r) in ("[ ]", "[~]")]
            if openc:
                _die("asset %s still has %d open row(s) - resolve them first [G5 depth-first]"
                     % (asset, len(openc)))
        st["pass"] = 5  # re-enter class-hunt for the next asset
        st["asset_cursor"] = None
        _save_state(d, st)
        print("campaign pass-done: asset complete, cursor advanced (re-enter pass 5)")
        return 0
    st["pass"] = p + 1
    _save_state(d, st)
    print("campaign pass-done: pass %d -> %d (%s)" % (p, st["pass"], PASS_LABELS[min(st["pass"], 9)]))
    return 0


def cmd_migrate(a):
    """Task 28: rewrite a pre-overhaul 4a board to the unified 9-column schema without touching
    findings. --unmigrate reverses it. Refuses nothing; reports and rewrites."""
    d = _resolve(a.eng)
    if not d:
        _die("no engagement")
    p = os.path.join(d, "killchain.md")
    old = E._parse_table(p)
    if a.unmigrate:
        if old and not any("id" in r for r in old):
            print("campaign migrate --unmigrate: board is already the old schema, nothing to do.")
            return 0
        cols = ["asset", "vuln class", "wiki", "payload/tool", "status", "poc"]
        out = []
        for r in old:
            out.append({"asset": r.get("asset") or r.get("host") or r.get("target") or "",
                        "vuln class": r.get("vuln class", ""), "wiki": r.get("arsenal", ""),
                        "payload/tool": r.get("tool", ""), "status": r.get("status", ""),
                        "poc": r.get("poc", "")})
        _write_generic_board(p, cols, out)
        print("campaign migrate --unmigrate: %d rows -> old 6-column schema" % len(out))
        return 0
    if old and "id" in old[0]:
        print("campaign migrate: already in the new schema (%d rows), nothing to do." % len(old))
        return 0
    rows, n = [], 0
    mismatches = []
    for r in old:
        n += 1
        asset = r.get("asset") or r.get("host") or r.get("target") or ""
        if not asset:
            mismatches.append("row %d has no asset/host/target" % n)
        rows.append({"id": "4a:%d" % n, "asset": asset, "vuln class": r.get("vuln class", ""),
                     "arsenal": r.get("wiki", ""), "skill": "", "tool": r.get("payload/tool", ""),
                     "status": r.get("status", "") or "[ ]", "poc": r.get("poc", ""), "poc_kind": ""})
    _write_generic_board(p, BOARD_COLS, rows)   # replaces the OLD table in place (matches on vuln class)
    print("campaign migrate: %d rows -> 9-column schema (findings untouched)." % len(rows))
    for m in mismatches:
        _warn("migrate: " + m)
    return 0


def _write_generic_board(path, cols, rows):
    text = open(path, encoding="utf-8", errors="ignore").read()
    header = "| " + " | ".join(cols) + " |\n"
    sep = "|" + "|".join("-" * (len(c) + 2) for c in cols) + "|\n"
    body = "".join("| " + " | ".join(str(r.get(c, "") or "") for c in cols) + " |\n" for r in rows)
    sec = _board_section(text)
    if sec:
        pre, _h, _s, _r, post = sec
        new = pre + header + sep + body + post
    else:
        new = re.sub(r"(^\|[^\n]*\bvuln class\b[^\n]*\n\|[-:\s|]+\|\s*\n)((?:\|.*\n?)*)",
                     header + sep + body, text, count=1, flags=re.M)
    open(path, "w", encoding="utf-8").write(new)


def cmd_pause_host(a):
    """Task 20d: mark a host banned/rate-walled so next stops serving its rows (it would only
    measure the ban). `--resume` clears it. Ban DETECTION is the agent's call (a 403 wall, a
    challenge page, resets); this is how it tells the driver."""
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign")
    host = _host_of(a.host)
    paused = st.setdefault("paused_hosts", [])
    if a.resume:
        st["paused_hosts"] = [h for h in paused if h.lower() != host]
        # Re-stamp the effort clock for this host's dormant [~] rows: while paused, work on OTHER
        # assets accrued into their window and would prematurely trip the effort ceiling on resume.
        rs = st.get("row_started") or {}
        for r in read_board(d):
            if _host_of(r.get("asset")) == host and _status_of(r) == "[~]":
                rs.pop((r.get("id") or "").strip(), None)
        st["row_started"] = rs
        print("campaign resume-host: %s (rows served again)" % host)
    elif host not in [h.lower() for h in paused]:
        paused.append(host)
        print("campaign pause-host: %s parked (ban/rate wall) - next will skip its rows" % host)
    _save_state(d, st)
    return 0


def _ledger_data(d, st):
    """Machine-readable driver counters for eval/learn (Task 33c). Board status counts + drift +
    reframe + budget, so the close-out retro can say where the harness fought the operator."""
    rows = read_board(d)
    counts = _counts(rows)
    budget = _budget(d)
    req = _req_count(d)
    return {
        "requests": req, "budget": budget, "over_budget": bool(budget and req >= budget),
        "drift": _drift(d, st), "mode": st.get("mode", "normal"),
        "board": {"total": len(rows), "closed": counts["[x]"], "dead": counts["[!]"],
                  "parked": counts["[?]"], "open": counts["open"]},
        "dry_streak": st.get("dry_streak", 0), "dry_rounds": st.get("dry_rounds", 0),
        "reframe_lenses_used": st.get("lenses_used", []),
        "paused_hosts": st.get("paused_hosts", []), "pass": st.get("pass", 0),
    }


def cmd_ledger(a):
    d = _resolve(a.eng)
    st = _load_state(d) if d else None
    if not d or not st:
        _die("no initialised campaign")
    data = _ledger_data(d, st)
    if getattr(a, "json", False):
        print(json.dumps(data, indent=1))
        return 0
    print("requests: %d / %s%s" % (data["requests"], data["budget"] or "-",
                                   "  [BUDGET SPENT -> report-only]" if data["over_budget"] else ""))
    print("drift:    %d network calls not emitted by next" % data["drift"])
    print("rate cap: %s req/s per host (envelope)" % (_scope_fm(d).get("rate_per_host") or "-"))
    b = data["board"]
    print("board:    %d rows (%d[x] %d[!] %d[?] %d open)"
          % (b["total"], b["closed"], b["dead"], b["parked"], b["open"]))
    print("dry_streak: %d   dry_rounds: %d   lenses_used: %s   mode: %s"
          % (data["dry_streak"], data["dry_rounds"],
             ",".join(data["reframe_lenses_used"]) or "-", data["mode"]))
    return 0


def cmd_tools(a):
    """Print the generated tool index (Task 14). --phase filters."""
    idx = tool_index()
    miss = [s for s, m in idx.items() if not m["invocation"]]
    for slug in sorted(idx):
        m = idx[slug]
        if a.phase and m["phase"] != a.phase:
            continue
        inv = m["invocation"] or "(no invocation - special-case)"
        print("%-16s %-7s %s" % (slug, m["phase"] or "?", inv[:70]))
    print("\n%d tools indexed, %d with an invocation, missing: %s"
          % (len(idx), len(idx) - len(miss), ", ".join(miss) or "none"))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="campaign.py")
    ap.add_argument("--eng", help="engagement name or path (default: targets/active.md)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init"); p.add_argument("--type", required=True); p.set_defaults(fn=cmd_init)
    sub.add_parser("board").set_defaults(fn=cmd_board)
    sub.add_parser("next").set_defaults(fn=cmd_next)
    p = sub.add_parser("note"); p.add_argument("row"); p.add_argument("--arsenal", required=True); p.set_defaults(fn=cmd_note)
    p = sub.add_parser("done")
    p.add_argument("row"); p.add_argument("--poc"); p.add_argument("--kind", choices=["req", "burp", "web"])
    p.add_argument("--find"); p.add_argument("--dead"); p.add_argument("--park")
    p.add_argument("--win", help="tmux window the foothold session landed in -> record it (post-ex routes through vm-rsh --win)")
    p.set_defaults(fn=cmd_done)
    p = sub.add_parser("foothold"); p.add_argument("asset", nargs="?"); p.add_argument("--win", required=True)
    p.set_defaults(fn=cmd_foothold)
    sub.add_parser("pass-done").set_defaults(fn=cmd_pass_done)
    p = sub.add_parser("pause-host"); p.add_argument("host"); p.add_argument("--resume", action="store_true"); p.set_defaults(fn=cmd_pause_host)
    p = sub.add_parser("ledger"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_ledger)
    p = sub.add_parser("tools"); p.add_argument("--phase"); p.set_defaults(fn=cmd_tools)
    p = sub.add_parser("migrate"); p.add_argument("--unmigrate", action="store_true"); p.set_defaults(fn=cmd_migrate)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
