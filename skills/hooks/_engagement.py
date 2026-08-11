"""Shared helpers for engagement-state hooks.

Resolves the active engagement and parses its state/loot/paths markdown tables.
Everything here is best-effort and never raises to the caller: callers wrap use
in try/except, but these helpers also degrade to empty/None on any problem.
"""
import ipaddress
import json
import os
import re
from datetime import date

# Self-locate: realpath resolves the ~/.claude/vault-hooks symlink to the real
# skills/hooks dir inside whichever machine's vault. skills/hooks -> skills -> root.
# Machine-independent: works regardless of user/path/spelling on each device.
HERE = os.path.dirname(os.path.realpath(__file__))
# CLAUDEBRAIN_VAULT overrides the self-located vault root (used by tests to point
# at a fixture vault). Unset in normal use -> self-locate via the symlinked path.
VAULT = os.environ.get("CLAUDEBRAIN_VAULT") or os.path.dirname(os.path.dirname(HERE))
TARGETS = os.path.join(VAULT, "targets")
# Templates live OUTSIDE targets/ (which is git-ignored) so they ship with the
# shareable repo. Engagement instances stay private under targets/.
TEMPLATES = os.path.join(VAULT, "setup", "templates")
STATE_FILES = ("state.md", "loot.md", "paths.md", "killchain.md")
TYPES = ("pentest", "bugbounty", "ctf")
# entity identifier columns by engagement type. Defined once here; next_move and
# coverage both import it so the mapping cannot drift between the two analyzers.
ENTITY_KEY = {"pentest": ("host", "ip"), "ctf": ("target",), "bugbounty": ("asset", "url")}

# Per-engagement-type heal set. state/loot/paths/killchain (STATE_FILES) come from the
# type's own template dir and are healed for every type. The shared type-agnostic files
# split into a common core (every type) and a pentest/bugbounty-only extension
# (Vuln-index/oob). CTF rooms never use the severity/OOB machinery (dead across every
# THM room), so ctf heals only the core; those two become opt-in via
# ensure_optional_file() (see below) or new-engagement.sh --with-oob. Per-asset test
# coverage now lives in the killchain.md 4a table (killchain.md is in STATE_FILES).
SHARED_CORE = (("log.md", "_log.md"), ("scope.md", "_scope.md"),
               ("walkthrough.md", "_walkthrough.md"),
               ("Deadends.md", "_deadends.md"),
               ("eval.md", "_eval.md"))
SHARED_FULL = (("Vuln-index.md", "_vuln-index.md"),
               ("oob.md", "_oob.md"))
# Standard dirs scaffolded for every type. poc/ = curated exploit/PoC/flag shots,
# ingest/ = raw tool output. Vulns/ is intentionally absent: it is created lazily on
# the first FIND (pentest/bugbounty), never at init.
STATE_DIRS = ("ingest", "poc")


def _heal_shared_set(etype):
    """Shared (dest, templatefile) pairs to heal for an engagement type. ctf gets the
    lean core only; pentest/bugbounty get core + the Vuln-index/oob machinery."""
    return SHARED_CORE if etype == "ctf" else SHARED_CORE + SHARED_FULL


# Opt-in shared files a ctf engagement omits at init. Created on demand: the
# new-engagement.sh --with-oob flag, ensure_optional_file() when a blind bug (oob)
# actually runs, or a manual findings roll-up (vuln-index). vuln-index is type-aware:
# ctf uses a slim findings list.
OPTIONAL_FILES = {"oob": ("oob.md", "_oob.md"),
                  "vuln-index": ("Vuln-index.md", "_vuln-index.md")}


def ensure_optional_file(kind, d=None):
    """Back-fill one opt-in shared file (oob/vuln-index) on demand for the
    active (or given) engagement. Returns the created filename, or '' if it already
    exists / kind is unknown / no engagement / the template is missing. For
    kind='vuln-index' a ctf engagement gets the slim setup/templates/ctf/vuln-index.md;
    every other case uses the shared template. Never overwrites (idempotent)."""
    d = d or active_dir()
    if not d or kind not in OPTIONAL_FILES:
        return ""
    fn, tplname = OPTIONAL_FILES[kind]
    dest = os.path.join(d, fn)
    if os.path.exists(dest):
        return ""
    tpl = ""
    if kind == "vuln-index":
        cand = os.path.join(TEMPLATES, engagement_type(d), "vuln-index.md")
        if os.path.isfile(cand):
            tpl = cand
    if not tpl:
        tpl = os.path.join(TEMPLATES, tplname)
    if not os.path.isfile(tpl):
        return ""
    name = os.path.basename(d)
    today = date.today().isoformat()
    text = open(tpl, encoding="utf-8", errors="ignore").read()
    text = text.replace("{{ENGAGEMENT}}", name).replace("{{DATE}}", today)
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(text)
    return fn


def entity(row, etype):
    """Identifier for a state/coverage row by engagement type (host/ip | target |
    asset/url), or '?' if none present."""
    for k in ENTITY_KEY.get(etype, ("host",)):
        if row.get(k):
            return row[k]
    return "?"


def _read_pointer():
    """Engagement name from targets/active.md (syncs via Obsidian, unlike a
    dotfile). First non-empty line that is not a markdown header/comment."""
    p = os.path.join(TARGETS, "active.md")
    if not os.path.isfile(p):
        return ""
    for line in open(p, encoding="utf-8", errors="ignore"):
        s = line.strip()
        if s and not s.startswith(("#", "<!--", "-", "*")):
            return s
    return ""


def active_dir():
    """Return path to the active engagement dir, or None.

    Priority: targets/active.md pointer, else most-recently-modified engagement
    dir (excluding _templates and dotfiles). Returns None if targets/ empty.
    """
    name = _read_pointer()
    if name:
        cand = os.path.join(TARGETS, name)
        if os.path.isdir(cand):
            return cand
    dirs = []
    for n in os.listdir(TARGETS):
        if n.startswith(".") or n == "_templates":
            continue
        p = os.path.join(TARGETS, n)
        if os.path.isdir(p):
            dirs.append(p)
    if not dirs:
        return None
    return max(dirs, key=os.path.getmtime)


def _parse_table(path):
    """Parse the first markdown table in a file into list-of-dicts keyed by
    lowercased header cell. Returns [] on any problem."""
    if not os.path.isfile(path):
        return []
    rows = []
    header = None
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line.startswith("|"):
            if header is not None:
                break  # table ended
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue  # separator row
        if header is None:
            header = [c.lower() for c in cells]
            continue
        if not any(cells):
            continue
        rows.append(dict(zip(header, cells)))
    return rows


def append_state_asset(d, target, service="?", port="?", access="port-open", notes=""):
    """Append one inventory row to <d>/state.md's FIRST markdown table, filling cells by the
    header's column order (target/host/asset<-target; service; port; access; notes). Dedups: a
    bare seed (port "?") is skipped if the target already has ANY row; a real port is skipped if
    target+port already exists. Returns True if a row was added. Fail-soft (returns False) on any
    IO/parse problem, so a caller (board auto-seed, the recon hook) never crashes on it.

    This is the plumbing that lets `campaign.py board` auto-populate from recon instead of
    requiring a hand-edited state.md - the friction that made the board easy to bypass."""
    p = os.path.join(d, "state.md")
    tgt = (target or "").strip()
    if not tgt or tgt in ("?", "-"):
        return False

    def _rk(r):
        return (r.get("target") or r.get("host") or r.get("asset") or "").strip().lower()

    existing = _parse_table(p)
    if str(port) in ("?", ""):
        if any(_rk(r) == tgt.lower() for r in existing):
            return False
    elif any(_rk(r) == tgt.lower() and (r.get("port") or "").strip() == str(port) for r in existing):
        return False

    try:
        lines = open(p, encoding="utf-8", errors="ignore").read().split("\n")
    except Exception:
        return False
    header = None
    header_i = None
    last_i = None
    for i, line in enumerate(lines):
        s = line.strip()
        if not s.startswith("|"):
            if header is not None:
                break  # first table ended
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            last_i = i  # separator is part of the table region
            continue
        if header is None:
            header = [c.lower() for c in cells]
            header_i = last_i = i
            continue
        last_i = i
    if header is None:
        return False
    valmap = {"target": tgt, "host": tgt, "asset": tgt, "service": str(service),
              "port": str(port), "access": access, "notes": notes}
    row = "| " + " | ".join(valmap.get(c, "") for c in header) + " |"
    lines.insert((last_i + 1) if last_i is not None else (header_i + 1), row)
    try:
        open(p, "w", encoding="utf-8").write("\n".join(lines))
    except Exception:
        return False
    return True


# vuln-class synonyms: phrases (beyond the literal class token) that credit a class
# as TESTED when they appear in a finding title/slug or a Deadends.md line. Keep
# additions specific -- a false positive silences a coverage-gap reminder early.
CLASS_ALIASES = {
    "sqli": ["sql injection", "sql-injection", "sqlmap", "union select", "blind sql"],
    "xss": ["cross-site scripting", "cross site scripting", "stored xss", "reflected xss", "dom xss"],
    "ssrf": ["server-side request forgery", "server side request forgery"],
    "idor": ["insecure direct object", "bola", "broken object level", "object-level auth"],
    "rce": ["remote code execution", "command injection", "os command", "code execution", "webshell"],
    "ssti": ["template injection", "server-side template"],
    "xxe": ["xml external entity", "xml entity"],
    "csrf": ["cross-site request forgery", "cross site request forgery"],
    "oauth-saml": ["oauth", "saml", "openid", "single sign-on", "federation"],
    "auth": ["authentication bypass", "auth bypass", "broken authentication", "login bypass"],
    "file-upload": ["file upload", "unrestricted upload", "arbitrary file upload"],
    "open-redirect": ["open redirect"],
    "request-smuggling": ["request smuggling", "desync"],
    "deserialization": ["insecure deserialization", "deserialisation", "object injection"],
    "prototype-pollution": ["prototype pollution"],
    "subdomain-takeover": ["subdomain takeover"],
    "web-cache": ["cache poisoning", "cache deception", "web cache"],
    "host-header": ["host header"],
    "jwt": ["json web token"],
    "graphql": ["graph ql"],
    "cors": ["cross-origin resource", "cross origin resource"],
    "race-condition": ["race condition", "toctou"],
    "business-logic": ["business logic", "logic flaw"],
    "default-creds": ["default credential", "default password", "default login", "weak credential"],
    "kerberoast": ["kerberoasting"],
    "asreproast": ["asrep roast", "as-rep roast", "asreproasting"],
    "adcs": ["esc1", "esc2", "esc3", "esc4", "esc8", "certifried", "certipy", "certificate template"],
    "privesc": ["privilege escalation", "local privilege"],
    "signing-relay": ["ntlm relay", "smb relay", "smb signing", "ldap relay", "coerce"],
    "lateral": ["lateral movement", "pass-the-hash", "pass the hash", "pass-the-ticket"],
    "shares": ["smb share", "open share", "anonymous share", "readable share"],
    "enum": ["enumeration"],
    "recon": ["reconnaissance"],
    "mcp": ["model context protocol"],
    "cicd": ["ci/cd", "pipeline injection", "github actions", "runner takeover"],
}


def _match_classes(text, classes):
    """Subset of `classes` whose bare token (word-boundaried, so 'rce' does not match
    'source') or a CLASS_ALIASES phrase (substring) appears in `text`. Case-insensitive."""
    if not text:
        return set()
    t = text.lower()
    hits = set()
    for c in classes:
        cl = c.lower()
        if re.search(r"\b" + re.escape(cl) + r"\b", t):
            hits.add(c)
            continue
        for phrase in CLASS_ALIASES.get(cl, ()):
            if phrase in t:
                hits.add(c)
                break
    return hits


def _frontmatter(text):
    """key->value dict from a leading --- YAML block, or {}. Scalars become strings;
    a key followed by `- item` lines becomes a list (so block-list `affected:` parses)."""
    m = re.match(r"\s*---\s*\n(.*?)\n---", text, re.S)
    if not m:
        return {}
    fm = {}
    key = None
    for line in m.group(1).splitlines():
        li = re.match(r"\s+-\s+(.*)$", line)
        if li and key:                                  # block-list item under the current key
            cur = fm.get(key)
            if not isinstance(cur, list):
                fm[key] = [] if (cur is None or cur == "") else [cur]
            fm[key].append(li.group(1).strip().strip('"').strip("'"))
            continue
        km = re.match(r"([A-Za-z][\w-]*):\s*(.*)$", line)
        if km:
            key = km.group(1).lower()
            fm[key] = km.group(2).strip().strip('"').strip("'")
    return fm


def tested_classes(d, etype, classes):
    """Vuln classes credited as TESTED for the engagement, inferred from the files the
    state-first discipline already produces -- so coverage stays current with no manual
    bookkeeping:
      1. killchain.md 4a table        -> explicit, per-asset ('vuln class' when status done)
      2. Vulns/**/FIND-*.md           -> tested-and-found, per 'affected' asset
      3. Deadends.md lines            -> tested-and-cleared (a named class, bounded-out)
    Returns (per_asset: {asset_lower: set}, glob: set); glob credits apply to every asset
    (un-attributed signals). Best-effort: any missing file is skipped. `classes` is the
    canonical vocabulary to match findings/dead-ends against."""
    per_asset, glob = {}, set()
    if not d or not classes:
        return per_asset, glob

    def credit(hits, asset):
        if not hits:
            return
        if asset:
            per_asset.setdefault(asset.lower(), set()).update(hits)
        else:
            glob.update(hits)

    # 1. explicit killchain.md 4a table: credit a row's 'vuln class' as tested when its
    #    status cell is done ([x] or "done"). Drop dash placeholders.
    try:
        for r in _parse_table(os.path.join(d, "killchain.md")):
            status = (r.get("status", "") or "").strip().lower()
            if "[x]" not in status and "done" not in status:
                continue
            a = (r.get("asset") or r.get("host") or r.get("target") or "").strip().lower()
            cls = (r.get("vuln class", "") or "").strip().lower()
            if cls and not re.fullmatch(r"-+", cls):
                credit({cls}, a)
    except Exception:
        pass

    # 2. written findings -> class proven tested on the affected asset
    vroot = os.path.join(d, "Vulns")
    if os.path.isdir(vroot):
        for root, _dirs, files in os.walk(vroot):
            if os.path.basename(root).lower().startswith(("skip", "false")):
                continue
            for f in files:
                if not (f.startswith("FIND-") and f.endswith(".md")):
                    continue
                try:
                    text = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                fm = _frontmatter(text)
                title = fm.get("title", "")
                if isinstance(title, list):
                    title = " ".join(title)
                explicit = (fm.get("class") or "").strip().lower()
                hits = ({explicit} if explicit in {c.lower() for c in classes}
                        else _match_classes(f + " " + title, classes))
                aff = fm.get("affected", "")
                for a in (aff if isinstance(aff, list) else [aff]):   # block-list affected -> per-asset
                    credit(hits, a)

    # 3. Deadends.md -> tested-and-cleared; attribute to a state entity if the line names one
    de = os.path.join(d, "Deadends.md")
    if os.path.isfile(de):
        ents = []
        try:
            for r in _parse_table(os.path.join(d, "state.md")):
                e = entity(r, etype)
                if e and e != "?":
                    ents.append(e)
        except Exception:
            pass
        try:
            raw = open(de, encoding="utf-8", errors="ignore").read()
            body = re.sub(r"^\s*---\s*\n.*?\n---\s*\n", "", raw, count=1, flags=re.S)
            for line in body.splitlines():
                s = line.strip()
                if not s or s.startswith(("#", "<!--", "|", "---")):
                    continue
                asset = next((e for e in ents if e.lower() in s.lower()), "")
                credit(_match_classes(s, classes), asset)
        except OSError:
            pass

    return per_asset, glob


def _class_vocab():
    """Full vuln-class vocabulary: every coverage-classes.json value + CLASS_ALIASES key.
    Lowercased. The canonical set confirmed_findings / chains.json validate against."""
    vocab = set(CLASS_ALIASES.keys())
    try:
        cc = json.load(open(os.path.join(VAULT, "scripts", "coverage-classes.json"),
                            encoding="utf-8"))
        for v in cc.values():
            if isinstance(v, list):
                vocab.update(c.lower() for c in v)
    except Exception:
        pass
    return {c.lower() for c in vocab}


def _vuln_index_confirmed_ids(d):
    """{FIND-NNN: host} for Vuln-index.md rows whose Status's first alphabetic word token
    is CONFIRMED or PARTIAL. Multi-table aware (_parse_table only reads the first table):
    rows are credited only under an `id | title | host | status` header, so the
    Severity-Count table is ignored. ID cell may be a bare `FIND-NNN` or a markdown link
    `[FIND-NNN](...)` (re.search, not match). Status may be decorated (emoji/`**`/leading
    whitespace); only the first alphabetic token is compared, so '(emoji/bold-decorated)
    CONFIRMED (Flag 1)' and '**CONFIRMED HIGH**' count, while 'VERSION CONFIRMED / PoC
    pending' (first token VERSION) and 'CLOSED' are excluded. -> {} on any problem."""
    ids = {}
    try:
        lines = open(os.path.join(d, "Vuln-index.md"), encoding="utf-8",
                     errors="ignore").read().splitlines()
    except OSError:
        return ids
    header = None
    for line in lines:
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue                       # separator row
        low = [c.lower() for c in cells]
        if low[:4] == ["id", "title", "host", "status"]:
            header = "finding"
            continue
        if low and low[0] == "severity":   # Severity-Count table header
            header = "other"
            continue
        if header != "finding" or len(cells) < 4:
            continue
        m = re.search(r"(FIND-\d+)", cells[0])
        tok = re.match(r"[^A-Za-z]*([A-Za-z]+)", cells[3].strip())
        first = tok.group(1).upper() if tok else ""
        if m and first in ("CONFIRMED", "PARTIAL"):
            ids[m.group(1)] = cells[2].strip()
    return ids


def confirmed_findings(d):
    """CONFIRMED/PARTIAL findings as typed records: [{class, asset, severity, status}].
    The Vuln-index Status column is the authoritative gate (a FIND file's own frontmatter
    `status:` stays Research in practice). One record per `affected` asset (comma-split
    when `affected` is a single scalar string, e.g. 'web08a, web08b'). Class = explicit
    frontmatter `class:` (when a known class) else fuzzy _match_classes(title+filename).
    The record's `status` field is always the literal 'confirmed', a gate-provenance
    tag meaning "passed the CONFIRMED/PARTIAL gate", not the original Vuln-index status.
    Error-safe -> []."""
    out = []
    if not d:
        return out
    ok = _vuln_index_confirmed_ids(d)
    if not ok:
        return out
    vocab = _class_vocab()
    vroot = os.path.join(d, "Vulns")
    if not os.path.isdir(vroot):
        return out
    for root, _dirs, files in os.walk(vroot):
        if os.path.basename(root).lower().startswith(("skip", "false")):
            continue
        for f in files:
            if not (f.startswith("FIND-") and f.endswith(".md")):
                continue
            m = re.match(r"(FIND-\d+)", f)
            if not m or m.group(1) not in ok:
                continue
            try:
                text = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            fm = _frontmatter(text)
            title = fm.get("title", "")
            if isinstance(title, list):
                title = " ".join(title)
            explicit = (fm.get("class") or "").strip().lower()
            if explicit in vocab:
                cls = explicit
            else:
                hits = _match_classes(f + " " + title, vocab)
                # multiple fuzzy hits: alphabetical-first is a fallback; explicit
                # frontmatter `class:` is the reliable disambiguator.
                cls = sorted(hits)[0] if hits else ""
            if not cls:
                continue
            sev_m = re.match(r"FIND-\d+-([A-Za-z]+)-", f)
            sev = (sev_m.group(1).upper() if sev_m else str(fm.get("severity", "")).upper())
            aff = fm.get("affected", "")
            raw = aff if isinstance(aff, list) else str(aff).split(",")
            assets = [a.strip() for a in raw if a and a.strip()] or [ok[m.group(1)]]
            for a in assets:
                out.append({"class": cls, "asset": a, "severity": sev, "status": "confirmed"})
    return out


def summary():
    """One-line-per-fact summary dict for the active engagement."""
    d = active_dir()
    if not d:
        return None
    name = os.path.basename(d)
    state = _parse_table(os.path.join(d, "state.md"))
    paths = _parse_table(os.path.join(d, "paths.md"))
    loot = _parse_table(os.path.join(d, "loot.md"))
    owned = sum(1 for r in state if r.get("owned", "").lower() == "yes")
    open_paths = [r for r in paths if r.get("status", "").lower() == "open"]
    creds = sum(1 for r in loot if r.get("status", "").lower() in ("active", "unconfirmed"))
    next_moves = [
        f"{r.get('path', '?')}: {r.get('next-move', '?')}"
        for r in open_paths
        if r.get("next-move")
    ][:3]
    return {
        "name": name,
        "hosts": len(state),
        "owned": owned,
        "creds": creds,
        "open_paths": len(open_paths),
        "next_moves": next_moves,
    }


def summary_text():
    """Compact counts-only summary string, or '' if no engagement. Move ranking
    is owned by scripts/next_move.py (the analyzer), not duplicated here."""
    s = summary()
    if not s:
        return ""
    return (
        f"Active engagement: {s['name']} | hosts {s['hosts']} (owned {s['owned']}) "
        f"| creds {s['creds']} | open paths {s['open_paths']}"
    )


def engagement_type(d=None):
    """Read engagement_type from any existing state/loot/paths frontmatter.
    Defaults to 'pentest' when unknown."""
    d = d or active_dir()
    if not d:
        return "pentest"
    for fn in STATE_FILES:
        p = os.path.join(d, fn)
        if not os.path.isfile(p):
            continue
        for line in open(p, encoding="utf-8", errors="ignore"):
            if line.startswith("engagement_type:"):
                val = line.split(":", 1)[1].strip().lower()
                if val in TYPES:
                    return val
    return "pentest"


_SCOPE_SECTIONS = {
    "in scope": "in_scope",
    "out of scope": "out_of_scope",
    "allowed tooling": "allowed_tooling",
    "rules of engagement": "roe",
}


def scope(d=None):
    """Parse scope.md: in/out-of-scope lists, allowed tooling, RoE, and the
    no_bruteforce/no_dos/passive_only flags. Empty defaults if absent."""
    res = {"in_scope": [], "out_of_scope": [], "allowed_tooling": [], "roe": [],
           "no_bruteforce": False, "no_dos": False, "passive_only": False,
           "tunnel_safe": False}
    d = d or active_dir()
    if not d:
        return res
    p = os.path.join(d, "scope.md")
    if not os.path.isfile(p):
        return res
    cur = None
    for line in open(p, encoding="utf-8", errors="ignore"):
        s = line.strip()
        fm = re.match(r"(no_bruteforce|no_dos|passive_only|tunnel_safe):\s*(true|false)", s, re.I)
        if fm:
            res[fm.group(1).lower()] = fm.group(2).lower() == "true"
            continue
        h = re.match(r"##\s+(.*)", s)
        if h:
            cur = _SCOPE_SECTIONS.get(h.group(1).strip().lower())
            continue
        if cur and s.startswith("-"):
            v = s[1:].strip()
            if v and not v.startswith("<!--"):
                res[cur].append(v)
    return res


def phase_explicit(d):
    """The killchain frontmatter `current_phase`, IFF present and its `entered_because`
    names no out-of-scope asset; else None (caller falls back to the heuristic phase scan).
    The citation-scope check keeps a phase transition in scope. Deterministic, no network."""
    if not d:
        return None
    try:
        raw = open(os.path.join(d, "killchain.md"), encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    fm = _frontmatter(raw)
    cp = (fm.get("current_phase") or "").strip()
    if not cp:
        return None
    cited = fm.get("entered_because") or ""
    if isinstance(cited, list):
        cited = " ".join(cited)
    sc = scope(d)
    for tok in re.findall(r"[A-Za-z0-9._:/-]+", cited):
        if out_of_scope_match(tok.lower(), sc):
            return None                    # citation names an out-of-scope asset -> ignore field
    return cp


def _host_of(s):
    """Reduce a URL / authority string to its bare host: drop scheme, userinfo, any
    path/query/fragment, and a trailing :port. A plain host or IP passes through. A
    single-colon `host:port` / `ipv4:port` is de-ported; IPv6 (>=2 colons) is left
    intact. Lets a URL-form scope entity (a bugbounty asset is a full URL) match a
    bare-host scope entry."""
    s = s.split("://", 1)[-1]      # strip scheme
    s = s.split("/", 1)[0]         # strip path/query/fragment
    s = s.rsplit("@", 1)[-1]       # strip userinfo
    if s.count(":") == 1:          # host:port / ipv4:port -> host; IPv6 keeps its colons
        s = s.split(":", 1)[0]
    return s


def _scope_entry_match(e, o, strict=False):
    """Boundary-aware match of host/ip `e` against scope entry `o`.

    Handles: exact host; `o` as a parent domain (`x.com` -> `api.x.com`, the
    `endswith("." + o)` arm, a genuine-subdomain relationship); `o` as a wildcard
    (`*.x.com` matches `x.com` and any subdomain); `o` as a CIDR/IP containing `e`;
    and URL-form `e`/`o` (each reduced to its bare host first, so a full-URL bugbounty
    asset matches a bare-host scope entry).

    The label-prefix arm (`o` as a bare-label prefix, `prod-db` -> `prod-db.x.com`,
    only when `o` has no dot) is ADVISORY-ONLY and applies only when `strict=False`.
    It is inherently attacker-spoofable: anyone can register `<label>.attacker.tld`,
    so a bare-label prefix does NOT prove `e` is the in-scope host. It is a
    convenience for advisory callers (scope-guard warnings, next_move ranking) but
    must never authorize a security decision that writes data to disk. Strict callers
    (the poc/pages disk-write gate) pass `strict=True` and get exact/parent/wildcard/CIDR
    only. Also avoids the old bidirectional-substring bug (`db` -> `db-staging`) and
    dotted label-prefix confusion (`10.0.0.9` -> `10.0.0.9.evil.com`).
    """
    if not o:
        return False
    e = _host_of(e)
    if o.startswith("*."):
        base = o[2:]   # *.x.com -> matches x.com and any subdomain of it
        return bool(base) and (e == base or e.endswith("." + base))
    if "/" in o:
        # CIDR/IP-network, checked before host-normalizing `o` (which would drop the /prefix).
        # A "/" that is NOT a parseable network is a URL path -> fall through to host match.
        try:
            net = ipaddress.ip_network(o, strict=False)
        except ValueError:
            net = None
        if net is not None:
            try:
                return ipaddress.ip_address(e) in net
            except ValueError:
                return False
    o = _host_of(o)
    if e == o or e.endswith("." + o):
        return True
    if not strict and "." not in o and e.startswith(o + "."):
        # advisory-only convenience: a bare-label entry matches its FQDN forms; NOT
        # trusted for a disk-write gate (a host can spoof <label>.attacker.tld).
        return True
    return False


def out_of_scope_match(entity, sc):
    """True if entity (host/ip/asset) matches any out-of-scope entry."""
    e = (entity or "").lower().strip()
    if not e:
        return False
    return any(_scope_entry_match(e, (o or "").lower().strip())
               for o in sc.get("out_of_scope", []))


def scope_text():
    """Compact scope/RoE summary for injection, or ''."""
    s = scope()
    parts = []
    if s["in_scope"]:
        parts.append(f"in-scope {len(s['in_scope'])}")
    if s["out_of_scope"]:
        parts.append(f"out-of-scope {len(s['out_of_scope'])}")
    flags = [k for k in ("no_bruteforce", "no_dos", "passive_only") if s[k]]
    if flags:
        parts.append("RoE: " + ", ".join(flags))
    return "Scope: " + " | ".join(parts) if parts else ""


def recent_log(maxlines=12):
    """Newest block of the active engagement's log.md, or ''. Lets the client
    narrative load from targets/<eng>/log.md instead of session/hot.md."""
    d = active_dir()
    if not d:
        return ""
    p = os.path.join(d, "log.md")
    if not os.path.isfile(p):
        return ""
    lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
    seps = [i for i, l in enumerate(lines) if l.strip() == "---"]
    start = (seps[2] + 1) if len(seps) >= 3 else (seps[1] + 1 if len(seps) >= 2 else 0)
    body = [l for l in lines[start:] if l.strip()]
    return "\n".join(body[:maxlines])


def oob_rows(d=None):
    """Rows of the active engagement's oob.md ledger (list of dicts), or []."""
    d = d or active_dir()
    if not d:
        return []
    return _parse_table(os.path.join(d, "oob.md"))


def oob_hits(d=None):
    """OOB ledger rows whose callback landed (status HIT) but are not yet actioned."""
    return [r for r in oob_rows(d) if r.get("status", "").strip().lower() == "hit"]


def flip_oob_status(d, token, new_status, source=""):
    """Flip the status (and optionally source) of the oob.md row whose token cell
    contains `token`, but only if it is still open (waiting/blank). Line-based edit
    so the rest of the table is untouched. Returns True if a row changed.
    Best-effort: never raises."""
    if not d or not token or len(token) < 4:
        return False
    p = os.path.join(d, "oob.md")
    try:
        lines = open(p, encoding="utf-8", errors="ignore").read().splitlines(keepends=True)
    except OSError:
        return False
    changed = False
    for i, line in enumerate(lines):
        if token not in line or not line.lstrip().startswith("|"):
            continue
        nl = "\n" if line.endswith("\n") else ""
        cells = line[:len(line) - len(nl)].split("|")
        # "| token | sink | class | planted | status | source |" -> 8 parts (lead/trail empty)
        if len(cells) < 8 or token not in cells[1]:
            continue
        if cells[5].strip().lower() not in ("waiting", ""):
            continue  # only flip an open row, never overwrite HIT/actioned/expired
        cells[5] = " " + new_status + " "
        if source:
            cells[6] = " " + source + " "
        lines[i] = "|".join(cells) + nl
        changed = True
    if changed:
        try:
            open(p, "w", encoding="utf-8").write("".join(lines))
        except OSError:
            return False
    return changed


_STATUS_RE = re.compile(r"^##\s*STATUS:\s*(SOLVED|OWNED|ROOTED|COMPLETE)\b",
                        re.IGNORECASE | re.MULTILINE)


def is_solved(d):
    """True iff <d>/state.md carries a '## STATUS: SOLVED' (or OWNED/ROOTED/COMPLETE)
    heading, case-insensitive -- the explicit close-out marker the walkthrough
    auto-assembly gate watches for. Missing file / any error -> False (fail-open:
    never nag on a detection error)."""
    if not d:
        return False
    p = os.path.join(d, "state.md")
    try:
        text = open(p, encoding="utf-8", errors="ignore").read()
        return bool(_STATUS_RE.search(text))
    except Exception:
        return False


# unfilled-template markers a scaffolded-but-untouched walkthrough.md still carries
_WALKTHROUGH_STUB_MARKERS = ("<entrypoint>", "<foothold")
_WALKTHROUGH_STUB_LINES = ("- target:", "- reach:")


def walkthrough_stale(d):
    """True (needs assembling) iff <d>/walkthrough.md is absent/empty/whitespace, OR
    still carries an unfilled-template marker (<entrypoint>, <foothold, or a bare
    '- target:'/'- reach:' stub line), OR its '## Evidence' section has no image row
    (![](...)). False once the narrative is filled in and the gallery has a shot.
    Any error -> False (fail-open: do NOT nag on a detection error)."""
    if not d:
        return False
    p = os.path.join(d, "walkthrough.md")
    try:
        if not os.path.isfile(p):
            return True
        text = open(p, encoding="utf-8", errors="ignore").read()
        if not text.strip():
            return True
        if any(m in text for m in _WALKTHROUGH_STUB_MARKERS):
            return True
        if any(line.strip() in _WALKTHROUGH_STUB_LINES for line in text.splitlines()):
            return True
        m = re.search(r"^##\s+Evidence\s*$(.*?)(?=^##\s|\Z)", text, re.MULTILINE | re.DOTALL)
        section = m.group(1) if m else ""
        if "![](" not in section:
            return True
        return False
    except Exception:
        return False


def learn_pending(d):
    """True (a knowledge-harvest pass is due) iff <d> is SOLVED, its walkthrough is
    already assembled (walkthrough_stale False), AND no fresh <d>/.learn-done marker
    exists. Skill(learn) writes .learn-done at the end of a harvest pass to self-clear
    this gate. A marker OLDER than state.md's mtime is stale (the operator changed
    close-out state since the last pass) and re-arms the gate. Placed strictly AFTER
    the walkthrough gate so it never nags while the walkthrough is still unassembled.
    Any error / missing file -> False (fail-open: never nag on a detection error)."""
    if not d:
        return False
    try:
        if not is_solved(d):
            return False
        if walkthrough_stale(d):
            return False                       # walkthrough gate owns this Stop first
        marker = os.path.join(d, ".learn-done")
        if not os.path.isfile(marker):
            return True
        try:
            state = os.path.join(d, "state.md")
            return os.path.getmtime(marker) < os.path.getmtime(state)
        except OSError:
            return False
    except Exception:
        return False


_WEB_PORT_RE = re.compile(r"(?:\b|:)(80|443|8080|8443|8000)\b|https?://|\bhttps?\b", re.I)


def web_evidence_gaps(d):
    """For a SOLVED WEB engagement, the evidence the operator expects before close-out is
    complete. Returns a list of missing categories (empty = complete, or not a web box).
    A web box = state.md shows an http port (80/443/8080/...) or an http(s) service.
    Checks, all reliably read from disk:
      - recon cards: recon/*.png  (EVERY scan tab carded - the thing skipped under momentum)
      - saved page source: poc/*source* or poc/*.html  (the raw site source, per operator ask)
    `capture.sh web` now auto-saves source next to each render, so a missing source file also
    means a site was never rendered. Fail-open: any error -> [] (never blocks a Stop)."""
    if not d:
        return []
    try:
        st = open(os.path.join(d, "state.md"), encoding="utf-8", errors="ignore").read()
        if not _WEB_PORT_RE.search(st):
            return []                                  # not a web box -> gate is silent
        import glob
        gaps = []
        if not glob.glob(os.path.join(d, "recon", "*.png")):
            gaps.append("recon cards (scripts/capture.sh recon <eng> <slug> <tab> for EACH scan tab)")
        poc = os.path.join(d, "poc")
        if not (glob.glob(os.path.join(poc, "*source*")) + glob.glob(os.path.join(poc, "*.html"))):
            gaps.append("website render + source (scripts/capture.sh web <eng> <slug> <url>)")
        return gaps
    except Exception:
        return []


def _table_data_rows(text):
    """Count real markdown-table DATA rows (skip header, `---` separators, and empty
    placeholder rows). A data row = a `|`-line whose first cell has content and is not a
    known column label. Lets a caller tell 'this table has real findings' from 'still stub'."""
    rows = 0
    for ln in text.splitlines():
        s = ln.strip()
        if not s.startswith("|"):
            continue
        first = s.strip("|").split("|", 1)[0].strip()
        if not first or set(first) <= set("-: "):          # empty leading cell or a --- separator
            continue
        if first.lower() in ("item", "path", "target", "host", "asset", "flag", "scope"):
            continue                                        # header row
        rows += 1
    return rows


def paths_write_gap(d):
    """Live state-discipline reflex: LOOT was captured (a cred/key/flag/technique row in
    loot.md) but paths.md still has ZERO chain rows -- a finding landed and the attack chain
    was never written down (the drift where paths.md is filled only at close-out). Returns the
    loot data-row count when a gap exists, else 0. Fail-open (0 on any error)."""
    if not d:
        return 0
    try:
        loot = open(os.path.join(d, "loot.md"), encoding="utf-8", errors="ignore").read()
        paths = open(os.path.join(d, "paths.md"), encoding="utf-8", errors="ignore").read()
        loot_rows = _table_data_rows(loot)
        if loot_rows >= 1 and _table_data_rows(paths) == 0:
            return loot_rows
        return 0
    except Exception:
        return 0


def unsprayed_cred_gap(d):
    """Live cred-reuse reflex: we hold MULTIPLE distinct credentials in loot.md, the box is
    still short of root, and Deadends.md records no cred-reuse/spray attempt -- the drift where
    a newly captured password is written down and then never tried against the auth surfaces
    while a new privesc vector is hunted instead. (Observed live: the app's real DB password sat
    in loot.md while filesystem privesc was ground for ~25min; that password's sibling was the
    root password.) Returns the loot cred-row count when a gap exists, else 0. Counts only rows
    that look like a credential, so a flag/technique row never triggers it. Fail-open (0)."""
    if not d:
        return 0
    try:
        if is_solved(d):
            return 0
        loot = open(os.path.join(d, "loot.md"), encoding="utf-8", errors="ignore").read()
        creds = 0
        for ln in loot.splitlines():
            s = ln.strip()
            if not s.startswith("|"):
                continue
            cells = [c.strip() for c in s.strip("|").split("|")]
            if not cells or not cells[0] or set(cells[0]) <= set("-: "):
                continue
            if cells[0].lower() in ("item", "cred", "credential", "type", "user", "scope"):
                continue                                    # header row
            row = " ".join(cells).lower()
            # " / " (spaced) catches the `user / password` loot form; a bare "/" would match
            # incidental cells like "n/a" or a path and count a flag row as a credential.
            if any(k in row for k in ("pass", "cred", "secret", "token", "key", "hash", " / ")):
                creds += 1
        if creds < 2:
            return 0
        try:
            de = open(os.path.join(d, "Deadends.md"), encoding="utf-8",
                      errors="ignore").read().lower()
        except Exception:
            de = ""
        if any(k in de for k in ("spray", "reuse", "cred-reuse", "password reuse")):
            return 0
        return creds
    except Exception:
        return 0


# a flag token in a loot.md item cell: PREFIX{...}. Excludes placeholder rows ("Base Flag")
# whose item is prose, so an un-captured flag never counts toward the total.
_FLAG_STR_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]+\}")


def captured_flags(d):
    """Distinct SCORED flag strings recorded in loot.md (any cell containing a PREFIX{...}
    token). De-duplicated by value so a copied flag file (e.g. /tmp/rootflag.txt ==
    /root/root.txt) counts once. A row labelled `decoy` (case-insensitive) is skipped, so a
    troll/decoy flag file does not inflate the count and mask a genuinely missing scored flag.
    Fail-open -> set() on any error."""
    out = set()
    if not d:
        return out
    try:
        loot = open(os.path.join(d, "loot.md"), encoding="utf-8", errors="ignore").read()
        for ln in loot.splitlines():
            if "decoy" in ln.lower():
                continue
            for m in _FLAG_STR_RE.finditer(ln):
                out.add(m.group(0))
    except Exception:
        pass
    return out


def flag_accounting_gap(d):
    """Close-out reflex for a SOLVED ctf box: returns a nudge string when the flags recorded
    in loot.md are fewer than state.md's `flags_expected`, OR flags_expected is unset/empty
    (can't verify -> still remind to set it + run the full-FS sweep). Returns "" when
    satisfied, not SOLVED, or not a ctf box. Fail-open ("" on any error).

    This is the guard a CTF flag-accounting retro exposed: a box was declared done with a
    mislabeled decoy user flag and a scored flag missed entirely, nothing checked completeness."""
    if not d:
        return ""
    try:
        if not is_solved(d):
            return ""
        if (engagement_type(d) or "").lower() != "ctf":
            return ""
        st = open(os.path.join(d, "state.md"), encoding="utf-8", errors="ignore").read()
        raw = (_frontmatter(st).get("flags_expected") or "").strip()
        flags = captured_flags(d)
        n = len(flags)
        fmt = next((f.split("{", 1)[0] for f in flags), "flag")   # infer sweep prefix
        sweep = ("`grep -RIn '%s{' / --exclude-dir={proc,sys,dev,run}`" % fmt)
        try:
            expected = int(raw)
        except (TypeError, ValueError):
            expected = None
        common = ("The first home-dir flag may be a DECOY and the scored user flag may belong "
                  "to a LATER user; verify each captured flag matches the room's answer format. "
                  "A scored flag that is nowhere on disk (a THM 'Base Flag') may live in the "
                  "ROOM-PAGE source (view-source), not the box.")
        if expected is None:
            return ("flags_expected is unset in state.md and %d flag(s) are recorded. Set "
                    "flags_expected from the room's answer boxes, then run %s to enumerate ALL "
                    "flags. %s" % (n, sweep, common))
        if n < expected:
            return ("SOLVED but only %d/%d flags recorded. Run %s to enumerate ALL flags. %s"
                    % (n, expected, sweep, common))
        return ""
    except Exception:
        return ""


def ensure_state_files():
    """Create any missing per-engagement files (from the type's template) and the
    standard dirs in the active engagement. The shared set is type-aware: a ctf
    engagement heals only the lean core (state/loot/paths/killchain/log/scope/
    walkthrough/Deadends), skipping the Vuln-index/oob severity machinery that is dead
    across CTF rooms; pentest/bugbounty heal the full set. poc/ is scaffolded for
    every type; Vulns/ is created lazily on the first FIND, never here. Returns the
    created names. Idempotent: never overwrites an existing file."""
    d = active_dir()
    if not d:
        return []
    name = os.path.basename(d)
    today = date.today().isoformat()
    etype = engagement_type(d)
    tpldir = os.path.join(TEMPLATES, etype)
    if not os.path.isdir(tpldir):
        tpldir = os.path.join(TEMPLATES, "pentest")
    created = []

    def _emit(dest, tpl):
        if os.path.exists(dest) or not os.path.isfile(tpl):
            return None
        text = open(tpl, encoding="utf-8", errors="ignore").read()
        text = text.replace("{{ENGAGEMENT}}", name).replace("{{DATE}}", today)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(text)
        return os.path.basename(dest)

    # 1. state/loot/paths from the type's own template dir (per-type columns)
    for fn in STATE_FILES:
        c = _emit(os.path.join(d, fn), os.path.join(tpldir, fn))
        if c:
            created.append(c)
    # 2. shared type-agnostic files, type-aware set (ctf omits Vuln-index/oob)
    for fn, tplname in _heal_shared_set(etype):
        c = _emit(os.path.join(d, fn), os.path.join(TEMPLATES, tplname))
        if c:
            created.append(c)
    # 3. standard dirs for every type (see STATE_DIRS). Vulns/ stays lazy (first FIND).
    for sub in STATE_DIRS:
        p = os.path.join(d, sub)
        if not os.path.isdir(p):
            os.makedirs(p, exist_ok=True)
            created.append(sub + "/")
    return created
