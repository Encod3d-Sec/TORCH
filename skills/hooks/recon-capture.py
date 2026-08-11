#!/usr/bin/env python3
"""PostToolUse(Bash) hook: fingerprint auto-router + OOB callback correlation.

Two jobs after a recon/exec tool runs:
  1. Fingerprint router: match scripts/playbook.json tech fingerprints against the
     command AND its output, and inject the matching "<tech> detected -> load Skill(x)"
     routing line. This auto-fires the hunt skill the moment tech is discovered,
     instead of waiting for the next SessionStart next-move pass. A framework-meta
     guard suppresses false fires when the command is reading/editing the vault's own
     playbook/hook/wiring machinery (its output is full of playbook tokens).
  2. OOB callback auto-correlation: flip a waiting oob.md row to HIT when its planted
     token appears in the command+output blob (operator polling OAST/Collaborator).

Keyword matching only (no structured/version-fragile parsing).
Emits Claude Code JSON additionalContext. Non-fatal: any error exits 0 silent.
"""
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# tools that produce host/service/asset intel
RECON_TOOLS = (r"nmap|masscan|nxc|netexec|crackmapexec|cme|ffuf|httpx|subfinder|rustscan|"
               r"naabu|dnsx|katana|gau|amass|gowitness|arjun|nuclei|gobuster|feroxbuster")
# tools that produce credentials/secrets
CRED_TOOLS = (r"secretsdump|getuserspns|getnpusers|gettgt|certipy|kerbrute|hashcat|john|"
              r"lsassy|nanodump|trufflehog|gitleaks")
# commands whose output is worth fingerprinting (discovery/probes/testers)
PROBE_TOOLS = RECON_TOOLS + r"|curl|wget|whatweb|wpscan|nikto|whatwaf|nslookup|dig|sqlmap|dalfox|swaks"

# unambiguous EXPLOITATION tools/patterns: their use means we are past recon into
# foothold/exploit -- the point GATE 1 (wiki-first) must have been cleared. Kept tight to
# avoid false-firing on recon (a bare nxc/cme enum is recon; `-x` command-exec is not).
EXPLOIT_TOOLS = (r"sqlmap|hydra|medusa|msfconsole|msfvenom|evil-winrm|"
                 r"(?:crackmapexec|cme|nxc|netexec)\s+\S.*\s-x\b")
_REVSHELL_RE = re.compile(r"/dev/tcp/|\bnc\b[^\n]*\s-e\b|\bbash\s+-i\b|\brlwrap\s+nc\b", re.I)

# --- capture/coverage reflexes (restored + hardened after the de-bloat over-removed them;
#     both are pure nudges, no staging/render machinery -- capture/route only, per charter) ---
_DISCOVERY_TOOLS = r"ffuf|feroxbuster|gobuster|dirb|dirsearch"        # content-discovery axis
# unambiguous web-app activity: probing/exploiting a web surface -> discovery should have run
_WEB_ACTIVITY = r"curl|wget|whatweb|httpx|nikto|wpscan|sqlmap|dalfox"
_RECON_GAP_CAP = 3   # escalate the recon-completeness nudge up to N times, then go silent

# web-evidence reflex: a web surface must be RENDERED (a page shot) AND its HTML SOURCE saved
# as it is first explored -- scan cards are NOT a page render/source (recurring evidence gap:
# engagements finished with recon scan cards but no rendered page and no saved source).
_WEB_RENDER_RE = re.compile(r"capture\.sh\s+web\b|shot\.py\s+\S*https?://|gowitness|aquatone|eyewitness", re.I)
_WEB_SOURCE_RE = re.compile(
    r"capture\.sh\s+(?:snippet|log)\b"
    r"|(?:curl|wget)\b[^\n;|&]*https?://[^\n;|&]*(?:>|-[oO]\s+)\s*\S*(?:source|\.html?|\.xml|\.json|\.js|\.aspx?)\b",
    re.I)
_WEB_CAP_CAP = 3     # escalate the web-evidence nudge up to N times, then go silent
# a LANDED finding: a full flag value, or a shell/privesc `id` -- narrow, unambiguous SUCCESS
_FINDING_RE = re.compile(
    r"(?:THM|FLAG|HTB|CTF)\{[^}\n]{0,80}\}"            # a full flag value (dedup key)
    r"|uid=\d+\([a-z_][^)]*\)\s*gid=",                  # `id` output = shell / privesc landing
    re.I)
# code-exec landed: an `id` line naming a NON-root service acct (uid!=0, a lowercase name) -- the
# signature of a fresh web-RCE/foothold, NOT a reflected attacker-root false positive.
_RCE_ID_RE = re.compile(r"uid=[1-9]\d*\([a-z_][^)]*\)\s*gid=", re.I)


def _is_rce_landing(text):
    """True when output shows an `id`-style uid=<nonzero>(<name>) gid= line = code execution
    landed as a service account (the moment to stand up a stabilized reverse shell). Excludes
    uid=0 so a reflected attacker-root `id` (the false-RCE trap) does not fire the reflex."""
    return bool(text) and bool(_RCE_ID_RE.search(text[:MAX_BLOB]))


# web content/vhost discovery + fetch tools; grinding these on one host with no foothold = the
# "widen the surface" drift (re-probing a dead surface instead of enumerating a new surface class).
_WEB_PROBE_RE = re.compile(r"\b(feroxbuster|ffuf|gobuster|dirb|dirsearch|wfuzz|nuclei|nikto|whatweb|wpscan|curl|wget)\b", re.I)
WIDEN_AT = 20   # web probes with no foothold before the widen-the-surface nudge fires (once)


def _is_web_probe(cmd):
    """A web content/vhost-discovery or fetch command against an http(s) target."""
    return bool(_WEB_PROBE_RE.search(cmd or "")) and "http" in (cmd or "").lower()


def _state_has_foothold(d):
    """Cheap check: has this engagement reached a foothold (so 'widen recon' no longer applies)."""
    try:
        t = open(os.path.join(d, "state.md"), encoding="utf-8", errors="ignore").read().lower()
        return "foothold" in t or "## status:" in t or "access=foothold" in t
    except Exception:
        return False

MAX_BLOB = 20000   # cap output scanned for fingerprints
MAX_HITS = 3


# leading wrappers/env-assignments to strip before checking a segment's command
_WRAP = re.compile(r"^(sudo|env|time|timeout|nice|nohup|stdbuf|doas|proxychains4?)\b", re.I)
_ASSIGN = re.compile(r"^\w+=\S*")
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")


def _blank_quotes(s):
    """Blank single/double-quoted spans (length-preserving) so shell operators and tool
    names INSIDE quotes are inert -- e.g. a `grep -E 'a|b|kerbrute'` pattern must not be
    split on its `|` alternation, nor have `kerbrute` read as an invoked command."""
    return _QUOTED.sub(lambda m: " " * len(m.group(0)), s)


def invokes(cmd, tools):
    """Return a match for a tool that is actually INVOKED (a segment's command), not merely
    mentioned as a path/argument or inside a quoted pattern. Blanks quoted spans, splits on
    ; | && || newline, strips sudo/env/timeout-style wrappers, then checks the first token
    of each segment. Avoids false fires like `ls /root/nuclei-templates`, `find . -name
    nuclei`, or `grep -E 'a|nuclei|kerbrute' f` (quoted alternation, the recurring one)."""
    rx = re.compile(r"^(" + tools + r")\b", re.IGNORECASE)
    for seg in re.split(r"&&|\|\||[;|\n]", _blank_quotes(cmd)):
        toks = seg.strip()
        prev = None
        while toks and toks != prev:   # peel wrappers/env-assignments/their args
            prev = toks
            m = _ASSIGN.match(toks)
            if m:
                toks = toks[m.end():].lstrip()
                continue
            w = _WRAP.match(toks)
            if w:
                toks = toks[w.end():].lstrip()
                toks = re.sub(r"^((-{1,2}\S+|\d+)\s+)*", "", toks)  # drop flags / timeout's secs
        m = rx.match(toks)
        if m:
            return m
    return None


def _invokes_any(cmd, tools):
    """invokes() for the outer command OR any inner vm.sh/ssh/wsl-wrapped command (scans run
    through the bridge, so the tool token lives inside the wrapper)."""
    return invokes(cmd, tools) or next(
        (m for ic in inner_cmds(cmd) if (m := invokes(ic, tools))), None)


# Bridge wrappers: this harness runs remote tooling via `bash /root/vm.sh '<cmd>'`,
# `sshpass ... ssh user@host '<cmd>'`, or `wsl ... -- <cmd>`. The real tool sits inside
# the wrapper's quoted arg, so invokes() (command-position) misses it. Extract the inner
# command(s) so the caller can run invokes()/fingerprinting against them too.
#
# Also unwraps two more shapes: a `-c`/`-e` code-exec payload (python3/node/bash/sh/perl/
# ruby/deno '<payload>') and a heredoc body. Both recurse so a wrapper NESTED inside one of
# these (e.g. vm.sh called from inside a `bash -c` body) still gets unwrapped too.
_CODE_C_RE = re.compile(
    r"^(?:\S*/)?(?:python3?|node|bash|sh|perl|ruby|deno)\s+-[ce]\s+(['\"])(.+)\1\s*$", re.S)
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1\s*\n(.*?)\n\s*\2\b", re.S)
_LOOP_PREFIX = re.compile(r"^(?:do|then|;)\s+", re.I)


def _segments(c):
    """Split c on ;|&&|\\|\\|/newline/pipe boundaries that are OUTSIDE quoted spans,
    returning the ORIGINAL (un-blanked) segment strings so a quoted URL/cookie survives.
    _blank_quotes is length-preserving, so split offsets computed on the blanked copy
    apply verbatim to the original."""
    blanked = _blank_quotes(c or "")
    out, last = [], 0
    for m in re.finditer(r"&&|\|\||[;|\n]", blanked):
        out.append((c or "")[last:m.start()])
        last = m.end()
    out.append((c or "")[last:])
    return out


def inner_cmds(cmd):
    """Inner remote command strings pulled out of vm.sh / ssh / wsl wrappers, a -c/-e
    code-exec payload, or a heredoc body ([] if none). Command-position anchored for the
    bridge wrappers: extracts only when the wrapper is actually invoked (first token of a
    ;|&&-split segment, after peeling sudo/env/timeout and a leading for/while/if loop-body
    keyword `do `/`then `), not merely quoted inside another command's argument."""
    inners = []
    # heredoc body: pulled from the WHOLE command first -- the per-segment split below
    # would shred a multi-line heredoc body across several bogus segments before this ever
    # got a chance to see it whole.
    for m in _HEREDOC_RE.finditer(cmd):
        body = m.group(3)
        inners.append(body)
        inners.extend(inner_cmds(body))
    # quote-aware split: a raw ;/|/&&/||/newline split shreds a wrapper's quoted arg when
    # that arg itself contains one of these separators (e.g. vm.sh 'C=x; curl ... | grep
    # ...'). _segments() splits on the same separator set but only OUTSIDE quoted spans.
    for seg in _segments(cmd):
        toks = seg.strip()
        toks = _LOOP_PREFIX.sub("", toks)     # a for/while/if loop's `do ...`/`then ...` body
        prev = None
        while toks and toks != prev:          # peel sudo/env/timeout + their args (same as invokes)
            prev = toks
            m = _ASSIGN.match(toks)
            if m:
                toks = toks[m.end():].lstrip()
                continue
            w = _WRAP.match(toks)
            if w:
                toks = toks[w.end():].lstrip()
                toks = re.sub(r"^((-{1,2}\S+|\d+)\s+)*", "", toks)
        # -c / -e code-exec payload: recurse so a wrapper nested inside it still unwraps.
        m = _CODE_C_RE.match(toks)
        if m:
            inner = m.group(2)
            inners.append(inner)
            inners.extend(inner_cmds(inner))
            continue
        # vm.sh:  [bash ]<path>vm.sh '<cmd>'
        m = re.match(r"(?:bash\s+)?\S*vm\.sh\s+(['\"])(.+?)\1", toks, re.S)
        if m:
            inners.append(m.group(2)); continue
        # ssh:    [sshpass ...] ssh [opts] user@host '<cmd>'
        m = re.match(r"(?:sshpass\b.*?\s)?ssh\b[^\n]*?\s\S+@\S+\s+(['\"])(.+?)\1", toks, re.S)
        if m:
            inners.append(m.group(2)); continue
        # wsl:    wsl [...] -- <cmd>
        m = re.match(r"wsl\b.*?\s--\s+(.+)", toks, re.S)
        if m:
            inners.append(m.group(1).strip()); continue
    return inners


def _response_text(data):
    r = data.get("tool_response")
    if r is None:
        return ""
    if isinstance(r, str):
        return r
    try:
        return json.dumps(r)[:MAX_BLOB]
    except Exception:
        return str(r)[:MAX_BLOB]


def fingerprint_records(blob):
    """Return up to MAX_HITS (label, spec) tuples matched from playbook.json. The label is
    the cleaned first fingerprint token; spec is the raw playbook record (skills/tools/refs/
    tests). Backs the routing display (fingerprint_hits)."""
    try:
        import _engagement
        pb = os.path.join(_engagement.VAULT, "scripts", "playbook.json")
        fps = json.load(open(pb, encoding="utf-8"))["fingerprints"]
    except Exception:
        return []
    out = []
    for key, spec in fps.items():
        try:
            if not re.search(key, blob, re.IGNORECASE):
                continue
        except re.error:
            continue
        label = key.split("|")[0].replace("\\b", "")   # clean regex tokens for display
        out.append((label, spec))
        if len(out) >= MAX_HITS:
            break
    return out


EXCERPT_MAX_LINES = 28
# Ranked: a BYPASS section first. Bypass tables (alternate loopback encodings, parser quirks)
# are the exact thing that gets re-derived from memory; a payload list is long and more easily
# recalled. Falls back down the list when a page has no bypass section.
_EXCERPT_RANK = (r"bypass", r"payload|example", r"exploit|attack|abuse", r"escalat|technique")


def _wiki_index():
    """slug -> best path, over wiki/**.md. On a duplicate basename (payloads/xss.md vs
    techniques/web/xss.md -- ~13 such pairs exist) keep the LARGEST file: the substantive
    twin. A plain dict assignment here silently dropped one of every pair and was a real bug
    in wiki-wiring-audit.py, so do not reintroduce it."""
    idx = {}
    try:
        import _engagement
        root = os.path.join(_engagement.VAULT, "wiki")
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                if not fn.endswith(".md"):
                    continue
                full = os.path.join(dirpath, fn)
                slug = fn[:-3]
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                prev = idx.get(slug)
                if prev is None or size > prev[0]:
                    idx[slug] = (size, full)
    except Exception:
        return {}
    return {k: v[1] for k, v in idx.items()}


def _wiki_excerpt(slugs):
    """Inline the mapped wiki knowledge INSTEAD of telling the model to go look it up. Returns
    (text, [rel_paths]) -- a bounded excerpt of the first bypass/payload/exploit-ish section of
    the first resolvable page, or that page's opening prose if it has no such section.

    WHY inline rather than nudge: the recurring drift is not that the lookup is hard to find,
    it is that complying costs a detour and recalling from memory feels cheaper mid-exploit. A
    page that is already in context cannot be skipped (observed live: an SSRF box where the
    documented case-variation/decimal/octal loopback bypass table was re-derived by hand)."""
    idx = None
    for slug in slugs:
        if idx is None:
            idx = _wiki_index()
        s = str(slug).strip().removesuffix(".md")
        path = idx.get(s)
        if not path and "/" in s:
            # refs are written both ways in playbook.json ("ssrf" and "payloads/ssrf"); a
            # path-form ref must resolve to that exact page, not to whichever basename twin
            # the index happens to prefer.
            try:
                import _engagement
                cand = os.path.join(_engagement.VAULT, "wiki", s + ".md")
                path = cand if os.path.isfile(cand) else idx.get(s.rsplit("/", 1)[-1])
            except Exception:
                path = None
        if not path:
            continue
        try:
            txt = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        body = re.sub(r"\A---\n.*?\n---\n", "", txt, count=1, flags=re.S)   # drop frontmatter
        lines = body.splitlines()
        start = None
        for pat in _EXCERPT_RANK:
            rx = re.compile(r"^(#{2,4})\s+.*\b(%s)\w*\b" % pat, re.I)
            start = next((i for i, ln in enumerate(lines) if rx.match(ln)), None)
            if start is not None:
                break
        if start is None:
            chunk = [ln for ln in lines if ln.strip()][:EXCERPT_MAX_LINES]
        else:
            level = len(re.match(r"^(#+)", lines[start]).group(1))
            chunk = [lines[start]]
            fenced = False
            for ln in lines[start + 1:]:
                if ln.lstrip().startswith("```"):
                    fenced = not fenced
                m = None if fenced else re.match(r"^(#{1,6})\s", ln)
                # break only on a SAME-or-higher-level heading, so a "## Bypasses" section
                # keeps its "### ..." children. Breaking on any heading returned the section
                # title plus a blank line and nothing else. Headings are only real OUTSIDE a
                # code fence: a `# comment` on the first line of a ```bash/```powershell block
                # is not a heading, and treating it as one truncated the excerpt to 2 lines on
                # any page whose payload section opens with a commented command (i.e. most).
                if m and len(m.group(1)) <= level:
                    break
                chunk.append(ln)
                if len(chunk) >= EXCERPT_MAX_LINES:
                    break
        try:
            import _engagement
            rel = os.path.relpath(path, _engagement.VAULT)
        except Exception:
            rel = path
        return "\n".join(chunk).rstrip(), rel
    return "", ""


def fingerprint_hits(blob):
    """Return up to MAX_HITS ROUTING lines ('<tech> detected -> load Skill(x) | run: <tools>')
    from playbook.json. Routing only: the named hunt skill owns the tests, payload arsenal,
    and cheatsheet reuse -- this hook surfaces the skill and the mapped tool, it does not
    prescribe methodology.

    The `tools` leg matters as much as `skills`: it was present in playbook.json from the
    start and went unread here, so a fingerprint that routed to hunt-sqli six times never
    once printed "sqlmap" while the bug was being hand-rolled with curl."""
    out = []
    for label, spec in fingerprint_records(blob):
        skills = spec.get("skills") or []
        sk = (" -> load " + ", ".join("Skill(%s)" % s for s in skills)) if skills else ""
        tools = spec.get("tools") or []
        tl = (" | run: " + ", ".join(tools)) if tools else ""
        out.append(f"  {label} detected{sk}{tl}")
    return out


# Framework-meta guard: a command that reads/edits the vault's OWN wiring/hook/playbook
# machinery is NOT target recon. Its output is full of playbook tokens (hunt-<class> skill
# names, fingerprint regexes, payload/technique page names) that would otherwise false-match
# the fingerprint router and get surfaced as a "discovered surface" (observed live: editing
# playbook.json / running apply-wiring falsely fingerprinted as deserialization/sqli). These
# tokens never appear in genuine target recon, so a plain presence check on the command is safe.
_FRAMEWORK_META = re.compile(
    r"playbook\.json|triggers\.json|wiki-wiring|apply-wiring|wiring-exempt|"
    r"recon-capture|hunt-trigger|scope-guard|engagement-init|"
    r"scripts/(?:playbook|wiki|gen_index|build_moc|wl-add|wiki-stage|check-hooks)|"
    r"skills/hooks|/vault-hooks/", re.IGNORECASE)


def _is_framework_meta(cmd):
    """True if the command operates on the vault's own framework machinery (playbook/hooks/
    wiki-wiring), so the fingerprint router must NOT treat its output as target recon.

    Delegates to the shared _meta helper (same regex, now also used by hunt-trigger); falls
    back to the local pattern if that import fails, so the guard stays fail-open."""
    try:
        import _meta
        return _meta.is_framework_meta(cmd)
    except Exception:
        return bool(_FRAMEWORK_META.search(cmd or ""))


def _emit(blocks):
    if not blocks:
        return
    try:
        import _telemetry
        _telemetry.hook("recon-capture", action="route")
    except Exception:
        pass
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n\n".join(blocks),
        }
    }))


def _is_exploit_cmd(cmd):
    """True if cmd (or an inner vm.sh/ssh/wsl-wrapped cmd) invokes an exploitation tool or a
    reverse-shell pattern -- past recon, into foothold/exploit."""
    for c in [cmd] + inner_cmds(cmd):
        if invokes(c, EXPLOIT_TOOLS) or _REVSHELL_RE.search(c):
            return True
    return False


GATE1_MAX = 3


def _gate1_state(d):
    """{skill: times_nudged} for this engagement. Replaces the old fire-once-per-ENGAGEMENT
    marker: one reminder for the whole box was trivially ridden past under momentum (observed
    live: six routed hunt-* skills, none invoked, on a box whose central bug was one of them).
    Per-SKILL and escalating up to GATE1_MAX is the smallest change that keeps nagging about
    the specific skill still being ignored without becoming noise."""
    try:
        return json.load(open(os.path.join(d, ".gate1-nudged.json"), encoding="utf-8"))
    except Exception:
        return {}


def _gate1_record(d, skill, n):
    st = _gate1_state(d)
    st[skill] = n
    try:
        json.dump(st, open(os.path.join(d, ".gate1-nudged.json"), "w", encoding="utf-8"))
    except OSError:
        pass


def _gate1_unmet(d):
    """(skill, page_or_None, nudge_number) for the highest-priority routed hunt skill that is
    STILL unsatisfied, else None. Every claim it returns is backed by `.events.jsonl`, never
    inferred: `route` events say what was routed, `tool` events carry the Skill name invoked
    and (since the tool-telemetry wiki field) the wiki page read. A skill counts as satisfied
    once it was invoked OR any wiki page was read after it was routed -- reading the mapped
    page IS the point, the skill is only the vehicle."""
    routed, invoked, read_any = [], set(), False
    try:
        with open(os.path.join(d, ".events.jsonl"), encoding="utf-8") as fh:
            for ln in fh:
                try:
                    e = json.loads(ln)
                except Exception:
                    continue
                if e.get("kind") == "route" and e.get("routed"):
                    if e["routed"] not in routed:
                        routed.append(e["routed"])
                elif e.get("kind") == "tool":
                    if e.get("skill"):
                        invoked.add(e["skill"])
                    if e.get("wiki"):
                        read_any = True
    except Exception:
        return None
    if read_any:
        return None
    st = _gate1_state(d)
    for s in routed:
        if s in invoked:
            continue
        n = int(st.get(s, 0)) + 1
        if n <= GATE1_MAX:
            page = None
            try:
                import _engagement
                sk = os.path.join(_engagement.VAULT, "skills", "hunt", s, "SKILL.md")
                m = re.search(r"Primary page:\s*\[\[([^\]]+)\]\]",
                              open(sk, encoding="utf-8", errors="ignore").read())
                if m:
                    page = _wiki_index().get(m.group(1).strip())
                    page = os.path.basename(page) if page else None
            except Exception:
                page = None
            return s, page, n
    return None


def _weaponize_undone(d):
    """GATE 1 signal: True iff the active killchain.md has a '## 2. Weaponize' section that
    has open '[ ]' items but NO '[~]'/'[x]' -- i.e. exploitation is starting before the
    wiki/CVE weaponization step. Fail-closed to False (no nudge) if the board or section is
    absent/unreadable, so this never fires spuriously."""
    try:
        txt = open(os.path.join(d, "killchain.md"), encoding="utf-8", errors="ignore").read()
    except OSError:
        return False
    m = re.search(r"^##\s+2\.\s+Weaponize\b.*?(?=^##\s+\d|\Z)", txt, re.M | re.S)
    if not m:
        return False
    body = m.group(0)
    return "[x]" not in body and "[~]" not in body and "[ ]" in body


_CHECKLIST_RE = re.compile(r"^\s*-\s*\[[ x~!\-]\]", re.I | re.M)


def _board_never_built(d):
    """GATE signal: True iff killchain.md EXISTS but carries no real board content -- no
    checklist item (`- [ ]`/`[x]`/`[~]`/`[!]`/`[-]`) AND no populated table data row. This is
    the 'campaign board was never built' state: `campaign.py board` was never run, so the 4a
    table + recon checklist are still the bare stub. Fail-closed to False (no nudge) when the
    board is absent/unreadable OR has any content, so it never fires spuriously. A MISSING
    killchain is deliberately NOT this case (a non-campaign engagement, board command N/A)."""
    p = os.path.join(d, "killchain.md")
    if not os.path.isfile(p):
        return False
    try:
        txt = open(p, encoding="utf-8", errors="ignore").read()
    except OSError:
        return False
    if _CHECKLIST_RE.search(txt):
        return False
    try:
        import _engagement
        if _engagement._parse_table(p):   # any populated (non-header/separator) data row
            return False
    except Exception:
        pass
    return True


_LOOP_RE = re.compile(r"\bfor\b[^\n]*\bin\b|\bwhile\b[^\n]*\bdo\b|\bseq\b\s+\d", re.I)
_FETCH_RE = re.compile(r"\b(?:curl|wget)\b", re.I)
_THREADED_RE = re.compile(r"xargs\s+-\S*[pP]|\bparallel\b|\bffuf\b|\bferoxbuster\b", re.I)


def _is_serial_enum_loop(cmd):
    """A shell loop fetching URLs one-at-a-time (for/while/seq + curl/wget) that is NOT already
    threaded (xargs -P / parallel / ffuf / feroxbuster). This is the exact serial-vs-parallel
    drift: a serial curl enumeration where a threaded ffuf sweep belongs."""
    return bool(_LOOP_RE.search(cmd) and _FETCH_RE.search(cmd) and not _THREADED_RE.search(cmd))


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd:
        return

    # active engagement dir (used by the OOB correlation)
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        _engagement = None
        d = None

    blocks = []

    # 0. OOB callback auto-correlation: flip a waiting oob.md row to HIT when its token
    #    appears in this command's output. Runs on EVERY command, INCLUDING a cat/grep/rg
    #    poll of a saved OAST/Collaborator log (the most common poll method), so it is
    #    placed BEFORE the doc-command skip below.
    if d and _engagement:
        blob_oob = cmd + "\n" + _response_text(data)
        flipped = []
        for row in _engagement.oob_rows(d):
            if row.get("status", "").strip().lower() not in ("waiting", ""):
                continue
            token = (row.get("token", "") or "").strip()
            if token and len(token) >= 4 and token in blob_oob:
                if _engagement.flip_oob_status(d, token, "HIT",
                                               source="callback " + time.strftime("%Y-%m-%d")):
                    flipped.append(row.get("sink", token) or token)
        if flipped:
            blocks.append(
                "OOB HIT auto-correlated -- callback landed for: " + "; ".join(flipped[:4])
                + ". Gate passed: scaffold + validate the FIND now (oob.md row is HIT)."
            )

    # GATE 1 nudge (fire-once per engagement, advisory, fail-open): an exploit-shaped command
    # while killchain.md Weaponize shows no progress means jumping to exploitation without the
    # wiki/CVE lookup. Framework-meta commands are exempt. This is the only ENFORCEMENT the
    # board's GATE lines get -- one cheap reminder, not a block.
    if d and _engagement and not _is_framework_meta(cmd):
        if _is_exploit_cmd(cmd) and _weaponize_undone(d):
            unmet = _gate1_unmet(d)
            if unmet:
                skill, page, n = unmet
                proof = ["Skill(%s) was routed for this target and has never been invoked" % skill]
                if page:
                    proof.append("%s has never been opened" % page)
                blocks.append(
                    "GATE 1 (wiki-first) [%d/%d]: an exploit-shaped command just ran, but %s. "
                    "Load Skill(%s) now (its ## Wiki map names the pages), or say in ONE line "
                    "why it is irrelevant here -- do not hand-roll from memory."
                    % (n, GATE1_MAX, "; and ".join(proof), skill))
                _gate1_record(d, skill, n)
            else:
                # Fallback to the original generic, fire-once-per-engagement reminder. Without
                # it a box where the router never fingerprinted anything (so there is no routed
                # skill to escalate on) would get NO wiki-first reminder at all -- the per-skill
                # gate above must add coverage, never replace it.
                marker = os.path.join(d, ".gate1-nudged")
                if not os.path.exists(marker):
                    blocks.append(
                        "GATE 1 (wiki-first): exploiting, but killchain.md Weaponize has no "
                        "progress. Query the wiki for this tech/CVE first (Skill(arsenal) / "
                        "qmd_query), pull the payload from wiki/payloads/, mark the Weaponize "
                        "item, THEN exploit.")
                    try:
                        open(marker, "w").close()
                    except OSError:
                        pass

    # board-never-built nudge (fire-once per engagement, advisory, fail-open): an exploit-shaped
    # command while killchain.md has NO board content (checklist empty + 4a table empty) means the
    # campaign board was never generated. Skipping `campaign.py board` loses foothold-recording,
    # vm-rsh routing, and the G3 typed-evidence gate. Framework-meta commands are exempt.
    if d and _engagement and not _is_framework_meta(cmd):
        marker = os.path.join(d, ".board-nudged")
        if not os.path.exists(marker) and _is_exploit_cmd(cmd) and _board_never_built(d):
            blocks.append(
                "BOARD NOT BUILT: an exploit-shaped command ran but killchain.md has no board rows "
                "-- the campaign board was never generated. Run `python3 scripts/campaign.py board` "
                "first: skipping it loses foothold-recording, vm-rsh routing, and the G3 typed-"
                "evidence gate.")
            try:
                open(marker, "w").close()
            except OSError:
                pass

    # serial-enumeration nudge (fire-once per engagement, advisory): a for/while/seq + curl loop
    # fetches one URL at a time -- the recurring serial-vs-parallel drift that turns a 10-min box
    # into 40. Nudge to fan out with a threaded ffuf sweep.
    if d and _engagement and not _is_framework_meta(cmd):
        marker = os.path.join(d, ".serial-enum-nudged")
        if not os.path.exists(marker) and _is_serial_enum_loop(cmd):
            blocks.append(
                "SERIAL ENUMERATION: a for/while/seq + curl loop fetches one URL at a time (slow). "
                "Fan out instead -- ffuf -t 80 over the range (e.g. `seq -f %04g 0 9999` as -w) or "
                "xargs -P50. Parallel discovery is the 10-min-vs-40-min difference.")
            try:
                open(marker, "w").close()
            except OSError:
                pass

    # recon-completeness reflex (coverage, not methodology): record which discovery axes ran
    # (content-discovery + nuclei), and while EITHER is missing, nudge on each web exploit/probe --
    # ESCALATING, not fire-once: two boxes ignored a single nudge and reached foothold with
    # ffuf/nuclei never run. Requires BOTH axes because "nuclei launched but never
    # read" and "content ran but nuclei didn't" are the observed gaps. Bounded to _RECON_GAP_CAP.
    if d and _engagement and not _is_framework_meta(cmd):
        try:
            rec = os.path.join(d, ".recon-tools")
            for axis, pat in (("content", _DISCOVERY_TOOLS), ("nuclei", r"nuclei")):
                if _invokes_any(cmd, pat):
                    with open(rec, "a", encoding="utf-8") as fh:
                        fh.write(axis + "\n")
            ran = open(rec, encoding="utf-8", errors="ignore").read() if os.path.exists(rec) else ""
            missing = [a for a in ("content", "nuclei") if a not in ran]
            # gate the NUDGE (not the recording) on an unsolved box: recon completeness is moot
            # once the box is owned, so a post-solve curl should not re-nudge.
            if missing and _invokes_any(cmd, _WEB_ACTIVITY) and not _engagement.is_solved(d):
                capf = os.path.join(d, ".recon-gap-fires")
                n = 0
                if os.path.exists(capf):
                    try:
                        n = int((open(capf).read().strip() or "0"))
                    except ValueError:
                        n = 0
                if n < _RECON_GAP_CAP:
                    with open(capf, "w") as fh:
                        fh.write(str(n + 1))
                    sharper = (" [reminder %d/%d]" % (n + 1, _RECON_GAP_CAP)) if n else ""
                    blocks.append(
                        "RECON COMPLETENESS: web activity but discovery is incomplete (missing: "
                        + ", ".join(missing) + "). A hidden route/param/CVE is often the intended "
                        "path -- launch ffuf/feroxbuster (content) + nuclei (CVE) in parallel tmux "
                        "tabs (scripts/vm-scan.sh) and READ their output before concluding no web "
                        "vuln." + sharper)
        except Exception:
            pass

    # web-evidence reflex (capture, not methodology): a web surface must be RENDERED and its HTML
    # SOURCE saved as it is first explored. Record which axes ran (render / source); while EITHER is
    # missing on an unsolved box with web activity, nudge -- ESCALATING+capped like recon-completeness.
    # Fixes the recurring "recon scan cards but no rendered page and no saved source" evidence gap.
    if d and _engagement and not _is_framework_meta(cmd):
        try:
            blob_cap = "\n".join([cmd] + inner_cmds(cmd))
            recw = os.path.join(d, ".web-cap")
            for axis, rx in (("render", _WEB_RENDER_RE), ("source", _WEB_SOURCE_RE)):
                if rx.search(blob_cap):
                    with open(recw, "a", encoding="utf-8") as fh:
                        fh.write(axis + "\n")
            ranw = open(recw, encoding="utf-8", errors="ignore").read() if os.path.exists(recw) else ""
            missing = [a for a in ("render", "source") if a not in ranw]
            if missing and _invokes_any(cmd, _WEB_ACTIVITY) and not _engagement.is_solved(d):
                capf = os.path.join(d, ".web-cap-fires")
                n = 0
                if os.path.exists(capf):
                    try:
                        n = int((open(capf).read().strip() or "0"))
                    except ValueError:
                        n = 0
                if n < _WEB_CAP_CAP:
                    with open(capf, "w") as fh:
                        fh.write(str(n + 1))
                    sharper = (" [reminder %d/%d]" % (n + 1, _WEB_CAP_CAP)) if n else ""
                    blocks.append(
                        "WEB EVIDENCE: web activity but the surface is not captured (missing: "
                        + ", ".join(missing) + "). As you first open each web page, RENDER it "
                        "(scripts/capture.sh web <eng> <slug> <url>) AND save its HTML SOURCE "
                        "(curl -s <url> > poc/<slug>-source.html) -- scan cards are not a page "
                        "render or source." + sharper)
        except Exception:
            pass

    # screenshot-on-finding reflex (capture, not methodology): when a finding lands in the OUTPUT
    # -- a flag read or a shell/privesc `id` -- nudge Skill(screenshot) of the deliberate state.
    # Fires PER DISTINCT finding (dedup by the full matched value), NOT once-per-engagement:
    # a nested multi-level chain got under-shot because the old fire-once nudge planted the discipline
    # only at level 1. A repeated `id` as the same uid dedups to one nudge; each new flag re-fires.
    if d and _engagement:
        try:
            raw = _response_text(data)
            m = _FINDING_RE.search(raw[:MAX_BLOB]) if raw else None
            if m:
                import hashlib
                sig = hashlib.sha1(m.group(0).lower().encode()).hexdigest()[:12]
                seenf = os.path.join(d, ".shot-nudged")
                seen = (open(seenf, encoding="utf-8", errors="ignore").read().split()
                        if os.path.exists(seenf) else [])
                if sig not in seen:
                    with open(seenf, "a", encoding="utf-8") as fh:
                        fh.write(sig + "\n")
                    blocks.append(
                        "FINDING landed -> Skill(screenshot) the live exploited/authed STATE now "
                        "(the flag in place, the payload firing, or the shell via --tmux) to poc/. "
                        "Capture at EACH success as it lands, not at the end -- a transient state "
                        "cannot be re-shot after this turn.")
        except Exception:
            pass

    # RCE -> reverse-shell -> STABILIZE reflex (fire-once per engagement, advisory, fail-open).
    # An `id` naming a service acct = code exec landed. Recurring drift on web-RCE boxes: keep
    # hand-poking one-shot payloads / ride an unstabilized `nc` shell instead of standing up a proper
    # session -- so post-ex is un-driveable and invisible to the operator. Nudge ONCE toward a real
    # stabilized shell. The ctf-box skill carries this discipline but the ctf-WORKFLOW driver did
    # not load it, so the hook is the safety net that fires regardless of which skill is active.
    if d and _engagement:
        try:
            if _is_rce_landing(_response_text(data)):
                seenr = os.path.join(d, ".rce-shell-nudged")
                if not os.path.exists(seenr):
                    open(seenr, "a").close()
                    blocks.append(
                        "RCE / code-exec confirmed (`id` shows a service account). If this came "
                        "from a web RCE or an unstabilized `nc` shell, STOP hand-poking one-liners: "
                        "(1) pop a reverse shell into tmux -- bash scripts/vm-scan.sh --win shell "
                        "<eng> <target> 'nc -lvnp <port>', then fire the shell via the RCE; "
                        "(2) STABILIZE it at once -- bash scripts/vm-stabilize.sh --win shell <eng> "
                        "(pty + job control + window size), or prefer pwncat-cs / an msf "
                        "multi-handler over a raw nc; (3) drive it with bash scripts/vm-rsh.sh "
                        "--win shell <eng> '<cmd>'. See Skill(ctf-box) Phase 3 (Deliver).")
        except Exception:
            pass

    # WIDEN-THE-SURFACE reflex (fire-once, advisory, fail-open). Grinding web recon/fetches on one
    # host with NO foothold is the recurring 40-min drift: re-probing a dead surface (a parameterized
    # login, an image-only upload) instead of enumerating a NEW surface class. After WIDEN_AT web
    # probes with no foothold, nudge ONCE to widen (userdir /~, vhost-by-redirect-location, another
    # port/vhost, source-read) or work the board. The two surface classes named are the exact ones
    # that cost a real box ~40 min (an Apache userdir + a vhost that 302s to a non-default Location).
    if d and _engagement and _is_web_probe(cmd):
        try:
            seenw = os.path.join(d, ".widen-nudged")
            footholded = os.path.exists(os.path.join(d, ".rce-shell-nudged")) or _state_has_foothold(d)
            if not os.path.exists(seenw) and not footholded:
                cf = os.path.join(d, ".web-probe-count")
                try:
                    n = int(open(cf, encoding="utf-8").read().strip() or "0")
                except Exception:
                    n = 0
                n += 1
                with open(cf, "w", encoding="utf-8") as fh:
                    fh.write(str(n))
                if n >= WIDEN_AT:
                    open(seenw, "a").close()
                    blocks.append(
                        "WIDEN THE SURFACE: %d web probes on this engagement with no foothold. A "
                        "dead OBVIOUS surface (a parameterized login, an image-only upload) is the "
                        "signal to enumerate a NEW surface class, not to keep grinding it: "
                        "(1) Apache userdir -- ffuf 'http://T/~FUZZ/' with a usernames list (NO dir "
                        "wordlist carries ~-prefixed names, so ferox/ffuf structurally miss it); "
                        "(2) vhost by redirect-LOCATION -- ffuf -mc all then diff the redirectlocations "
                        "(a real vhost 302s ELSEWHERE; -fc 302 / -ac hides it); (3) another port or "
                        "the second vhost's OWN app; (4) source-read (LFI/.git/backup) before brute. "
                        "Or run `python3 scripts/campaign.py board` and work it depth-first." % n)
        except Exception:
            pass

    # 1. fingerprint router. Pure documentation/discussion commands (a comment, echo, a
    #    cat/grep/rg of some file) never invoke a probe tool, so the router is pointless on
    #    them -- skip it (OOB correlation above already ran). command-position match: the
    #    tool must be invoked, not just named in a path/arg; also check inside vm.sh/ssh/wsl
    #    bridge wrappers. Skip framework-meta commands (editing/reading the vault's own
    #    playbook/wiki/hooks emits playbook tokens that would false-fingerprint).
    if not re.match(r"\s*(#|echo\b|printf\b|cat\b|grep\b|rg\b)", cmd, re.IGNORECASE):
        _inners = inner_cmds(cmd)
        is_probe = invokes(cmd, PROBE_TOOLS) or next(
            (m for ic in _inners if (m := invokes(ic, PROBE_TOOLS))), None)
        if is_probe and not _is_framework_meta(cmd):
            blob = (cmd + "\n" + _response_text(data))[:MAX_BLOB]
            lines = fingerprint_hits(blob)
            if lines:
                routed_block = (
                    "Tech fingerprinted (playbook.json) -> load the hunt Skill named below; it "
                    "carries the wiki-first, tooling-first, tests, and payload steps:\n"
                    + "\n".join(lines)
                )
                # GATE 1, satisfied FOR you: inline the mapped wiki section rather than telling
                # the model to go fetch it. Cheapest possible compliance -- the documented
                # bypasses/payloads are in context before the first exploit attempt.
                try:
                    _slugs = []
                    for _lbl, _spec in fingerprint_records(blob):
                        _slugs.extend(_spec.get("refs") or [])
                    _ex, _rel = _wiki_excerpt(_slugs)
                    if _ex:
                        routed_block += ("\n\n--- wiki (already looked up for you) :: %s ---\n%s"
                                         "\n--- read the full page before hand-rolling ---"
                                         % (_rel, _ex))
                except Exception:
                    pass
                blocks.append(routed_block)
                # log routed hunt skills so eval_metrics can flag any never invoked (drift signal)
                if d:
                    try:
                        import _telemetry
                        for _lbl, _spec in fingerprint_records(blob):
                            for _s in (_spec.get("skills") or []):
                                if str(_s).startswith("hunt-"):
                                    _telemetry.log_event("route", d=d, routed=_s)
                    except Exception:
                        pass

    _emit(blocks)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
