#!/usr/bin/env python3
"""Suggest NEW generic web path/param tokens for the harness wordlists.

Mines targets/*/ (Killchain, walkthrough, state, log, Vuln-index) for path segments and
param names that are NOT already in scripts/wordlists/harness-{paths,params}.txt, then
prints them for review. READ-ONLY: it never writes the lists (you curate via wl-add.sh),
so client-specific branding stays out of the tracked, shippable wordlist.

Leak-safe: drops anything that is an IP, a scope host/domain (any engagement), an
engagement dir name, a flag, a filesystem path (etc/home/root/...), or an opaque
per-object identifier (UUID / long hex / digit-heavy ID -- IDOR/customer IDs).

Usage: python3 scripts/wordlist-suggest.py [--top N]
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.environ.get("CLAUDEBRAIN_VAULT") or os.path.dirname(HERE)
WL = os.path.join(HERE, "wordlists")
TARGETS = os.path.join(VAULT, "targets")

# filesystem dirs / sensitive filenames -> never a web-route suggestion
FS_STOP = {
    "etc", "root", "var", "proc", "sys", "dev", "bin", "sbin", "lib", "lib64", "mnt",
    "boot", "run", "lost+found", "passwd", "shadow", "group", "gshadow", "hosts",
    "hostname", "sudoers", "crontab", "bashrc", "bash_history", "id_rsa", "id_ed25519",
    "authorized_keys",   # home/tmp/opt/media/www etc. are allowed (legit web routes)
}
# markup / prose noise that leaks in from md + html dumps
NOISE = {
    "http", "https", "html", "body", "div", "span", "head", "header", "footer", "title",
    "style", "script", "meta", "link", "form", "input", "button", "the", "and", "for",
    "with", "this", "that", "from", "via", "txt", "com", "org", "net", "www", "localhost",
    "tcp", "udp", "icmp", "true", "false", "null", "none", "see", "use",
}
PATH_SEG = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,38}$")
PARAM_RE = re.compile(r"^[a-z][a-z0-9_]{1,24}$")
IP_ISH = re.compile(r"\d{1,3}\.\d{1,3}")
# opaque per-object identifiers (UUIDs, long hex/alnum IDs) are client-specific
# (IDOR/customer/object IDs) -> never a generic route, though PATH_SEG would accept them
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX_RE = re.compile(r"[0-9a-f]+$")
# a dotted token is only kept if it's a single name.<web-ext> file (so domains like
# api.example.com / login.example.org / www.x.tv are dropped, but preview.php / secret.config stay)
WEB_EXT = {"php", "py", "asp", "aspx", "jsp", "json", "xml", "yml", "yaml", "txt", "config",
           "env", "bak", "old", "sql", "do", "action", "cgi", "html", "js", "ini", "conf"}


def _read_lines(p):
    try:
        return [l.strip() for l in open(p, encoding="utf-8", errors="ignore") if l.strip()]
    except OSError:
        return []


def existing(name):
    return set(_read_lines(os.path.join(WL, name)))


def deny_markers():
    """Engagement dir names + every scope host/domain label, lowercased."""
    deny = set()
    if not os.path.isdir(TARGETS):
        return deny
    for eng in os.listdir(TARGETS):
        d = os.path.join(TARGETS, eng)
        if not os.path.isdir(d):
            continue
        deny.add(eng.lower())
        for part in re.split(r"[_\-.]", eng.lower()):
            if len(part) > 2:
                deny.add(part)
        for line in _read_lines(os.path.join(d, "scope.md")):
            for tok in re.findall(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{2,}", line):
                t = tok.lower()
                deny.add(t)
                for lbl in t.split("."):           # subdomain/host labels
                    if len(lbl) > 2 and not lbl.isdigit():
                        deny.add(lbl)
    return deny


def _opaque_id(t):
    """True if t looks like a per-object identifier (not a reusable route):
    a UUID, a >=12-char hex blob, or a >=12-char digit-heavy token."""
    if UUID_RE.match(t):
        return True
    core = t.replace("-", "")
    if len(core) >= 12 and HEX_RE.match(core):
        return True
    if len(t) >= 12 and sum(c.isdigit() for c in t) / len(t) > 0.4:
        return True
    return False


def clean(tok, deny, kind):
    t = tok.strip().lower().strip("/")
    if not t or IP_ISH.search(t) or t.replace(".", "").isdigit():
        return None
    if kind == "path" and _opaque_id(t):                   # UUID / hex object-id leak guard
        return None
    if any(x in t for x in ("flag", "thm", "ctf")):        # box/flag-specific
        return None
    if "." in t:                                            # drop domains; keep one name.<web-ext>
        parts = t.lstrip(".").split(".")
        if len(parts) != 2 or parts[1] not in WEB_EXT:
            return None
    if t in FS_STOP or t in NOISE or t in deny:
        return None
    if any(lbl in t for lbl in deny if len(lbl) >= 4):      # brand/scope label as substring
        return None
    rx = PARAM_RE if kind == "param" else PATH_SEG
    if not rx.match(t):
        return None
    return t


def mine():
    paths, params = {}, {}
    if not os.path.isdir(TARGETS):
        return paths, params
    deny = deny_markers()
    ign = set(_read_lines(os.path.join(WL, ".wl-ignore")))   # explicitly-rejected tokens
    have_p = existing("harness-paths.txt") | ign
    have_q = existing("harness-params.txt") | ign
    for eng in os.listdir(TARGETS):
        d = os.path.join(TARGETS, eng)
        if not os.path.isdir(d):
            continue
        blob = ""
        for f in ("Killchain.md", "walkthrough.md", "state.md", "log.md", "Vuln-index.md"):
            blob += "\n" + "\n".join(_read_lines(os.path.join(d, f)))
        # path segments: from URLs, /route notation, and *.php/.py files
        segs = []
        for m in re.findall(r"https?://[^\s/'\"]+(/[A-Za-z0-9_./?=&-]+)", blob):
            segs += re.split(r"[/?&=]", m)
        segs += re.findall(r"(?<![A-Za-z0-9])/([a-z][a-z0-9_.-]{2,})", blob)
        for fn in re.findall(r"\b([a-z0-9_-]{2,})\.(?:php|py|aspx|jsp|do|action|cgi)\b", blob):
            segs.append(fn)
        for s in segs:
            c = clean(s, deny, "path")
            if c and c not in have_p:
                paths[c] = paths.get(c, 0) + 1
        # param names
        for m in re.findall(r"[?&]([a-z][a-z0-9_]{1,24})=", blob):
            c = clean(m, deny, "param")
            if c and c not in have_q:
                params[c] = params.get(c, 0) + 1
        for m in re.findall(r'name="([a-z][a-z0-9_]{1,24})"', blob):
            c = clean(m, deny, "param")
            if c and c not in have_q:
                params[c] = params.get(c, 0) + 1
    return paths, params


def main():
    top = 40
    if "--top" in sys.argv:
        try:
            top = int(sys.argv[sys.argv.index("--top") + 1])
        except (ValueError, IndexError):
            pass
    paths, params = mine()
    if "--count" in sys.argv:                      # terse mode for the SessionStart surface
        print("%d %d" % (len(paths), len(params)))
        return
    if not paths and not params:
        print("wordlist-suggest: no new generic candidates from targets/.")
        return
    if paths:
        ranked = sorted(paths, key=lambda k: (-paths[k], k))[:top]
        print("NEW PATH candidates (review, then: scripts/wl-add.sh paths <w>...):")
        print("  " + " ".join(ranked))
    if params:
        ranked = sorted(params, key=lambda k: (-params[k], k))[:top]
        print("NEW PARAM candidates (review, then: scripts/wl-add.sh params <w>...):")
        print("  " + " ".join(ranked))
    print("(read-only; curate out client-specific branding before adding)")


if __name__ == "__main__":
    main()
