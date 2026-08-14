---
name: wiki-recon
description: External recon and OSINT pipeline - subdomain enum, live host discovery, URL crawl, JS analysis, nuclei scan. Outputs to Attack-surface.md and scope/. Queries wiki before each phase. Use when starting recon on any target.
---

# Wiki-Recon: External Recon Pipeline

## Phase 0: Wiki Query (MANDATORY)
```
qmd_query "recon subdomain enumeration" via wiki-search MCP -> read matching pages.
qmd_query "OSINT external attack surface" -> apply known techniques.
```
If no matching page: proceed. Do not block on missing wiki coverage. Dorks to find exposed/vulnerable assets: `wiki/cheatsheets/recon-dorks.md`; attack paths once in: `wiki/cheatsheets/attack-chains.md`.

## Scope Check
- Confirm target domain(s) are in scope
- Read Attack-surface.md - skip hosts already fully documented
- Read Deadends.md - skip recon paths already exhausted

## Recon Pipeline

Tool-first: `subfinder`/`assetfinder` for subdomains, `httpx` for live-host probing, `katana`/`gau` for URLs, `ffuf` for content discovery, `nuclei` for templated checks. The crt.sh `curl` below is the one hand request kept (a passive source with no tool wrapper); everywhere else lean on the tool, not a curl loop.

### Stage 1: Subdomain Discovery
```bash
TARGET="target.com"
RECON_DIR="poc/recon/$TARGET"
mkdir -p $RECON_DIR

# Passive sources
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $RECON_DIR/subs.txt

subfinder -d $TARGET -silent | tee -a $RECON_DIR/subs.txt
assetfinder --subs-only $TARGET | tee -a $RECON_DIR/subs.txt
sort -u $RECON_DIR/subs.txt -o $RECON_DIR/subs.txt
```

### Stage 2: Live Host Discovery
```bash
cat $RECON_DIR/subs.txt | dnsx -silent | \
  httpx -silent -status-code -title -tech-detect | tee $RECON_DIR/live.txt
```

On any TLS host from Stage 2, dump the cert SANs early; a hidden vhost none of the above discovers can be listed only in the Subject Alternative Name, see [[cdn-waf-bypass]].

### Stage 3: URL Crawl + Historical
```bash
cat $RECON_DIR/live.txt | awk '{print $1}' | \
  katana -d 3 -jc -kf all -silent | tee $RECON_DIR/urls.txt
echo $TARGET | waybackurls | tee -a $RECON_DIR/urls.txt
gau $TARGET --subs | tee -a $RECON_DIR/urls.txt
sort -u $RECON_DIR/urls.txt -o $RECON_DIR/urls.txt
```

### Stage 4: Nuclei Scan
```bash
nuclei -l $RECON_DIR/live.txt -t ~/nuclei-templates/ \
  -severity critical,high,medium -o $RECON_DIR/nuclei.txt
```

### Stage 5: Attack Surface Triage
```bash
# Content discovery on live hosts: OUR high-signal list first (non-obvious routes the crawl missed)
ffuf -c -u https://HOST/FUZZ -w scripts/wordlists/harness-paths.txt -e .php,.py -mc 200,301,302,401,403 -ac

# High-value URL patterns
cat $RECON_DIR/urls.txt | grep -E "\?.*=" | grep -E "url=|redirect=|src=|dest=|fetch=" > $RECON_DIR/ssrf_candidates.txt
cat $RECON_DIR/urls.txt | grep -E "\?.*=" | grep -E "id=|user_id=|order_id=|doc_id=" > $RECON_DIR/idor_candidates.txt
cat $RECON_DIR/urls.txt | grep -E "graphql|/gql|/graph" > $RECON_DIR/graphql_candidates.txt
cat $RECON_DIR/urls.txt | grep -E "upload|import|parse|convert|preview|render" > $RECON_DIR/upload_candidates.txt

# JS secret scanning
cat $RECON_DIR/urls.txt | grep "\.js$" | \
  xargs -I {} curl -sk {} | grep -E "(api_key|apikey|secret|token|password|credential).*['\"][A-Za-z0-9+/]{20,}" \
  > $RECON_DIR/js_secrets.txt
```

**READ each app `.js` / inline `<script>` / button `onclick` / `href` END-TO-END, do not stop at the grep.**
The secret-scan above only surfaces hardcoded keys; the *initial attack vector* (an AJAX handler POSTing to
an undocumented endpoint, a commented route, a hidden param) hides in code the grep filters out. Open every
first-party bundle and read it top to bottom, grep only to LOCATE inside a large file, then read the block.
A page that looks like a static template is often a dynamic app whose whole endpoint map lives in one JS file.

Run each scan in its own tmux tab on the VM (root, persistent), one tab per target: `bash scripts/vm-scan.sh <eng> <target> '<scan>'` (multi-web target -> `<target>-web-<ip-or-domain>`). Capture a live/finished tab with Skill(screenshot) `--tmux <eng>:<tab>` (use the `@NN` id or sanitized tab name it prints). Capture standalone tool output (nmap service surface, ffuf/feroxbuster hits, nuclei findings) as terminal-card PNGs via Skill(screenshot) `--term` for the Attack-surface evidence.

## Output to Attack-surface.md

For each discovered live host, add a row to the target's Attack-surface.md:

```markdown
| sub.target.com | 1.2.3.4 | [status] | - | [finding or notes] |
```

Add newly discovered hosts to `scope/` IP/domain lists.

Record recon progress in `targets/<eng>/Approach.md` Phase 1 items.

If nuclei finds CRITICAL or HIGH severity issues: create a FIND-XXX entry immediately.

**Distill to wiki (when confirmed):** if a novel subdomain takeover or recon-bypass technique is found, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/osint/web-attack-surface.md`. Promote later via `scripts/wiki-promote.py`.

## Context tools

<!-- auto-wired: documented tools to reach for; do not hand-roll -->
- [[amass]]
- [[subfinder]]
- [[dnsx]]
- [[gau]]
- [[gowitness]]
- [[wiki/tools/httpx]]
- [[katana]]
