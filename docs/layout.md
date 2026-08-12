# Directory layout (full annotated tree)

`CLAUDE.md` carries the compact top-level tree; this is the detailed per-file reference.

```
TORCH/
├── CLAUDE.md                    <- this file  (+ README.md, LICENSE)
├── targets/                     <- engagements (PRIVATE; client data only here, git-ignored)
│   ├── active.md                <- pointer: current engagement dir name
│   ├── scrub-terms.txt          <- private leak-check extras (not shipped)
│   └── <eng>/                   <- self-healed set (state,loot,Killchain,Approach,log,scope,walkthrough,eval,oob,hot,Vuln-index,Deadends) + ingest/ + poc/ (curated PoC shots) + Vulns/ (pentest)
├── wiki/
│   ├── index.md                 <- catalog of all wiki pages
│   ├── moc.md                   <- graph map-of-content (domain hubs; navigate here)
│   ├── overview.md              <- methodology map and coverage status
│   ├── techniques/              <- active-directory, cloud, web, osint, cracking, network,
│   │                              red-team, linux, exploit-dev, methodology, mobile-iot
│   ├── payloads/                <- per-vuln-class payload arsenal (hunt skills pull from here)
│   ├── tools/                   <- per-tool reference pages
│   ├── cheatsheets/             <- quick-reference command sheets
│   └── courses/  CTF/           <- course notes; challenge writeups
├── session/
│   ├── hot.md                   <- rolling 3-entry summary (auto-loaded at startup)
│   ├── log.md                   <- append-only audit trail
│   └── memory.md                <- long-term editorial patterns
├── docs/
│   ├── workflows.md             <- step-by-step workflow guide
│   ├── page-types.md            <- required sections per page type
│   ├── setup.md                 <- machine setup and path config
│   ├── virtual-machine.md       <- Kali attack VM + vm.sh SSH bridge; when/how to run tooling vs. targets
│   ├── sharing.md               <- client-data boundary; how to share safely
│   ├── conventions.md           <- cross-referencing, log format, style guide
│   ├── auto-triggers.md         <- what auto-fires (hooks, triggers.json, playbook) and when
│   └── layout.md                <- this file: full annotated directory tree
├── scripts/                     <- automation (self-documenting via docstrings): next_move,
│                                   status.py (on-demand engagement dashboard: phase/counts/evidence/deadends/moves),
│                                   wiki-query.sh (qmd CLI wiki-first fallback when the MCP drops),
│                                   wiki-eval.py (retrieval eval + regression gate over scripts/wiki-eval-gold.json: hit@3/hit@5/MRR; run --check before/after any qmd chunker/index change),
│                                   find-lint, lint-wiki, lint-md-tables.py (GFM table integrity), gen_index, build_moc, cve_feed, freshness,
│                                   check-hooks, check-leaks.sh, trigger-stats, wordlist-* (+wordlists/),
│                                   shot.py, capture.sh (one entrypoint, modes: ev=live cmd+url card / req=curl
│                                   request-response / tmux=real tmux-session card / burp=Burp Repeater PoC), vm-scan.sh, burp/ (burp-mcp-cli.py bridge + burp-transport.sh resolver + burp-scope-sync.py),
│                                   build-walkthrough.py (scaffold + auto-populate the walkthrough Evidence gallery),
│                                   playbook.json
├── setup/                       <- bootstrap.sh, install-hooks.sh (per-device hook reg), install-skills.sh, new-engagement.sh, new-research.sh, templates/<type>/ + templates/research/, burp/ (disable-lock.sh)
├── tests/                       <- pytest suite for engagement + wiki automation
├── skills/                      <- obsidian/ wiki/ research/ disclosure/
│   │                               claude-md-improver/ (offline fallback) + hooks/ (hook scripts)
│   ├── burp/                    <- hunt-burp (MCP driver) + screenshot-burp (Repeater PoC capture)
│   └── hunt/                    <- all hunt-* (except hunt-burp) + triage/evidence/coverage/ingest/next-move/
│                                   wiki-recon/nday/research-ingest/ctf-box/ctf-category/screenshot/learn + triggers.json
└── raw/
    ├── research/                <- CVE writeups/blogs/advisories + active research projects (<project>/ from new-research.sh; the research skill writes loop state here)
    ├── assets/                  <- screenshots and other non-text files (read-only)
    └── git/                     <- cloned repos (WSL path, not Windows mount)
```
