# Page types and frontmatter

Every wiki page starts with YAML frontmatter:

```yaml
---
title: "Page Title"
type: technique | tool | cheatsheet | course | target | overview
tags: []
phase: recon | enumeration | exploitation | post-exploitation | reporting   # for techniques (omit or pick one primary phase; avoid non-schema values such as `all`)
severity: critical | high | medium | low | info                             # for targets/findings
status: active | completed | on-hold                                        # for targets
date_created: YYYY-MM-DD
date_updated: YYYY-MM-DD
sources: []    # list of ingested slugs that contributed to this page, e.g. [cpts-sqli-fundamentals, ps-labs-sqli, thm-adv-sqli-advanced]
---
```

The `sources` list is the key token-saving field. Before reading a full wiki page to decide whether to update it, read only the frontmatter -- if the slug you're ingesting is already in `sources`, the page is up to date and can be skipped. Only read the full page content if you're going to update it.

### Meta pages (`overview` type outside `overview.md`)

Use `type: overview` with minimal `sources: []` for machine-readable operational files that are not methodologies: **`wiki/index.md`**, **`wiki/overview.md`** (still in `wiki/`); **`session/hot.md`**, **`session/log.md`**, **`session/memory.md`** (all in `session/`); and legal boilerplate imported next to technique material (example: **`wiki/techniques/disclaimer.md`**). Keep `wiki/overview.md` as the single methodology coverage map referenced by `docs/workflows.md`.

---

## technique pages (`wiki/techniques/`)

One page per attack technique or vulnerability class (e.g. SQL Injection, SSRF, Password Spraying, Kerberoasting).

Sections:
- **What it is**: 1-2 sentence definition.
- **How it works**: mechanism, or why the vulnerability exists.
- **Attack phases**: which pentest phase(s) this applies to.
- **Prerequisites**: what conditions must exist for this to be exploitable.
- **Methodology**: step-by-step exploitation approach.
- **Key payloads / examples**: concrete command examples and payload snippets in code blocks.
- **Bypasses and variants**: common WAF/filter bypasses, technique variations.
- **Detection and defence**: how defenders detect and mitigate this (useful for reporting).
- **Tools**: links to `[[tool]]` pages for tools used in this technique.
- **Sources**: which course modules or research articles cover this technique.

Update this page every time a new source adds depth, a new payload, or a bypass variant.

---

## tool pages (`wiki/tools/`)

One page per tool (e.g. Nmap, FFuf, SQLMap, Metasploit, Hydra, CrackMapExec, Burp Suite).

Sections:
- **Purpose**: what the tool does in one sentence.
- **Install / setup**: how to install or configure it.
- **Core usage**: the most important flags and invocation patterns.
- **Common use cases**: bulleted list of typical scenarios with example commands.
- **Tips and gotchas**: non-obvious behaviour, common mistakes.
- **Related techniques**: links to `[[technique]]` pages that use this tool.
- **Sources**: which course modules or docs cover this tool.

---

## cheatsheet pages (`wiki/cheatsheets/`)

Dense, command-focused quick reference. No prose explanations -- just commands, flags, and one-line annotations. Organised by task. Designed for copy-paste during an engagement.

Examples: `Nmap Cheatsheet`, `SQLi Payloads`, `Reverse Shell One-Liners`, `Password Cracking Commands`, `Active Directory Attacks`.

Format:
```
## Task or scenario

# short annotation
command --flags target
```

A cheatsheet is generated from technique and tool pages, not the other way around. When a technique or tool page is mature enough, offer to generate a cheatsheet from it.

---

## course pages (`wiki/courses/`)

One page per course or major module. Source material is looked up via `raw/manifest.md` (slug -> file paths).

Sections:
- **Course**: name and provider (e.g. HackTheBox CPTS, PortSwigger Academy).
- **Module**: which module or section this covers.
- **Summary**: what this module teaches in 3-5 sentences.
- **Key techniques covered**: links to `[[technique]]` pages.
- **Key tools covered**: links to `[[tool]]` pages.
- **Notable commands / payloads**: the most important practical examples from the module.
- **Gaps and questions**: what the module left unclear or what to research further.

---

## target pages (`targets/`)

One directory per engagement, `targets/<eng>/`, created by `bash setup/new-engagement.sh <name> <pentest|bugbounty|ctf>` and self-healed by the `engagement-init` hook. The `engagement_type` in `state.md` frontmatter drives the analyzer and self-heal. A ctf engagement scaffolds a lean upfront set (`state`, `loot`, `Approach`, `scope`, `Deadends` + `ingest/`/`poc/`); pentest/bugbounty scaffold the full set below, including `Killchain.md` and `log.md`. Root files (all git-ignored; client/engagement data lives ONLY here):

| File | Purpose |
|------|---------|
| `scope.md` | In/out-of-scope + RoE flags (`no_bruteforce`/`no_dos`/`passive_only`); read before any action |
| `state.md` | Host/service/access table (per-type entity columns); the primary target map |
| `loot.md` | Captured credentials + reuse map |
| `Killchain.md` | The evolving kill-chain: attack-path rows (chain notation) built from findings + the Confirmed-chain header (pentest/bugbounty core; a ctf's live chain lives in `state.md`'s `## Chain`/`## Status` sections instead) |
| `Approach.md` | The plan board: phase checklist + `### 4a` per-asset tested-class table + GATE lines |
| `Deadends.md` | Exhausted vectors + false positives, with reason; never re-run without new input |
| `Vuln-index.md` | Finding index by severity + attack chains + severity count table |
| `oob.md` | Out-of-band callback tracking (the blind-bug gate) |
| `log.md` | Append-only audit trail (terse) (pentest/bugbounty; a ctf box has no separate audit log) |
| `walkthrough.md` | Full copy-pasteable boot-to-root reproduction (scaffolded upfront for pentest/bugbounty; self-creates at close-out for every type if missing) |
| `eval.md` | Per-engagement AGENT self-assessment (tokens/time/drift); `close-out.py` auto-writes its Metrics block at SOLVED, `Skill(learn)` fills the rest (scaffolded upfront for pentest/bugbounty; on-demand for ctf) |
| `hot.md` | Rolling per-engagement session cache |

**`Vulns/` subdirectory** (pentest): each finding is a `FIND-NNN-SEVERITY-title.md`. `find-lint` skips `Skipped*` / `False*` dirs, so group as: confirmed at the root or `Completed/`, `Research/` for in-progress, `False Positive/` for disproven, `Skipped-but-usefull/` for out-of-scope-but-noted.

**Other subdirectories:** `ingest/` (raw tool output for the ingest skill), `poc/` (PoC scripts + screenshot cards), `scope/` (IP/domain/wordlists), `reports/` (report drafts).

See `targets/TARGETS.md` for the full engagement playbook: FIND naming, severity definitions, and the wiki integration rule.

---

## overview page (`wiki/overview.md`)

A methodology map and coverage status for the entire wiki. Updated after every ingest.

Sections:
- **Methodology coverage**: which phases are well-documented vs. sparse (recon, enumeration, exploitation, post-exploitation, reporting).
- **Technique coverage**: which technique pages exist and which are stubs or missing.
- **Active targets**: brief status of each target page.
- **Gaps**: techniques or tools with no page yet that have appeared in sources.
- **Next steps**: highest-value ingests or technique pages to build next.
