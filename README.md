# TORCH

```sh
	 )
    ( (
   ) ) (
  ( ( ) )       T   O   R   C   H
   ) (*)        ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    )|(         Targeted Offensive
     |          Recon & Compromise Harness
    |=|
    | |
    |_|
```

**An AI-powered penetration testing and bug-bounty knowledge base and automation harness for [Claude Code](https://claude.com/claude-code).** It turns an Obsidian vault into an opinionated offensive-security workflow: autonomous campaign drivers (`/pt-workflow`, `/bb-workflow`, `/ctf-workflow`) that run a whole engagement end to end, a searchable wiki of 500+ hacking technique pages, per-vulnerability "hunt" skills, deterministic hooks that fire the right skill at the right moment, and a state-first engagement model that stops you (and the model) from repeating work.

[![Built for Claude Code](https://img.shields.io/badge/built%20for-Claude%20Code-blueviolet.svg)](https://claude.com/claude-code)
[![Wiki pages](https://img.shields.io/badge/wiki-500%2B%20pages-brightgreen.svg)](wiki/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Tomas%20Zabukas-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/tomas-zabukas/)



TORCH is a red-team / bug-bounty second brain built on Andrej Karpathy's [LLM Wiki](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f) pattern: a persistent, AI-maintained knowledge base the model synthesizes each new source into over time, instead of re-deriving from raw documents on every query. Concretely, an offensive-security wiki, an agentic hunt-skill library, and a Model Context Protocol (MCP) search layer, wired together so Claude Code always checks the knowledge base before it attacks and never repeats a dead end. Think HackTricks or PayloadsAllTheThings, but indexed for semantic search and driven by an autonomous AI agent.

> **Authorized testing only.** Everything here assumes a legal engagement: a signed penetration test, a bug-bounty program in scope, or your own lab / CTF. You are responsible for staying in scope and within the rules of engagement.

If TORCH saves you time on an engagement, a [star](https://github.com/Encod3d-Sec/TORCH) helps other pentesters and bug-bounty hunters find it.

---

## Contents

- [Features](#features)
- [The knowledge base](#the-knowledge-base-500-pages-ship-with-the-repo)
- [What ships vs what stays private](#what-ships-vs-what-stays-private)
- [Requirements](#requirements)
- [Quickstart](#quickstart)
- [Plugins and MCP servers](#plugins-and-mcp-servers)
- [Layout](#layout)
- [The model underneath](#the-model-underneath)
- [Safety and boundaries](#safety-and-boundaries)
- [License](#license)

---

## Features

- **Autonomous engagement workflows** (`/pt-workflow`, `/bb-workflow`, `/ctf-workflow`): the headline capability, run a whole pentest, bug-bounty program, or boot-to-root box end to end with no operator approvals. A deterministic driver (`scripts/campaign.py`) owns pass state, builds a kill-chain board from recon, and prints the exact next action (which skill + tool) every turn, enforcing the wiki-first, tool-first, typed-evidence, and dead-end-first gates. Single agent, refuter-verified; the pentest flow delivers a client report. Verify the driver is wired up on a new machine with `/campaign-health`.
- **Wiki-first methodology.** 500+ markdown technique pages indexed by `qmd` for semantic and keyword search over an MCP server (`wiki-search`). Every hunt skill queries the wiki *before* attacking, so knowledge compounds instead of scattering.
- **Hunt skills** (`skills/hunt/hunt-*`): one per vulnerability class, XSS, SQLi, SSRF, IDOR, RCE, auth bypass, OAuth/SAML federation, deserialization, cloud (AWS/Azure/GCP), Active Directory, local Windows and macOS privilege escalation, API (OWASP API Top 10), LLM/AI, ICS/OT, request smuggling, cache poisoning, and more. Each is wiki-first, out-of-band-gated for blind bugs, and emits a uniform FIND finding schema.
- **Deterministic automation (hooks).** Plain Python that fires on Claude Code lifecycle events:
  - `hunt-trigger.py` (UserPromptSubmit) matches your prompt against `skills/hunt/triggers.json` and loads the matching hunt skill.
  - `recon-capture.py` (PostToolUse) fingerprints discovered tech against `scripts/playbook.json`, routes to targeted tests, and auto-captures results into engagement state and PoC evidence.
  - `engagement-init.py` (SessionStart) self-heals the engagement file set and injects a ranked next-move summary.
  - `scope-guard.py` (PreToolUse) denies a command that targets an out-of-scope host or uses rules-of-engagement-forbidden tooling (deterministic enforcement; a `.enforce-off` marker downgrades it to advisory).
- **State-first engagement model.** Each engagement lives under `targets/<name>/` (`state`, `loot`, `paths`, `scope`, `coverage`). Analyzers (`next_move.py`, `coverage.py`) rank what to do next and surface untested vulnerability classes so nothing in scope is skipped.
- **Research loop** (`skills/research`) for CVE discovery on binaries, libraries, and repos, with its own persistent state under `raw/research/`.
- **Hard client-data boundary.** Every client specific stays under `targets/` (git-ignored); `scripts/check-leaks.sh` gates tracked files before you ever push.

---

## The knowledge base (500+ pages ship with the repo)

The `wiki/` corpus is the heart of TORCH and it is fully committed, clone it and you get the whole library, not an empty shell. It is a living offensive-security reference organized as:

| Area | Covers |
|---|---|
| `wiki/techniques/` | Active Directory, cloud, web, network, Linux, macOS, exploit-dev, OSINT, cracking, red-team, mobile/IoT, blockchain, methodology |
| `wiki/payloads/` | Per-vulnerability-class payload arsenals the hunt skills pull from |
| `wiki/tools/` | Per-tool references (nmap, ffuf, nuclei, httpx, sqlmap, BloodHound, netexec, ...) |
| `wiki/cheatsheets/` | Quick-reference command sheets and default-credential tables |

Pages are cross-linked Obsidian-style and indexed for semantic search, so "SSRF to cloud metadata" or "ESC1 ADCS" resolves to the right page in one query. The wiki grows every engagement through the `learn` skill, which distills generic, client-free lessons back into it.

---

## What ships vs what stays private

The wiki and the entire harness are public. Only client data and per-machine state are held back by [`.gitignore`](.gitignore):

| Tracked (ships, safe to push) | Git-ignored (stays private) |
|---|---|
| `wiki/` the full 500+ page corpus | `targets/` client engagements and findings |
| `skills/`, `scripts/`, `setup/`, `docs/`, `tests/` | `CLAUDE.local.md` machine hostnames and paths |
| `CLAUDE.md`, `README.md`, `LICENSE` | `session/`, `raw/` local working state |
| `targets/TARGETS.md` the generic engagement playbook | `.claude/`, `.obsidian/`, runtime stamps and caches |

**The client-data boundary is a hard rule.** Hosts, credentials, findings, and engagement narrative live *only* under `targets/`, which git ignores wholesale (with the single generic playbook whitelisted). Run `bash scripts/check-leaks.sh` before your first push, it scans tracked files for engagement markers, private IPs, and emails.

---

## Requirements

- Linux or WSL, `bash`, `python3` (3.10+)
- [Claude Code](https://claude.com/claude-code) CLI
- Node.js >= 18 and [bun](https://bun.sh)
- `qmd` (installed by the bootstrap via `bun install -g @qmd/cli`), which provides the `wiki-search` MCP server via `qmd mcp`

## Quickstart

```bash
git clone <this-repo> TORCH
cd TORCH

# One-time, per-machine setup. NOTE: bootstrap.sh mutates ~/.claude: it writes a
# CLAUDE.md include, symlinks the hooks, registers the MCP servers, and installs
# qmd + the official Claude plugins. Read it first; it is aggressive by design.
bash setup/bootstrap.sh

# Build the search index (re-run after adding wiki pages)
qmd update

# Restart Claude Code so it loads the hooks, skills, and MCP servers.

# Start an engagement (pentest | bugbounty | ctf)
bash setup/new-engagement.sh acme pentest

# Then, inside Claude Code, drive the whole engagement autonomously with the matching workflow:
#   /pt-workflow    pentest (client-report deliverable)
#   /bb-workflow    bug-bounty program
#   /ctf-workflow   CTF / boot-to-root box

# Run the test suite
python3 -m pytest -q

# Before any push, run the leak gate
bash scripts/check-leaks.sh
```

`bootstrap.sh` self-locates the vault; if it cannot, set `OBSIDIAN_VAULT` (and `QMD_VAULT` for the search index) to the repo root. Per-machine paths go in the git-ignored `CLAUDE.local.md`, copy [`CLAUDE.local.example.md`](CLAUDE.local.example.md) to create it. See [`docs/setup.md`](docs/setup.md) for the full walkthrough.

---

## Plugins and MCP servers

TORCH runs on Claude Code plus a set of plugins and MCP servers. `setup/bootstrap.sh`
installs the core set for you; the rest are referenced by the workflow and installed separately.

**Installed by `bootstrap.sh`:**

- **qmd** - the semantic + keyword search engine over `wiki/` (`bun install -g @qmd/cli`); registers the `wiki-search` MCP (`qmd mcp`).
- **caveman** - terse-output / prose-compression mode; also registers the `caveman-shrink` MCP (a token-compressed `wiki-search`).
- **ponytail** - "lazy senior dev" engineering-discipline mode (pushes for the simplest working solution; governs code, not prose), from marketplace `DietrichGebert/ponytail`.
- Official Claude Code plugins: **code-review**, **claude-md-management**, **skill-creator**, **frontend-design** (`claude plugins install <name>@claude-plugins-official`).

**Install separately (referenced by the harness):**

- **superpowers** (recommended) - the planning / execution / debugging workflow the CLAUDE.md loop routes to: `brainstorming` -> `writing-plans` -> `subagent-driven-development`, plus `systematic-debugging`, `dispatching-parallel-agents`, and `verification-before-completion`.
- **context7** (optional MCP) - up-to-date library / API docs, used for vendor-default and dependency lookups.
- **gsd** (optional) - the `pause-work` session-end helper.
- **burp-mcp** (optional MCP) - drives Burp Suite for the `hunt-burp` workflow.

Install plugins from Claude Code's plugin marketplace (`/plugin`), and MCP servers with `claude mcp add`.
Everything degrades gracefully: the hooks fail open and the hunt/wiki skills work without the optional
plugins, but the documented planning loop assumes `superpowers`.

## Layout

```
CLAUDE.md         top-level instructions loaded by Claude Code
wiki/             500+ page technique corpus (ships; semantic + keyword indexed)
skills/           hunt-* skills, research / disclosure, hooks/, meta-skills
scripts/          next_move, coverage, find-lint, check-leaks, index / lint tooling
setup/            bootstrap, install-hooks, install-skills, new-engagement / research, templates
docs/             workflows, page-types, setup, sharing (client-data boundary), conventions
tests/            pytest suite for the automation
targets/          engagements (git-ignored; client data lives ONLY here)
```

Full annotated tree in [`docs/layout.md`](docs/layout.md). Start with [`docs/workflows.md`](docs/workflows.md) for the day-to-day flow and [`docs/sharing.md`](docs/sharing.md) for the client-data boundary rules.

---

## The model underneath

TORCH is a *harness*, the intelligence it orchestrates is a large language model (Claude). If you want to understand what an LLM actually is under the hood, tokens, attention, training, and inference, the clearest from-scratch implementations on the internet are Andrej Karpathy's:

- **[nanoGPT](https://github.com/karpathy/nanoGPT)** a minimal, readable GPT training and finetuning codebase; the canonical "here is a transformer, end to end."
- **[nanochat](https://github.com/karpathy/nanochat)** a full ChatGPT-style pipeline (pretraining, supervised finetuning, RL, and inference with a web UI) in one hackable repo.
- **[Neural Networks: Zero to Hero](https://karpathy.ai/zero-to-hero.html)** the video series that builds an LLM line by line, from `micrograd` up to a GPT.

Those repos show you the engine; TORCH shows you how to point that engine at a target and keep it disciplined.

---

## Safety and boundaries

- Client and engagement data (hosts, credentials, findings) lives **only** under `targets/`, which is git-ignored. Never write it into `wiki/`, `docs/`, `skills/`, or commit messages.
- `scripts/check-leaks.sh` scans tracked files for engagement markers and flags emails and private IPs before you publish. Run it before any push.
- The hunt skills enforce out-of-band confirmation for blind vulnerability classes, no inference-only findings.

---

## License

MIT, see [LICENSE](LICENSE).
