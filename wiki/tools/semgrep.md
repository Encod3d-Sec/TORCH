---
title: "Semgrep"
type: tool
tags: [static-analysis, sast, cve-research, code-audit, vuln-discovery]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**Semgrep** is a fast, lightweight static analyzer that matches code against patterns written like the code itself (with metavariables + limited dataflow/taint). Used to sweep a codebase for dangerous sinks and known bug patterns in minutes - the fast first pass of a source audit before deeper [[codeql]] work.

## Install / setup

```bash
pipx install semgrep        # or: brew install semgrep
```

## Core usage

```bash
semgrep --config auto .                      # registry rules auto-selected by language
semgrep --config p/security-audit .          # curated security ruleset
semgrep --config p/owasp-top-ten .
semgrep --config ./myrules.yaml src/         # custom rules
```

## Common use cases

```bash
# Hunt specific dangerous sinks
semgrep -e 'system(...)'  --lang c .                 # quick one-off pattern
semgrep -e 'eval($X)'     --lang python .
semgrep --config p/command-injection --config p/sql-injection .

# CI / triage output
semgrep --config auto --sarif -o out.sarif .
semgrep --config auto --severity ERROR --json .
```

Custom rule with taint mode (source -> sink dataflow):
```yaml
rules:
  - id: tainted-exec
    mode: taint
    pattern-sources: [{pattern: 'request.args.get(...)'}]
    pattern-sinks:   [{pattern: 'os.system(...)'}]
    message: user input reaches os.system - command injection
    languages: [python]
    severity: ERROR
```

## Tips and gotchas
- **Triage is the work**: registry rules are noisy and miss things; treat hits as leads, confirm reachability by hand. False positives + false negatives are expected.
- Intraprocedural by default - taint tracking is shallow across functions/files. For deep, cross-function dataflow on a hard target, use [[codeql]]; use Semgrep to find candidate sinks fast, then CodeQL to prove the path.
- Write a custom rule the moment you spot a bug *class*: it finds every sibling instance (the "variant analysis" step of the `research` loop).
- `--lang generic` matches non-code/config; great for grepping templates, Dockerfiles, CI YAML.

## Related techniques
[[static-code-analysis]], [[secret-hunting]], plus the matching vuln-class pages ([[os-command-injection]], [[sql-injection]], [[ssti]]). Deeper dataflow -> [[codeql]]. Drives the source-audit path of the `research` skill.

## Sources
