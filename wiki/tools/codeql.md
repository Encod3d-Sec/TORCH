---
title: "CodeQL"
type: tool
tags: [static-analysis, sast, taint-analysis, cve-research, code-audit, vuln-discovery]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**CodeQL** treats code as a queryable database: you write QL queries to find vulnerable patterns with deep, interprocedural **dataflow and taint tracking**. It is the gold standard for source-driven CVE discovery (GitHub Security Lab finds many CVEs with it) - heavier than [[semgrep]] but it proves whole source-to-sink paths.

## Install / setup

```bash
# download the CodeQL CLI bundle from github.com/github/codeql-action/releases
# add codeql to PATH; clone the query packs:
git clone https://github.com/github/codeql.git
```

## Core usage

```bash
# 1. build a database (compiled languages need the build command so CodeQL traces it)
codeql database create db --language=cpp --command="make"
codeql database create db --language=python      # interpreted: no build cmd

# 2. run a query pack
codeql database analyze db codeql/cpp-queries:codeql-suites/cpp-security-extended.qls \
  --format=sarifv2.1.0 --output=results.sarif
```

## Common use cases

```bash
# Run a single custom query
codeql query run -d db myquery.ql

# Languages: cpp, java, csharp, javascript, python, go, ruby, swift
# View results.sarif in VS Code (CodeQL extension) to walk each dataflow path.
```

Taint-tracking query skeleton (user input -> dangerous sink):
```ql
import cpp
import semmle.code.cpp.dataflow.TaintTracking

class Cfg extends TaintTracking::Configuration {
  Cfg() { this = "tainted-system" }
  override predicate isSource(DataFlow::Node s) {
    s.asExpr().(FunctionCall).getTarget().hasName("recv")
  }
  override predicate isSink(DataFlow::Node s) {
    exists(FunctionCall c | c.getTarget().hasName("system") and
                            s.asExpr() = c.getArgument(0))
  }
}
from Cfg cfg, DataFlow::Node src, DataFlow::Node sink
where cfg.hasFlow(src, sink)
select sink, "attacker-controlled data reaches system()"
```

## Tips and gotchas
- The build trap: for C/C++/Java the database needs a working `--command` build; if the build fails the DB is empty. Build the target first.
- Start from the **standard security suites** (`security-extended`), then write a custom taint query modelling the target's own source (its input API) and sink (its dangerous function) - that is where novel CVEs come from.
- It models the source-to-sink path explicitly - use the SARIF path view to confirm reachability instead of guessing. Pair with [[semgrep]] for the fast first sweep.
- Variant analysis: once you find one bug, generalise the query to find every sibling instance across the codebase.

## Related techniques
[[static-code-analysis]], [[reverse-engineering]] (when source is partial), and the matching vuln-class pages. Fast first pass -> [[semgrep]]. Core of the source-audit path in the `research` skill.

## Sources
