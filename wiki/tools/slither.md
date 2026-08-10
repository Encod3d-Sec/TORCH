---
title: "Slither"
type: tool
tags: [blockchain, web3, smart-contract, solidity, static-analysis, sast, mutation-testing]
phase: aux
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-blockchain]
---

## Purpose

**Slither** is a static-analysis framework for Solidity that parses contracts into an AST and applies vulnerability detectors. Its `slither-mutate` extension drives mutation testing: it uses that same Solidity AST to inject small code changes (mutants) and re-run the test suite, exposing missing assertions that line/branch coverage cannot see. Coverage proves a line executed; mutation testing proves behavior is actually asserted. Pairs with [[smart-contract-web3-attacks]] and [[defi-amm-exploitation]].

## Install / setup

```bash
pip install slither-analyzer   # provides slither and slither-mutate
slither-mutate --help
slither-mutate --list-mutators
```

## Core usage

Mutation testing injects small changes into contract code and re-runs the suite: a failing test kills the mutant, a surviving (UNCAUGHT) mutant reveals a blind spot. Prefer syntax-aware engines (slither-mutate uses Slither's Solidity AST; `mewt` uses Tree-sitter; `MuTON` adds TON FunC/Tolk/Tact) over regex rewriting for reliable multi-line and expression-level mutations.

```bash
# Foundry, keep a full log:
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)

# non-Foundry: point at the other runner (artifacts -> ./mutation_campaign)
slither-mutate ./src/contracts --test-cmd="npx hardhat test"
```

## Common use cases

A report line like:
```text
[CR] Line 123: 'x = y' ==> '//x = y' --> UNCAUGHT
```
means commenting the assignment did not break any test, i.e. a missing post-state assertion. Real Arkis finding: code trusted a user-controlled `_cmd.value` instead of validating actual transfers, allowing solvency drain.

For contracts, surviving mutants most often map to:
- Missing checks around authorization / role boundaries.
- Accounting / value-transfer invariants that are never asserted.
- Unexercised revert / failure paths.
- Boundary conditions (`==`, zero, empty arrays, min/max).

Highest-signal mutators: statement -> `revert()` (expose unexecuted paths), comment-out lines (unverified side effects), then operator/constant swaps (`>=` -> `>`, `+` -> `-`).

## Tips and gotchas
- Runtime is brutal (1000 mutants x 5-min tests ~= 83 h). Scope to critical contracts; skip lower-priority variants once a high-priority mutant on a line survives; run two-phase (fast suite first, full suite only on survivors).
- Triage: strengthen tests to assert state (balances, supply, auth effects, events), not just return values.
- Do not blindly generate a test per mutant. A surviving mutant may indicate the implementation itself is the bug, not just a weak test.

## Related techniques
[[smart-contract-web3-attacks]] (audit toolchain), [[defi-amm-exploitation]] (accounting/rounding invariants that mutation testing surfaces). Complementary tools: `mythril` (symbolic execution), `echidna` (property fuzzing), `foundry`/`forge` (forked-mainnet PoC).

## Sources

- HackTricks (blockchain), ingest slug `hacktricks-blockchain`.
