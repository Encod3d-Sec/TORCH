---
title: "angr"
type: tool
tags: [reverse-engineering, symbolic-execution, ctf, cve-research, binary]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**angr** is a Python binary-analysis platform with symbolic execution: it explores program paths by treating inputs as symbols and solving constraints, so it can compute the input that reaches a target (a "win"/vulnerable state) without you reversing every branch. Used for CTF reversing, automated input generation, and reachability in CVE research.

## Install / setup

```bash
pip install angr        # heavy deps; a venv is recommended
```

## Core usage

```python
import angr, claripy
proj = angr.Project("./bin", auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x<win_addr>, avoid=[0x<fail_addr>])
if simgr.found:
    print(simgr.found[0].posix.dumps(0))    # stdin that reaches 'find'
```

## Common use cases

```python
# Symbolic argv/stdin of a fixed length
flag = claripy.BVS("flag", 8*32)
state = proj.factory.entry_state(stdin=flag)
# constrain to printable, then explore + solve:
for b in flag.chop(8):
    state.solver.add(b >= 0x20, b <= 0x7e)
```
- **Reach a target / avoid failures:** classic "find the input that prints the flag" (`explore(find=, avoid=)`).
- **Find a vulnerable state:** explore for an address after an unchecked `memcpy`, or detect symbolic instruction pointer (`state.regs.pip` symbolic = control-flow hijack) for exploit reachability.
- **Hook/stub** slow or external functions (`proj.hook(addr, SimProcedure)`) to keep exploration tractable.

## Tips and gotchas
- **Path explosion** is the enemy: constrain input length, hook expensive functions, use `LAZY_SOLVES`, and prefer a tight `find` address over exploring everything.
- Best for self-contained logic (crackmes, parsers, constraint checks); a heavily syscall/IO-bound or huge binary may not be tractable - fall back to manual RE in [[ghidra]].
- Use `claripy` to add constraints (printable chars, known prefix) and shrink the search.

## Related techniques
[[reverse-engineering]], [[binary-exploitation]], [[fuzzing]] (complementary: fuzz for breadth, angr for a specific hard branch). Pairs with [[ghidra]], [[radare2]]. Used in the binary path of the `research` skill.

## Sources
