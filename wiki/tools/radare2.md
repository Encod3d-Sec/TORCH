---
title: "radare2"
type: tool
tags: [ctf, reverse-engineering, disassembler, debugger, binary]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**radare2** (`r2`) is a free, scriptable reverse-engineering framework: disassembler, decompiler (via r2ghidra/Cutter), debugger, and binary patcher in one CLI. Cutter is its Qt GUI.

## Install / setup

```bash
git clone https://github.com/radareorg/radare2; radare2/sys/install.sh   # newest
# or: apt install radare2 ; pip install r2pipe  (scripting)
```

## Core usage

```bash
r2 -A ./bin          # open + auto-analyze (equivalent to aaa)
r2 -d ./bin          # open in debug mode
r2 -w ./bin          # writable (patching)
```

Inside r2 (commands are terse; `?` after any prefix lists subcommands):

| Command | Action |
|---|---|
| `aaa` | analyze all (functions, refs, strings) |
| `afl` | list functions; `afl~main` greps |
| `pdf @main` | disassemble function; `pdc` pseudo-decompile |
| `s main` / `s 0x...` | seek to symbol/address |
| `VV` | visual graph mode (function CFG) |
| `V` then `p` | visual hexdump/disasm modes |
| `iz` / `izz` | strings in data / whole binary |
| `axt 0x...` | xrefs TO an address |
| `iaj` | imports/exports/symbols (json) |

## Common use cases

```bash
# Find and read the success branch
r2 -A ./crackme -qc 'afl;pdf @main' | less
```
```bash
# Patch a conditional jump to always take the win path
r2 -w ./bin
> s 0x004011a5
> "wa jmp 0x004011d0"      # assemble in place
```
```bash
# Debug: break, run, inspect compare operands
r2 -d ./bin
> db 0x004011b3; dc; dr; px 32 @ rdi
```
```python
# Script with r2pipe
import r2pipe; r = r2pipe.open("./bin"); r.cmd("aaa")
print(r.cmdj("aflj")[0]["name"])
```

## Tips and gotchas
- `-A`/`aaa` before anything or xrefs and function names are missing.
- Use Cutter (GUI + r2ghidra decompiler) for large binaries; r2 CLI for quick triage and patching.
- `e asm.syntax=att` if you prefer AT&T; `pdc`/r2ghidra `pdg` for decompilation.

## Related techniques
[[reverse-engineering]], [[binary-exploitation]]. Pairs with [[gdb-gef]] for dynamic analysis.

## Sources
