---
title: "Ghidra"
type: tool
tags: [reverse-engineering, decompiler, cve-research, binary, malware]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**Ghidra** is the NSA's open-source reverse-engineering suite: a multi-architecture disassembler with a strong **decompiler** (machine code -> readable C-like pseudocode). The free heavyweight for understanding closed-source binaries, finding the vulnerable function, and feeding a fuzz harness or exploit.

## Install / setup

```bash
# needs JDK 21+; download from ghidra-sre.org or github.com/NationalSecurityAgency/ghidra
unzip ghidra_*.zip && ./ghidra_*/ghidraRun
```

## Core usage

GUI workflow:
1. New Project -> Import the binary -> let auto-analysis run (default analyzers).
2. **Symbol Tree** / **Functions** -> open `main` (or the parser/entry of interest).
3. **Decompiler** pane (right) shows C-like pseudocode beside the disassembly.
4. Rename variables/functions (`L`), set types, add comments (`;`) - re-typing struct fields makes the decompiler output far clearer.
5. Follow xrefs (`Ctrl+Shift+F`) from input-handling functions to dangerous sinks.

## Common use cases

```bash
# Headless analysis (batch / scripted, no GUI) - good for triage at scale
./support/analyzeHeadless /proj projName -import ./target \
  -postScript MyScript.java -scriptPath ./scripts

# Find calls to dangerous functions, then read their callers in the decompiler:
#   strcpy/memcpy/sprintf/gets/system/exec/malloc-with-attacker-size
```
- **CVE workflow:** locate attacker-reachable input handling -> trace to an unchecked `memcpy`/length math / format string -> confirm the bug in pseudocode -> build a trigger or point [[aflplusplus]] at that code path.
- **Version diffing (patch-gap / n-day):** import the pre- and post-patch binaries and diff functions (BSim, or the Version Tracking tool) to locate exactly what a security patch changed - a fast route to a PoC.
- Scripting: Java or Python (Ghidrathon/PyGhidra) over the program API for bulk analysis.

## Tips and gotchas
- The decompiler is an aid, not truth - cross-check against the disassembly for anything that drives an exploit (calling convention, stack layout, optimizer artifacts).
- Re-type the key struct/variable and the pseudocode often goes from unreadable to obvious; invest there before concluding "no bug".
- For dynamic confirmation pair with [[gdb-gef]]; for quick CLI triage and patching, [[radare2]] is lighter.

## Related techniques
[[reverse-engineering]], [[binary-exploitation]], [[firmware-hardware]] (analyze extracted binaries). Pairs with [[radare2]], [[gdb-gef]], [[aflplusplus]]. Core of the binary path in the `research` skill.

## Sources
