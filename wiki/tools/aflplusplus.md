---
title: "AFL++"
type: tool
tags: [fuzzing, cve-research, binary, coverage-guided, vuln-discovery]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: fuzz
---

## Purpose

**AFL++** (american fuzzy lop plus plus) is a coverage-guided mutational fuzzer for native code. It feeds mutated inputs to a target, tracks edge coverage via instrumentation, and keeps inputs that reach new paths - the standard tool for finding memory-safety CVEs in parsers and file/protocol handlers.

## Install / setup

```bash
apt install afl++          # or build from github.com/AFLplusplus/AFLplusplus
# sanitizers catch bugs that don't crash on their own - build the target with one:
export AFL_USE_ASAN=1      # AddressSanitizer (heap/stack overflow, UAF)
```

## Core usage

```bash
# 1. instrument the target at compile time
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure && make
# 2. seed corpus = a few valid sample inputs
mkdir in && cp samples/*.jpg in/
# 3. fuzz (@@ = the input file path the target reads)
afl-fuzz -i in -o out -- ./target @@
```

## Common use cases

```bash
# Persistent mode (10-100x faster: loop in-process instead of fork/exec)
#   add to the harness:  while (__AFL_LOOP(10000)) { read_input(); target(); }
afl-clang-fast -o harness harness.c

# Parallel fuzzing (one main + N secondaries across cores)
afl-fuzz -i in -o out -M main -- ./t @@
afl-fuzz -i in -o out -S sec1 -- ./t @@

# Dictionary (tokens/magic bytes -> reaches deep parser states faster)
afl-fuzz -i in -o out -x png.dict -- ./t @@

# No source (black-box binary) via QEMU mode
afl-fuzz -Q -i in -o out -- ./closed_bin @@

# Triage crashes
ls out/default/crashes/
./target out/default/crashes/id:000000*     # reproduce; analyze with [[gdb-gef]]
afl-cmin -i out/default/queue -o min -- ./t @@    # minimise corpus
afl-tmin -i crash -o crash.min -- ./t @@          # minimise a single crash
```

## Tips and gotchas
- **Always build with a sanitizer** (`AFL_USE_ASAN`/`UBSAN`); many bugs corrupt memory silently and only ASan turns them into a crash you can find.
- Coverage is everything: good seeds + a dictionary + persistent mode decide whether you find anything. Watch the `map density` and `paths` in the UI.
- A libFuzzer harness (`LLVMFuzzerTestOneInput`) compiles under AFL++ too (`afl-clang-fast` + `-fsanitize=fuzzer`) - write the harness once, run both. See [[libfuzzer]].
- Reproduce + root-cause every crash before claiming a bug; dedupe by stack hash (ASan) since many crashes share one root cause.

## Related techniques
[[fuzzing]], [[crash-analysis]], [[binary-exploitation]]. Drives the investigate step of the `research` skill. Pairs with [[libfuzzer]], [[gdb-gef]], [[ghidra]].

## Sources
