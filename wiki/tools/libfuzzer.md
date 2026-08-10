---
title: "libFuzzer"
type: tool
tags: [fuzzing, cve-research, in-process, coverage-guided, sanitizers]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: fuzz
---

## Purpose

**libFuzzer** is an in-process, coverage-guided fuzzer built into LLVM/Clang. You write one function that feeds bytes to the code under test; libFuzzer mutates inputs in-process (no fork/exec) and pairs with sanitizers to surface memory bugs. Ideal for fuzzing a **library function or parser** directly.

## Install / setup

```bash
# ships with clang; just compile with the fuzzer + a sanitizer
clang -g -O1 -fsanitize=fuzzer,address harness.c target.c -o fuzzer
```

## Core usage

The harness is one entry point - feed the bytes into the API under test:
```c
#include <stdint.h>
#include <stddef.h>
extern int parse(const uint8_t *data, size_t len);   // code under test

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse(data, size);     // must not leak/crash on ANY input
    return 0;
}
```
```bash
./fuzzer corpus/                 # run, seeding from corpus/ (creates new inputs there)
./fuzzer -max_len=4096 corpus/
./fuzzer crash-<hash>            # reproduce a saved crash
```

## Common use cases

```bash
# Structured input -> use the FuzzedDataProvider helper to carve typed fields
#   #include <fuzzer/FuzzedDataProvider.h>
#   FuzzedDataProvider fdp(data, size); int w = fdp.ConsumeIntegral<int>(); ...

# Sanitizer choice (combine as needed)
-fsanitize=fuzzer,address        # ASan: overflow / use-after-free / double-free
-fsanitize=fuzzer,memory         # MSan: uninitialized reads
-fsanitize=fuzzer,undefined      # UBSan: integer overflow, bad shifts

# Corpus management + coverage
./fuzzer -merge=1 corpus_new corpus_old      # minimise/merge corpora
./fuzzer -runs=1000000 corpus/               # bounded run (CI)

# OSS-Fuzz: the same harness drops straight into Google's OSS-Fuzz for
# continuous fuzzing of open-source targets -> a common CVE pipeline.
```

## Tips and gotchas
- The target must be **deterministic and free of global state leakage** between runs (in-process reuse) - reset state in the harness if needed.
- A good seed corpus + `FuzzedDataProvider` for structured formats massively improves depth; add a `.dict` with `-dict=file`.
- Same harness runs under [[aflplusplus]] (`afl-clang-fast -fsanitize=fuzzer`) - write once, fuzz with both engines for better coverage.
- Found a crash with ASan -> read the report top-frame, minimise with `-minimize_crash=1`, then root-cause in source.

## Related techniques
[[fuzzing]], [[crash-analysis]], [[static-code-analysis]] (find the harness target), [[binary-exploitation]]. Pairs with [[aflplusplus]]. Drives the investigate step of the `research` skill.

## Sources
