---
title: "GDB + GEF"
type: tool
tags: [binary, bof, linux]
date_created: 2026-05-09
date_updated: 2026-05-09
sources: [Malware-ccdcoe-essentials-bof]
phase: aux
---

# GDB + GEF

## Purpose

GNU Debugger (GDB) with the GEF (GDB Enhanced Features) extension — the primary tool for dynamic analysis of Linux binaries during buffer overflow exploitation: offset calculation, register inspection, memory examination, and shellcode verification.

## Install / setup

```sh
# GEF one-liner install
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
# or from source: https://hugsy.github.io/gef/install/

# Verify
gdb -q ./binary
gef➤ version
```

## Core usage

```sh
gdb -q ./binary          # quiet mode (no banner)
gef> run                 # run until exit
gef> start               # run and stop at entry point (main)
gef> c                   # continue after breakpoint
gef> ni                  # next instruction (step over calls)
gef> si                  # step into calls
```

### Setting breakpoints
```sh
gef> info functions          # list all symbols/functions
gef> disas main              # disassemble main
gef> disas vuln              # disassemble specific function
gef> break main              # breakpoint at function
gef> break *0x08049236       # breakpoint at address
gef> hb *0xffffcd30          # HARDWARE breakpoint — doesn't inject int3 opcode
                              # use when software bp shifts stack addresses
```

### Cyclic pattern (offset finding)
```sh
gef> pattern create 200      # generate De Bruijn pattern of 200 bytes
# send pattern to program → crash
gef> pattern offset $eip     # x86: compute offset from EIP value
gef> pattern offset $rsp     # x64: compute offset from RSP after crash
```

Alternative with Metasploit pattern:
```sh
/usr/bin/msf-pattern_create -l 200
msf-pattern_offset -q 0x41336541   # find offset from hex EIP value
```

### Memory inspection
```sh
gef> x/20c $esp              # 20 chars at ESP — inspect for bad chars / shellcode
gef> x/20gx $rsp             # 20 qwords at RSP (x64)
gef> x/i $eip                # disassemble at EIP
gef> info registers          # dump all registers
gef> telescope $rsp 20       # GEF: stack display with pointer derefs
```

### Finding addresses in stripped binaries
```sh
gef> info functions          # only PLT stubs visible; look for entry sequence
gef> disas 0x080491f6        # disassemble at known address from static analysis
gef> find &system,+9999999,"/bin/sh"   # locate /bin/sh in mapped libc
```

## Common use cases

| Task | Command |
|------|---------|
| Generate offset pattern | `pattern create 200` |
| Get offset from crash | `pattern offset $eip` |
| List functions (non-stripped) | `info functions` |
| Disassemble function | `disas vuln` |
| Hardware breakpoint | `hb *0xADDR` |
| Inspect stack bytes | `x/20c $esp` |
| Attach to running process | `gdb -q -p <PID>` |
| Debug with pwntools | `context.terminal = ['tmux','splitw','-h']` + `gdb.debug(elf.path)` |
| Find libc string | `find &system,+9999999,"/bin/sh"` |

## Tips and gotchas

- **Software vs hardware breakpoints:** `break *0xADDR` injects `\xCC` (int3) into the code, which can shift relative addresses or trigger bad-char detection. Use `hb *0xADDR` for hardware breakpoints when exploiting with shellcode.
- **x64 RSP vs RIP after crash:** On 64-bit, the overflow often crashes on a `ret` with a bad return address. The offset is to RSP (what gets popped into RIP), not a direct RIP overwrite — use `pattern offset $rsp`.
- **ASLR for local testing:** `echo 0 > /proc/sys/kernel/randomize_va_space` to disable; remember libc addresses will differ from remote.
- **Stack alignment (x64):** If `system("/bin/sh")` segfaults on `movaps`, the stack is misaligned. Insert a bare `ret` gadget before the `system` call.
- **Stripped binaries:** Use decompiler (Ghidra/IDA) or `objdump -d` to locate the priv-escalation / shell function address; then use it as EIP target directly.

## pwntools integration

```python
from pwn import *
context(terminal=['tmux', 'splitw', '-h'])

elf = context.binary = ELF('./binary')

# Local with GDB attached:
if args.GDB:
    io = gdb.debug(elf.path)
# Local process:
elif args.LOCAL:
    io = process(elf.path)
# Remote:
else:
    io = remote("target", 9999)
```

## Related techniques

- [[binary-exploitation]] — BOF protections, ROP chains, heap exploitation
- [[seh-exploitation]] — Windows SEH; uses xdbg instead of GDB for Windows targets
- [[exploit-development]] — full pwntools exploit templates
