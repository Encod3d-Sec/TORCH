---
title: "jadx"
type: tool
tags: [mobile, android, reverse-engineering, decompiler, secrets]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**jadx** decompiles Android `dex`/APK bytecode to readable **Java** source, with a GUI (`jadx-gui`) for browsing, searching, and cross-referencing. The fastest way to read what an Android app actually does: find hardcoded secrets, endpoints, crypto, and the logic to attack.

## Install / setup

```bash
apt install jadx           # provides jadx (CLI) and jadx-gui
```

## Core usage

```bash
jadx app.apk -d out/                 # decompile to Java source tree
jadx-gui app.apk                     # browse + global search + xrefs
```

## Common use cases

```bash
# Decompile then grep the source for the usual wins
jadx app.apk -d out/
grep -rinE 'https?://|api[_-]?key|secret|password|token|BEGIN .*PRIVATE KEY|Authorization' out/sources/ | head
grep -rinE 'AES|DES|IvParameterSpec|SecretKeySpec|Cipher.getInstance' out/sources/   # crypto / hardcoded keys
grep -rin "PinningTrustManager\|CertificatePinner\|checkServerTrusted" out/sources/    # SSL pinning to bypass

# In jadx-gui: search a string (Ctrl+Shift+F), jump to usage, follow xrefs to
# reconstruct auth/payment/license logic, then attack the backend API or hook with frida.
```

## Tips and gotchas
- Decompilation can fail on some methods (shows partial/`// decompilation error`) - fall back to the smali view or [[apktool]] for those.
- The real attack surface is usually the **backend API** the app talks to - use jadx to recover endpoints, headers, and signing logic, then test the API directly.
- Heavily obfuscated apps (R8/ProGuard) decompile to single-letter names; combine with [[frida]] runtime traces to recover behaviour.

## Related techniques
[[android-application]], [[reverse-engineering]], [[secret-hunting]]. Modify/repackage with [[apktool]]; instrument with [[frida]].

## Sources
