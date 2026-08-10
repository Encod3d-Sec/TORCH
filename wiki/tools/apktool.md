---
title: "Apktool"
type: tool
tags: [mobile, android, reverse-engineering, smali, repackaging]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**Apktool** decodes an Android APK back to its resources and **smali** (disassembled Dalvik bytecode), then rebuilds a modified APK. Used to read the manifest/resources, patch app logic in smali, and repackage (e.g. to disable certificate pinning or add a Frida gadget).

## Install / setup

```bash
apt install apktool        # or download the jar from apktool.org
```

## Core usage

```bash
apktool d app.apk -o app_src        # decode -> AndroidManifest.xml, res/, smali/
# ... edit smali / resources ...
apktool b app_src -o app_mod.apk     # rebuild
# rebuilt APKs must be re-signed before install:
apksigner sign --ks debug.keystore app_mod.apk    # or uber-apk-signer
```

## Common use cases

```bash
# Read the manifest for attack surface
apktool d app.apk -o out
grep -nE 'android:exported="true"|<uses-permission|android:debuggable|usesCleartextTraffic' out/AndroidManifest.xml
# exported activities/services/receivers/providers = IPC attack surface
# android:debuggable="true" / cleartext traffic = quick wins

# Patch out a check in smali (e.g. root/pinning) then rebuild + sign
#   find the method in smali/, flip the return, apktool b, re-sign, install

# Add a network_security_config to allow user CAs (intercept TLS in Burp)
```

## Tips and gotchas
- Rebuilt APKs **must be re-signed** (`apksigner`/`uber-apk-signer`) or they won't install; the original signature is invalidated.
- Smali is verbose but mechanical - for *reading* logic use [[jadx]] (decompiled Java); use Apktool to *modify and repackage*.
- Check `AndroidManifest.xml` first: `exported` components, custom permissions, deep-link schemes, `debuggable`, backup flags, and `networkSecurityConfig`.

## Related techniques
[[android-application]], [[reverse-engineering]], [[firmware-hardware]]. Read source with [[jadx]]; instrument at runtime with [[frida]].

## Sources
