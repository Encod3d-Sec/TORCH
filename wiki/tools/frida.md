---
title: "Frida"
type: tool
tags: [mobile, instrumentation, hooking, reverse-engineering, ssl-pinning]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
phase: aux
---

## Purpose

**Frida** is a dynamic instrumentation toolkit: it injects a JavaScript engine into a running process to hook functions, read/modify arguments and return values, and trace calls at runtime. The core tool for mobile app testing (Android/iOS) and runtime RE. **objection** is a Frida-powered wrapper that automates the common mobile tasks.

## Install / setup

```bash
pip install frida-tools objection
# Android: push the matching frida-server to the device and run it as root
# iOS: install frida via Cydia/TrollStore on a jailbroken device
```

## Core usage

```bash
frida-ps -U                       # list processes on the USB device
frida-trace -U -i "open" com.app  # auto-generate + run hooks for a function
frida -U -f com.app -l hook.js    # spawn the app with your script
```
```javascript
// hook.js - force a function to return true (e.g. a root/jailbreak check)
Java.perform(() => {
  const C = Java.use("com.app.security.RootCheck");
  C.isRooted.implementation = function () { return false; };
});
```

## Common use cases

```bash
# objection automates the usual mobile bypasses (built on Frida)
objection -g com.app explore
> android sslpinning disable        # or: ios sslpinning disable
> android root disable              # or: ios jailbreak disable
> android hooking watch class_method com.app.LoginActivity.checkPin --dump-args
> memory search / dump
```
- Bypass SSL pinning to intercept the API in Burp; defeat root/jailbreak detection; dump secrets from memory; hook crypto to capture keys/plaintext; trace native (`Interceptor.attach(ptr(addr), ...)`).

## Tips and gotchas
- **Match frida-server version to the client** exactly or attach fails.
- iOS classes are ObjC/Swift (`ObjC.classes`), Android are Java (`Java.use`) or native (`Module`/`Interceptor`) - pick the right API for the layer.
- Anti-Frida apps detect the server port/threads; use `frida-server` renamed, gadget injection, or stealth forks. Start with objection (fast), drop to raw Frida scripts for custom hooks.

## Related techniques
[[android-application]], [[ios-application]], [[reverse-engineering]]. Pairs with Burp ([[burp-suite]]) for traffic, [[radare2]]/[[ghidra]] for the native layer.

## Sources
