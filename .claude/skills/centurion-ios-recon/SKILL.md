---
name: centurion-ios-recon
description: Use at the start of an iOS app assessment to enumerate connected iOS devices and apps via libimobiledevice, confirm tool availability, and pull a decrypted IPA. Drives the Centurion MCP server.
---

# Centurion: iOS Recon

Establish the iOS baseline before deeper analysis. Use the Centurion MCP server. Operate
only on devices and apps you are authorized to test.

## Steps

1. **Check capability.** Call `doctor` and confirm the iOS tools (`idevice`,
   `ideviceinstaller`, `frida-ios-dump`, `class-dump`, `otool`, `ldid`). Report which are
   missing with their install hints; suggest `centurion install --group ios`. Never
   auto-install.

2. **Enumerate devices.** Call `ios_device_list`. If none is connected, ask the user to
   connect a device and trust the host (`idevicepair pair`). If multiple, confirm which UDID.

3. **Enumerate apps.** Call `ios_app_list` to list installed bundle IDs and confirm the
   target with the user.

4. **Pull a decrypted IPA (optional).** For App Store apps, call
   `ios_app_pull(bundle_id, target)` — this needs a **jailbroken** device running
   frida-server. If the device isn't jailbroken, note that static analysis is limited to
   what can be obtained otherwise and skip this step.

5. **Inspect the binary (optional).** Once you have the app's Mach-O binary (from a pulled
   IPA's `Payload/*.app/`), call `ios_binary_info(binary, target)` for hardening
   (PIE/encryption/stack-canary/ARC — records findings) and `ios_entitlements(binary)` for
   the code-signing entitlements. To reach an on-device service (SSH, a frida port) over USB,
   start a relay with `ios_relay(local_port, device_port, target)` (iproxy).

6. **Summarize the baseline.** Report the selected device, the installed iOS tool set, and
   propose next steps: static analysis via `centurion-static-analysis` (with
   `ios_static_ipa`), dynamic analysis via `centurion-dynamic-analysis` (with the iOS Frida
   scripts), or network interception via `centurion-network-intercept`.

## Scope reminder

Only operate on devices and apps the user is authorized to test.
