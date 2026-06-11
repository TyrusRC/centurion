---
name: centurion-recon
description: Use at the start of a mobile app assessment to enumerate connected devices, confirm tool availability, and establish a baseline before static or dynamic analysis. Drives the Centurion MCP server.
---

# Centurion: Recon

Establish the lay of the land before deeper analysis. Use the Centurion MCP server.

## Steps

1. **Check capability.** Call the `doctor` MCP tool. Report which tools are installed
   and which are missing (with their install hints). If a tool the user needs is
   missing, suggest `centurion install --group <group>`.

2. **Enumerate devices.** Call `device_list`. If no device is connected, ask the user to
   connect a device / start an emulator and enable USB debugging. If multiple devices are
   present, ask which serial to target.

3. **Summarize the baseline.** Report the selected device, the installed tool set mapped
   to MASTG categories (device-qa / static / dynamic / network), and propose next steps
   (e.g. static analysis via the `centurion-static-analysis` skill, or screen mirroring
   with scrcpy).

## Scope reminder

Only operate on devices and apps the user is authorized to test.
