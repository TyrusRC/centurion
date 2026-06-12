---
name: centurion-static-analysis
description: Use to statically analyze an Android app — pull its APK, decode it, run an Opengrep ruleset, and record findings. Drives the Centurion MCP server.
---

# Centurion: Static Analysis

Pull, decode, scan, record. Use the Centurion MCP server. Operate only on apps you are authorized to test.

## Steps

1. **Pick the target app.** Call `app_list` to enumerate installed packages and confirm the package name with the user. Choose a short workspace `target` name (e.g. the app name).

2. **Pull the APK.** Call `app_pull(package, target)`. Note the returned artifact path.

3. **Decode resources/manifest.** Call `static_decode(apk, target)` with the pulled APK path. The result is a decoded tree under the workspace artifacts.

4. **Scan.** Call `static_scan(path, target)` on the decoded tree. If it reports that rules are missing, tell the user to install an Opengrep ruleset into `~/.centurion/rules` (see `doctor` install hint) or pass an explicit `rules` path — never auto-fetch rules.

5. **Report.** Summarize findings by severity and list them with their MASTG references. Findings are persisted; the `centurion-triage` subagent can pick them up via `findings_list`.

## iOS variant

For iOS apps, run `centurion-ios-recon` first, then `ios_app_pull(bundle_id, target)` to get
a decrypted IPA (jailbreak + frida-server) and `ios_static_ipa(ipa, target)` to summarize the
Info.plist — it records an ATS (NSAllowsArbitraryLoads) finding automatically. Use
`ios_plist(path)` to inspect individual plists, and `ios_classdump(binary, target)` to dump
Objective-C headers from the app's Mach-O binary. Opengrep `static_scan` still applies to any
extracted source.

## Scope reminder

Authorized assessments only.
