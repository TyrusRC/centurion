# Centurion Phase 3 — iOS Support Design

**Date:** 2026-06-12
**Status:** Approved (architecture)
**Builds on:** Phase 1, Phase 2a, Phase 2b (all merged to `main`).

## Summary

Phase 3 extends Centurion from Android-only to iOS, adding an iOS device layer
(libimobiledevice), iOS-specific app and static tooling, decrypted-IPA pull, and
iOS-targeted Frida scripts. It follows the proven `Adapter` pattern and the same "wrap,
do not reimplement" and "detect + manual install hint, never auto-install" philosophies.
Crucially, the dynamic / network / recon / static-scan adapters built in Phases 1–2 are
already platform-agnostic (Frida, objection, radare2, strings, opengrep, mitmproxy,
tcpdump) and are **reused unchanged** for iOS — so Phase 3's net-new work is the iOS
device backend, app/IPA handling, two iOS static tools, and iOS Frida scripts.

### Decisions (locked)
- **Device posture:** both jailbroken and non-jailbroken workflows, detect-only. Each
  tool detects presence and prints a manual install hint; the operator runs whatever
  their device supports.
- **Device backend:** **libimobiledevice** (cross-platform, runs on the Linux host),
  not macOS-only `xcrun`/`ios-deploy`.
- **App decryption:** wrap **frida-ios-dump** as the iOS equivalent of `pull_apk`
  (needs a jailbroken device + frida-server). Detect-only, manual install, never
  auto-fetch.
- **iOS Frida scripts:** add `ios_ssl_unpin.js` and `ios_jailbreak_bypass.js` to the
  existing bundled `ScriptLibrary` (platform `ios`).
- **Mach-O recon:** reuse the existing radare2 / strings adapters; do NOT add otool/nm
  (avoids redundancy — YAGNI).
- **IPA extraction + plist parsing:** use stdlib `zipfile` to extract
  `Payload/*.app/Info.plist` and stdlib `plistlib` to parse it (neither is a security tool
  to wrap; `plistlib` reads both binary and XML plists natively) — no external plist tool.
- **Implementation:** one spec, two plans (3a adapters/state, 3b MCP/skills), each
  independently green/mergeable — mirroring Phase 2.

## 1. New iOS adapters (`src/centurion/adapters/ios/`)

All follow the Phase-1 `Adapter` pattern (metadata + `detect()` + `install_hint()` +
operations that shell out via the injected `Runner` and parse to structured models).
`platform = Platform.IOS`. `mastg_id` is set where a confirmed MASTG-TOOL id exists,
otherwise `None` (same convention already used for dex2jar / strings / mitmproxy).

| Adapter | Binary | Category | Key operations |
|---|---|---|---|
| `IdeviceAdapter` | `idevice_id` (+ `ideviceinfo`) | device-qa | `devices() -> list[AppleDevice]`; `info(udid) -> dict` |
| `IdeviceinstallerAdapter` | `ideviceinstaller` | device-qa | `apps() -> list[str]` (bundle IDs) |
| `FridaIosDumpAdapter` | `frida-ios-dump` | dynamic | `dump(bundle_id, out_dir) -> Artifact` (decrypted IPA) |
| `ClassDumpAdapter` | `class-dump` | static | `headers(binary, out_path) -> Artifact` (Obj-C headers) |

Notes:
- `IdeviceAdapter` detects on `idevice_id` (the enumeration binary); `info()` additionally
  shells out to `ideviceinfo`. Both ship in the libimobiledevice package and are normally
  installed together — matching how `AdbAdapter` drives several adb subcommands.
- `IdeviceinstallerAdapter.apps()` parses `ideviceinstaller -l` output to bundle IDs.
- `FridaIosDumpAdapter.dump()` returns an `Artifact(kind="binary", tool="frida-ios-dump")`
  pointing at the pulled `.ipa`. It is long-running but one-shot (not a durable process).
- `ClassDumpAdapter.headers()` runs `class-dump -H -o <out> <binary>` and returns an
  `Artifact(kind="decoded", tool="class-dump")`.

### Plist + IPA handling (stdlib helpers, not tool-wrapping adapters)
Plist parsing uses Python's stdlib **`plistlib`**, which natively reads both binary and
XML plists — so no external plist tool is wrapped (the same rationale as using stdlib
`zipfile` for IPA extraction; neither is a security tool). A small helper module
(`src/centurion/ios/ipa.py`) provides `read_plist(path) -> dict` (plistlib) and
`ipa_info(ipa_path) -> dict` (extract `Payload/*.app/Info.plist` via `zipfile`, then
`read_plist`). These helpers carry no `detect()`/install-hint surface because they depend
only on the standard library.

## 2. New model

`AppleDevice` dataclass in `models.py` (mirrors `AndroidDevice`):
`udid: str`, `name: str | None`, `ios_version: str | None`, with `to_dict()`.

## 3. iOS Frida scripts

Add to `src/centurion/scripts/frida/`:
- `ios_ssl_unpin.js` — bypass common iOS TLS pinning (NSURLSession / `SecTrustEvaluate`
  paths). Authorized-testing-only header.
- `ios_jailbreak_bypass.js` — neutralise common jailbreak-detection checks
  (file-existence, `fork`, URL-scheme probes). Authorized-testing-only header.

Both are added to the `ScriptLibrary` `_CATALOG` with `platform="ios"`. `frida_list_scripts`
already returns `platform`, so clients can filter Android vs iOS scripts. No change to the
`ScriptLibrary` interface.

## 4. Registry

All four iOS adapters are registered in `default_registry`. `doctor` and
`install --group ios` already work (the `ios` platform group exists in `install.py`),
so they light up automatically once the adapters are registered.

## 5. MCP surface (Phase 3b)

New tools (all return structured JSON; reuse the existing workspace/findings/process
plumbing):
- `ios_device_list` — `IdeviceAdapter.devices()` → list of AppleDevice dicts.
- `ios_app_list` — `IdeviceinstallerAdapter.apps()` → bundle IDs.
- `ios_app_pull(bundle_id, target)` — `FridaIosDumpAdapter.dump()` into the workspace;
  records an artifact.
- `ios_static_ipa(ipa, target)` — `ipa_info()` helper (extract Info.plist via zipfile +
  parse via stdlib plistlib), optionally `class-dump` the app binary; records artifacts
  and returns a structured summary (bundle id, minimum OS, ATS settings, URL schemes).
- `ios_plist(path)` — parse a single plist to a dict via the `read_plist()` helper.

**Reused unchanged for iOS** (already platform-agnostic — the operator passes an iOS
bundle id / target): `objection_run`, `frida_run_named_script` / `ssl_unpin`
(point at the `ios_ssl_unpin` script), `frida_run_script`, `proxy_start/stop/flows`,
`recon_strings`, `recon_radare2`, `static_scan`, `findings_list`. Resources unchanged.

## 6. Skills + subagents (Phase 3b)

- New skill **`centurion-ios-recon`** — enumerate iOS devices/apps via libimobiledevice,
  confirm tool availability, and guide decrypted-IPA pull (jailbreak + frida-server
  prerequisites). Mirrors `centurion-recon`.
- Update the three Phase-2b skills (`static-analysis`, `dynamic-analysis`,
  `network-intercept`) with short iOS-variant notes: iOS uses bundle IDs, the
  `ios_static_ipa` / `ios_app_pull` tools, and the `ios_ssl_unpin` / `ios_jailbreak_bypass`
  scripts; decrypt the IPA before static scanning an App Store app.
- Subagents: the existing `centurion-static-analyst` / `-dynamic-analyst` / `-triage`
  stay; triage is platform-agnostic. (No new subagent — YAGNI.)

Skills/agents reference only MCP tools that exist after 3b.

## 7. Testing strategy

Same `FakeRunner` discipline as Phases 1–2:
- Command builders + output parsers tested with canned tool output: `idevice_id -l` →
  UDIDs; `ideviceinfo` → device dict; `ideviceinstaller -l` → bundle IDs;
  `class-dump` artifact; `frida-ios-dump` artifact.
- `ScriptLibrary` test extended to assert the two iOS scripts list with `platform="ios"`.
- The `read_plist` / `ipa_info` helpers tested with in-test fixtures: a binary and an XML
  plist written via stdlib `plistlib`, and a small zip containing `Payload/X.app/
  Info.plist` (built in a `tmp_path`, no real device).
- MCP tools tested by monkeypatching the registry/workspace exactly as in Phase 2b.
- Skills/agents are markdown; the existing guard test that scans `.claude/**` for tool
  references is extended to include the new `ios_*` tools.
- The opt-in integration tier (real iOS device) remains deferred.

## 8. Implementation phasing (one spec, two plans)

- **Plan 3a — adapters + state:** the four iOS adapters; the `read_plist`/`ipa_info`
  stdlib helpers; `AppleDevice` model; the two iOS Frida scripts; registry registration.
  Fully unit-tested. No new MCP tools or skills.
- **Plan 3b — workflows:** the five `ios_*` MCP tools (wiring the IPA helper); the
  `centurion-ios-recon` skill; iOS notes in the three Phase-2b skills; guard-test update.

Each plan ends green and is independently mergeable.

## Out of scope (deferred to a later phase)

macOS-only tooling (`xcrun`, `ios-deploy`, native `otool`/`plutil`); on-device keychain
dumping; report generation; MASTG test-case checklists; MobSF; GUI tools (Grapefruit /
Passionfruit). No auto-installation of any tool. Real-device integration tests remain
opt-in/deferred.

## Legal / ethical scope

Unchanged: authorized mobile security testing and QA only. The bundled iOS Frida scripts
are original and labelled for authorized use; the README scope statement continues to
apply.
