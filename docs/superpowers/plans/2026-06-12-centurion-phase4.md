# Centurion Phase 4 — Competitor-Gap Tool Coverage

> **For agentic workers:** TDD, one logical unit per commit. Steps use checkbox syntax.

**Goal:** Close the capability gaps versus MobSF / objection / passionfruit / apkid by wrapping
seven more MASTG tools and exposing them over the CLI/MCP, keeping the "wrap, never reimplement"
adapter pattern.

**Architecture:** Each tool gets a thin `Adapter` (class attrs + `install_hint` + pure
`*_command` builders + pure parsers + an orchestrating op that shells out via the injected
Runner). New MCP tools record `Finding`s into the workspace where the tool produces issues.
No real device/subprocess is touched in tests (FakeRunner + pre-written output files).

**Tech stack:** Python 3.12, Typer, FastMCP, pytest, hatchling. stdlib `json`/`plistlib`.

---

## Scope (approved gap analysis)

| Adapter | binary | MASTG id | platform / category | Key op(s) |
|---|---|---|---|---|
| APKiD | `apkid` | 0009 | android / static | `scan(apk) -> [Finding]` (packer/obfuscator/compiler tags) |
| Apkleaks | `apkleaks` | 0125 | android / static | `scan(apk, out) -> [Finding]` (secrets/endpoints) |
| gitleaks | `gitleaks` | 0144 | generic / static | `scan(path, report) -> [Finding]` (secrets) |
| nm | `nm` | 0003 | generic / recon | `symbols(path, dynamic) -> [dict]` |
| aapt2 | `aapt2` | 0124 | android / static | `badging(apk) -> dict` (pkg/version/perms) |
| otool | `otool` | 0060 | ios / static | `hardening(binary) -> dict` (pie/encrypted/canary/arc/libs) |
| ldid | `ldid` | 0111 | ios / static | `entitlements(binary) -> dict` |

Plus: `IdeviceAdapter.relay_command(local, device)` wrapping iproxy (MASTG-TOOL-0055, same
libimobiledevice suite).

## New MCP tools (server.py)

- `apkid_scan(apk, target)` — record info findings, return list
- `apkleaks_scan(apk, target)` — write JSON into workspace, record findings, return list
- `secrets_scan(path, target)` — gitleaks over a source tree, record findings
- `apk_badging(apk)` — aapt2 badging dict
- `recon_symbols(path)` — nm symbol list
- `ios_binary_info(binary, target)` — otool hardening; record findings for missing PIE /
  not-encrypted / missing stack canary
- `ios_entitlements(binary)` — ldid entitlements dict
- `ios_relay(local_port, device_port, target)` — durable iproxy process via the process manager

→ 18 adapters become **25**; 23 MCP tools become **31**.

## Tasks

1. APKiD adapter + test (`adapters/android/apkid.py`, `tests/test_apkid.py`)
2. Apkleaks adapter + test
3. gitleaks adapter + test
4. nm adapter + test
5. aapt2 adapter + test
6. otool adapter + test
7. ldid adapter + iproxy `relay_command` on IdeviceAdapter + tests
8. Register all 7 in `default_registry`; add the 8 MCP tools; extend both guard-test name sets
9. Wire skills (static/dynamic/ios-recon) + rewrite README counts; update memory

Each task: write failing test → implement → `\.venv/bin/python -m pytest` green → commit
(`feat:`/`test:`). Final: full-suite review pass, then a single push when the user asks.
