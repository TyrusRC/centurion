# Centurion — Mobile QA + Pentest Toolkit Design

**Date:** 2026-06-11
**Status:** Approved (architecture + Phase 1)

## Summary

Centurion is a Python toolkit that unifies mobile **QA/device tooling** (scrcpy, adb,
device control) and **mobile penetration-testing tooling** (the OWASP MASTG tool list,
Android + iOS) behind a single, consistent layer. It is designed to *integrate with*
existing tools rather than replace them, to fit a daily workflow, and to be driven by
Claude Code through an MCP server plus shipped skills and subagents.

It deliberately **wraps** real tools (shells out + parses output into structured
results); it never reimplements them.

### Non-goals / explicit exclusions
- **MobSF is excluded** — Centurion overlaps with it in role.
- **No MASTG test-case checklist** feature.
- **No report generation.**

## Decisions (locked)

| Decision | Choice |
|---|---|
| Form | Research-driven toolkit: CLI + MCP server + Claude skills/agents |
| Language/runtime | Python |
| Platforms | Android **and** iOS (full OWASP MASTG tool coverage) |
| Tool binaries | Detect + bootstrap installer (`doctor` / `install`); run natively |
| MCP scope | Full engagement assistant: launch/control + structured results + session/state |
| Architecture | Approach A — unified package, single stdio MCP server, pluggable tool adapters |

## Architecture (Approach A)

One installable Python package exposing three faces over a shared core:

- **`centurion` CLI** (Typer) — daily-workflow use.
- **`centurion-mcp` server** — stdio, official `mcp` Python SDK (FastMCP) — for Claude Code.
- **core library** — adapters, registry, session, devices, process manager, models.

The CLI and MCP server are both thin; all real logic lives in the core so the two faces
cannot drift apart.

### 1. Tool adapter layer (the heart)

One adapter module per external tool. Each adapter implements a common protocol:

- **metadata:** `name`, `mastg_id` (e.g. `MASTG-TOOL-0001`), `platform`
  (`android` | `ios` | `generic` | `network`), `category`
  (`device-qa` | `static` | `dynamic` | `network` | `recon`).
- **`detect() -> ToolStatus`** — installed?, version, resolved path.
- **`install()` / `install_hint()`** — platform-appropriate (brew / pip / apt /
  sdkmanager); idempotent; never installs silently.
- **operations** — shell out to the real tool and parse output into structured models
  (`Finding`, `Artifact`, `ToolStatus`).

#### Tool taxonomy mapped to MASTG categories

| Category | Android | iOS | Generic / Network |
|---|---|---|---|
| device / QA | adb, **scrcpy**, screenrecord | libimobiledevice (ideviceinstaller, iproxy), ios-deploy | Appium / Maestro *(optional)* |
| static | apktool, jadx, dex2jar, apksigner, semgrep + MASTG rules | class-dump, otool/nm, plutil, frida-ios-dump | radare2, ghidra (headless) |
| dynamic | frida (+ frida-server mgmt), objection, drozer | frida, objection, lldb | r2frida |
| network | — | — | mitmproxy, Burp/ZAP launch + cert helper, tcpdump |

### 2. Session / workspace

A "target" is one app/device engagement. State lives at
`~/.centurion/workspaces/<slug>/`:

- `session.json` — target metadata, selected device, run history, artifact index.
- `artifacts/` — decompiled code, pcaps, frida logs, screenshots, pulled binaries.

Long-running tools (scrcpy, mitmproxy, frida-server) run as **managed background
processes** referenced by handle in session state, so both the CLI and the MCP server
can observe and stop them.

### 3. MCP surface

FastMCP. **Tools return structured JSON, not raw dumps.**

Tools (representative): `device_list`, `device_select`, `app_list`, `app_pull`,
`scrcpy_start` / `scrcpy_stop`, `static_decompile`, `static_scan` (→ findings),
`dynamic_frida_attach`, `frida_run_script`, `objection_run`, `ssl_unpin`,
`proxy_start` (→ flows), `recon_strings`, `doctor`.

Resources (read-only state): `centurion://session/current`,
`centurion://tools` (registry + MASTG map), `centurion://artifacts/{id}`.

### 4. Claude Code skills + subagents (`.claude/`)

- **Skills:** `centurion:recon`, `centurion:static-analysis`,
  `centurion:dynamic-analysis`, `centurion:network-intercept` — each guides Claude
  through a workflow built on the MCP tools.
- **Subagents:** `centurion-static-analyst`, `centurion-dynamic-analyst`,
  `centurion-triage` (dedup/prioritize findings across runs).

### 5. Install / bootstrap

- `centurion doctor` — table of every tool: name, MASTG-ID, platform, installed?,
  version, install hint. Same data exposed via the MCP `doctor` tool.
- `centurion install [--group static|dynamic|network|ios|android|all]` — idempotent,
  confirms before installing.

## Project layout

```
centurion/
  pyproject.toml
  README.md
  src/centurion/
    __init__.py
    cli/...                 # Typer app
    mcp/server.py           # FastMCP server
    adapters/
      base.py               # adapter protocol
      android/*, ios/*, generic/*, network/*
    registry.py             # adapter discovery + MASTG mapping
    session.py              # workspace + session.json
    devices/
      android.py            # adb device layer
      ios.py                # libimobiledevice device layer
    process.py              # background process manager
    models.py               # Finding, Artifact, ToolStatus dataclasses
  .claude/
    skills/centurion-*/SKILL.md
    agents/centurion-*.md
  tests/
  docs/
```

## Testing strategy

- **TDD.** Adapters tested by injecting a fake subprocess-runner returning canned tool
  output; assert the parser produces correct structured models. No real devices in unit
  tests.
- Registry / session tested against a tmp workspace.
- MCP server smoke-tested via an in-process FastMCP client.
- A separate, opt-in **integration tier** requires a real device/emulator (marked,
  not run by default).

## Phasing

The MASTG tool list is large (~40 tools), so the work is sliced. Each phase gets its own
spec → plan → implementation cycle.

- **Phase 1 (detailed in this spec):** core (adapter base, registry, session, process
  manager, models) + Android device layer + `doctor` / `install` + CLI and MCP skeletons
  + **4 anchor adapters: adb, scrcpy, jadx, frida** + one skill + tests. Proves the full
  vertical slice end-to-end.
- **Phase 2:** remaining Android static / dynamic / network adapters + all skills and
  agents.
- **Phase 3:** iOS device layer + iOS adapters.

## Legal / ethical scope

Centurion is for **authorized** mobile security testing and QA only (pentest
engagements, security research, CTFs, testing apps you own or are permitted to test).
This intent is documented in the README.

## References

- OWASP MASTG tools index: https://mas.owasp.org/MASTG/tools/
- Tools are organized in the MASTG repo under `tools/{android,ios,generic,network}/`,
  each with a `MASTG-TOOL-XXXX` identifier (e.g. Frida = `MASTG-TOOL-0001`,
  Apktool = `MASTG-TOOL-0011`, jadx = `MASTG-TOOL-0018`, drozer = `MASTG-TOOL-0015`).
- Semgrep MASTG Android rules: https://github.com/mindedsecurity/semgrep-rules-android-security
- scrcpy: device screen mirroring/control (QA layer).
```