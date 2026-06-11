# Centurion Phase 2 — Android Sweep + Workflows Design

**Date:** 2026-06-11
**Status:** Approved (architecture)
**Builds on:** Phase 1 (`docs/superpowers/specs/2026-06-11-centurion-toolkit-design.md`), merged to `main`.

## Summary

Phase 2 broadens Centurion from the four anchor adapters to a wide MASTG Android tool
set, makes the toolkit usable day-to-day from Claude Code by shipping the static /
dynamic / network workflows, and adds engagement state (findings + durable long-running
process handles). It follows the proven Phase-1 `Adapter` pattern and the same "wrap, do
not reimplement" and "detect + manual install hint, never auto-install" philosophies.

### Decisions (locked)
- **Tool breadth:** broad MASTG Android sweep (~9–10 new adapters).
- **Frida exposure:** curated, vetted script library bundled in the package, plus raw
  passthrough.
- **Static scanner:** Opengrep (the open-source Semgrep fork; CLI/rule-compatible, uses a
  `scan` subcommand). Detect presence; if missing, print a manual install hint. Never
  auto-fetch/clone. `static_scan` takes a rules path (default `~/.centurion/rules`).
- **Long-running state:** persist process handles (and findings) to the workspace; no
  daemon (Approach A).
- **GUI-only tools excluded** (jadx-gui, bytecode-viewer) — they do not fit a CLI/MCP flow.
- **Implementation:** one spec, two plans (2a, 2b), each independently green/mergeable.

## 1. New tool adapters

All follow the Phase-1 `Adapter` pattern (metadata + `detect()` + `install_hint()` +
operations that shell out via the injected `Runner` and parse to structured models).

| Category | Adapters | Key operations |
|---|---|---|
| static | apktool (MASTG-TOOL-0011), dex2jar, apksigner, opengrep | decode manifest/resources; dex→jar; verify signature scheme; `scan(target, rules) -> Finding[]` |
| recon | radare2 (MASTG-TOOL-0028), strings | `info` / `strings` -> text + `Artifact` |
| dynamic | objection (MASTG-TOOL-0029), drozer (MASTG-TOOL-0015) | `objection_run(commands)`; drozer module run |
| network | mitmproxy, tcpdump | proxy lifecycle (section 2); on-device/host capture |

`AdbAdapter` gains `packages() -> list[str]` and `pull_apk(package, out_dir) -> Artifact`
to back `app_list` / `app_pull`.

opengrep is `platform=generic`, `category=static`; radare2/strings `category=recon`.

## 2. Session / state extensions

`Session` (in `session.py`) gains:
- **`findings: list[dict]`** — persisted across runs so the triage subagent can read them.
  `Workspace.add_finding(finding)` mirrors the existing `add_artifact`.
- The existing **`processes: list[dict]`** becomes the durable handle store. Long-running
  tools record `{handle, pid, command}` into `session.json`.

`ProcessManager` gains a workspace-backed mode:
- `start(handle, command)` spawns, then persists `{handle, pid, command}` to the session.
- `stop(handle)` reads the handle from the session, signals the pid to terminate
  (injectable `kill` function for tests — default `os.kill` with `SIGTERM`), and removes
  it from the session.
- `list()` reads persisted handles.

This lets `proxy_stop` / `scrcpy_stop` work across separate MCP server invocations
(each Claude Code session is a fresh MCP process), without a daemon.

## 3. Frida script library

`src/centurion/scripts/frida/` ships vetted, original scripts:
`ssl_unpin.js`, `root_bypass.js`, `debugger_bypass.js`, `dump_class_hooks.js`.

A `ScriptLibrary` registry maps name -> `{path, description, platform}` and loads files
via `importlib.resources`. The `frida/` directory is packaged as data (hatch wheel
`include` / `force-include`, or `[tool.hatch.build]` artifacts entry for `*.js`).

Scripts are invoked by name (`frida_run_named_script`) or ad hoc
(`frida_run_script` raw passthrough). Each script header states it is for authorized
testing only.

## 4. MCP surface additions

Tools (all return structured JSON):
`app_list`, `app_pull`, `static_decode` (apktool), `static_scan` (opengrep -> findings),
`objection_run`, `frida_list_scripts`, `frida_run_named_script`, `frida_run_script`,
`ssl_unpin`, `proxy_start`, `proxy_stop`, `proxy_flows`, `recon_strings`,
`recon_radare2`, `findings_list`.

Resources: `centurion://findings`, `centurion://scripts`, `centurion://processes`.

Long-running tools (`proxy_start`, frida-server) go through the durable `ProcessManager`
so their handles survive across MCP invocations.

## 5. Skills + subagents (`.claude/`)

Skills:
- **centurion-static-analysis** — pull APK -> decode/decompile -> opengrep scan -> record
  findings.
- **centurion-dynamic-analysis** — frida/objection attach, named-script hooks, `ssl_unpin`.
- **centurion-network-intercept** — `proxy_start` -> CA-cert install guidance ->
  `proxy_flows` summary.

Subagents (`.claude/agents/`):
- **centurion-static-analyst** — drives the static MCP tools, returns structured findings.
- **centurion-dynamic-analyst** — drives frida/objection.
- **centurion-triage** — reads `findings_list`, dedups/prioritizes, writes back a triaged
  set.

Skills/agents reference only MCP tools that exist.

## 6. Folded-in hardening (from the Phase-1 final review)

- `Registry.get` raises `KeyError(f"No adapter registered for '{name}'")` (clear message).
- CLI `device list` uses a rich `Table` for consistency with `doctor`.
- `detect()` keeps `path` honest: only report a path when one is actually resolved; a
  version-only detection is represented explicitly rather than "installed: yes" with a
  blank path.

## 7. Testing strategy

Same `FakeRunner` discipline as Phase 1:
- Command builders + output parsers tested with canned tool output: opengrep JSON ->
  `Finding[]`; mitmproxy flow dump -> flow summaries; objection/drozer output parsing;
  apktool/apksigner output parsing.
- `ScriptLibrary` tested by listing the bundled files and resolving one by name.
- Durable `ProcessManager` tested with a tmp workspace, fake spawn, and an injected
  `kill` function — no real processes or signals in unit tests.
- Skills/agents are markdown; verified by confirming they reference only existing MCP
  tools.
- The opt-in integration tier (real device/emulator) remains deferred.

## 8. Implementation phasing (one spec, two plans)

- **Plan 2a — adapters + state + hardening:** all new adapters; `adb` app ops;
  `Session.findings` + `Workspace.add_finding`; durable `ProcessManager`; the three
  hardening fixes. Fully unit-tested. No new MCP tools or skills yet.
- **Plan 2b — workflows:** Frida script library + `ScriptLibrary`; expanded MCP
  tools/resources; the three skills + three subagents.

Each plan ends green and is independently mergeable.

## Out of scope (deferred to Phase 3 or later)

iOS device layer and iOS adapters; report generation; MASTG test-case checklist; MobSF;
GUI-only tools. No auto-installation of any tool or ruleset.

## Legal / ethical scope

Unchanged from Phase 1: authorized mobile security testing and QA only. The bundled
Frida scripts are original and labelled for authorized use; the README scope statement
continues to apply.
