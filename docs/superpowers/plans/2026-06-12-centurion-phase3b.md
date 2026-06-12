# Centurion Phase 3b — iOS Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the Phase-3a iOS adapters and IPA helper through five `ios_*` MCP tools, add the `centurion-ios-recon` skill, give the existing static/dynamic/network skills iOS notes, and extend the guard tests — making iOS usable day-to-day from Claude Code.

**Architecture:** Five new `@mcp.tool()` functions appended to `src/centurion/mcp/server.py`, reusing the existing `get_registry`/`get_workspace` factories exactly as the Android tools do. Device/app tools delegate to the iOS adapters; `ios_plist`/`ios_static_ipa` call the stdlib `centurion.ios.ipa` helpers (no registry). `ios_static_ipa` records an ATS finding into the workspace when an app opts out of App Transport Security. Skills/subagents are markdown referencing only shipped tools; two guard tests enforce that.

**Tech Stack:** Python 3.11+, FastMCP (`mcp.server.fastmcp`), pytest with `FakeRunner`. All commands run via `.venv/bin/python -m pytest` (system Python is externally-managed; never bare `pytest`/`python`).

**Builds on:** `docs/superpowers/specs/2026-06-12-centurion-phase3-ios-design.md` §5–§6, Phase 3a (merged to `main`).

---

## Reference: existing server factories + adapters (already implemented, do NOT change)

`src/centurion/mcp/server.py` already defines:
- `get_registry() -> Registry`, `get_workspace(target)`, `get_process_manager(target)`, `get_script_library()`.
- 17 tools (doctor, device_list, app_list, app_pull, static_decode, static_scan, objection_run,
  frida_list_scripts, frida_run_named_script, frida_run_script, ssl_unpin, proxy_start, proxy_stop,
  proxy_flows, recon_strings, recon_radare2, findings_list) and 3 resources.

Phase-3a adapters reachable via `get_registry().get(name)`:
- `"idevice"` → `IdeviceAdapter`: `devices() -> list[AppleDevice]` (`.to_dict()` → udid/name/ios_version).
- `"ideviceinstaller"` → `IdeviceinstallerAdapter`: `apps() -> list[str]`.
- `"frida-ios-dump"` → `FridaIosDumpAdapter`: `dump(bundle_id, out_dir) -> Artifact`.
- `"class-dump"` → `ClassDumpAdapter`: `headers(binary, out_dir) -> Artifact`.

Stdlib helpers in `src/centurion/ios/ipa.py`:
- `read_plist(path) -> dict`.
- `ipa_info(ipa_path) -> dict` with keys: `bundle_id`, `minimum_os`, `url_schemes`,
  `ats_allows_arbitrary_loads` (bool), `app_path`, `info_plist`.

`Workspace.add_finding(Finding)` and `Finding(id, title, severity, tool, detail="", location=None, mastg_refs=[])` exist.

Test pattern (from `tests/test_mcp_server.py`): monkeypatch `server.get_registry` with a
`Registry([...FakeRunner-backed adapters...])`, and for workspace tools monkeypatch
`centurion.session.default_root` to a `tmp_path`.

---

## File Structure

**Modify:**
- `src/centurion/mcp/server.py` — add 5 `ios_*` tools (after `findings_list`, before the resources).
- `tests/test_mcp_server.py` — tests for the 5 tools + extend the two guard-test name sets.
- `.claude/skills/centurion-dynamic-analysis/SKILL.md`, `.../centurion-network-intercept/SKILL.md`,
  `.../centurion-static-analysis/SKILL.md` — add a short "iOS variant" note to each.

**Create:**
- `.claude/skills/centurion-ios-recon/SKILL.md`.

---

## Task 1: iOS device + app listing tools

**Files:**
- Modify: `src/centurion/mcp/server.py`
- Test: `tests/test_mcp_server.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mcp_server.py` (add the imports near the top with the others):
```python
from centurion.adapters.ios.idevice import IdeviceAdapter
from centurion.adapters.ios.ideviceinstaller import IdeviceinstallerAdapter
```
Then append:
```python
def test_ios_device_list_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("idevice_id -l", stdout="00008030-AAAA\n", path="/usr/bin/idevice_id")
    fake.register("ideviceinfo -u 00008030-AAAA -k DeviceName", stdout="Alice iPhone\n")
    fake.register("ideviceinfo -u 00008030-AAAA -k ProductVersion", stdout="16.4\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([IdeviceAdapter(fake)]))
    assert server.ios_device_list() == [
        {"udid": "00008030-AAAA", "name": "Alice iPhone", "ios_version": "16.4"}
    ]


def test_ios_app_list_tool(monkeypatch):
    out = (
        "CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName\n"
        "com.acme.bank, 1.0, Acme Bank\n"
    )
    fake = FakeRunner()
    fake.register("ideviceinstaller -l", stdout=out, path="/usr/bin/ideviceinstaller")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([IdeviceinstallerAdapter(fake)]))
    assert server.ios_app_list() == ["com.acme.bank"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "ios_device_list or ios_app_list" -v`
Expected: FAIL — `AttributeError: module 'centurion.mcp.server' has no attribute 'ios_device_list'`

- [ ] **Step 3: Add the tools**

In `src/centurion/mcp/server.py`, after the `findings_list` tool (line ~161) and before the
`@mcp.resource("centurion://scripts")` block, add:
```python
@mcp.tool()
def ios_device_list() -> list[dict]:
    """List connected iOS devices (udid, name, ios_version)."""
    return [d.to_dict() for d in get_registry().get("idevice").devices()]


@mcp.tool()
def ios_app_list() -> list[str]:
    """List installed app bundle IDs on the connected iOS device."""
    return get_registry().get("ideviceinstaller").apps()
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "ios_device_list or ios_app_list" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/centurion/mcp/server.py tests/test_mcp_server.py
git commit -m "feat: add ios_device_list + ios_app_list MCP tools"
```

---

## Task 2: `ios_app_pull` (decrypted IPA into the workspace)

**Files:**
- Modify: `src/centurion/mcp/server.py`
- Test: `tests/test_mcp_server.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mcp_server.py` (add the import near the others):
```python
from centurion.adapters.ios.frida_ios_dump import FridaIosDumpAdapter
```
Then append:
```python
def test_ios_app_pull_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("frida-ios-dump", stdout="Done\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([FridaIosDumpAdapter(fake)]))
    result = server.ios_app_pull("com.acme.bank", "AcmeIOS")
    assert result["kind"] == "binary"
    assert result["path"].endswith("com.acme.bank.ipa")
    assert server.get_workspace("AcmeIOS").load().artifacts[0]["id"] == "ipa-com.acme.bank"
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k ios_app_pull -v`
Expected: FAIL — `AttributeError: ... has no attribute 'ios_app_pull'`

- [ ] **Step 3: Add the tool**

In `src/centurion/mcp/server.py`, after `ios_app_list`, add:
```python
@mcp.tool()
def ios_app_pull(bundle_id: str, target: str) -> dict:
    """Pull a decrypted IPA (frida-ios-dump) into the workspace; records an artifact."""
    ws = get_workspace(target)
    artifact = get_registry().get("frida-ios-dump").dump(bundle_id, str(ws.artifacts_dir))
    ws.add_artifact(artifact)
    return artifact.to_dict()
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k ios_app_pull -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/centurion/mcp/server.py tests/test_mcp_server.py
git commit -m "feat: add ios_app_pull MCP tool (decrypted IPA)"
```

---

## Task 3: `ios_plist` + `ios_static_ipa`

**Files:**
- Modify: `src/centurion/mcp/server.py`
- Test: `tests/test_mcp_server.py`

`ios_static_ipa` summarizes the IPA's Info.plist via `ipa_info` and, when the app opts out of
App Transport Security (`ats_allows_arbitrary_loads` is true), records a `medium` finding so the
triage flow can pick it up. It returns the summary dict.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mcp_server.py` (add imports near the others):
```python
import plistlib as _plistlib
import zipfile as _zipfile
```
Then append:
```python
def test_ios_plist_tool(tmp_path):
    p = tmp_path / "Info.plist"
    p.write_bytes(_plistlib.dumps({"CFBundleIdentifier": "com.acme.bank"}, fmt=_plistlib.FMT_BINARY))
    assert server.ios_plist(str(p))["CFBundleIdentifier"] == "com.acme.bank"


def _make_ipa(path, info):
    with _zipfile.ZipFile(path, "w") as zf:
        zf.writestr("Payload/Acme.app/Info.plist", _plistlib.dumps(info, fmt=_plistlib.FMT_XML))


def test_ios_static_ipa_returns_summary(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ipa = tmp_path / "app.ipa"
    _make_ipa(ipa, {"CFBundleIdentifier": "com.acme.bank", "MinimumOSVersion": "15.0"})
    summary = server.ios_static_ipa(str(ipa), "AcmeIOS")
    assert summary["bundle_id"] == "com.acme.bank"
    assert summary["minimum_os"] == "15.0"
    # No ATS opt-out → no finding recorded.
    assert server.get_workspace("AcmeIOS").load().findings == []


def test_ios_static_ipa_records_ats_finding(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ipa = tmp_path / "app.ipa"
    _make_ipa(ipa, {
        "CFBundleIdentifier": "com.acme.bank",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    })
    summary = server.ios_static_ipa(str(ipa), "AcmeIOS")
    assert summary["ats_allows_arbitrary_loads"] is True
    findings = server.get_workspace("AcmeIOS").load().findings
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "Transport Security" in findings[0]["title"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "ios_plist or ios_static_ipa" -v`
Expected: FAIL — `AttributeError: ... has no attribute 'ios_plist'`

- [ ] **Step 3: Add the tools**

In `src/centurion/mcp/server.py`, add the import to the top import block (after the existing
`from ..scripts import ScriptLibrary` line):
```python
from ..ios.ipa import ipa_info, read_plist
```
Also add `from ..models import Finding` to the top imports (it is not yet imported there).

Then after `ios_app_pull`, add:
```python
@mcp.tool()
def ios_plist(path: str) -> dict:
    """Parse an iOS plist (binary or XML) into a dict."""
    return read_plist(path)


@mcp.tool()
def ios_static_ipa(ipa: str, target: str) -> dict:
    """Summarize an IPA's Info.plist; records an ATS finding if the app opts out of
    App Transport Security. Returns the summary (bundle id, min OS, URL schemes, ATS)."""
    ws = get_workspace(target)
    summary = ipa_info(ipa)
    if summary.get("ats_allows_arbitrary_loads"):
        ws.add_finding(
            Finding(
                id=f"ats-{summary.get('bundle_id') or ipa}",
                title="App Transport Security disabled (NSAllowsArbitraryLoads)",
                severity="medium",
                tool="ios-static-ipa",
                detail="Info.plist sets NSAllowsArbitraryLoads=true, permitting cleartext HTTP.",
                location=summary.get("info_plist"),
            )
        )
    return summary
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "ios_plist or ios_static_ipa" -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Run the full suite + clean import**

Run:
```bash
.venv/bin/python -m pytest -q
.venv/bin/python -c "import centurion.mcp.server as s; print('ios tools ok')"
```
Expected: all pass; prints `ios tools ok`.

- [ ] **Step 6: Commit**

```bash
git add src/centurion/mcp/server.py tests/test_mcp_server.py
git commit -m "feat: add ios_plist + ios_static_ipa MCP tools"
```

---

## Task 4: `centurion-ios-recon` skill

**Files:**
- Create: `.claude/skills/centurion-ios-recon/SKILL.md`

- [ ] **Step 1: Write the skill**

`.claude/skills/centurion-ios-recon/SKILL.md`:
```markdown
---
name: centurion-ios-recon
description: Use at the start of an iOS app assessment to enumerate connected iOS devices and apps via libimobiledevice, confirm tool availability, and pull a decrypted IPA. Drives the Centurion MCP server.
---

# Centurion: iOS Recon

Establish the iOS baseline before deeper analysis. Use the Centurion MCP server. Operate
only on devices and apps you are authorized to test.

## Steps

1. **Check capability.** Call `doctor` and confirm the iOS tools (`idevice`,
   `ideviceinstaller`, `frida-ios-dump`, `class-dump`). Report which are missing with their
   install hints; suggest `centurion install --group ios`. Never auto-install.

2. **Enumerate devices.** Call `ios_device_list`. If none is connected, ask the user to
   connect a device and trust the host (`idevicepair pair`). If multiple, confirm which UDID.

3. **Enumerate apps.** Call `ios_app_list` to list installed bundle IDs and confirm the
   target with the user.

4. **Pull a decrypted IPA (optional).** For App Store apps, call
   `ios_app_pull(bundle_id, target)` — this needs a **jailbroken** device running
   frida-server. If the device isn't jailbroken, note that static analysis is limited to
   what can be obtained otherwise and skip this step.

5. **Summarize the baseline.** Report the selected device, the installed iOS tool set, and
   propose next steps: static analysis via `centurion-static-analysis` (with
   `ios_static_ipa`), dynamic analysis via `centurion-dynamic-analysis` (with the iOS Frida
   scripts), or network interception via `centurion-network-intercept`.

## Scope reminder

Only operate on devices and apps the user is authorized to test.
```

- [ ] **Step 2: Verify it loads and references only shipped tools**

Run:
```bash
grep -oE '`[a-z_]+\(' .claude/skills/centurion-ios-recon/SKILL.md | tr -d '`(' | sort -u
```
Expected: only `doctor`, `ios_app_list`, `ios_app_pull`, `ios_device_list` (all shipped).

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/centurion-ios-recon
git commit -m "feat: add centurion-ios-recon skill"
```

---

## Task 5: iOS notes in the existing skills

**Files:**
- Modify: `.claude/skills/centurion-static-analysis/SKILL.md`,
  `.claude/skills/centurion-dynamic-analysis/SKILL.md`,
  `.claude/skills/centurion-network-intercept/SKILL.md`

Each gets a short "## iOS variant" section appended before the final "## Scope reminder"
section. Use only shipped tool names.

- [ ] **Step 1: Append the iOS note to the static-analysis skill**

In `.claude/skills/centurion-static-analysis/SKILL.md`, immediately before the
`## Scope reminder` line, insert:
```markdown
## iOS variant

For iOS apps, run `centurion-ios-recon` first, then `ios_app_pull(bundle_id, target)` to get
a decrypted IPA (jailbreak + frida-server) and `ios_static_ipa(ipa, target)` to summarize the
Info.plist — it records an ATS (NSAllowsArbitraryLoads) finding automatically. Use
`ios_plist(path)` to inspect individual plists. Opengrep `static_scan` still applies to any
extracted source.

```

- [ ] **Step 2: Append the iOS note to the dynamic-analysis skill**

In `.claude/skills/centurion-dynamic-analysis/SKILL.md`, immediately before the
`## Scope reminder` line, insert:
```markdown
## iOS variant

For iOS targets, pass the app's bundle ID. The bundled Frida scripts include `ios_ssl_unpin`
and `ios_jailbreak_bypass` (run via `frida_run_named_script(bundle_id, "ios_ssl_unpin", target)`);
`frida_list_scripts` reports each script's platform. `objection_run` and `frida_run_script`
work against iOS bundle IDs as well.

```

- [ ] **Step 3: Append the iOS note to the network-intercept skill**

In `.claude/skills/centurion-network-intercept/SKILL.md`, immediately before the
`## Scope reminder` line, insert:
```markdown
## iOS variant

The proxy flow is identical for iOS. To trust mitmproxy, install the CA profile via Settings
and enable it under General > About > Certificate Trust Settings. App-level pinning still
needs a bypass — run the `ios_ssl_unpin` Frida script via
`frida_run_named_script(bundle_id, "ios_ssl_unpin", target)`.

```

- [ ] **Step 4: Verify the modified skills reference only shipped tools**

Run:
```bash
grep -rhoE '`[a-z_]+\(' .claude/skills/centurion-static-analysis .claude/skills/centurion-dynamic-analysis .claude/skills/centurion-network-intercept | tr -d '`(' | sort -u
```
Expected: every token is one of the shipped tools (doctor, app_list, app_pull, static_decode,
static_scan, objection_run, frida_list_scripts, frida_run_named_script, frida_run_script,
ssl_unpin, proxy_start, proxy_stop, proxy_flows, recon_strings, recon_radare2, findings_list,
ios_device_list, ios_app_list, ios_app_pull, ios_static_ipa, ios_plist).

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/centurion-static-analysis .claude/skills/centurion-dynamic-analysis .claude/skills/centurion-network-intercept
git commit -m "docs: add iOS variant notes to the analysis skills"
```

---

## Task 6: Extend the guard tests + final verification

**Files:**
- Modify: `tests/test_mcp_server.py`

The two guard tests pin the shipped-tool set. Both must grow by the five `ios_*` names.

- [ ] **Step 1: Update `test_all_documented_tools_are_defined`**

In `tests/test_mcp_server.py`, in `test_all_documented_tools_are_defined`, add the five iOS
names to the `expected` set so it reads:
```python
def test_all_documented_tools_are_defined():
    expected = {
        "doctor", "device_list", "app_list", "app_pull", "static_decode",
        "static_scan", "objection_run", "frida_list_scripts",
        "frida_run_named_script", "frida_run_script", "ssl_unpin",
        "proxy_start", "proxy_stop", "proxy_flows", "recon_strings",
        "recon_radare2", "findings_list",
        "ios_device_list", "ios_app_list", "ios_app_pull", "ios_static_ipa", "ios_plist",
    }
    for name in expected:
        assert callable(getattr(server, name)), f"missing MCP tool: {name}"
```

- [ ] **Step 2: Update `test_skills_and_agents_reference_only_shipped_tools`**

In the same file, in `test_skills_and_agents_reference_only_shipped_tools`, add the five iOS
names to the `shipped` set (the set literal inside that test) so it matches:
```python
    shipped = {
        "doctor", "device_list", "app_list", "app_pull", "static_decode",
        "static_scan", "objection_run", "frida_list_scripts",
        "frida_run_named_script", "frida_run_script", "ssl_unpin",
        "proxy_start", "proxy_stop", "proxy_flows", "recon_strings",
        "recon_radare2", "findings_list",
        "ios_device_list", "ios_app_list", "ios_app_pull", "ios_static_ipa", "ios_plist",
    }
```

- [ ] **Step 3: Run the guard tests**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "documented or reference_only" -v`
Expected: PASS (both). The markdown-scan test now sees the `ios_*` references in the new/edited
skills and finds them all in `shipped`.

- [ ] **Step 4: Run the full suite + clean import**

Run:
```bash
.venv/bin/python -m pytest -q
.venv/bin/python -c "import centurion.mcp.server as s; print('all ok')"
```
Expected: all pass; prints `all ok`.

- [ ] **Step 5: Commit**

```bash
git add tests/test_mcp_server.py
git commit -m "test: extend MCP tool guards with ios_* tools"
```

---

## Done-When

- The MCP server exposes 22 tools (17 prior + `ios_device_list`, `ios_app_list`,
  `ios_app_pull`, `ios_static_ipa`, `ios_plist`).
- `ios_static_ipa` records an ATS finding when an app opts out of App Transport Security.
- The `centurion-ios-recon` skill exists and the three existing analysis skills have iOS notes.
- Both guard tests pass with the expanded shipped-tool set, confirming all skill/agent tool
  references are shipped.
- `.venv/bin/python -m pytest -q` is fully green.

## Notes / deviations from spec

- §5 listed `ios_static_ipa` as "optionally class-dump the app binary"; class-dump is **not**
  auto-run inside the tool (it needs the extracted Mach-O on disk and there is no `ios_classdump`
  tool in the spec's surface). The `class-dump` adapter remains available via the registry for a
  future tool. `ios_static_ipa` instead records the actionable ATS finding — keeping the tool
  focused (YAGNI). The IPA artifact is already recorded by `ios_app_pull`, so `ios_static_ipa`
  records a finding rather than a redundant artifact.
```
