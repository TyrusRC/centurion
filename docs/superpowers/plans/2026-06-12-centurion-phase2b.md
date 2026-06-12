# Centurion Phase 2b — Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Centurion usable day-to-day from Claude Code by shipping the Frida script library, the expanded MCP tool/resource surface, and the static/dynamic/network skills + subagents on top of the Phase-2a adapters.

**Architecture:** A bundled `ScriptLibrary` (importlib.resources over `src/centurion/scripts/frida/*.js`) plus a widened FastMCP server. The server gains factory helpers (`get_workspace`, `get_process_manager`, `get_script_library`) so tools can resolve a per-target workspace, persist findings/process handles via the durable `WorkspaceProcessManager`, and reach every Phase-2a adapter through the registry. Long-running tools (mitmdump, frida scripts) are started through the durable process manager so their handles survive across MCP invocations. Skills/agents are markdown that reference only the tools this plan ships.

**Tech Stack:** Python 3.11+, FastMCP (`mcp.server.fastmcp`), hatchling packaging, pytest with `FakeRunner`. All commands run via `.venv/bin/python -m pytest` (system Python is externally-managed).

**Builds on:** `docs/superpowers/specs/2026-06-11-centurion-phase2-design.md` §3–§5, Phase 2a (merged to `main`).

---

## File Structure

**Create:**
- `src/centurion/scripts/__init__.py` — `ScriptInfo`, `ScriptLibrary` (list/get/path over bundled JS).
- `src/centurion/scripts/frida/ssl_unpin.js`
- `src/centurion/scripts/frida/root_bypass.js`
- `src/centurion/scripts/frida/debugger_bypass.js`
- `src/centurion/scripts/frida/dump_class_hooks.js`
- `tests/test_script_library.py`
- `.claude/skills/centurion-static-analysis/SKILL.md`
- `.claude/skills/centurion-dynamic-analysis/SKILL.md`
- `.claude/skills/centurion-network-intercept/SKILL.md`
- `.claude/agents/centurion-static-analyst.md`
- `.claude/agents/centurion-dynamic-analyst.md`
- `.claude/agents/centurion-triage.md`

**Modify:**
- `src/centurion/mcp/server.py` — factories + ~15 tools + 3 resources.
- `src/centurion/adapters/generic/frida.py` — add `run_script_command`.
- `src/centurion/adapters/generic/mitmproxy.py` — add `parse_flows`.
- `src/centurion/adapters/generic/radare2.py` — add `info`.
- `tests/test_mcp_server.py` — tests for the new tools/resources.
- `tests/test_frida.py`, `tests/test_mitmproxy.py`, `tests/test_radare2.py` — new adapter-method tests.
- `pyproject.toml` — ensure bundled `*.js` ship in the wheel.

---

## Task 1: Frida script library

**Files:**
- Create: `src/centurion/scripts/__init__.py`, `src/centurion/scripts/frida/*.js`
- Test: `tests/test_script_library.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Write the four bundled scripts**

`src/centurion/scripts/frida/ssl_unpin.js`:
```javascript
// Centurion — TLS pinning bypass (Android). AUTHORIZED TESTING ONLY.
// Neutralises common pinning paths: custom TrustManager + OkHttp CertificatePinner.
Java.perform(function () {
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.centurion.TrustAll',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom');
    init.implementation = function (km, tm, sr) {
      init.call(this, km, [TrustManager.$new()], sr);
    };
    console.log('[centurion] SSLContext TrustManager neutralised');
  } catch (e) { console.log('[centurion] TrustManager hook skipped: ' + e); }
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
      console.log('[centurion] OkHttp CertificatePinner.check bypassed');
    };
  } catch (e) { console.log('[centurion] OkHttp pinner not present: ' + e); }
});
```

`src/centurion/scripts/frida/root_bypass.js`:
```javascript
// Centurion — root-detection bypass (Android). AUTHORIZED TESTING ONLY.
Java.perform(function () {
  try {
    var File = Java.use('java.io.File');
    var blocked = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su'];
    File.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (blocked.indexOf(p) !== -1) {
        console.log('[centurion] hiding root path: ' + p);
        return false;
      }
      return this.exists();
    };
    console.log('[centurion] File.exists root checks hooked');
  } catch (e) { console.log('[centurion] root_bypass skipped: ' + e); }
});
```

`src/centurion/scripts/frida/debugger_bypass.js`:
```javascript
// Centurion — anti-debug bypass (Android). AUTHORIZED TESTING ONLY.
Java.perform(function () {
  try {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
      console.log('[centurion] isDebuggerConnected -> false');
      return false;
    };
    console.log('[centurion] Debug.isDebuggerConnected hooked');
  } catch (e) { console.log('[centurion] debugger_bypass skipped: ' + e); }
});
```

`src/centurion/scripts/frida/dump_class_hooks.js`:
```javascript
// Centurion — enumerate methods of a target class. AUTHORIZED TESTING ONLY.
// Set CENTURION_CLASS in the spawned env, or edit the constant below.
Java.perform(function () {
  var target = 'java.lang.String';
  try {
    var clazz = Java.use(target);
    var methods = clazz.class.getDeclaredMethods();
    console.log('[centurion] methods of ' + target + ':');
    methods.forEach(function (m) { console.log('  ' + m.toString()); });
  } catch (e) { console.log('[centurion] dump_class_hooks skipped: ' + e); }
});
```

- [ ] **Step 2: Write the failing test**

`tests/test_script_library.py`:
```python
from pathlib import Path

from centurion.scripts import ScriptLibrary


def test_lists_all_bundled_scripts():
    lib = ScriptLibrary()
    names = {s.name for s in lib.list()}
    assert names == {"ssl_unpin", "root_bypass", "debugger_bypass", "dump_class_hooks"}


def test_each_script_has_description_and_platform():
    lib = ScriptLibrary()
    info = {s.name: s for s in lib.list()}
    assert info["ssl_unpin"].platform == "android"
    assert "pinning" in info["ssl_unpin"].description.lower()


def test_get_resolves_a_real_readable_file():
    lib = ScriptLibrary()
    info = lib.get("ssl_unpin")
    assert Path(info.path).is_file()
    assert "AUTHORIZED TESTING ONLY" in Path(info.path).read_text()


def test_get_unknown_raises():
    lib = ScriptLibrary()
    try:
        lib.get("does_not_exist")
        assert False, "expected KeyError"
    except KeyError as e:
        assert "does_not_exist" in str(e)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_script_library.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.scripts'`

- [ ] **Step 4: Implement `ScriptLibrary`**

`src/centurion/scripts/__init__.py`:
```python
"""Bundled, vetted Frida scripts and the registry that exposes them.

All scripts are original and labelled for authorized testing only.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources


@dataclass
class ScriptInfo:
    name: str
    description: str
    platform: str
    path: str


_CATALOG = {
    "ssl_unpin": ("Bypass common TLS certificate pinning (TrustManager + OkHttp)", "android"),
    "root_bypass": ("Hide common root indicators from File.exists checks", "android"),
    "debugger_bypass": ("Force isDebuggerConnected to report false", "android"),
    "dump_class_hooks": ("Enumerate declared methods of a target class", "android"),
}


class ScriptLibrary:
    """Lists and resolves the bundled Frida scripts via importlib.resources."""

    _package = "centurion.scripts.frida"

    def list(self) -> list[ScriptInfo]:
        return [self.get(name) for name in _CATALOG]

    def get(self, name: str) -> ScriptInfo:
        if name not in _CATALOG:
            raise KeyError(f"No bundled script named '{name}'")
        description, platform = _CATALOG[name]
        path = resources.files(self._package).joinpath(f"{name}.js")
        return ScriptInfo(name=name, description=description, platform=platform, path=str(path))

    def path(self, name: str) -> str:
        return self.get(name).path
```

- [ ] **Step 5: Ensure scripts ship in the wheel**

Edit `pyproject.toml` — add under `[tool.hatch.build.targets.wheel]` (after the `packages` line):
```toml
[tool.hatch.build.targets.wheel]
packages = ["src/centurion"]

[tool.hatch.build.targets.wheel.force-include]
"src/centurion/scripts/frida" = "centurion/scripts/frida"
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_script_library.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Commit**

```bash
git add src/centurion/scripts tests/test_script_library.py pyproject.toml
git commit -m "feat: add bundled Frida script library"
```

---

## Task 2: MCP server workspace/process/script factories

**Files:**
- Modify: `src/centurion/mcp/server.py`
- Test: `tests/test_mcp_server.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mcp_server.py`:
```python
def test_get_workspace_creates_under_target(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ws = server.get_workspace("Acme Bank")
    assert ws.slug == "acme-bank"
    assert ws.session_file.exists()


def test_get_process_manager_is_workspace_backed(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    pm = server.get_process_manager("Acme Bank")
    assert pm.list() == []


def test_get_script_library_lists_scripts():
    assert len(server.get_script_library().list()) == 4
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k factory -v` (and the three names above)
Expected: FAIL — `AttributeError: module 'centurion.mcp.server' has no attribute 'get_workspace'`

- [ ] **Step 3: Add the factories**

Edit `src/centurion/mcp/server.py` — replace the imports/header block (lines 1–15) with:
```python
"""FastMCP server exposing Centurion tools to Claude Code over stdio."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..process import WorkspaceProcessManager
from ..registry import Registry, default_registry
from ..scripts import ScriptLibrary
from ..session import Workspace, default_root

mcp = FastMCP("centurion")


def get_registry() -> Registry:
    """Factory so tests can monkeypatch with a FakeRunner-backed registry."""
    return default_registry()


def get_workspace(target: str) -> Workspace:
    """Resolve (creating if needed) the per-target workspace."""
    ws = Workspace(default_root(), target)
    ws.create()
    return ws


def get_process_manager(target: str) -> WorkspaceProcessManager:
    """Durable process manager backed by the target workspace."""
    return WorkspaceProcessManager(get_workspace(target))


def get_script_library() -> ScriptLibrary:
    return ScriptLibrary()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -v`
Expected: PASS (existing 3 + new 3)

- [ ] **Step 5: Commit**

```bash
git add src/centurion/mcp/server.py tests/test_mcp_server.py
git commit -m "feat: add workspace/process/script factories to MCP server"
```

---

## Task 3: Static MCP tools (app_list, app_pull, static_decode, static_scan)

**Files:**
- Modify: `src/centurion/mcp/server.py`
- Test: `tests/test_mcp_server.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mcp_server.py`:
```python
from centurion.adapters.android.apktool import ApktoolAdapter
from centurion.adapters.generic.opengrep import OpengrepAdapter


def _static_registry(fake):
    return Registry([AdbAdapter(fake), ApktoolAdapter(fake), OpengrepAdapter(fake)])


def test_app_list_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("adb shell pm list packages",
                  stdout="package:com.acme.app\npackage:com.other\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    assert server.app_list() == ["com.acme.app", "com.other"]


def test_app_pull_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("adb shell pm path com.acme.app", stdout="package:/data/app/base.apk\n")
    fake.register("adb pull", stdout="1 file pulled\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    result = server.app_pull("com.acme.app", "Acme")
    assert result["kind"] == "binary"
    assert result["path"].endswith("com.acme.app.apk")
    assert server.get_workspace("Acme").load().artifacts[0]["id"] == "apk-com.acme.app"


def test_static_decode_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("apktool d", stdout="I: Using Apktool\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    result = server.static_decode("/tmp/app.apk", "Acme")
    assert result["kind"] == "decoded"
    assert server.get_workspace("Acme").load().artifacts[0]["tool"] == "apktool"


def test_static_scan_records_findings(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    fake = FakeRunner()
    fake.register("opengrep scan", stdout=(
        '{"results":[{"check_id":"cleartext","path":"a/A.java",'
        '"start":{"line":12},"extra":{"severity":"ERROR","message":"cleartext HTTP"}}]}'
    ))
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    findings = server.static_scan("/tmp/decoded", "Acme", str(rules))
    assert findings[0]["severity"] == "high"
    assert server.get_workspace("Acme").load().findings[0]["title"] == "cleartext"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "app_list or app_pull or static" -v`
Expected: FAIL — `AttributeError: module 'centurion.mcp.server' has no attribute 'app_list'`

- [ ] **Step 3: Add the static tools**

Append to `src/centurion/mcp/server.py` (after `device_list`, before `main`):
```python
@mcp.tool()
def app_list() -> list[str]:
    """List installed package names on the connected Android device."""
    return get_registry().get("adb").packages()


@mcp.tool()
def app_pull(package: str, target: str) -> dict:
    """Pull a package's base APK into the target workspace; records an artifact."""
    ws = get_workspace(target)
    artifact = get_registry().get("adb").pull_apk(package, str(ws.artifacts_dir))
    ws.add_artifact(artifact)
    return artifact.to_dict()


@mcp.tool()
def static_decode(apk: str, target: str) -> dict:
    """Decode an APK's manifest/resources with apktool; records an artifact."""
    ws = get_workspace(target)
    out_dir = str(ws.artifacts_dir / "decoded")
    artifact = get_registry().get("apktool").decode(apk, out_dir)
    ws.add_artifact(artifact)
    return artifact.to_dict()


@mcp.tool()
def static_scan(path: str, target: str, rules: str | None = None) -> list[dict]:
    """Scan a decoded/source tree with Opengrep; records and returns findings."""
    ws = get_workspace(target)
    findings = get_registry().get("opengrep").scan(path, rules)
    for finding in findings:
        ws.add_finding(finding)
    return [f.to_dict() for f in findings]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/centurion/mcp/server.py tests/test_mcp_server.py
git commit -m "feat: add static MCP tools (app_list, app_pull, static_decode, static_scan)"
```

---

## Task 4: Dynamic MCP tools (objection + frida)

**Files:**
- Modify: `src/centurion/adapters/generic/frida.py`, `src/centurion/mcp/server.py`
- Test: `tests/test_frida.py`, `tests/test_mcp_server.py`

- [ ] **Step 1: Write the failing adapter test**

Append to `tests/test_frida.py`:
```python
def test_run_script_command_attaches_over_usb():
    from centurion.adapters.generic.frida import FridaAdapter
    cmd = FridaAdapter().run_script_command("com.acme.app", "/tmp/ssl_unpin.js")
    assert cmd == ["frida", "-U", "-f", "com.acme.app", "-l", "/tmp/ssl_unpin.js"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_frida.py -k run_script_command -v`
Expected: FAIL — `AttributeError: 'FridaAdapter' object has no attribute 'run_script_command'`

- [ ] **Step 3: Add `run_script_command` to FridaAdapter**

Edit `src/centurion/adapters/generic/frida.py` — add after `ps_command`:
```python
    def run_script_command(self, target_app: str, script: str, usb: bool = True) -> list[str]:
        cmd = ["frida"]
        if usb:
            cmd.append("-U")
        cmd += ["-f", target_app, "-l", script]
        return cmd
```

- [ ] **Step 4: Run adapter test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_frida.py -k run_script_command -v`
Expected: PASS

- [ ] **Step 5: Write the failing MCP test**

Append to `tests/test_mcp_server.py`:
```python
from centurion.adapters.generic.frida import FridaAdapter
from centurion.adapters.android.objection import ObjectionAdapter


def test_objection_run_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("objection -g com.acme.app explore",
                  stdout="android hooking ... done\n")
    monkeypatch.setattr(server, "get_registry",
                        lambda: Registry([ObjectionAdapter(fake)]))
    out = server.objection_run("com.acme.app", ["android hooking list classes"])
    assert "done" in out


def test_frida_list_scripts_tool():
    names = {s["name"] for s in server.frida_list_scripts()}
    assert "ssl_unpin" in names


def test_frida_run_named_script_starts_process(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)

    class FakeProc:
        pid = 4321

    monkeypatch.setattr(server, "get_process_manager",
                        lambda target: WorkspaceProcessManager(
                            server.get_workspace(target), spawn=lambda cmd: FakeProc()))
    result = server.frida_run_named_script("com.acme.app", "ssl_unpin", "Acme")
    assert result["handle"] == "frida-com.acme.app"
    assert result["pid"] == 4321
    assert any("ssl_unpin.js" in part for part in result["command"])


def test_ssl_unpin_is_named_script_shortcut(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)

    class FakeProc:
        pid = 99

    monkeypatch.setattr(server, "get_process_manager",
                        lambda target: WorkspaceProcessManager(
                            server.get_workspace(target), spawn=lambda cmd: FakeProc()))
    result = server.ssl_unpin("com.acme.app", "Acme")
    assert any("ssl_unpin.js" in part for part in result["command"])
```

Add the import at the top of the test file if not present:
```python
from centurion.process import WorkspaceProcessManager
```

- [ ] **Step 6: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "objection or frida or ssl_unpin" -v`
Expected: FAIL — `AttributeError: ... has no attribute 'objection_run'`

- [ ] **Step 7: Add the dynamic tools**

Append to `src/centurion/mcp/server.py`:
```python
@mcp.tool()
def objection_run(package: str, commands: list[str]) -> str:
    """Run objection startup commands against a package; returns raw output."""
    return get_registry().get("objection").run(package, commands)


@mcp.tool()
def frida_list_scripts() -> list[dict]:
    """List the bundled, vetted Frida scripts (name, description, platform)."""
    return [s.__dict__ for s in get_script_library().list()]


@mcp.tool()
def frida_run_named_script(target_app: str, script: str, target: str) -> dict:
    """Spawn target_app under Frida with a bundled script; durable process handle."""
    script_path = get_script_library().path(script)
    command = get_registry().get("frida").run_script_command(target_app, script_path)
    proc = get_process_manager(target).start(f"frida-{target_app}", command)
    return proc.to_dict()


@mcp.tool()
def frida_run_script(target_app: str, script_path: str, target: str) -> dict:
    """Spawn target_app under Frida with an arbitrary script (raw passthrough)."""
    command = get_registry().get("frida").run_script_command(target_app, script_path)
    proc = get_process_manager(target).start(f"frida-{target_app}", command)
    return proc.to_dict()


@mcp.tool()
def ssl_unpin(target_app: str, target: str) -> dict:
    """Shortcut: run the bundled ssl_unpin script against target_app."""
    return frida_run_named_script(target_app, "ssl_unpin", target)
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_frida.py tests/test_mcp_server.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/centurion/adapters/generic/frida.py src/centurion/mcp/server.py tests/test_frida.py tests/test_mcp_server.py
git commit -m "feat: add dynamic MCP tools (objection + frida scripts)"
```

---

## Task 5: Network MCP tools (proxy_start, proxy_stop, proxy_flows)

**Files:**
- Modify: `src/centurion/adapters/generic/mitmproxy.py`, `src/centurion/mcp/server.py`
- Test: `tests/test_mitmproxy.py`, `tests/test_mcp_server.py`

- [ ] **Step 1: Write the failing adapter test**

Append to `tests/test_mitmproxy.py`:
```python
def test_parse_flows_extracts_method_and_url():
    from centurion.adapters.generic.mitmproxy import MitmproxyAdapter
    dump = (
        "GET https://api.acme.com/login\n"
        "    << 200 OK 1.2k\n"
        "POST https://api.acme.com/pay\n"
        "    << 403 Forbidden 0b\n"
    )
    flows = MitmproxyAdapter().parse_flows(dump)
    assert flows == [
        {"method": "GET", "url": "https://api.acme.com/login"},
        {"method": "POST", "url": "https://api.acme.com/pay"},
    ]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mitmproxy.py -k parse_flows -v`
Expected: FAIL — `AttributeError: ... has no attribute 'parse_flows'`

- [ ] **Step 3: Add `parse_flows` to MitmproxyAdapter**

Edit `src/centurion/adapters/generic/mitmproxy.py` — add after `read_command`:
```python
    _METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

    def parse_flows(self, stdout: str) -> list[dict]:
        flows: list[dict] = []
        for line in stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0] in self._METHODS:
                flows.append({"method": parts[0], "url": parts[1].strip()})
        return flows
```

- [ ] **Step 4: Run adapter test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_mitmproxy.py -k parse_flows -v`
Expected: PASS

- [ ] **Step 5: Write the failing MCP test**

Append to `tests/test_mcp_server.py`:
```python
from centurion.adapters.generic.mitmproxy import MitmproxyAdapter


def test_proxy_start_and_stop(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)

    class FakeProc:
        pid = 555

    monkeypatch.setattr(server, "get_registry", lambda: Registry([MitmproxyAdapter(FakeRunner())]))
    monkeypatch.setattr(server, "get_process_manager",
                        lambda target: WorkspaceProcessManager(
                            server.get_workspace(target), spawn=lambda cmd: FakeProc(),
                            kill=lambda pid: None))
    started = server.proxy_start("Acme", 8080)
    assert started["handle"] == "proxy"
    assert started["pid"] == 555
    assert server.proxy_stop("Acme") == {"stopped": True}


def test_proxy_flows_reads_flow_file(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("mitmdump -nr", stdout="GET https://api.acme.com/x\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([MitmproxyAdapter(fake)]))
    flows = server.proxy_flows("Acme")
    assert flows == [{"method": "GET", "url": "https://api.acme.com/x"}]
```

- [ ] **Step 6: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k proxy -v`
Expected: FAIL — `AttributeError: ... has no attribute 'proxy_start'`

- [ ] **Step 7: Add the network tools**

Append to `src/centurion/mcp/server.py`:
```python
def _flow_file(target: str) -> str:
    return str(get_workspace(target).artifacts_dir / "flows.mitm")


@mcp.tool()
def proxy_start(target: str, port: int = 8080) -> dict:
    """Start mitmdump (durable handle 'proxy'), writing flows into the workspace."""
    adapter = get_registry().get("mitmproxy")
    command = adapter.start_command(port=port, flow_out=_flow_file(target))
    proc = get_process_manager(target).start("proxy", command)
    return proc.to_dict()


@mcp.tool()
def proxy_stop(target: str) -> dict:
    """Stop the running mitmdump proxy for the target."""
    return {"stopped": get_process_manager(target).stop("proxy")}


@mcp.tool()
def proxy_flows(target: str) -> list[dict]:
    """Summarize captured flows (method + URL) from the workspace flow file."""
    adapter = get_registry().get("mitmproxy")
    result = adapter.runner.run(adapter.read_command(_flow_file(target)), timeout=120)
    return adapter.parse_flows(result.stdout)
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_mitmproxy.py tests/test_mcp_server.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/centurion/adapters/generic/mitmproxy.py src/centurion/mcp/server.py tests/test_mitmproxy.py tests/test_mcp_server.py
git commit -m "feat: add network MCP tools (proxy_start, proxy_stop, proxy_flows)"
```

---

## Task 6: Recon + findings tools (recon_strings, recon_radare2, findings_list)

**Files:**
- Modify: `src/centurion/adapters/generic/radare2.py`, `src/centurion/mcp/server.py`
- Test: `tests/test_radare2.py`, `tests/test_mcp_server.py`

- [ ] **Step 1: Write the failing adapter test**

Append to `tests/test_radare2.py`:
```python
def test_info_returns_stdout():
    from centurion.adapters.generic.radare2 import Radare2Adapter
    from centurion.process import FakeRunner
    fake = FakeRunner()
    fake.register("rabin2 -I", stdout="arch     arm\nbits     64\n")
    info = Radare2Adapter(fake).info("/tmp/libfoo.so")
    assert "arch" in info
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_radare2.py -k test_info -v`
Expected: FAIL — `AttributeError: ... has no attribute 'info'`

- [ ] **Step 3: Add `info` to Radare2Adapter**

Edit `src/centurion/adapters/generic/radare2.py` — add after `info_command`:
```python
    def info(self, path: str) -> str:
        return self.runner.run(self.info_command(path), timeout=120).stdout
```

- [ ] **Step 4: Run adapter test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_radare2.py -k test_info -v`
Expected: PASS

- [ ] **Step 5: Write the failing MCP test**

Append to `tests/test_mcp_server.py`:
```python
from centurion.adapters.generic.strings import StringsAdapter
from centurion.adapters.generic.radare2 import Radare2Adapter
from centurion.models import Finding


def test_recon_strings_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("strings -n 8", stdout="hardcoded_api_key\nshort\nanother_long_str\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([StringsAdapter(fake)]))
    out = server.recon_strings("/tmp/libfoo.so")
    assert "hardcoded_api_key" in out


def test_recon_radare2_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("rabin2 -I", stdout="arch arm\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([Radare2Adapter(fake)]))
    assert "arch" in server.recon_radare2("/tmp/libfoo.so")["info"]


def test_findings_list_tool(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ws = server.get_workspace("Acme")
    ws.add_finding(Finding(id="f1", title="Cleartext", severity="high", tool="opengrep"))
    assert server.findings_list("Acme")[0]["id"] == "f1"
```

- [ ] **Step 6: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k "recon or findings_list" -v`
Expected: FAIL — `AttributeError: ... has no attribute 'recon_strings'`

- [ ] **Step 7: Add the recon + findings tools**

Append to `src/centurion/mcp/server.py`:
```python
@mcp.tool()
def recon_strings(path: str, min_len: int = 8) -> list[str]:
    """Extract printable strings (>= min_len) from a binary."""
    return get_registry().get("strings").extract(path, min_len)


@mcp.tool()
def recon_radare2(path: str) -> dict:
    """Return rabin2 binary info for a target file."""
    return {"info": get_registry().get("radare2").info(path)}


@mcp.tool()
def findings_list(target: str) -> list[dict]:
    """List recorded findings for the target workspace (for triage)."""
    return get_workspace(target).load().findings
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_radare2.py tests/test_mcp_server.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/centurion/adapters/generic/radare2.py src/centurion/mcp/server.py tests/test_radare2.py tests/test_mcp_server.py
git commit -m "feat: add recon + findings MCP tools"
```

---

## Task 7: MCP resources (scripts, findings, processes)

**Files:**
- Modify: `src/centurion/mcp/server.py`
- Test: `tests/test_mcp_server.py`

The functions backing the resources are tested directly; the `@mcp.resource` decorator only registers a URI template. Resources that need a target are templated (`centurion://findings/{target}`); `centurion://scripts` is static.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mcp_server.py`:
```python
def test_scripts_resource_lists_bundled():
    data = server.scripts_resource()
    assert {s["name"] for s in data} >= {"ssl_unpin", "root_bypass"}


def test_findings_resource(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ws = server.get_workspace("Acme")
    ws.add_finding(Finding(id="f9", title="X", severity="low", tool="opengrep"))
    assert server.findings_resource("Acme")[0]["id"] == "f9"


def test_processes_resource(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    server.get_workspace("Acme")  # create
    assert server.processes_resource("Acme") == []
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k resource -v`
Expected: FAIL — `AttributeError: ... has no attribute 'scripts_resource'`

- [ ] **Step 3: Add the resources**

Append to `src/centurion/mcp/server.py` (before `main`):
```python
@mcp.resource("centurion://scripts")
def scripts_resource() -> list[dict]:
    """The bundled Frida script catalog."""
    return [s.__dict__ for s in get_script_library().list()]


@mcp.resource("centurion://findings/{target}")
def findings_resource(target: str) -> list[dict]:
    """Recorded findings for a target workspace."""
    return get_workspace(target).load().findings


@mcp.resource("centurion://processes/{target}")
def processes_resource(target: str) -> list[dict]:
    """Durable long-running process handles for a target workspace."""
    return get_process_manager(target).list()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS (all Phase-1/2a tests plus the new ones)

- [ ] **Step 6: Commit**

```bash
git add src/centurion/mcp/server.py tests/test_mcp_server.py
git commit -m "feat: add MCP resources (scripts, findings, processes)"
```

---

## Task 8: Skills (static / dynamic / network)

**Files:**
- Create: `.claude/skills/centurion-static-analysis/SKILL.md`, `.claude/skills/centurion-dynamic-analysis/SKILL.md`, `.claude/skills/centurion-network-intercept/SKILL.md`

No tests; these are markdown verified in Task 10 against the tool names shipped above.

- [ ] **Step 1: Write the static-analysis skill**

`.claude/skills/centurion-static-analysis/SKILL.md`:
```markdown
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

## Scope reminder

Authorized assessments only.
```

- [ ] **Step 2: Write the dynamic-analysis skill**

`.claude/skills/centurion-dynamic-analysis/SKILL.md`:
```markdown
---
name: centurion-dynamic-analysis
description: Use to dynamically instrument a running Android app with Frida/objection — list and run vetted hook scripts, bypass TLS pinning, and explore at runtime. Drives the Centurion MCP server.
---

# Centurion: Dynamic Analysis

Attach, hook, observe. Use the Centurion MCP server. Operate only on apps you are authorized to test.

## Steps

1. **Confirm Frida is ready.** Call `doctor` and check `frida`/`objection`. A frida-server must be running on the device/emulator; if missing, give the user the install hint (don't auto-install).

2. **Browse hooks.** Call `frida_list_scripts` to show the bundled, vetted scripts (ssl_unpin, root_bypass, debugger_bypass, dump_class_hooks) with descriptions.

3. **Run a hook.** Call `frida_run_named_script(target_app, script, target)` to spawn the app under a bundled script, or `ssl_unpin(target_app, target)` for the common pinning bypass. For a custom script, use `frida_run_script(target_app, script_path, target)`. Each returns a durable process handle that survives across sessions.

4. **Explore with objection.** For interactive-style runtime queries, call `objection_run(package, commands)` with startup commands (e.g. `android hooking list classes`).

5. **Report.** Summarize what the hooks observed. Long-running handles appear in `centurion://processes/{target}`.

## Scope reminder

Authorized assessments only. The bundled scripts are for authorized testing.
```

- [ ] **Step 3: Write the network-intercept skill**

`.claude/skills/centurion-network-intercept/SKILL.md`:
```markdown
---
name: centurion-network-intercept
description: Use to intercept an Android app's HTTPS traffic — start a mitmproxy capture, guide CA-cert install, then summarize captured flows. Drives the Centurion MCP server.
---

# Centurion: Network Intercept

Proxy, trust, capture, summarize. Use the Centurion MCP server. Operate only on traffic you are authorized to intercept.

## Steps

1. **Start the proxy.** Call `proxy_start(target, port)` (default port 8080). It returns a durable `proxy` handle; flows are written into the workspace.

2. **Make the device trust mitmproxy.** Guide the user: set the device/emulator Wi-Fi proxy to the host IP and port, browse to `mitm.it` to install the CA certificate, and (for API ≥ 24) note that user CAs are not trusted by apps unless they opt in — system-CA install or a Frida pinning/`ssl_unpin` bypass may be required.

3. **Exercise the app**, then **summarize.** Call `proxy_flows(target)` to list captured request method + URL pairs. Highlight cleartext, sensitive endpoints, and tokens.

4. **Stop.** Call `proxy_stop(target)` when done.

## Scope reminder

Authorized assessments only.
```

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/centurion-static-analysis .claude/skills/centurion-dynamic-analysis .claude/skills/centurion-network-intercept
git commit -m "feat: add static/dynamic/network analysis skills"
```

---

## Task 9: Subagents (static-analyst / dynamic-analyst / triage)

**Files:**
- Create: `.claude/agents/centurion-static-analyst.md`, `.claude/agents/centurion-dynamic-analyst.md`, `.claude/agents/centurion-triage.md`

- [ ] **Step 1: Write the static-analyst subagent**

`.claude/agents/centurion-static-analyst.md`:
```markdown
---
name: centurion-static-analyst
description: Drives Centurion's static MCP tools to pull, decode, and scan an Android app and return structured findings. Use when a task needs an isolated static pass.
---

You are a mobile static-analysis specialist driving the Centurion MCP server.

Given a package name (and optionally an APK path) and a workspace `target`:
1. If no APK is provided, call `app_pull(package, target)`.
2. Call `static_decode(apk, target)`.
3. Call `static_scan(path, target)` on the decoded tree. If rules are missing, report that the user must install an Opengrep ruleset into `~/.centurion/rules` — never auto-fetch.
4. Return a concise structured summary: counts by severity and the top findings with `title`, `severity`, `location`, and `mastg_refs`.

Operate only on authorized apps. Do not install tools or rules automatically; surface install hints instead.
```

- [ ] **Step 2: Write the dynamic-analyst subagent**

`.claude/agents/centurion-dynamic-analyst.md`:
```markdown
---
name: centurion-dynamic-analyst
description: Drives Centurion's Frida/objection MCP tools to instrument a running Android app. Use when a task needs an isolated dynamic pass.
---

You are a mobile dynamic-analysis specialist driving the Centurion MCP server.

Given a target app package and a workspace `target`:
1. Call `doctor` and confirm `frida`/`objection` are installed and a frida-server is running; if not, report install hints (never auto-install).
2. Use `frida_list_scripts` to choose a vetted hook, then `frida_run_named_script` / `ssl_unpin` / `frida_run_script` to run it, or `objection_run` for runtime queries.
3. Report what was observed and the durable process handle(s) returned.

Operate only on authorized apps. The bundled scripts are for authorized testing.
```

- [ ] **Step 3: Write the triage subagent**

`.claude/agents/centurion-triage.md`:
```markdown
---
name: centurion-triage
description: Reads recorded Centurion findings, dedups and prioritizes them, and returns a triaged set. Use after static/dynamic passes have recorded findings.
---

You are a mobile-security triage specialist driving the Centurion MCP server.

Given a workspace `target`:
1. Call `findings_list(target)` (or read `centurion://findings/{target}`).
2. Deduplicate findings that share a `title` + `location`. Prioritize by severity (critical > high > medium > low > info), then by MASTG reference coverage.
3. Return a ranked, deduplicated list with a one-line rationale per item and an overall risk summary. Do not invent findings beyond those recorded.

Operate only on authorized engagement data.
```

- [ ] **Step 4: Commit**

```bash
git add .claude/agents/centurion-static-analyst.md .claude/agents/centurion-dynamic-analyst.md .claude/agents/centurion-triage.md
git commit -m "feat: add static-analyst/dynamic-analyst/triage subagents"
```

---

## Task 10: Final verification (skills/agents reference only existing tools)

**Files:**
- Test: `tests/test_mcp_server.py`

- [ ] **Step 1: Write a guard test that the documented tools exist on the server**

Append to `tests/test_mcp_server.py`:
```python
def test_all_documented_tools_are_defined():
    expected = {
        "doctor", "device_list", "app_list", "app_pull", "static_decode",
        "static_scan", "objection_run", "frida_list_scripts",
        "frida_run_named_script", "frida_run_script", "ssl_unpin",
        "proxy_start", "proxy_stop", "proxy_flows", "recon_strings",
        "recon_radare2", "findings_list",
    }
    for name in expected:
        assert callable(getattr(server, name)), f"missing MCP tool: {name}"
```

- [ ] **Step 2: Run the guard test**

Run: `.venv/bin/python -m pytest tests/test_mcp_server.py -k documented -v`
Expected: PASS

- [ ] **Step 3: Cross-check skills/agents against shipped tool names**

Run:
```bash
grep -rhoE '`(doctor|device_list|app_list|app_pull|static_decode|static_scan|objection_run|frida_list_scripts|frida_run_named_script|frida_run_script|ssl_unpin|proxy_start|proxy_stop|proxy_flows|recon_strings|recon_radare2|findings_list)`' .claude/skills .claude/agents | sort -u
```
Expected: every tool referenced in the skills/agents is one of the shipped names (no unknown tool names). Manually confirm no skill/agent references a tool not in the list above.

- [ ] **Step 4: Run the full suite + verify the server imports cleanly**

Run:
```bash
.venv/bin/python -m pytest -q
.venv/bin/python -c "import centurion.mcp.server as s; print('tools ok')"
```
Expected: all tests pass; import prints `tools ok`.

- [ ] **Step 5: Commit**

```bash
git add tests/test_mcp_server.py
git commit -m "test: guard that all documented MCP tools are defined"
```

---

## Done-When

- `ScriptLibrary` lists/resolves the four bundled Frida scripts; they ship in the wheel.
- The MCP server exposes all 17 tools (2 existing + 15 new) and 3 resources.
- The three skills and three subagents exist and reference only shipped tool names.
- `.venv/bin/python -m pytest -q` is fully green.

## Notes / deviations from spec

- Resources that need engagement context are **templated** (`centurion://findings/{target}`, `centurion://processes/{target}`) rather than bare URIs, because a finding/process list is meaningless without a workspace; `centurion://scripts` stays static. This honors the spec's intent (the three resource families) while remaining functional.
- `frida_run_named_script`/`frida_run_script` use `-f` (spawn) for deterministic startup; switch to attach-by-name if a workflow needs to attach to an already-running process.
```
