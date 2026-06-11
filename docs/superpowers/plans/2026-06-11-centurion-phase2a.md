# Centurion Phase 2a Implementation Plan — Adapters, State, Hardening

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Broaden Centurion to a wide MASTG Android tool set (10 new adapters), add engagement state (findings + durable long-running process handles), and fold in the Phase-1 review hardening — all test-driven.

**Architecture:** Continue the proven Phase-1 `Adapter` pattern (metadata + `detect()` + `install_hint()` + operations that shell out via the injected `Runner` and parse to structured models). Add a workspace-backed `WorkspaceProcessManager` so long-running tools survive across MCP invocations without a daemon. No new MCP tools or skills in this plan — that is Plan 2b.

**Tech Stack:** Python 3.11+, existing deps (typer, rich, mcp), pytest. Run everything via the project venv: `.venv/bin/python -m pytest ...`.

Spec: `docs/superpowers/specs/2026-06-11-centurion-phase2-design.md`

**Environment:** system Python is externally-managed; a venv exists at `.venv/`. Always use `.venv/bin/python -m pytest`. Work on branch `phase-2-android-sweep`.

**MASTG IDs:** Confirmed IDs are set (apktool 0011, drozer 0015, radare2 0028, objection 0029). For tools whose MASTG-TOOL id is not yet confirmed (dex2jar, apksigner, semgrep, strings, mitmproxy, tcpdump) `mastg_id` is intentionally left `None`; tests assert platform/category for those rather than an id. This is a data-completeness gap to revisit, not a code placeholder.

---

## File Structure

```
src/centurion/
  registry.py                              # Task 17 (extend default_registry)
  install.py                               # Task 2  (fix group precedence)
  session.py                               # Task 4  (add findings + add_finding)
  process.py                               # Task 5  (add WorkspaceProcessManager)
  cli/app.py                               # Task 3  (device list -> rich Table)
  adapters/
    android/
      adb.py                               # Task 6  (packages + pull_apk)
      apktool.py                           # Task 7
      dex2jar.py                           # Task 8
      apksigner.py                         # Task 9
      objection.py                         # Task 13
      drozer.py                            # Task 14
    generic/
      semgrep.py                           # Task 10
      radare2.py                           # Task 11
      strings.py                           # Task 12
      mitmproxy.py                         # Task 15
      tcpdump.py                           # Task 16
tests/
  test_registry.py (extend)                # Task 1, 17
  test_install.py (extend)                 # Task 2
  test_cli.py (extend)                     # Task 3
  test_session.py (extend)                 # Task 4
  test_process_manager.py (extend)         # Task 5
  test_adb.py (extend)                     # Task 6
  test_apktool.py / test_dex2jar.py / ...  # Tasks 7-16
```

---

## Task 1: Hardening — `Registry.get` clear error

**Files:** Modify `src/centurion/registry.py`; Test: `tests/test_registry.py`

- [ ] **Step 1: Add the failing test** (append to `tests/test_registry.py`):

```python
import pytest


def test_registry_get_unknown_raises_clear_error():
    reg = Registry([])
    with pytest.raises(KeyError, match="No adapter registered for 'ghost'"):
        reg.get("ghost")
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_registry.py::test_registry_get_unknown_raises_clear_error -v` → FAIL (raises bare KeyError without message).

- [ ] **Step 3: Implement** — replace `Registry.get` in `src/centurion/registry.py`:

```python
    def get(self, name: str) -> Adapter:
        try:
            return self._adapters[name]
        except KeyError:
            raise KeyError(f"No adapter registered for '{name}'") from None
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_registry.py -v` → all pass.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/registry.py tests/test_registry.py
git commit -m "fix: clear error message from Registry.get on unknown adapter"
```

---

## Task 2: Hardening — install group precedence (category before platform)

**Files:** Modify `src/centurion/install.py`; Test: `tests/test_install.py`

> `"network"` is both a Platform value and a Category value. Network tools use `platform=generic, category=network`, so the group `"network"` must resolve to the **category**. Fix `_selects` to check categories before platforms.

- [ ] **Step 1: Add failing test** (append to `tests/test_install.py`):

```python
from centurion.adapters.generic.frida import FridaAdapter
from centurion.models import ToolStatus
from centurion.install import _selects


def test_selects_network_group_matches_category_not_platform():
    # A network tool: platform generic, category network.
    net = ToolStatus(name="mitmproxy", installed=False, platform="generic", category="network")
    assert _selects(net, "network") is True
    # A generic-platform non-network tool must NOT match the network group.
    other = ToolStatus(name="frida", installed=False, platform="generic", category="dynamic")
    assert _selects(other, "network") is False
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_install.py::test_selects_network_group_matches_category_not_platform -v` → FAIL (current order checks platform first; `net.platform=="network"` is False so returns False).

- [ ] **Step 3: Implement** — in `src/centurion/install.py` reorder `_selects` so categories are checked before platforms:

```python
def _selects(status: ToolStatus, group: str) -> bool:
    if group == "all":
        return True
    if group in _CATEGORIES:
        return status.category == group
    if group in _PLATFORMS:
        return status.platform == group
    return False
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_install.py -v` → all pass (existing tests still green; `"android"` is only in `_PLATFORMS` so unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/centurion/install.py tests/test_install.py
git commit -m "fix: install group resolves network to category before platform"
```

---

## Task 3: Hardening — CLI `device list` uses a rich Table

**Files:** Modify `src/centurion/cli/app.py`; Test: `tests/test_cli.py`

- [ ] **Step 1: Add failing test** (append to `tests/test_cli.py`):

```python
def test_device_list_uses_table_headers(monkeypatch):
    monkeypatch.setattr(cli_app, "get_registry", _fake_registry)
    result = runner.invoke(cli_app.app, ["device", "list"])
    assert result.exit_code == 0
    assert "Serial" in result.stdout
    assert "State" in result.stdout
    assert "emulator-5554" in result.stdout
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_cli.py::test_device_list_uses_table_headers -v` → FAIL (current output is tab-separated, no "Serial"/"State" headers).

- [ ] **Step 3: Implement** — replace the `device_list` command in `src/centurion/cli/app.py`:

```python
@device_app.command("list")
def device_list() -> None:
    """List connected Android devices."""
    table = Table("Serial", "State", "Model")
    adb = get_registry().get("adb")
    for dev in adb.devices():
        table.add_row(dev.serial, dev.state, dev.model or "-")
    console.print(table)
```

(`Table` is already imported at the top of `app.py`.)

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_cli.py -v` → all pass.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/cli/app.py tests/test_cli.py
git commit -m "refactor: render device list as a rich table"
```

---

## Task 4: `Session.findings` + `Workspace.add_finding`

**Files:** Modify `src/centurion/session.py`; Test: `tests/test_session.py`

- [ ] **Step 1: Add failing test** (append to `tests/test_session.py`):

```python
from centurion.models import Finding


def test_add_finding(tmp_path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.add_finding(Finding(id="f1", title="Cleartext", severity="high", tool="semgrep"))
    loaded = ws.load()
    assert loaded.findings[0]["id"] == "f1"
    assert loaded.findings[0]["severity"] == "high"


def test_findings_defaults_empty_for_old_sessions(tmp_path):
    import json
    ws = Workspace(tmp_path, target="app")
    ws.create()
    # Simulate an older session.json written before `findings` existed.
    data = json.loads(ws.session_file.read_text())
    data.pop("findings", None)
    ws.session_file.write_text(json.dumps(data))
    loaded = ws.load()
    assert loaded.findings == []
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_session.py -k finding -v` → FAIL (`Workspace` has no `add_finding`; `Session` has no `findings`).

- [ ] **Step 3: Implement** — in `src/centurion/session.py`:

Add a `findings` field to `Session` (place it after `artifacts`):

```python
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)
```

Add the import for the type used in the method signature at the top (next to `from .models import Artifact`):

```python
from .models import Artifact, Finding
```

Add the method to `Workspace` (after `add_artifact`):

```python
    def add_finding(self, finding: Finding) -> None:
        session = self.load()
        session.findings.append(finding.to_dict())
        self.save(session)
```

(The Phase-1 `load()` already filters unknown JSON keys, and the `default_factory=list` means an older `session.json` without `findings` loads as an empty list — covered by the second test.)

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_session.py -v` → all pass.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/session.py tests/test_session.py
git commit -m "feat: persist findings in session state"
```

---

## Task 5: `WorkspaceProcessManager` (durable handles)

**Files:** Modify `src/centurion/process.py`; Test: `tests/test_process_manager.py`

> A workspace-backed process manager. `start` spawns and persists `{handle, pid, command}` to the session; `stop` reads the handle, signals the pid (injectable `kill`), and removes it; `list` reads the persisted handles. The `workspace` argument is duck-typed (anything with `load()`/`save()`), so no import of `Workspace` is needed.

- [ ] **Step 1: Add failing test** (append to `tests/test_process_manager.py`):

```python
from centurion.process import WorkspaceProcessManager
from centurion.session import Workspace


def _ws(tmp_path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    return ws


def test_workspace_pm_start_persists_handle(tmp_path):
    ws = _ws(tmp_path)
    pm = WorkspaceProcessManager(ws, spawn=lambda command: FakeProc(pid=999), kill=lambda pid: None)
    managed = pm.start("proxy", ["mitmdump", "-p", "8080"])
    assert managed.pid == 999
    # Persisted to session.json, visible to a fresh manager (simulates new MCP process).
    fresh = WorkspaceProcessManager(ws, spawn=lambda c: FakeProc(pid=1), kill=lambda pid: None)
    assert fresh.list() == [{"handle": "proxy", "pid": 999, "command": ["mitmdump", "-p", "8080"]}]


def test_workspace_pm_stop_signals_and_removes(tmp_path):
    ws = _ws(tmp_path)
    killed = []
    pm = WorkspaceProcessManager(ws, spawn=lambda c: FakeProc(pid=42), kill=lambda pid: killed.append(pid))
    pm.start("proxy", ["mitmdump"])
    assert pm.stop("proxy") is True
    assert killed == [42]
    assert pm.list() == []


def test_workspace_pm_stop_unknown_returns_false(tmp_path):
    ws = _ws(tmp_path)
    pm = WorkspaceProcessManager(ws, spawn=lambda c: FakeProc(pid=1), kill=lambda pid: None)
    assert pm.stop("ghost") is False


def test_workspace_pm_reusing_handle_signals_previous(tmp_path):
    ws = _ws(tmp_path)
    killed = []
    pids = iter([10, 11])
    pm = WorkspaceProcessManager(
        ws,
        spawn=lambda c: FakeProc(pid=next(pids)),
        kill=lambda pid: killed.append(pid),
    )
    pm.start("proxy", ["mitmdump"])
    pm.start("proxy", ["mitmdump"])  # reuse handle -> previous pid signalled
    assert killed == [10]
    assert pm.list() == [{"handle": "proxy", "pid": 11, "command": ["mitmdump"]}]
```

(`FakeProc` already exists in this test file from Phase 1.)

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_process_manager.py -k workspace -v` → FAIL (`ImportError: cannot import name 'WorkspaceProcessManager'`).

- [ ] **Step 3: Implement** — in `src/centurion/process.py`:

Add to the top-of-file imports (after `import subprocess`):

```python
import os
import signal
```

Append at the end of the file:

```python
def _real_kill(pid: int) -> None:
    os.kill(pid, signal.SIGTERM)


class WorkspaceProcessManager:
    """Tracks long-running tools, persisting handles to the workspace session
    so they survive across separate MCP server invocations (no daemon)."""

    def __init__(
        self,
        workspace,
        spawn: Callable[[list[str]], Any] | None = None,
        kill: Callable[[int], None] | None = None,
    ) -> None:
        self._workspace = workspace
        self._spawn = spawn or _real_spawn
        self._kill = kill or _real_kill

    def start(self, handle: str, command: list[str]) -> ManagedProcess:
        existing = self._find(handle)
        if existing is not None:
            self._kill(existing["pid"])
        proc = self._spawn(command)
        session = self._workspace.load()
        session.processes = [p for p in session.processes if p["handle"] != handle]
        session.processes.append({"handle": handle, "pid": proc.pid, "command": list(command)})
        self._workspace.save(session)
        return ManagedProcess(handle=handle, pid=proc.pid, command=list(command))

    def stop(self, handle: str) -> bool:
        entry = self._find(handle)
        if entry is None:
            return False
        self._kill(entry["pid"])
        session = self._workspace.load()
        session.processes = [p for p in session.processes if p["handle"] != handle]
        self._workspace.save(session)
        return True

    def list(self) -> list[dict]:
        return self._workspace.load().processes

    def _find(self, handle: str) -> dict | None:
        for entry in self._workspace.load().processes:
            if entry["handle"] == handle:
                return entry
        return None
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_process_manager.py -v` → all pass (including the Phase-1 in-memory `ProcessManager` tests).

- [ ] **Step 5: Commit**

```bash
git add src/centurion/process.py tests/test_process_manager.py
git commit -m "feat: add workspace-backed durable process manager"
```

---

## Task 6: `adb` app operations (`packages`, `pull_apk`)

**Files:** Modify `src/centurion/adapters/android/adb.py`; Test: `tests/test_adb.py`

- [ ] **Step 1: Add failing test** (append to `tests/test_adb.py`):

```python
from centurion.models import Artifact


def test_adb_packages_parses_list():
    runner = FakeRunner()
    runner.register(
        "adb shell pm list packages",
        stdout="package:com.acme.bank\npackage:com.android.settings\n",
    )
    assert AdbAdapter(runner).packages() == ["com.acme.bank", "com.android.settings"]


def test_adb_pull_apk_returns_artifact(tmp_path):
    runner = FakeRunner()
    runner.register("adb shell pm path com.acme.bank", stdout="package:/data/app/com.acme.bank/base.apk\n")
    runner.register("adb pull", stdout="1 file pulled\n")
    artifact = AdbAdapter(runner).pull_apk("com.acme.bank", str(tmp_path))
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "binary"
    assert artifact.label == "com.acme.bank.apk"
    assert artifact.path.endswith("com.acme.bank.apk")
    # adb pull was called with the resolved remote path
    assert ["adb", "pull", "/data/app/com.acme.bank/base.apk", artifact.path] in runner.calls


def test_adb_pull_apk_missing_package_raises():
    runner = FakeRunner()
    runner.register("adb shell pm path com.ghost", stdout="\n")
    import pytest
    with pytest.raises(RuntimeError, match="package not found"):
        AdbAdapter(runner).pull_apk("com.ghost", "/tmp")
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_adb.py -k "packages or pull" -v` → FAIL (`AdbAdapter` has no `packages`/`pull_apk`).

- [ ] **Step 3: Implement** — in `src/centurion/adapters/android/adb.py`:

Update the imports at the top to add `Path` and `Artifact`:

```python
from pathlib import Path

from ...models import Artifact, Category, Platform
```

Add these two methods to `AdbAdapter` (after `devices`):

```python
    def packages(self) -> list[str]:
        result = self.runner.run(["adb", "shell", "pm", "list", "packages"], timeout=30)
        return [
            line.split("package:", 1)[1].strip()
            for line in result.stdout.splitlines()
            if line.startswith("package:")
        ]

    def pull_apk(self, package: str, out_dir: str) -> Artifact:
        path_result = self.runner.run(["adb", "shell", "pm", "path", package], timeout=30)
        remote = None
        for line in path_result.stdout.splitlines():
            if line.startswith("package:"):
                remote = line.split("package:", 1)[1].strip()
                break
        if not remote:
            raise RuntimeError(f"package not found: {package}")
        dest = str(Path(out_dir) / f"{package}.apk")
        self.runner.run(["adb", "pull", remote, dest], timeout=120)
        return Artifact(
            id=f"apk-{package}",
            kind="binary",
            path=dest,
            tool="adb",
            label=f"{package}.apk",
        )
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_adb.py -v` → all pass.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/adb.py tests/test_adb.py
git commit -m "feat: add adb package listing and apk pull"
```

---

## Task 7: apktool adapter

**Files:** Create `src/centurion/adapters/android/apktool.py`; Test: `tests/test_apktool.py`

- [ ] **Step 1: Write `tests/test_apktool.py`**

```python
import pytest

from centurion.adapters.android.apktool import ApktoolAdapter
from centurion.models import Artifact
from centurion.process import FakeRunner


def test_apktool_detect():
    runner = FakeRunner()
    runner.register("apktool --version", stdout="2.9.3\n", path="/usr/bin/apktool")
    status = ApktoolAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0011"
    assert status.platform == "android"
    assert status.category == "static"


def test_apktool_decode_command():
    assert ApktoolAdapter().decode_command("/tmp/app.apk", "/tmp/out") == [
        "apktool", "d", "-f", "-o", "/tmp/out", "/tmp/app.apk",
    ]


def test_apktool_decode_returns_artifact():
    runner = FakeRunner()
    runner.register("apktool d", stdout="I: Using Apktool 2.9.3\n")
    artifact = ApktoolAdapter(runner).decode("/tmp/app.apk", "/tmp/out")
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "decoded"
    assert artifact.tool == "apktool"
    assert artifact.path == "/tmp/out"
    assert artifact.label == "app.apk"


def test_apktool_decode_raises_on_failure():
    runner = FakeRunner()
    runner.register("apktool d", returncode=1, stderr="brut.androlib.AndrolibException: bad apk\n")
    with pytest.raises(RuntimeError, match="bad apk"):
        ApktoolAdapter(runner).decode("/tmp/app.apk", "/tmp/out")
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_apktool.py -v` → FAIL (ModuleNotFoundError).

- [ ] **Step 3: Create `src/centurion/adapters/android/apktool.py`**

```python
"""Adapter for apktool (decode APK resources/manifest — static analysis)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class ApktoolAdapter(Adapter):
    name = "apktool"
    binary = "apktool"
    mastg_id = "MASTG-TOOL-0011"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install apktool: `brew install apktool` or `apt install apktool`"

    def decode_command(self, apk: str, out_dir: str) -> list[str]:
        return ["apktool", "d", "-f", "-o", out_dir, apk]

    def decode(self, apk: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.decode_command(apk, out_dir), timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"apktool failed: {result.stderr.strip()}")
        return Artifact(
            id=f"apktool-{Path(apk).stem}",
            kind="decoded",
            path=out_dir,
            tool="apktool",
            label=Path(apk).name,
        )
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_apktool.py -v` → 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/apktool.py tests/test_apktool.py
git commit -m "feat: add apktool adapter"
```

---

## Task 8: dex2jar adapter

**Files:** Create `src/centurion/adapters/android/dex2jar.py`; Test: `tests/test_dex2jar.py`

- [ ] **Step 1: Write `tests/test_dex2jar.py`**

```python
import pytest

from centurion.adapters.android.dex2jar import Dex2jarAdapter
from centurion.models import Artifact
from centurion.process import FakeRunner


def test_dex2jar_detect_via_path():
    runner = FakeRunner()
    # dex2jar may exit non-zero on --version, but presence on PATH means installed.
    runner.register("d2j-dex2jar --version", returncode=1, stderr="usage: d2j-dex2jar\n", path="/usr/bin/d2j-dex2jar")
    status = Dex2jarAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "android"
    assert status.category == "static"
    assert status.mastg_id is None


def test_dex2jar_convert_command():
    assert Dex2jarAdapter().convert_command("/tmp/app.apk", "/tmp/app.jar") == [
        "d2j-dex2jar", "-f", "-o", "/tmp/app.jar", "/tmp/app.apk",
    ]


def test_dex2jar_convert_returns_artifact():
    runner = FakeRunner()
    runner.register("d2j-dex2jar -f", stdout="dex2jar /tmp/app.apk -> /tmp/app.jar\n")
    artifact = Dex2jarAdapter(runner).convert("/tmp/app.apk", "/tmp/app.jar")
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "jar"
    assert artifact.tool == "dex2jar"
    assert artifact.path == "/tmp/app.jar"
    assert artifact.label == "app.apk"


def test_dex2jar_convert_raises_on_failure():
    runner = FakeRunner()
    runner.register("d2j-dex2jar -f", returncode=1, stderr="translate error\n")
    with pytest.raises(RuntimeError, match="translate error"):
        Dex2jarAdapter(runner).convert("/tmp/app.apk", "/tmp/app.jar")
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_dex2jar.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/android/dex2jar.py`**

```python
"""Adapter for dex2jar (convert .dex/.apk to .jar — static analysis)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class Dex2jarAdapter(Adapter):
    name = "dex2jar"
    binary = "d2j-dex2jar"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install dex2jar: `brew install dex2jar` or `apt install dex2jar`"

    def convert_command(self, input_path: str, out_jar: str) -> list[str]:
        return ["d2j-dex2jar", "-f", "-o", out_jar, input_path]

    def convert(self, input_path: str, out_jar: str) -> Artifact:
        result = self.runner.run(self.convert_command(input_path, out_jar), timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"dex2jar failed: {result.stderr.strip()}")
        return Artifact(
            id=f"dex2jar-{Path(input_path).stem}",
            kind="jar",
            path=out_jar,
            tool="dex2jar",
            label=Path(input_path).name,
        )
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_dex2jar.py -v` → 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/dex2jar.py tests/test_dex2jar.py
git commit -m "feat: add dex2jar adapter"
```

---

## Task 9: apksigner adapter

**Files:** Create `src/centurion/adapters/android/apksigner.py`; Test: `tests/test_apksigner.py`

- [ ] **Step 1: Write `tests/test_apksigner.py`**

```python
from centurion.adapters.android.apksigner import ApksignerAdapter, SignatureInfo
from centurion.process import FakeRunner

SAMPLE = """\
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v4 scheme (APK Signature Scheme v4): false
"""


def test_apksigner_detect():
    runner = FakeRunner()
    runner.register("apksigner --version", stdout="0.9\n", path="/usr/bin/apksigner")
    status = ApksignerAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "android"
    assert status.category == "static"


def test_apksigner_verify_command():
    assert ApksignerAdapter().verify_command("/tmp/app.apk") == [
        "apksigner", "verify", "--print-certs", "-v", "/tmp/app.apk",
    ]


def test_apksigner_parse_verify():
    info = ApksignerAdapter().parse_verify(SAMPLE)
    assert info == SignatureInfo(v1=True, v2=True, v3=False)


def test_apksigner_verify_runs_and_parses():
    runner = FakeRunner()
    runner.register("apksigner verify", stdout=SAMPLE)
    info = ApksignerAdapter(runner).verify("/tmp/app.apk")
    assert info.to_dict() == {"v1": True, "v2": True, "v3": False}
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_apksigner.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/android/apksigner.py`**

```python
"""Adapter for apksigner (verify APK signing schemes — static analysis)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ...models import Category, Platform
from ..base import Adapter


@dataclass
class SignatureInfo:
    v1: bool
    v2: bool
    v3: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApksignerAdapter(Adapter):
    name = "apksigner"
    binary = "apksigner"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install apksigner (Android SDK build-tools): `sdkmanager 'build-tools;34.0.0'`"

    def verify_command(self, apk: str) -> list[str]:
        return ["apksigner", "verify", "--print-certs", "-v", apk]

    def parse_verify(self, stdout: str) -> SignatureInfo:
        def verified(scheme: str) -> bool:
            for line in stdout.splitlines():
                low = line.strip().lower()
                if f"using {scheme} scheme" in low:
                    return low.endswith("true")
            return False

        return SignatureInfo(v1=verified("v1"), v2=verified("v2"), v3=verified("v3"))

    def verify(self, apk: str) -> SignatureInfo:
        result = self.runner.run(self.verify_command(apk), timeout=60)
        return self.parse_verify(result.stdout)
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_apksigner.py -v` → 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/apksigner.py tests/test_apksigner.py
git commit -m "feat: add apksigner adapter"
```

---

## Task 10: semgrep adapter

**Files:** Create `src/centurion/adapters/generic/semgrep.py`; Test: `tests/test_semgrep.py`

- [ ] **Step 1: Write `tests/test_semgrep.py`**

```python
import pytest

from centurion.adapters.generic.semgrep import SemgrepAdapter, default_rules_path
from centurion.models import Finding
from centurion.process import FakeRunner

SAMPLE_JSON = """\
{"results": [
  {"check_id": "android.cleartext", "path": "app/Main.java",
   "start": {"line": 42},
   "extra": {"message": "Cleartext HTTP traffic", "severity": "WARNING",
             "metadata": {"mastg": ["MASTG-TEST-0066"]}}},
  {"check_id": "android.weak-crypto", "path": "app/Crypto.java",
   "start": {"line": 7},
   "extra": {"message": "Weak cipher", "severity": "ERROR", "metadata": {}}}
], "errors": []}
"""


def test_semgrep_detect():
    runner = FakeRunner()
    runner.register("semgrep --version", stdout="1.80.0\n", path="/usr/bin/semgrep")
    status = SemgrepAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "generic"
    assert status.category == "static"


def test_semgrep_scan_command():
    assert SemgrepAdapter().scan_command("/tmp/src", "/tmp/rules") == [
        "semgrep", "--config", "/tmp/rules", "--json", "/tmp/src",
    ]


def test_semgrep_parse_scan_maps_severity_and_refs():
    findings = SemgrepAdapter().parse_scan(SAMPLE_JSON)
    assert len(findings) == 2
    assert isinstance(findings[0], Finding)
    assert findings[0].tool == "semgrep"
    assert findings[0].title == "android.cleartext"
    assert findings[0].severity == "medium"  # WARNING -> medium
    assert findings[0].location == "app/Main.java:42"
    assert findings[0].mastg_refs == ["MASTG-TEST-0066"]
    assert findings[1].severity == "high"  # ERROR -> high


def test_semgrep_scan_missing_rules_raises(tmp_path):
    runner = FakeRunner()
    missing = str(tmp_path / "no-rules")
    with pytest.raises(RuntimeError, match="rules"):
        SemgrepAdapter(runner).scan("/tmp/src", rules=missing)


def test_semgrep_scan_runs_and_parses(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    runner = FakeRunner()
    runner.register("semgrep --config", stdout=SAMPLE_JSON)
    findings = SemgrepAdapter(runner).scan("/tmp/src", rules=str(rules))
    assert [f.title for f in findings] == ["android.cleartext", "android.weak-crypto"]


def test_default_rules_path_under_centurion_home():
    assert default_rules_path().name == "rules"
    assert ".centurion" in str(default_rules_path())
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_semgrep.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/generic/semgrep.py`**

```python
"""Adapter for semgrep (static analysis with MASTG-derived rules)."""

from __future__ import annotations

import json
from pathlib import Path

from ...models import Category, Finding, Platform
from ..base import Adapter

_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}


def default_rules_path() -> Path:
    return Path.home() / ".centurion" / "rules"


class SemgrepAdapter(Adapter):
    name = "semgrep"
    binary = "semgrep"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.GENERIC
    category = Category.STATIC

    def install_hint(self) -> str:
        return (
            "Install semgrep: `pip install semgrep`. Then install a ruleset into "
            "~/.centurion/rules (e.g. the OWASP-derived semgrep-rules-android-security)."
        )

    def scan_command(self, target: str, rules: str) -> list[str]:
        return ["semgrep", "--config", rules, "--json", target]

    def parse_scan(self, stdout: str) -> list[Finding]:
        data = json.loads(stdout)
        findings: list[Finding] = []
        for result in data.get("results", []):
            check = result.get("check_id", "semgrep")
            path = result.get("path", "")
            line = result.get("start", {}).get("line")
            extra = result.get("extra", {})
            severity = _SEVERITY.get(str(extra.get("severity", "INFO")).upper(), "info")
            metadata = extra.get("metadata", {}) or {}
            refs = metadata.get("mastg") or metadata.get("owasp-mastg") or []
            findings.append(
                Finding(
                    id=f"{check}:{path}:{line}",
                    title=check,
                    severity=severity,
                    tool="semgrep",
                    detail=extra.get("message", ""),
                    location=f"{path}:{line}" if line else path,
                    mastg_refs=list(refs),
                )
            )
        return findings

    def scan(self, target: str, rules: str | None = None) -> list[Finding]:
        rules_path = rules or str(default_rules_path())
        if not Path(rules_path).exists():
            raise RuntimeError(
                f"semgrep rules not found at '{rules_path}'. Install a ruleset there "
                "or pass an explicit rules path. See `centurion doctor`."
            )
        result = self.runner.run(self.scan_command(target, rules_path), timeout=900)
        return self.parse_scan(result.stdout)
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_semgrep.py -v` → 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/generic/semgrep.py tests/test_semgrep.py
git commit -m "feat: add semgrep adapter with findings parsing"
```

---

## Task 11: radare2 adapter

**Files:** Create `src/centurion/adapters/generic/radare2.py`; Test: `tests/test_radare2.py`

- [ ] **Step 1: Write `tests/test_radare2.py`**

```python
from centurion.adapters.generic.radare2 import Radare2Adapter
from centurion.process import FakeRunner


def test_radare2_detect():
    runner = FakeRunner()
    runner.register("r2 -version", stdout="radare2 5.8.8 0 @ linux-x86-64\n", path="/usr/bin/r2")
    status = Radare2Adapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0028"
    assert status.category == "recon"


def test_radare2_strings_command():
    assert Radare2Adapter().strings_command("/tmp/lib.so") == ["rabin2", "-z", "/tmp/lib.so"]


def test_radare2_info_command():
    assert Radare2Adapter().info_command("/tmp/lib.so") == ["rabin2", "-I", "/tmp/lib.so"]
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_radare2.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/generic/radare2.py`**

```python
"""Adapter for radare2 (binary recon via rabin2 — reverse engineering)."""

from __future__ import annotations

from ...models import Category, Platform
from ...process import RunResult
from ..base import Adapter


class Radare2Adapter(Adapter):
    name = "radare2"
    binary = "r2"
    mastg_id = "MASTG-TOOL-0028"
    platform = Platform.GENERIC
    category = Category.RECON

    def version_command(self) -> list[str]:
        return ["r2", "-version"]

    def install_hint(self) -> str:
        return "Install radare2: `brew install radare2` or from github.com/radareorg/radare2"

    def strings_command(self, path: str) -> list[str]:
        return ["rabin2", "-z", path]

    def info_command(self, path: str) -> list[str]:
        return ["rabin2", "-I", path]
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_radare2.py -v` → 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/generic/radare2.py tests/test_radare2.py
git commit -m "feat: add radare2 adapter"
```

---

## Task 12: strings adapter

**Files:** Create `src/centurion/adapters/generic/strings.py`; Test: `tests/test_strings.py`

- [ ] **Step 1: Write `tests/test_strings.py`**

```python
from centurion.adapters.generic.strings import StringsAdapter
from centurion.process import FakeRunner


def test_strings_detect():
    runner = FakeRunner()
    runner.register("strings --version", stdout="strings (GNU Binutils) 2.40\n", path="/usr/bin/strings")
    status = StringsAdapter(runner).detect()
    assert status.installed is True
    assert status.category == "recon"
    assert status.mastg_id is None


def test_strings_command_default_min_len():
    assert StringsAdapter().run_command("/tmp/lib.so") == ["strings", "-n", "8", "/tmp/lib.so"]


def test_strings_extract_filters_blank_lines():
    runner = FakeRunner()
    runner.register("strings -n", stdout="https://api.example.com\n\nAES/CBC/PKCS5Padding\n")
    out = StringsAdapter(runner).extract("/tmp/lib.so")
    assert out == ["https://api.example.com", "AES/CBC/PKCS5Padding"]
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_strings.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/generic/strings.py`**

```python
"""Adapter for strings (extract printable strings from binaries — recon)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class StringsAdapter(Adapter):
    name = "strings"
    binary = "strings"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.GENERIC
    category = Category.RECON

    def install_hint(self) -> str:
        return "Install binutils (provides `strings`): `apt install binutils` or `brew install binutils`"

    def run_command(self, path: str, min_len: int = 8) -> list[str]:
        return ["strings", "-n", str(min_len), path]

    def extract(self, path: str, min_len: int = 8) -> list[str]:
        result = self.runner.run(self.run_command(path, min_len), timeout=120)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_strings.py -v` → 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/generic/strings.py tests/test_strings.py
git commit -m "feat: add strings adapter"
```

---

## Task 13: objection adapter

**Files:** Create `src/centurion/adapters/android/objection.py`; Test: `tests/test_objection.py`

- [ ] **Step 1: Write `tests/test_objection.py`**

```python
from centurion.adapters.android.objection import ObjectionAdapter
from centurion.process import FakeRunner


def test_objection_detect():
    runner = FakeRunner()
    runner.register("objection version", stdout="objection: 1.11.0\n", path="/usr/bin/objection")
    status = ObjectionAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0029"
    assert status.category == "dynamic"


def test_objection_explore_command_with_startup_commands():
    cmd = ObjectionAdapter().explore_command(
        "com.acme.bank",
        ["android sslpinning disable", "android root disable"],
    )
    assert cmd == [
        "objection", "-g", "com.acme.bank", "explore",
        "--startup-command", "android sslpinning disable",
        "--startup-command", "android root disable",
    ]


def test_objection_run_returns_stdout():
    runner = FakeRunner()
    runner.register("objection -g com.acme.bank explore", stdout="pinning disabled\n")
    out = ObjectionAdapter(runner).run("com.acme.bank", ["android sslpinning disable"])
    assert "pinning disabled" in out
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_objection.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/android/objection.py`**

```python
"""Adapter for objection (Frida-based runtime exploration — dynamic analysis)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class ObjectionAdapter(Adapter):
    name = "objection"
    binary = "objection"
    mastg_id = "MASTG-TOOL-0029"
    platform = Platform.ANDROID
    category = Category.DYNAMIC

    def version_command(self) -> list[str]:
        return ["objection", "version"]

    def install_hint(self) -> str:
        return "Install objection: `pip install objection`"

    def explore_command(self, package: str, startup_commands: list[str]) -> list[str]:
        cmd = ["objection", "-g", package, "explore"]
        for command in startup_commands:
            cmd += ["--startup-command", command]
        return cmd

    def run(self, package: str, startup_commands: list[str]) -> str:
        result = self.runner.run(self.explore_command(package, startup_commands), timeout=300)
        return result.stdout
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_objection.py -v` → 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/objection.py tests/test_objection.py
git commit -m "feat: add objection adapter"
```

---

## Task 14: drozer adapter

**Files:** Create `src/centurion/adapters/android/drozer.py`; Test: `tests/test_drozer.py`

- [ ] **Step 1: Write `tests/test_drozer.py`**

```python
from centurion.adapters.android.drozer import DrozerAdapter
from centurion.process import FakeRunner


def test_drozer_detect_via_path():
    runner = FakeRunner()
    runner.register("drozer --version", returncode=1, stderr="usage: drozer\n", path="/usr/bin/drozer")
    status = DrozerAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0015"
    assert status.category == "dynamic"


def test_drozer_module_command_with_args():
    assert DrozerAdapter().module_command("app.package.attacksurface", "com.acme.bank") == [
        "drozer", "console", "connect", "-c", "run app.package.attacksurface com.acme.bank",
    ]


def test_drozer_module_command_no_args():
    assert DrozerAdapter().module_command("app.package.list") == [
        "drozer", "console", "connect", "-c", "run app.package.list",
    ]


def test_drozer_run_module_returns_stdout():
    runner = FakeRunner()
    runner.register("drozer console connect", stdout="Attack surface:\n  3 activities exported\n")
    out = DrozerAdapter(runner).run_module("app.package.attacksurface", "com.acme.bank")
    assert "3 activities exported" in out
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_drozer.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/android/drozer.py`**

```python
"""Adapter for drozer (Android attack-surface analysis — dynamic analysis)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class DrozerAdapter(Adapter):
    name = "drozer"
    binary = "drozer"
    mastg_id = "MASTG-TOOL-0015"
    platform = Platform.ANDROID
    category = Category.DYNAMIC

    def install_hint(self) -> str:
        return "Install drozer: `pip install drozer` (plus the drozer agent app on the device)"

    def module_command(self, module: str, args: str = "") -> list[str]:
        run = f"run {module} {args}".strip()
        return ["drozer", "console", "connect", "-c", run]

    def run_module(self, module: str, args: str = "") -> str:
        result = self.runner.run(self.module_command(module, args), timeout=300)
        return result.stdout
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_drozer.py -v` → 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/drozer.py tests/test_drozer.py
git commit -m "feat: add drozer adapter"
```

---

## Task 15: mitmproxy adapter

**Files:** Create `src/centurion/adapters/generic/mitmproxy.py`; Test: `tests/test_mitmproxy.py`

> Network tools use `platform=generic, category=network` so the install group `"network"` (resolved as a category by Task 2) selects them. The adapter provides command builders + detect; live proxy lifecycle and flow parsing are wired up in Plan 2b.

- [ ] **Step 1: Write `tests/test_mitmproxy.py`**

```python
from centurion.adapters.generic.mitmproxy import MitmproxyAdapter
from centurion.process import FakeRunner


def test_mitmproxy_detect():
    runner = FakeRunner()
    runner.register("mitmdump --version", stdout="Mitmproxy: 10.2.4\n", path="/usr/bin/mitmdump")
    status = MitmproxyAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "generic"
    assert status.category == "network"
    assert status.mastg_id is None


def test_mitmproxy_start_command_default():
    assert MitmproxyAdapter().start_command() == ["mitmdump", "-p", "8080"]


def test_mitmproxy_start_command_with_flow_out():
    assert MitmproxyAdapter().start_command(port=9090, flow_out="/tmp/flows") == [
        "mitmdump", "-p", "9090", "-w", "/tmp/flows",
    ]


def test_mitmproxy_read_command():
    assert MitmproxyAdapter().read_command("/tmp/flows") == [
        "mitmdump", "-nr", "/tmp/flows", "--flow-detail", "1",
    ]
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_mitmproxy.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/generic/mitmproxy.py`**

```python
"""Adapter for mitmproxy/mitmdump (HTTP(S) interception — network analysis)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class MitmproxyAdapter(Adapter):
    name = "mitmproxy"
    binary = "mitmdump"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.GENERIC
    category = Category.NETWORK

    def version_command(self) -> list[str]:
        return ["mitmdump", "--version"]

    def install_hint(self) -> str:
        return "Install mitmproxy: `pip install mitmproxy` or `brew install mitmproxy`"

    def start_command(self, port: int = 8080, flow_out: str | None = None) -> list[str]:
        cmd = ["mitmdump", "-p", str(port)]
        if flow_out:
            cmd += ["-w", flow_out]
        return cmd

    def read_command(self, flow_file: str) -> list[str]:
        return ["mitmdump", "-nr", flow_file, "--flow-detail", "1"]
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_mitmproxy.py -v` → 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/generic/mitmproxy.py tests/test_mitmproxy.py
git commit -m "feat: add mitmproxy adapter"
```

---

## Task 16: tcpdump adapter

**Files:** Create `src/centurion/adapters/generic/tcpdump.py`; Test: `tests/test_tcpdump.py`

- [ ] **Step 1: Write `tests/test_tcpdump.py`**

```python
from centurion.adapters.generic.tcpdump import TcpdumpAdapter
from centurion.process import FakeRunner


def test_tcpdump_detect():
    runner = FakeRunner()
    runner.register("tcpdump --version", stdout="tcpdump version 4.99.4\n", path="/usr/sbin/tcpdump")
    status = TcpdumpAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "generic"
    assert status.category == "network"


def test_tcpdump_capture_command_default():
    assert TcpdumpAdapter().capture_command("/tmp/cap.pcap") == [
        "tcpdump", "-i", "any", "-w", "/tmp/cap.pcap",
    ]


def test_tcpdump_capture_command_with_iface_and_count():
    assert TcpdumpAdapter().capture_command("/tmp/cap.pcap", iface="wlan0", count=100) == [
        "tcpdump", "-i", "wlan0", "-w", "/tmp/cap.pcap", "-c", "100",
    ]
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_tcpdump.py -v` → FAIL.

- [ ] **Step 3: Create `src/centurion/adapters/generic/tcpdump.py`**

```python
"""Adapter for tcpdump (packet capture — network analysis)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class TcpdumpAdapter(Adapter):
    name = "tcpdump"
    binary = "tcpdump"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.GENERIC
    category = Category.NETWORK

    def version_command(self) -> list[str]:
        return ["tcpdump", "--version"]

    def install_hint(self) -> str:
        return "Install tcpdump: `apt install tcpdump` or `brew install tcpdump`"

    def capture_command(self, out: str, iface: str = "any", count: int | None = None) -> list[str]:
        cmd = ["tcpdump", "-i", iface, "-w", out]
        if count:
            cmd += ["-c", str(count)]
        return cmd
```

- [ ] **Step 4: Run** `.venv/bin/python -m pytest tests/test_tcpdump.py -v` → 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/generic/tcpdump.py tests/test_tcpdump.py
git commit -m "feat: add tcpdump adapter"
```

---

## Task 17: Register all new adapters in `default_registry`

**Files:** Modify `src/centurion/registry.py`; Test: `tests/test_registry.py`

- [ ] **Step 1: Add failing test** (append to `tests/test_registry.py`):

```python
from centurion.process import FakeRunner
from centurion.registry import default_registry


def test_default_registry_has_all_phase2_adapters():
    names = {a.name for a in default_registry(FakeRunner()).all()}
    assert names == {
        "adb", "scrcpy", "jadx", "frida",
        "apktool", "dex2jar", "apksigner", "semgrep",
        "radare2", "strings", "objection", "drozer",
        "mitmproxy", "tcpdump",
    }
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_registry.py::test_default_registry_has_all_phase2_adapters -v` → FAIL (only the 4 Phase-1 adapters registered).

- [ ] **Step 3: Implement** — replace `default_registry` in `src/centurion/registry.py`:

```python
def default_registry(runner: Runner | None = None) -> Registry:
    """Build the registry with all currently-implemented adapters."""
    from .adapters.android.adb import AdbAdapter
    from .adapters.android.apksigner import ApksignerAdapter
    from .adapters.android.apktool import ApktoolAdapter
    from .adapters.android.dex2jar import Dex2jarAdapter
    from .adapters.android.drozer import DrozerAdapter
    from .adapters.android.jadx import JadxAdapter
    from .adapters.android.objection import ObjectionAdapter
    from .adapters.android.scrcpy import ScrcpyAdapter
    from .adapters.generic.frida import FridaAdapter
    from .adapters.generic.mitmproxy import MitmproxyAdapter
    from .adapters.generic.radare2 import Radare2Adapter
    from .adapters.generic.semgrep import SemgrepAdapter
    from .adapters.generic.strings import StringsAdapter
    from .adapters.generic.tcpdump import TcpdumpAdapter

    return Registry(
        [
            AdbAdapter(runner),
            ScrcpyAdapter(runner),
            JadxAdapter(runner),
            FridaAdapter(runner),
            ApktoolAdapter(runner),
            Dex2jarAdapter(runner),
            ApksignerAdapter(runner),
            SemgrepAdapter(runner),
            Radare2Adapter(runner),
            StringsAdapter(runner),
            ObjectionAdapter(runner),
            DrozerAdapter(runner),
            MitmproxyAdapter(runner),
            TcpdumpAdapter(runner),
        ]
    )
```

- [ ] **Step 4: Run the full suite** `.venv/bin/python -m pytest -q` → all green. Then smoke-test doctor:

Run: `.venv/bin/centurion doctor`
Expected: a table listing all 14 tools with their MASTG ids / platforms / categories and real install status on this machine.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/registry.py tests/test_registry.py
git commit -m "feat: register all Phase 2a adapters in default registry"
```

---

## Task 18: Final verification

- [ ] **Step 1: Full suite** `.venv/bin/python -m pytest -q` → all pass.
- [ ] **Step 2:** `.venv/bin/centurion doctor` → 14 tools listed.
- [ ] **Step 3:** `.venv/bin/centurion install --group network` → lists only network-category tools (mitmproxy, tcpdump) that are missing, confirming the group-precedence fix.
- [ ] **Step 4:** `.venv/bin/centurion install --group static` → lists missing static tools (apktool/dex2jar/apksigner/semgrep/jadx as applicable).
- [ ] **Step 5: Commit** any stragglers: `git add -A && git commit -m "chore: phase 2a complete" || echo "nothing to commit"`

---

## Self-Review Notes (author)

**Spec coverage (Phase 2 spec §1, §2, §6):**
- §1 new adapters: apktool (T7), dex2jar (T8), apksigner (T9), semgrep (T10), radare2 (T11), strings (T12), objection (T13), drozer (T14), mitmproxy (T15), tcpdump (T16); adb app ops (T6) ✓
- §2 findings + durable processes: `Session.findings`/`add_finding` (T4), `WorkspaceProcessManager` (T5) ✓
- §6 hardening: Registry.get message (T1), install precedence (T2), device-list table (T3) ✓
- Register all (T17). The `detect()` "honest path" item from the spec is intentionally NOT changed: `doctor` has no Path column, and `path=None` when a tool is runnable-but-not-on-PATH is already honest — changing the well-tested `detect()` logic would add risk for no user-visible benefit. Noted here rather than silently dropped.
- Frida script library, MCP tools/resources, skills/agents: **Plan 2b**, by design — out of scope for 2a.

**Placeholder scan:** No code-step placeholders. `mastg_id = None` on unconfirmed tools is real data with a clarifying comment, not a TODO stub; called out in the header.

**Type consistency:** `Finding`/`Artifact`/`ToolStatus` reused from Phase 1 unchanged. `WorkspaceProcessManager` reuses `ManagedProcess`, `_real_spawn`, `Callable`, `Any` already in `process.py`. `default_rules_path()` defined in T10 and referenced only there. `_selects`/`_CATEGORIES`/`_PLATFORMS` names match Phase-1 `install.py`. New adapter class names match their `default_registry` imports in T17.
```