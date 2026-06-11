# Centurion Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the vertical slice of Centurion — a Python package with a core (models, subprocess runner, adapter base, registry, session/workspace, background process manager), an Android device layer, `doctor`/`install`, CLI and MCP skeletons, four anchor tool adapters (adb, scrcpy, jadx, frida), and one Claude skill — all test-driven.

**Architecture:** Approach A from the spec. One package exposes a CLI (Typer) and a stdio MCP server (FastMCP) over a shared core. Every external tool is wrapped by a thin **adapter** that shells out and parses output into structured dataclasses. Subprocess execution goes through an injectable `Runner` so adapters are unit-testable with canned output and never touch a real device in tests.

**Tech Stack:** Python 3.11+, `typer` (CLI), `mcp` (FastMCP server), `rich` (tables), `pytest` (tests). src layout, hatchling build.

Spec: `docs/superpowers/specs/2026-06-11-centurion-toolkit-design.md`

---

## File Structure

```
centurion/
  pyproject.toml                          # Task 1
  README.md                               # Task 15
  src/centurion/
    __init__.py                           # Task 1
    models.py                             # Task 2  — Platform, Category, Severity, ToolStatus, Artifact, Finding
    process.py                            # Task 3  — RunResult, Runner, RealRunner, FakeRunner, ProcessManager, ManagedProcess
    adapters/
      __init__.py                         # Task 4
      base.py                             # Task 4  — Adapter ABC
      android/
        __init__.py                       # Task 5
        adb.py                            # Task 5  — AdbAdapter, AndroidDevice
        scrcpy.py                         # Task 9  — ScrcpyAdapter
        jadx.py                           # Task 10 — JadxAdapter
      generic/
        __init__.py                       # Task 11
        frida.py                          # Task 11 — FridaAdapter, FridaProcess
    registry.py                           # Task 6  — Registry, default_registry
    session.py                            # Task 7  — Session, Workspace, default_root
    install.py                            # Task 8  — plan_install
    cli/
      __init__.py                         # Task 13
      app.py                              # Task 13 — Typer app, get_registry
    mcp/
      __init__.py                         # Task 14
      server.py                           # Task 14 — FastMCP server, main
  .claude/
    skills/centurion-recon/SKILL.md       # Task 15
  tests/
    test_models.py                        # Task 2
    test_process.py                       # Task 3
    test_adapter_base.py                  # Task 4
    test_adb.py                           # Task 5
    test_registry.py                      # Task 6
    test_session.py                       # Task 7
    test_install.py                       # Task 8
    test_scrcpy.py                        # Task 9
    test_jadx.py                          # Task 10
    test_frida.py                         # Task 11
    test_process_manager.py               # Task 12
    test_cli.py                           # Task 13
    test_mcp_server.py                    # Task 14
```

---

## Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/centurion/__init__.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "centurion"
version = "0.1.0"
description = "Mobile QA + pentest toolkit wrapping OWASP MASTG tools, with a Claude Code MCP server"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
dependencies = [
    "typer>=0.12",
    "rich>=13.0",
    "mcp>=1.2",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
centurion = "centurion.cli.app:app"
centurion-mcp = "centurion.mcp.server:main"

[tool.hatch.build.targets.wheel]
packages = ["src/centurion"]

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

- [ ] **Step 2: Create the package init**

`src/centurion/__init__.py`:

```python
"""Centurion — mobile QA + pentest toolkit."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Install the project in editable mode with dev deps**

Run: `pip install -e ".[dev]"`
Expected: installs typer, rich, mcp, pytest; `Successfully installed centurion-0.1.0`.

- [ ] **Step 4: Verify pytest runs (no tests yet)**

Run: `pytest -q`
Expected: `no tests ran` (exit code 5 is acceptable here).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/centurion/__init__.py
git commit -m "chore: scaffold centurion python package"
```

---

## Task 2: Core models

**Files:**
- Create: `src/centurion/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:

```python
from centurion.models import (
    Platform, Category, Severity, ToolStatus, Artifact, Finding,
)


def test_toolstatus_to_dict_roundtrip():
    status = ToolStatus(
        name="adb",
        installed=True,
        mastg_id="MASTG-TOOL-0006",
        platform=Platform.ANDROID.value,
        category=Category.DEVICE_QA.value,
        version="1.0.41",
        path="/usr/bin/adb",
        install_hint="brew install android-platform-tools",
    )
    d = status.to_dict()
    assert d["name"] == "adb"
    assert d["installed"] is True
    assert d["mastg_id"] == "MASTG-TOOL-0006"
    assert d["platform"] == "android"


def test_finding_defaults():
    f = Finding(id="f1", title="Cleartext traffic", severity=Severity.HIGH.value, tool="semgrep")
    assert f.detail == ""
    assert f.location is None
    assert f.mastg_refs == []
    assert f.to_dict()["severity"] == "high"


def test_artifact_to_dict():
    a = Artifact(id="jadx-app", kind="decompiled", path="/tmp/out", tool="jadx", label="app.apk")
    assert a.to_dict() == {
        "id": "jadx-app",
        "kind": "decompiled",
        "path": "/tmp/out",
        "tool": "jadx",
        "label": "app.apk",
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.models'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/models.py`:

```python
"""Structured data models shared across Centurion."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    GENERIC = "generic"
    NETWORK = "network"


class Category(str, Enum):
    DEVICE_QA = "device-qa"
    STATIC = "static"
    DYNAMIC = "dynamic"
    NETWORK = "network"
    RECON = "recon"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolStatus:
    name: str
    installed: bool
    mastg_id: str | None = None
    platform: str | None = None
    category: str | None = None
    version: str | None = None
    path: str | None = None
    install_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Artifact:
    id: str
    kind: str  # decompiled | pcap | frida-log | screenshot | binary
    path: str
    tool: str
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    tool: str
    detail: str = ""
    location: str | None = None
    mastg_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/models.py tests/test_models.py
git commit -m "feat: add core data models"
```

---

## Task 3: Subprocess runner abstraction

**Files:**
- Create: `src/centurion/process.py` (Runner part; ProcessManager added in Task 12)
- Test: `tests/test_process.py`

- [ ] **Step 1: Write the failing test**

`tests/test_process.py`:

```python
import pytest

from centurion.process import FakeRunner, RunResult


def test_fakerunner_returns_registered_response():
    runner = FakeRunner()
    runner.register("adb version", stdout="Android Debug Bridge version 1.0.41", path="/usr/bin/adb")

    result = runner.run(["adb", "version"])

    assert isinstance(result, RunResult)
    assert result.returncode == 0
    assert "1.0.41" in result.stdout
    assert runner.calls == [["adb", "version"]]


def test_fakerunner_matches_by_prefix():
    runner = FakeRunner()
    runner.register("adb devices", stdout="List of devices attached\nemulator-5554\tdevice\n")

    result = runner.run(["adb", "devices", "-l"])

    assert "emulator-5554" in result.stdout


def test_fakerunner_unregistered_raises_filenotfound():
    runner = FakeRunner()
    with pytest.raises(FileNotFoundError):
        runner.run(["nope", "--version"])


def test_fakerunner_which():
    runner = FakeRunner()
    runner.register("adb version", path="/usr/bin/adb")
    assert runner.which("adb") == "/usr/bin/adb"
    assert runner.which("ghost") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_process.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.process'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/process.py`:

```python
"""Subprocess execution abstraction.

Everything that shells out goes through a Runner so adapters can be unit-tested
with canned output and never touch a real device.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass
class RunResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    def run(self, args: list[str], *, timeout: float | None = None) -> RunResult: ...

    def which(self, binary: str) -> str | None: ...


class RealRunner:
    """Runs commands for real via subprocess."""

    def run(self, args: list[str], *, timeout: float | None = None) -> RunResult:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return RunResult(list(args), proc.returncode, proc.stdout, proc.stderr)

    def which(self, binary: str) -> str | None:
        return shutil.which(binary)


class FakeRunner:
    """Test double. Register canned responses keyed by command-line prefix."""

    def __init__(self) -> None:
        self._responses: dict[str, RunResult] = {}
        self._paths: dict[str, str] = {}
        self.calls: list[list[str]] = []

    def register(
        self,
        prefix: str,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        path: str | None = None,
    ) -> None:
        self._responses[prefix] = RunResult([], returncode, stdout, stderr)
        if path is not None:
            self._paths[prefix.split()[0]] = path

    def run(self, args: list[str], *, timeout: float | None = None) -> RunResult:
        self.calls.append(list(args))
        key = " ".join(args)
        for prefix, resp in self._responses.items():
            if key.startswith(prefix):
                return RunResult(list(args), resp.returncode, resp.stdout, resp.stderr)
        raise FileNotFoundError(args[0])

    def which(self, binary: str) -> str | None:
        return self._paths.get(binary)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_process.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/process.py tests/test_process.py
git commit -m "feat: add injectable subprocess runner"
```

---

## Task 4: Adapter base class

**Files:**
- Create: `src/centurion/adapters/__init__.py`
- Create: `src/centurion/adapters/base.py`
- Test: `tests/test_adapter_base.py`

- [ ] **Step 1: Write the failing test**

`tests/test_adapter_base.py`:

```python
from centurion.adapters.base import Adapter
from centurion.models import Platform, Category
from centurion.process import FakeRunner


class DummyAdapter(Adapter):
    name = "dummy"
    binary = "dummy"
    mastg_id = "MASTG-TOOL-9999"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "pip install dummy"


def test_detect_installed_parses_version():
    runner = FakeRunner()
    runner.register("dummy --version", stdout="dummy 2.3.4\n", path="/usr/bin/dummy")
    status = DummyAdapter(runner).detect()
    assert status.installed is True
    assert status.version == "dummy 2.3.4"
    assert status.path == "/usr/bin/dummy"
    assert status.mastg_id == "MASTG-TOOL-9999"
    assert status.platform == "android"
    assert status.category == "static"
    assert status.install_hint == "pip install dummy"


def test_detect_missing_tool_reports_not_installed():
    runner = FakeRunner()  # nothing registered -> run() raises FileNotFoundError
    status = DummyAdapter(runner).detect()
    assert status.installed is False
    assert status.version is None
    assert status.path is None
    assert status.install_hint == "pip install dummy"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_adapter_base.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.adapters'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/adapters/__init__.py`:

```python
"""Tool adapters: one module per wrapped external tool."""
```

`src/centurion/adapters/base.py`:

```python
"""Base class every tool adapter inherits from."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Category, Platform, ToolStatus
from ..process import RealRunner, RunResult, Runner


class Adapter(ABC):
    # Subclasses set these as class attributes.
    name: str
    binary: str
    mastg_id: str | None = None
    platform: Platform = Platform.GENERIC
    category: Category = Category.RECON

    def __init__(self, runner: Runner | None = None) -> None:
        self.runner = runner or RealRunner()

    def version_command(self) -> list[str]:
        return [self.binary, "--version"]

    def parse_version(self, result: RunResult) -> str | None:
        out = (result.stdout or result.stderr).strip()
        return out.splitlines()[0] if out else None

    @abstractmethod
    def install_hint(self) -> str:
        """Human-readable instruction for installing this tool."""

    def detect(self) -> ToolStatus:
        try:
            result = self.runner.run(self.version_command(), timeout=10)
        except FileNotFoundError:
            return self._status(installed=False)

        path = self.runner.which(self.binary)
        installed = path is not None or result.returncode == 0
        return self._status(
            installed=installed,
            version=self.parse_version(result) if installed else None,
            path=path,
        )

    def _status(
        self,
        *,
        installed: bool,
        version: str | None = None,
        path: str | None = None,
    ) -> ToolStatus:
        return ToolStatus(
            name=self.name,
            installed=installed,
            mastg_id=self.mastg_id,
            platform=self.platform.value,
            category=self.category.value,
            version=version,
            path=path,
            install_hint=self.install_hint(),
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_adapter_base.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/__init__.py src/centurion/adapters/base.py tests/test_adapter_base.py
git commit -m "feat: add adapter base class with detect()"
```

---

## Task 5: adb adapter + Android device model

**Files:**
- Create: `src/centurion/adapters/android/__init__.py`
- Create: `src/centurion/adapters/android/adb.py`
- Test: `tests/test_adb.py`

- [ ] **Step 1: Write the failing test**

`tests/test_adb.py`:

```python
from centurion.adapters.android.adb import AdbAdapter, AndroidDevice
from centurion.process import FakeRunner


def test_adb_detect_parses_version():
    runner = FakeRunner()
    runner.register(
        "adb version",
        stdout="Android Debug Bridge version 1.0.41\nVersion 34.0.4\n",
        path="/usr/bin/adb",
    )
    status = AdbAdapter(runner).detect()
    assert status.installed is True
    assert status.version == "1.0.41"
    assert status.mastg_id == "MASTG-TOOL-0006"
    assert status.platform == "android"


def test_adb_devices_parses_list():
    runner = FakeRunner()
    runner.register(
        "adb devices -l",
        stdout=(
            "List of devices attached\n"
            "emulator-5554          device product:sdk_gphone model:Pixel_6 device:emu64\n"
            "RZ8N12345              device product:p3 model:Pixel_3 device:blueline\n"
            "\n"
        ),
    )
    devices = AdbAdapter(runner).devices()
    assert devices == [
        AndroidDevice(serial="emulator-5554", state="device", model="Pixel_6"),
        AndroidDevice(serial="RZ8N12345", state="device", model="Pixel_3"),
    ]


def test_adb_devices_empty():
    runner = FakeRunner()
    runner.register("adb devices -l", stdout="List of devices attached\n\n")
    assert AdbAdapter(runner).devices() == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_adb.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.adapters.android'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/adapters/android/__init__.py`:

```python
"""Android-specific tool adapters."""
```

`src/centurion/adapters/android/adb.py`:

```python
"""Adapter for the Android Debug Bridge (adb)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...models import Category, Platform
from ...process import RunResult
from ..base import Adapter


@dataclass
class AndroidDevice:
    serial: str
    state: str
    model: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"serial": self.serial, "state": self.state, "model": self.model}


class AdbAdapter(Adapter):
    name = "adb"
    binary = "adb"
    mastg_id = "MASTG-TOOL-0006"  # Android SDK / platform-tools
    platform = Platform.ANDROID
    category = Category.DEVICE_QA

    def version_command(self) -> list[str]:
        return ["adb", "version"]

    def parse_version(self, result: RunResult) -> str | None:
        for line in result.stdout.splitlines():
            if "version" in line.lower():
                return line.strip().split()[-1]
        return None

    def install_hint(self) -> str:
        return (
            "Install Android platform-tools: `brew install android-platform-tools` "
            "or via the Android SDK `sdkmanager 'platform-tools'`"
        )

    def devices(self) -> list[AndroidDevice]:
        result = self.runner.run(["adb", "devices", "-l"], timeout=10)
        devices: list[AndroidDevice] = []
        for line in result.stdout.splitlines()[1:]:  # skip "List of devices attached"
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"
            model = None
            for token in parts[2:]:
                if token.startswith("model:"):
                    model = token.split(":", 1)[1]
            devices.append(AndroidDevice(serial=serial, state=state, model=model))
        return devices
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_adb.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/__init__.py src/centurion/adapters/android/adb.py tests/test_adb.py
git commit -m "feat: add adb adapter and device listing"
```

---

## Task 6: Registry

**Files:**
- Create: `src/centurion/registry.py`
- Test: `tests/test_registry.py`

> Note: `default_registry` imports scrcpy/jadx/frida adapters created in Tasks 9–11. In this task, define `default_registry` to import only adapters that exist now (adb), and extend it in Task 11. The body below shows the **final** form; if running tasks in order, temporarily include only `AdbAdapter` until Task 11, then update.

- [ ] **Step 1: Write the failing test**

`tests/test_registry.py`:

```python
from centurion.adapters.android.adb import AdbAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner
from centurion.registry import Registry


def test_registry_register_and_get():
    reg = Registry([AdbAdapter()])
    assert reg.get("adb").name == "adb"
    assert [a.name for a in reg.all()] == ["adb"]


def test_registry_filter_by_platform_and_category():
    reg = Registry([AdbAdapter()])
    assert reg.by_platform(Platform.ANDROID)[0].name == "adb"
    assert reg.by_platform(Platform.IOS) == []
    assert reg.by_category(Category.DEVICE_QA)[0].name == "adb"


def test_registry_doctor_returns_statuses():
    runner = FakeRunner()
    runner.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    reg = Registry([AdbAdapter(runner)])
    statuses = reg.doctor()
    assert len(statuses) == 1
    assert statuses[0].name == "adb"
    assert statuses[0].installed is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.registry'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/registry.py`:

```python
"""Adapter registry: discovery, filtering, and the MASTG mapping."""

from __future__ import annotations

from .adapters.base import Adapter
from .models import Category, Platform, ToolStatus
from .process import Runner


class Registry:
    def __init__(self, adapters: list[Adapter] | None = None) -> None:
        self._adapters: dict[str, Adapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: Adapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> Adapter:
        return self._adapters[name]

    def all(self) -> list[Adapter]:
        return list(self._adapters.values())

    def by_platform(self, platform: Platform) -> list[Adapter]:
        return [a for a in self._adapters.values() if a.platform == platform]

    def by_category(self, category: Category) -> list[Adapter]:
        return [a for a in self._adapters.values() if a.category == category]

    def doctor(self) -> list[ToolStatus]:
        return [a.detect() for a in self._adapters.values()]


def default_registry(runner: Runner | None = None) -> Registry:
    """Build the registry with all Phase 1 adapters."""
    from .adapters.android.adb import AdbAdapter
    from .adapters.android.jadx import JadxAdapter
    from .adapters.android.scrcpy import ScrcpyAdapter
    from .adapters.generic.frida import FridaAdapter

    return Registry(
        [
            AdbAdapter(runner),
            ScrcpyAdapter(runner),
            JadxAdapter(runner),
            FridaAdapter(runner),
        ]
    )
```

> If running in strict order, the `default_registry` imports for scrcpy/jadx/frida will not resolve until Tasks 9–11. That is fine: `default_registry` is not exercised until Task 13's tests. The unit tests in this task only use `Registry` directly.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_registry.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/registry.py tests/test_registry.py
git commit -m "feat: add adapter registry"
```

---

## Task 7: Session / workspace

**Files:**
- Create: `src/centurion/session.py`
- Test: `tests/test_session.py`

- [ ] **Step 1: Write the failing test**

`tests/test_session.py`:

```python
from pathlib import Path

from centurion.models import Artifact
from centurion.session import Session, Workspace


def test_create_workspace_writes_session_json(tmp_path: Path):
    ws = Workspace(tmp_path, target="Acme Banking", platform="android")
    session = ws.create()

    assert ws.slug == "acme-banking"
    assert ws.dir == tmp_path / "acme-banking"
    assert ws.artifacts_dir.is_dir()
    assert ws.session_file.exists()
    assert session.target == "Acme Banking"
    assert session.platform == "android"
    assert session.runs == []


def test_create_is_idempotent(tmp_path: Path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.record_run("adb", ["adb", "devices"], "ok")
    reopened = ws.create()  # must not clobber
    assert len(reopened.runs) == 1


def test_record_run_appends(tmp_path: Path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.record_run("jadx", ["jadx", "app.apk"], "ok")
    loaded = ws.load()
    assert loaded.runs == [{"tool": "jadx", "command": ["jadx", "app.apk"], "status": "ok"}]


def test_add_artifact(tmp_path: Path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.add_artifact(Artifact(id="a1", kind="decompiled", path="/tmp/out", tool="jadx"))
    loaded = ws.load()
    assert loaded.artifacts[0]["id"] == "a1"
    assert isinstance(loaded, Session)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_session.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.session'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/session.py`:

```python
"""Per-target workspace and session state."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import Artifact


def default_root() -> Path:
    return Path.home() / ".centurion" / "workspaces"


def _slugify(name: str) -> str:
    slug = "".join(c if (c.isalnum() or c in "-_") else "-" for c in name.lower())
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


@dataclass
class Session:
    target: str
    platform: str
    device: str | None = None
    runs: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)


class Workspace:
    def __init__(self, root: Path, target: str, platform: str = "android") -> None:
        self.root = Path(root)
        self.slug = _slugify(target)
        self.dir = self.root / self.slug
        self.artifacts_dir = self.dir / "artifacts"
        self.session_file = self.dir / "session.json"
        self._target = target
        self._platform = platform

    def create(self) -> Session:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        if self.session_file.exists():
            return self.load()
        session = Session(target=self._target, platform=self._platform)
        self.save(session)
        return session

    def load(self) -> Session:
        data = json.loads(self.session_file.read_text())
        return Session(**data)

    def save(self, session: Session) -> None:
        self.session_file.write_text(json.dumps(asdict(session), indent=2))

    def record_run(self, tool: str, command: list[str], status: str) -> None:
        session = self.load()
        session.runs.append({"tool": tool, "command": command, "status": status})
        self.save(session)

    def add_artifact(self, artifact: Artifact) -> None:
        session = self.load()
        session.artifacts.append(artifact.to_dict())
        self.save(session)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_session.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/session.py tests/test_session.py
git commit -m "feat: add workspace and session state"
```

---

## Task 8: Install planner

**Files:**
- Create: `src/centurion/install.py`
- Test: `tests/test_install.py`

> `plan_install` decides *which* tools a `--group` selects and which are missing. It does NOT run installers (that stays interactive in the CLI). Groups select by platform name, category value, or `all`.

- [ ] **Step 1: Write the failing test**

`tests/test_install.py`:

```python
from centurion.adapters.android.adb import AdbAdapter
from centurion.install import plan_install
from centurion.process import FakeRunner
from centurion.registry import Registry


def _registry():
    runner = FakeRunner()
    # adb is installed; nothing else registered would be "missing" if present
    runner.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    return Registry([AdbAdapter(runner)])


def test_plan_install_all_returns_only_missing():
    reg = _registry()  # adb present -> nothing missing
    assert plan_install(reg, "all") == []


def test_plan_install_reports_missing_tool():
    reg = Registry([AdbAdapter(FakeRunner())])  # adb not registered -> missing
    missing = plan_install(reg, "android")
    assert [s.name for s in missing] == ["adb"]
    assert missing[0].install_hint is not None


def test_plan_install_unknown_group_is_empty():
    reg = Registry([AdbAdapter(FakeRunner())])
    assert plan_install(reg, "ios") == []  # no ios adapters in Phase 1 registry
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_install.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.install'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/install.py`:

```python
"""Install planning: choose which tools a group selects, return the missing ones."""

from __future__ import annotations

from .models import ToolStatus
from .registry import Registry

_PLATFORMS = {"android", "ios", "generic", "network"}
_CATEGORIES = {"device-qa", "static", "dynamic", "network", "recon"}


def _selects(status: ToolStatus, group: str) -> bool:
    if group == "all":
        return True
    if group in _PLATFORMS:
        return status.platform == group
    if group in _CATEGORIES:
        return status.category == group
    return False


def plan_install(registry: Registry, group: str) -> list[ToolStatus]:
    """Return ToolStatus entries in `group` that are not yet installed."""
    return [s for s in registry.doctor() if _selects(s, group) and not s.installed]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_install.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/install.py tests/test_install.py
git commit -m "feat: add install planner"
```

---

## Task 9: scrcpy adapter

**Files:**
- Create: `src/centurion/adapters/android/scrcpy.py`
- Test: `tests/test_scrcpy.py`

- [ ] **Step 1: Write the failing test**

`tests/test_scrcpy.py`:

```python
from centurion.adapters.android.scrcpy import ScrcpyAdapter
from centurion.process import FakeRunner


def test_scrcpy_detect():
    runner = FakeRunner()
    runner.register("scrcpy --version", stdout="scrcpy 2.4\n", path="/usr/bin/scrcpy")
    status = ScrcpyAdapter(runner).detect()
    assert status.installed is True
    assert status.version == "scrcpy 2.4"
    assert status.category == "device-qa"
    assert status.mastg_id is None  # QA tool, not a MASTG tool


def test_scrcpy_start_command_no_serial():
    assert ScrcpyAdapter().start_command() == ["scrcpy"]


def test_scrcpy_start_command_with_serial():
    assert ScrcpyAdapter().start_command(serial="emulator-5554") == [
        "scrcpy",
        "--serial",
        "emulator-5554",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scrcpy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.adapters.android.scrcpy'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/adapters/android/scrcpy.py`:

```python
"""Adapter for scrcpy (Android screen mirroring / control — QA layer)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class ScrcpyAdapter(Adapter):
    name = "scrcpy"
    binary = "scrcpy"
    mastg_id = None  # QA / device tool, not part of the MASTG tool list
    platform = Platform.ANDROID
    category = Category.DEVICE_QA

    def version_command(self) -> list[str]:
        return ["scrcpy", "--version"]

    def install_hint(self) -> str:
        return "Install scrcpy: `brew install scrcpy` or `apt install scrcpy`"

    def start_command(self, serial: str | None = None) -> list[str]:
        cmd = ["scrcpy"]
        if serial:
            cmd += ["--serial", serial]
        return cmd
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scrcpy.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/scrcpy.py tests/test_scrcpy.py
git commit -m "feat: add scrcpy adapter"
```

---

## Task 10: jadx adapter

**Files:**
- Create: `src/centurion/adapters/android/jadx.py`
- Test: `tests/test_jadx.py`

- [ ] **Step 1: Write the failing test**

`tests/test_jadx.py`:

```python
import pytest

from centurion.adapters.android.jadx import JadxAdapter
from centurion.models import Artifact
from centurion.process import FakeRunner


def test_jadx_detect():
    runner = FakeRunner()
    runner.register("jadx --version", stdout="1.5.0\n", path="/usr/bin/jadx")
    status = JadxAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0018"
    assert status.category == "static"


def test_jadx_decompile_command():
    cmd = JadxAdapter().decompile_command("/tmp/app.apk", "/tmp/out")
    assert cmd == ["jadx", "--output-dir", "/tmp/out", "/tmp/app.apk"]


def test_jadx_decompile_returns_artifact():
    runner = FakeRunner()
    runner.register("jadx --output-dir", stdout="INFO - done\n")
    artifact = JadxAdapter(runner).decompile("/tmp/app.apk", "/tmp/out")
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "decompiled"
    assert artifact.path == "/tmp/out"
    assert artifact.tool == "jadx"
    assert artifact.label == "app.apk"


def test_jadx_decompile_raises_on_failure():
    runner = FakeRunner()
    runner.register("jadx --output-dir", returncode=1, stderr="ERROR - bad apk\n")
    with pytest.raises(RuntimeError, match="bad apk"):
        JadxAdapter(runner).decompile("/tmp/app.apk", "/tmp/out")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_jadx.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.adapters.android.jadx'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/adapters/android/jadx.py`:

```python
"""Adapter for jadx (Dex/Java decompiler — static analysis)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class JadxAdapter(Adapter):
    name = "jadx"
    binary = "jadx"
    mastg_id = "MASTG-TOOL-0018"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install jadx: `brew install jadx` or download from github.com/skylot/jadx"

    def decompile_command(self, apk: str, out_dir: str) -> list[str]:
        return ["jadx", "--output-dir", out_dir, apk]

    def decompile(self, apk: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.decompile_command(apk, out_dir), timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"jadx failed: {result.stderr.strip()}")
        name = Path(apk).name
        return Artifact(
            id=f"jadx-{Path(apk).stem}",
            kind="decompiled",
            path=out_dir,
            tool="jadx",
            label=name,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_jadx.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/android/jadx.py tests/test_jadx.py
git commit -m "feat: add jadx adapter"
```

---

## Task 11: frida adapter (generic dynamic)

**Files:**
- Create: `src/centurion/adapters/generic/__init__.py`
- Create: `src/centurion/adapters/generic/frida.py`
- Test: `tests/test_frida.py`
- Verify: `default_registry` in `src/centurion/registry.py` now resolves all imports.

- [ ] **Step 1: Write the failing test**

`tests/test_frida.py`:

```python
from centurion.adapters.generic.frida import FridaAdapter, FridaProcess
from centurion.process import FakeRunner
from centurion.registry import default_registry


def test_frida_detect():
    runner = FakeRunner()
    runner.register("frida --version", stdout="16.2.1\n", path="/usr/bin/frida")
    status = FridaAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0001"
    assert status.category == "dynamic"
    assert status.platform == "generic"


def test_frida_ps_command_usb():
    assert FridaAdapter().ps_command(usb=True) == ["frida-ps", "-U"]
    assert FridaAdapter().ps_command(usb=False) == ["frida-ps"]


def test_frida_parse_ps_list():
    runner = FakeRunner()
    runner.register(
        "frida-ps -U",
        stdout=(
            "  PID  Name\n"
            "-----  ----------------\n"
            " 1234  com.acme.bank\n"
            " 5678  System UI\n"
        ),
    )
    procs = FridaAdapter(runner).list_processes(usb=True)
    assert procs == [
        FridaProcess(pid=1234, name="com.acme.bank"),
        FridaProcess(pid=5678, name="System UI"),
    ]


def test_default_registry_has_all_phase1_adapters():
    runner = FakeRunner()
    names = {a.name for a in default_registry(runner).all()}
    assert names == {"adb", "scrcpy", "jadx", "frida"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_frida.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.adapters.generic'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/adapters/generic/__init__.py`:

```python
"""Generic (cross-platform) tool adapters."""
```

`src/centurion/adapters/generic/frida.py`:

```python
"""Adapter for Frida (dynamic instrumentation — MASTG-TOOL-0001)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ...models import Category, Platform
from ..base import Adapter


@dataclass
class FridaProcess:
    pid: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FridaAdapter(Adapter):
    name = "frida"
    binary = "frida"
    mastg_id = "MASTG-TOOL-0001"
    platform = Platform.GENERIC
    category = Category.DYNAMIC

    def install_hint(self) -> str:
        return "Install Frida: `pip install frida-tools`"

    def ps_command(self, usb: bool = True) -> list[str]:
        return ["frida-ps", "-U"] if usb else ["frida-ps"]

    def parse_ps(self, stdout: str) -> list[FridaProcess]:
        procs: list[FridaProcess] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("PID") or set(line) <= set("- "):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                procs.append(FridaProcess(pid=int(parts[0]), name=parts[1].strip()))
        return procs

    def list_processes(self, usb: bool = True) -> list[FridaProcess]:
        result = self.runner.run(self.ps_command(usb), timeout=30)
        return self.parse_ps(result.stdout)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_frida.py -v`
Expected: 4 passed.

- [ ] **Step 5: Run the full suite to confirm `default_registry` resolves**

Run: `pytest -q`
Expected: all tests pass (Tasks 2–11).

- [ ] **Step 6: Commit**

```bash
git add src/centurion/adapters/generic/__init__.py src/centurion/adapters/generic/frida.py tests/test_frida.py
git commit -m "feat: add frida adapter and complete default registry"
```

---

## Task 12: Background process manager

**Files:**
- Modify: `src/centurion/process.py` (append `ManagedProcess` + `ProcessManager`)
- Test: `tests/test_process_manager.py`

- [ ] **Step 1: Write the failing test**

`tests/test_process_manager.py`:

```python
from centurion.process import ManagedProcess, ProcessManager


class FakeProc:
    def __init__(self, pid):
        self.pid = pid
        self.terminated = False

    def terminate(self):
        self.terminated = True


def test_start_registers_process():
    spawned = {}

    def fake_spawn(command):
        proc = FakeProc(pid=4242)
        spawned["proc"] = proc
        spawned["command"] = command
        return proc

    pm = ProcessManager(spawn=fake_spawn)
    managed = pm.start("scrcpy", ["scrcpy", "--serial", "x"])

    assert isinstance(managed, ManagedProcess)
    assert managed.handle == "scrcpy"
    assert managed.pid == 4242
    assert managed.command == ["scrcpy", "--serial", "x"]
    assert pm.list() == ["scrcpy"]


def test_stop_terminates_and_removes():
    proc = FakeProc(pid=1)
    pm = ProcessManager(spawn=lambda command: proc)
    pm.start("scrcpy", ["scrcpy"])

    assert pm.stop("scrcpy") is True
    assert proc.terminated is True
    assert pm.list() == []


def test_stop_unknown_handle_returns_false():
    pm = ProcessManager(spawn=lambda command: FakeProc(pid=1))
    assert pm.stop("ghost") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_process_manager.py -v`
Expected: FAIL — `ImportError: cannot import name 'ProcessManager'`.

- [ ] **Step 3: Append implementation to `src/centurion/process.py`**

Add at the end of `src/centurion/process.py`:

```python
from dataclasses import asdict
from typing import Any, Callable


@dataclass
class ManagedProcess:
    handle: str
    pid: int
    command: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _real_spawn(command: list[str]):
    return subprocess.Popen(command)


class ProcessManager:
    """Tracks long-running background tools (scrcpy, mitmproxy, frida-server)."""

    def __init__(self, spawn: Callable[[list[str]], Any] | None = None) -> None:
        self._spawn = spawn or _real_spawn
        self._procs: dict[str, Any] = {}

    def start(self, handle: str, command: list[str]) -> ManagedProcess:
        proc = self._spawn(command)
        self._procs[handle] = proc
        return ManagedProcess(handle=handle, pid=proc.pid, command=list(command))

    def stop(self, handle: str) -> bool:
        proc = self._procs.get(handle)
        if proc is None:
            return False
        proc.terminate()
        del self._procs[handle]
        return True

    def list(self) -> list[str]:
        return list(self._procs)
```

> `asdict` and `dataclass` are already imported at the top of the file from Task 3; the duplicate `from dataclasses import asdict` here is harmless but you may remove it and instead ensure the top import reads `from dataclasses import asdict, dataclass`. Pick one; do not leave `asdict` unimported.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_process_manager.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/process.py tests/test_process_manager.py
git commit -m "feat: add background process manager"
```

---

## Task 13: CLI skeleton

**Files:**
- Create: `src/centurion/cli/__init__.py`
- Create: `src/centurion/cli/app.py`
- Test: `tests/test_cli.py`

> The CLI calls `get_registry()` (a module-level factory) so tests can monkeypatch it with a `FakeRunner`-backed registry instead of touching real tools.

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py`:

```python
import centurion.cli.app as cli_app
from centurion.adapters.android.adb import AdbAdapter
from centurion.process import FakeRunner
from centurion.registry import Registry
from typer.testing import CliRunner

runner = CliRunner()


def _fake_registry():
    fake = FakeRunner()
    fake.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    fake.register("adb devices -l", stdout="List of devices attached\nemulator-5554\tdevice model:Pixel_6\n")
    return Registry([AdbAdapter(fake)])


def test_doctor_lists_tools(monkeypatch):
    monkeypatch.setattr(cli_app, "get_registry", _fake_registry)
    result = runner.invoke(cli_app.app, ["doctor"])
    assert result.exit_code == 0
    assert "adb" in result.stdout
    assert "MASTG-TOOL-0006" in result.stdout


def test_device_list(monkeypatch):
    monkeypatch.setattr(cli_app, "get_registry", _fake_registry)
    result = runner.invoke(cli_app.app, ["device", "list"])
    assert result.exit_code == 0
    assert "emulator-5554" in result.stdout


def test_version():
    result = runner.invoke(cli_app.app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.cli'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/cli/__init__.py`:

```python
"""Centurion command-line interface."""
```

`src/centurion/cli/app.py`:

```python
"""Typer CLI for daily-workflow use."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..registry import Registry, default_registry

app = typer.Typer(help="Centurion — mobile QA + pentest toolkit.")
device_app = typer.Typer(help="Device commands.")
app.add_typer(device_app, name="device")

console = Console()


def get_registry() -> Registry:
    """Factory so tests can monkeypatch with a FakeRunner-backed registry."""
    return default_registry()


@app.command()
def version() -> None:
    """Print the Centurion version."""
    console.print(f"centurion {__version__}")


@app.command()
def doctor() -> None:
    """Show every wrapped tool and whether it is installed."""
    table = Table("Tool", "MASTG", "Platform", "Category", "Installed", "Version")
    for status in get_registry().doctor():
        table.add_row(
            status.name,
            status.mastg_id or "-",
            status.platform or "-",
            status.category or "-",
            "yes" if status.installed else "no",
            status.version or "-",
        )
    console.print(table)


@device_app.command("list")
def device_list() -> None:
    """List connected Android devices."""
    adb = get_registry().get("adb")
    for dev in adb.devices():
        console.print(f"{dev.serial}\t{dev.state}\t{dev.model or '-'}")


if __name__ == "__main__":
    app()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/centurion/cli/__init__.py src/centurion/cli/app.py tests/test_cli.py
git commit -m "feat: add typer CLI with doctor and device list"
```

---

## Task 14: MCP server skeleton

**Files:**
- Create: `src/centurion/mcp/__init__.py`
- Create: `src/centurion/mcp/server.py`
- Test: `tests/test_mcp_server.py`

> FastMCP's `@mcp.tool()` registers the function and returns it unchanged, so the underlying functions remain directly callable in tests. The server also exposes `get_registry()` (monkeypatchable, same pattern as the CLI).

- [ ] **Step 1: Write the failing test**

`tests/test_mcp_server.py`:

```python
import centurion.mcp.server as server
from centurion.adapters.android.adb import AdbAdapter
from centurion.process import FakeRunner
from centurion.registry import Registry


def _fake_registry():
    fake = FakeRunner()
    fake.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    fake.register("adb devices -l", stdout="List of devices attached\nemulator-5554\tdevice model:Pixel_6\n")
    return Registry([AdbAdapter(fake)])


def test_server_name():
    assert server.mcp.name == "centurion"


def test_doctor_tool_returns_dicts(monkeypatch):
    monkeypatch.setattr(server, "get_registry", _fake_registry)
    result = server.doctor()
    assert isinstance(result, list)
    assert result[0]["name"] == "adb"
    assert result[0]["installed"] is True


def test_device_list_tool(monkeypatch):
    monkeypatch.setattr(server, "get_registry", _fake_registry)
    result = server.device_list()
    assert result == [{"serial": "emulator-5554", "state": "device", "model": "Pixel_6"}]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_mcp_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.mcp'`.

- [ ] **Step 3: Write minimal implementation**

`src/centurion/mcp/__init__.py`:

```python
"""Centurion MCP server package."""
```

`src/centurion/mcp/server.py`:

```python
"""FastMCP server exposing Centurion tools to Claude Code over stdio."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..registry import Registry, default_registry

mcp = FastMCP("centurion")


def get_registry() -> Registry:
    """Factory so tests can monkeypatch with a FakeRunner-backed registry."""
    return default_registry()


@mcp.tool()
def doctor() -> list[dict]:
    """List every wrapped tool with installation status (name, MASTG id, version)."""
    return [s.to_dict() for s in get_registry().doctor()]


@mcp.tool()
def device_list() -> list[dict]:
    """List connected Android devices (serial, state, model)."""
    adb = get_registry().get("adb")
    return [d.to_dict() for d in adb.devices()]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_mcp_server.py -v`
Expected: 3 passed.

- [ ] **Step 5: Run the full suite**

Run: `pytest -q`
Expected: every test passes.

- [ ] **Step 6: Commit**

```bash
git add src/centurion/mcp/__init__.py src/centurion/mcp/server.py tests/test_mcp_server.py
git commit -m "feat: add FastMCP server skeleton"
```

---

## Task 15: Claude skill + README

**Files:**
- Create: `.claude/skills/centurion-recon/SKILL.md`
- Create: `README.md`

> No automated test — this is documentation/config. Verification is reading it back and confirming the MCP tool names referenced exist (`doctor`, `device_list`).

- [ ] **Step 1: Create the recon skill**

`.claude/skills/centurion-recon/SKILL.md`:

```markdown
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
```

- [ ] **Step 2: Create the README**

`README.md`:

```markdown
# Centurion

A mobile QA + penetration-testing toolkit. Centurion wraps the OWASP MASTG tool set
(Android + iOS) and device/QA tooling like scrcpy behind one consistent layer: a CLI for
daily use and an MCP server so Claude Code can drive it, with shipped skills and subagents.

Centurion **wraps** existing tools — it does not reimplement them, and it deliberately
does not duplicate MobSF.

## Status

Phase 1 (vertical slice): core, Android device layer, `doctor`/`install`, CLI + MCP
skeletons, and four anchor adapters — adb, scrcpy, jadx, frida.

## Install

```bash
pip install -e ".[dev]"
centurion doctor
```

## MCP (Claude Code)

Register the stdio server:

```bash
claude mcp add centurion -- centurion-mcp
```

Then use the bundled skills (e.g. `centurion-recon`).

## Legal / ethical scope

Centurion is for **authorized** mobile security testing and QA only — pentest engagements,
security research, CTFs, and testing applications you own or are explicitly permitted to
test. You are responsible for staying within the scope of your authorization.

## License

Apache-2.0.
```

- [ ] **Step 3: Verify the skill frontmatter and MCP tool names**

Run: `head -5 .claude/skills/centurion-recon/SKILL.md`
Expected: shows the `---` frontmatter with `name: centurion-recon`.

Confirm by eye that the skill references only MCP tools that exist (`doctor`, `device_list`).

- [ ] **Step 4: Commit**

```bash
git add README.md .claude/skills/centurion-recon/SKILL.md
git commit -m "docs: add recon skill and README with legal scope"
```

---

## Task 16: Final verification

- [ ] **Step 1: Run the full test suite**

Run: `pytest -q`
Expected: all tests pass, no errors.

- [ ] **Step 2: Smoke-test the CLI**

Run: `centurion version` → prints `centurion 0.1.0`.
Run: `centurion doctor` → prints a table of the four tools with real install status on this machine.

- [ ] **Step 3: Smoke-test the MCP server entrypoint imports**

Run: `python -c "import centurion.mcp.server as s; print(s.mcp.name)"`
Expected: prints `centurion`.

- [ ] **Step 4: Final commit (if anything is uncommitted)**

```bash
git add -A
git commit -m "chore: phase 1 complete" || echo "nothing to commit"
```

---

## Self-Review Notes (author)

**Spec coverage:**
- Core (models, runner, adapter base, registry, session, process manager) → Tasks 2,3,4,6,7,12 ✓
- Android device layer (adb) → Task 5 ✓
- `doctor` / `install` → Tasks 8 (planner), 13 (doctor CLI), 14 (doctor MCP) ✓
- CLI skeleton → Task 13 ✓; MCP skeleton → Task 14 ✓
- 4 anchor adapters adb/scrcpy/jadx/frida → Tasks 5,9,10,11 ✓
- One skill → Task 15 ✓
- Tests throughout (TDD) ✓
- MobSF excluded; no report gen; no MASTG checklist ✓ (none added)
- Legal scope documented → README Task 15 ✓
- iOS adapters / remaining Android tools / additional skills+agents → **deferred to Phase 2/3** by design (out of scope for this plan).

**Type consistency:** `Runner`/`RunResult`/`FakeRunner` (Task 3) used consistently in Tasks 4–14. `ToolStatus`/`Artifact`/`Finding` (Task 2) used consistently. `Registry`/`default_registry` (Task 6) used in 8,13,14. `get_registry` factory pattern identical in CLI (13) and MCP (14). `AndroidDevice.to_dict()`, `FridaProcess.to_dict()`, `Artifact.to_dict()` all present and used.

**Ordering caveat called out:** `default_registry` (Task 6) imports adapters built in Tasks 9–11; flagged in Task 6 and exercised only from Task 11 onward.
```