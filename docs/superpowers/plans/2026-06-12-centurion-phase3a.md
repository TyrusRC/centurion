# Centurion Phase 3a — iOS Adapters + State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the iOS device/app/static adapter layer (libimobiledevice + frida-ios-dump + class-dump), stdlib plist/IPA helpers, the `AppleDevice` model, and two iOS Frida scripts — all unit-tested and registered — with no new MCP tools yet.

**Architecture:** Four new `Adapter` subclasses under `src/centurion/adapters/ios/`, each wrapping one iOS binary and shelling out through the injected `Runner` (identical pattern to the Android adapters). Plist/IPA parsing lives in a stdlib-only helper module `src/centurion/ios/ipa.py` (no external tool). The two iOS Frida scripts are added to the existing bundled `ScriptLibrary` catalog. All four adapters are registered in `default_registry`.

**Tech Stack:** Python 3.11+, stdlib `plistlib`/`zipfile`, pytest with `FakeRunner`. All commands run via `.venv/bin/python -m pytest` (system Python is externally-managed; never bare `pytest`/`python`).

**Builds on:** `docs/superpowers/specs/2026-06-12-centurion-phase3-ios-design.md` §1–§4, Phases 1–2b (merged to `main`).

---

## Reference: the Adapter base class (already implemented, do NOT change)

`src/centurion/adapters/base.py` provides `Adapter(ABC)`:
- Class attrs to set: `name`, `binary`, `mastg_id` (default None), `platform`, `category`.
- `__init__(self, runner=None)` → `self.runner` (a `Runner`; default `RealRunner`).
- Override `install_hint()` (abstract). Optionally override `version_command()` (default
  `[binary, "--version"]`) and `parse_version(result)` (default: first non-empty line).
- `detect()` is inherited and works off `version_command()` + `which(binary)`.
- Operations call `self.runner.run([...], timeout=...) -> RunResult(args, returncode, stdout, stderr)`.

`Platform` enum has `IOS = "ios"`. `Category` enum has `DEVICE_QA`, `STATIC`, `DYNAMIC`,
`RECON`, `NETWORK`. `Artifact(id, kind, path, tool, label=None)` and its `.to_dict()` exist
in `models.py`.

The `FakeRunner` (in `process.py`) matches canned responses by command-line **prefix**:
`fake.register("idevice_id -l", stdout="...", path="/usr/bin/idevice_id")` and
`fake.run(args)` returns the canned `RunResult` for the first registered prefix that
`" ".join(args)` starts with, else raises `FileNotFoundError(args[0])`.

---

## File Structure

**Create:**
- `src/centurion/adapters/ios/__init__.py` (empty package marker)
- `src/centurion/adapters/ios/idevice.py` — `IdeviceAdapter` + `AppleDevice` import.
- `src/centurion/adapters/ios/ideviceinstaller.py` — `IdeviceinstallerAdapter`.
- `src/centurion/adapters/ios/frida_ios_dump.py` — `FridaIosDumpAdapter`.
- `src/centurion/adapters/ios/classdump.py` — `ClassDumpAdapter`.
- `src/centurion/ios/__init__.py` (empty package marker)
- `src/centurion/ios/ipa.py` — `read_plist`, `ipa_info` stdlib helpers.
- `src/centurion/scripts/frida/ios_ssl_unpin.js`
- `src/centurion/scripts/frida/ios_jailbreak_bypass.js`
- `tests/test_idevice.py`, `tests/test_ideviceinstaller.py`, `tests/test_frida_ios_dump.py`,
  `tests/test_classdump.py`, `tests/test_ios_ipa.py`

**Modify:**
- `src/centurion/models.py` — add `AppleDevice` dataclass.
- `src/centurion/scripts/__init__.py` — add the two iOS scripts to `_CATALOG`.
- `src/centurion/registry.py` — register the four iOS adapters.
- `tests/test_registry.py` — extend the registry-contents assertion.
- `tests/test_script_library.py` — assert the iOS scripts list with `platform="ios"`.

---

## Task 1: `AppleDevice` model

**Files:**
- Modify: `src/centurion/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_models.py`:
```python
def test_apple_device_to_dict():
    from centurion.models import AppleDevice
    dev = AppleDevice(udid="00008030-ABC", name="Test iPhone", ios_version="16.4")
    assert dev.to_dict() == {
        "udid": "00008030-ABC",
        "name": "Test iPhone",
        "ios_version": "16.4",
    }


def test_apple_device_defaults():
    from centurion.models import AppleDevice
    dev = AppleDevice(udid="00008030-ABC")
    assert dev.name is None
    assert dev.ios_version is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_models.py -k apple_device -v`
Expected: FAIL — `ImportError: cannot import name 'AppleDevice'`

- [ ] **Step 3: Add the dataclass**

In `src/centurion/models.py`, after the `Artifact` dataclass (before `Finding`), add:
```python
@dataclass
class AppleDevice:
    udid: str
    name: str | None = None
    ios_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_models.py -k apple_device -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/centurion/models.py tests/test_models.py
git commit -m "feat: add AppleDevice model"
```

---

## Task 2: `IdeviceAdapter` (device layer)

**Files:**
- Create: `src/centurion/adapters/ios/__init__.py`, `src/centurion/adapters/ios/idevice.py`
- Test: `tests/test_idevice.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_idevice.py`:
```python
from centurion.adapters.ios.idevice import IdeviceAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = IdeviceAdapter()
    assert a.name == "idevice"
    assert a.binary == "idevice_id"
    assert a.platform == Platform.IOS
    assert a.category == Category.DEVICE_QA


def test_devices_parses_udids_with_info():
    fake = FakeRunner()
    fake.register("idevice_id -l", stdout="00008030-AAAA\n00008030-BBBB\n", path="/usr/bin/idevice_id")
    fake.register("ideviceinfo -u 00008030-AAAA -k DeviceName", stdout="Alice iPhone\n")
    fake.register("ideviceinfo -u 00008030-AAAA -k ProductVersion", stdout="16.4\n")
    fake.register("ideviceinfo -u 00008030-BBBB -k DeviceName", stdout="Bob iPad\n")
    fake.register("ideviceinfo -u 00008030-BBBB -k ProductVersion", stdout="17.1\n")
    devices = IdeviceAdapter(fake).devices()
    assert [d.udid for d in devices] == ["00008030-AAAA", "00008030-BBBB"]
    assert devices[0].name == "Alice iPhone"
    assert devices[0].ios_version == "16.4"


def test_devices_empty_when_none_attached():
    fake = FakeRunner()
    fake.register("idevice_id -l", stdout="\n", path="/usr/bin/idevice_id")
    assert IdeviceAdapter(fake).devices() == []


def test_info_returns_keyed_values():
    fake = FakeRunner()
    fake.register("ideviceinfo -u UDID -k DeviceName", stdout="Alice iPhone\n")
    fake.register("ideviceinfo -u UDID -k ProductVersion", stdout="16.4\n")
    info = IdeviceAdapter(fake).info("UDID")
    assert info == {"name": "Alice iPhone", "ios_version": "16.4"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_idevice.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.adapters.ios'`

- [ ] **Step 3: Implement**

Create `src/centurion/adapters/ios/__init__.py` (empty file).

Create `src/centurion/adapters/ios/idevice.py`:
```python
"""Adapter for libimobiledevice device enumeration (idevice_id / ideviceinfo)."""

from __future__ import annotations

from ...models import AppleDevice, Category, Platform
from ..base import Adapter


class IdeviceAdapter(Adapter):
    name = "idevice"
    binary = "idevice_id"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.IOS
    category = Category.DEVICE_QA

    def version_command(self) -> list[str]:
        return ["idevice_id", "-v"]

    def install_hint(self) -> str:
        return (
            "Install libimobiledevice: `brew install libimobiledevice` or "
            "`apt install libimobiledevice-utils`"
        )

    def _field(self, udid: str, key: str) -> str | None:
        result = self.runner.run(["ideviceinfo", "-u", udid, "-k", key], timeout=10)
        value = result.stdout.strip()
        return value or None

    def info(self, udid: str) -> dict:
        return {
            "name": self._field(udid, "DeviceName"),
            "ios_version": self._field(udid, "ProductVersion"),
        }

    def devices(self) -> list[AppleDevice]:
        result = self.runner.run(["idevice_id", "-l"], timeout=10)
        devices: list[AppleDevice] = []
        for line in result.stdout.splitlines():
            udid = line.strip()
            if not udid:
                continue
            meta = self.info(udid)
            devices.append(
                AppleDevice(udid=udid, name=meta["name"], ios_version=meta["ios_version"])
            )
        return devices
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_idevice.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/ios/__init__.py src/centurion/adapters/ios/idevice.py tests/test_idevice.py
git commit -m "feat: add IdeviceAdapter (iOS device layer)"
```

---

## Task 3: `IdeviceinstallerAdapter` (app listing)

**Files:**
- Create: `src/centurion/adapters/ios/ideviceinstaller.py`
- Test: `tests/test_ideviceinstaller.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ideviceinstaller.py`:
```python
from centurion.adapters.ios.ideviceinstaller import IdeviceinstallerAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = IdeviceinstallerAdapter()
    assert a.name == "ideviceinstaller"
    assert a.binary == "ideviceinstaller"
    assert a.platform == Platform.IOS
    assert a.category == Category.DEVICE_QA


def test_apps_parses_bundle_ids():
    # `ideviceinstaller -l` prints a CSV-ish header then "BundleID, Version, Name" rows.
    out = (
        "CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName\n"
        "com.acme.bank, 1.2.0, Acme Bank\n"
        "com.example.notes, 3.0, Notes\n"
    )
    fake = FakeRunner()
    fake.register("ideviceinstaller -l", stdout=out, path="/usr/bin/ideviceinstaller")
    assert IdeviceinstallerAdapter(fake).apps() == ["com.acme.bank", "com.example.notes"]


def test_apps_empty():
    fake = FakeRunner()
    fake.register("ideviceinstaller -l", stdout="CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName\n")
    assert IdeviceinstallerAdapter(fake).apps() == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ideviceinstaller.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement**

Create `src/centurion/adapters/ios/ideviceinstaller.py`:
```python
"""Adapter for ideviceinstaller (list installed iOS apps)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class IdeviceinstallerAdapter(Adapter):
    name = "ideviceinstaller"
    binary = "ideviceinstaller"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.IOS
    category = Category.DEVICE_QA

    def install_hint(self) -> str:
        return "Install ideviceinstaller: `brew install ideviceinstaller` or `apt install ideviceinstaller`"

    def apps(self) -> list[str]:
        result = self.runner.run(["ideviceinstaller", "-l"], timeout=60)
        bundles: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("CFBundleIdentifier"):
                continue
            bundle_id = line.split(",", 1)[0].strip()
            if bundle_id:
                bundles.append(bundle_id)
        return bundles
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ideviceinstaller.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/ios/ideviceinstaller.py tests/test_ideviceinstaller.py
git commit -m "feat: add IdeviceinstallerAdapter (iOS app listing)"
```

---

## Task 4: `FridaIosDumpAdapter` (decrypted-IPA pull)

**Files:**
- Create: `src/centurion/adapters/ios/frida_ios_dump.py`
- Test: `tests/test_frida_ios_dump.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_frida_ios_dump.py`:
```python
from centurion.adapters.ios.frida_ios_dump import FridaIosDumpAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = FridaIosDumpAdapter()
    assert a.name == "frida-ios-dump"
    assert a.binary == "frida-ios-dump"
    assert a.platform == Platform.IOS
    assert a.category == Category.DYNAMIC


def test_dump_command():
    a = FridaIosDumpAdapter()
    cmd = a.dump_command("com.acme.bank", "/tmp/out")
    assert cmd == ["frida-ios-dump", "-o", "/tmp/out/com.acme.bank.ipa", "com.acme.bank"]


def test_dump_returns_artifact():
    fake = FakeRunner()
    fake.register("frida-ios-dump", stdout="Generating dump... Done\n")
    artifact = FridaIosDumpAdapter(fake).dump("com.acme.bank", "/tmp/out")
    assert artifact.kind == "binary"
    assert artifact.tool == "frida-ios-dump"
    assert artifact.path == "/tmp/out/com.acme.bank.ipa"
    assert artifact.id == "ipa-com.acme.bank"


def test_dump_raises_on_failure():
    fake = FakeRunner()
    fake.register("frida-ios-dump", returncode=1, stderr="Failed to connect to frida-server\n")
    try:
        FridaIosDumpAdapter(fake).dump("com.acme.bank", "/tmp/out")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "frida-server" in str(e)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_frida_ios_dump.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement**

Create `src/centurion/adapters/ios/frida_ios_dump.py`:
```python
"""Adapter for frida-ios-dump (pull a decrypted IPA off a jailbroken device)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class FridaIosDumpAdapter(Adapter):
    name = "frida-ios-dump"
    binary = "frida-ios-dump"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.IOS
    category = Category.DYNAMIC

    def install_hint(self) -> str:
        return (
            "Install frida-ios-dump: see github.com/AloneMonkey/frida-ios-dump. "
            "Requires a jailbroken device running frida-server."
        )

    def dump_command(self, bundle_id: str, out_dir: str) -> list[str]:
        dest = str(Path(out_dir) / f"{bundle_id}.ipa")
        return ["frida-ios-dump", "-o", dest, bundle_id]

    def dump(self, bundle_id: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.dump_command(bundle_id, out_dir), timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"frida-ios-dump failed: {result.stderr.strip()}")
        dest = str(Path(out_dir) / f"{bundle_id}.ipa")
        return Artifact(
            id=f"ipa-{bundle_id}",
            kind="binary",
            path=dest,
            tool="frida-ios-dump",
            label=f"{bundle_id}.ipa",
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_frida_ios_dump.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/ios/frida_ios_dump.py tests/test_frida_ios_dump.py
git commit -m "feat: add FridaIosDumpAdapter (decrypted IPA pull)"
```

---

## Task 5: `ClassDumpAdapter` (Obj-C header dump)

**Files:**
- Create: `src/centurion/adapters/ios/classdump.py`
- Test: `tests/test_classdump.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_classdump.py`:
```python
from centurion.adapters.ios.classdump import ClassDumpAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = ClassDumpAdapter()
    assert a.name == "class-dump"
    assert a.binary == "class-dump"
    assert a.platform == Platform.IOS
    assert a.category == Category.STATIC


def test_headers_command():
    a = ClassDumpAdapter()
    assert a.headers_command("/tmp/App", "/tmp/hdr") == ["class-dump", "-H", "-o", "/tmp/hdr", "/tmp/App"]


def test_headers_returns_artifact():
    fake = FakeRunner()
    fake.register("class-dump -H -o /tmp/hdr /tmp/App", stdout="")
    artifact = ClassDumpAdapter(fake).headers("/tmp/App", "/tmp/hdr")
    assert artifact.kind == "decoded"
    assert artifact.tool == "class-dump"
    assert artifact.path == "/tmp/hdr"
    assert artifact.id == "classdump-App"


def test_headers_raises_on_failure():
    fake = FakeRunner()
    fake.register("class-dump", returncode=1, stderr="not an Objective-C binary\n")
    try:
        ClassDumpAdapter(fake).headers("/tmp/App", "/tmp/hdr")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "Objective-C" in str(e)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_classdump.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement**

Create `src/centurion/adapters/ios/classdump.py`:
```python
"""Adapter for class-dump (extract Objective-C headers from a Mach-O binary)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class ClassDumpAdapter(Adapter):
    name = "class-dump"
    binary = "class-dump"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.IOS
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install class-dump: `brew install class-dump` or from github.com/nygard/class-dump"

    def headers_command(self, binary: str, out_dir: str) -> list[str]:
        return ["class-dump", "-H", "-o", out_dir, binary]

    def headers(self, binary: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.headers_command(binary, out_dir), timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"class-dump failed: {result.stderr.strip()}")
        return Artifact(
            id=f"classdump-{Path(binary).stem}",
            kind="decoded",
            path=out_dir,
            tool="class-dump",
            label=Path(binary).name,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_classdump.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/centurion/adapters/ios/classdump.py tests/test_classdump.py
git commit -m "feat: add ClassDumpAdapter (Obj-C header dump)"
```

---

## Task 6: Plist + IPA stdlib helpers

**Files:**
- Create: `src/centurion/ios/__init__.py`, `src/centurion/ios/ipa.py`
- Test: `tests/test_ios_ipa.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ios_ipa.py`:
```python
import plistlib
import zipfile
from pathlib import Path

from centurion.ios.ipa import read_plist, ipa_info


def test_read_plist_binary(tmp_path: Path):
    p = tmp_path / "Info.plist"
    p.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.acme.bank"}, fmt=plistlib.FMT_BINARY))
    assert read_plist(str(p))["CFBundleIdentifier"] == "com.acme.bank"


def test_read_plist_xml(tmp_path: Path):
    p = tmp_path / "Info.plist"
    p.write_bytes(plistlib.dumps({"MinimumOSVersion": "15.0"}, fmt=plistlib.FMT_XML))
    assert read_plist(str(p))["MinimumOSVersion"] == "15.0"


def test_ipa_info_extracts_app_plist(tmp_path: Path):
    ipa = tmp_path / "app.ipa"
    info = {"CFBundleIdentifier": "com.acme.bank", "MinimumOSVersion": "15.0"}
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/Acme.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_XML))
        zf.writestr("Payload/Acme.app/Acme", b"\xca\xfe\xba\xbe")  # fake Mach-O
    result = ipa_info(str(ipa))
    assert result["bundle_id"] == "com.acme.bank"
    assert result["minimum_os"] == "15.0"
    assert result["app_path"] == "Payload/Acme.app"


def test_ipa_info_raises_without_payload(tmp_path: Path):
    ipa = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("not_payload/x.txt", "nope")
    try:
        ipa_info(str(ipa))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "Info.plist" in str(e)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ios_ipa.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'centurion.ios'`

- [ ] **Step 3: Implement**

Create `src/centurion/ios/__init__.py` (empty file).

Create `src/centurion/ios/ipa.py`:
```python
"""Stdlib-only iOS helpers: plist parsing and IPA introspection.

Neither wraps an external tool — `plistlib` reads binary and XML plists, and `zipfile`
unpacks the IPA archive (an IPA is a zip). Kept out of the adapter layer for that reason.
"""

from __future__ import annotations

import plistlib
import zipfile


def read_plist(path: str) -> dict:
    """Parse a binary or XML plist file into a dict."""
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def ipa_info(ipa_path: str) -> dict:
    """Extract the app's Info.plist from an .ipa and summarize key fields."""
    with zipfile.ZipFile(ipa_path) as zf:
        plist_name = next(
            (
                n
                for n in zf.namelist()
                if n.startswith("Payload/")
                and n.endswith(".app/Info.plist")
                and n.count("/") == 2
            ),
            None,
        )
        if plist_name is None:
            raise ValueError(f"no Payload/*.app/Info.plist found in {ipa_path}")
        info = plistlib.loads(zf.read(plist_name))
    app_path = plist_name.rsplit("/", 1)[0]
    return {
        "bundle_id": info.get("CFBundleIdentifier"),
        "minimum_os": info.get("MinimumOSVersion"),
        "url_schemes": _url_schemes(info),
        "ats_allows_arbitrary_loads": (
            info.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoads", False)
        ),
        "app_path": app_path,
        "info_plist": plist_name,
    }


def _url_schemes(info: dict) -> list[str]:
    schemes: list[str] = []
    for entry in info.get("CFBundleURLTypes", []) or []:
        schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    return schemes
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ios_ipa.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/centurion/ios/__init__.py src/centurion/ios/ipa.py tests/test_ios_ipa.py
git commit -m "feat: add stdlib plist + IPA helpers"
```

---

## Task 7: iOS Frida scripts

**Files:**
- Create: `src/centurion/scripts/frida/ios_ssl_unpin.js`, `src/centurion/scripts/frida/ios_jailbreak_bypass.js`
- Modify: `src/centurion/scripts/__init__.py`
- Test: `tests/test_script_library.py`

- [ ] **Step 1: Write the two scripts**

`src/centurion/scripts/frida/ios_ssl_unpin.js`:
```javascript
// Centurion — iOS TLS pinning bypass. AUTHORIZED TESTING ONLY.
// Neutralises SecTrustEvaluate-based pinning by forcing the trust result to proceed.
if (ObjC.available) {
  try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
        if (!result.isNull()) { result.writeU32(1); }  // kSecTrustResultProceed
        return 0;  // errSecSuccess
      }, 'int', ['pointer', 'pointer']));
      console.log('[centurion] SecTrustEvaluate forced to proceed');
    }
  } catch (e) { console.log('[centurion] ios_ssl_unpin skipped: ' + e); }
} else {
  console.log('[centurion] Objective-C runtime unavailable');
}
```

`src/centurion/scripts/frida/ios_jailbreak_bypass.js`:
```javascript
// Centurion — iOS jailbreak-detection bypass. AUTHORIZED TESTING ONLY.
// Hides common JB artifacts from fileExistsAtPath: checks.
if (ObjC.available) {
  try {
    var NSFileManager = ObjC.classes.NSFileManager;
    var blocked = ['/Applications/Cydia.app', '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/private/var/lib/apt/'];
    var orig = NSFileManager['- fileExistsAtPath:'];
    Interceptor.attach(orig.implementation, {
      onEnter: function (args) { this.path = new ObjC.Object(args[2]).toString(); },
      onLeave: function (retval) {
        if (blocked.indexOf(this.path) !== -1) {
          console.log('[centurion] hiding JB path: ' + this.path);
          retval.replace(0x0);
        }
      }
    });
    console.log('[centurion] fileExistsAtPath: JB checks hooked');
  } catch (e) { console.log('[centurion] ios_jailbreak_bypass skipped: ' + e); }
} else {
  console.log('[centurion] Objective-C runtime unavailable');
}
```

- [ ] **Step 2: Write the failing test**

Append to `tests/test_script_library.py`:
```python
def test_ios_scripts_listed_with_ios_platform():
    lib = ScriptLibrary()
    info = {s.name: s for s in lib.list()}
    assert info["ios_ssl_unpin"].platform == "ios"
    assert info["ios_jailbreak_bypass"].platform == "ios"


def test_ios_ssl_unpin_resolves_to_real_file():
    info = ScriptLibrary().get("ios_ssl_unpin")
    assert Path(info.path).is_file()
    assert "AUTHORIZED TESTING ONLY" in Path(info.path).read_text()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_script_library.py -k ios -v`
Expected: FAIL — `KeyError: 'ios_ssl_unpin'` (not yet in catalog)

- [ ] **Step 4: Add the iOS scripts to the catalog**

In `src/centurion/scripts/__init__.py`, extend `_CATALOG` with two entries (keep the existing four):
```python
    "ios_ssl_unpin": ("Bypass common iOS TLS pinning (SecTrustEvaluate)", "ios"),
    "ios_jailbreak_bypass": ("Hide common iOS jailbreak indicators", "ios"),
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_script_library.py -v`
Expected: PASS (existing + 2 new)

- [ ] **Step 6: Commit**

```bash
git add src/centurion/scripts/frida/ios_ssl_unpin.js src/centurion/scripts/frida/ios_jailbreak_bypass.js src/centurion/scripts/__init__.py tests/test_script_library.py
git commit -m "feat: add iOS Frida scripts (ssl unpin, jailbreak bypass)"
```

---

## Task 8: Register iOS adapters

**Files:**
- Modify: `src/centurion/registry.py`
- Test: `tests/test_registry.py`

- [ ] **Step 1: Update the failing test**

In `tests/test_registry.py`, replace the body of `test_default_registry_has_all_phase2_adapters` so the expected set includes the iOS adapters (rename it too):
```python
def test_default_registry_has_all_adapters():
    names = {a.name for a in default_registry(FakeRunner()).all()}
    assert names == {
        "adb", "scrcpy", "jadx", "frida",
        "apktool", "dex2jar", "apksigner", "opengrep",
        "radare2", "strings", "objection", "drozer",
        "mitmproxy", "tcpdump",
        "idevice", "ideviceinstaller", "frida-ios-dump", "class-dump",
    }
```
Add a focused test for the iOS platform filter:
```python
def test_registry_filters_ios_adapters():
    from centurion.models import Platform
    names = {a.name for a in default_registry(FakeRunner()).by_platform(Platform.IOS)}
    assert names == {"idevice", "ideviceinstaller", "frida-ios-dump", "class-dump"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_registry.py -k "all_adapters or ios" -v`
Expected: FAIL — the iOS names are missing from the registry.

- [ ] **Step 3: Register the adapters**

In `src/centurion/registry.py`, inside `default_registry`, add the imports alongside the existing ones:
```python
    from .adapters.ios.classdump import ClassDumpAdapter
    from .adapters.ios.frida_ios_dump import FridaIosDumpAdapter
    from .adapters.ios.idevice import IdeviceAdapter
    from .adapters.ios.ideviceinstaller import IdeviceinstallerAdapter
```
and append four entries to the `Registry([...])` list (after `TcpdumpAdapter(runner)`):
```python
            IdeviceAdapter(runner),
            IdeviceinstallerAdapter(runner),
            FridaIosDumpAdapter(runner),
            ClassDumpAdapter(runner),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_registry.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/centurion/registry.py tests/test_registry.py
git commit -m "feat: register iOS adapters in default registry"
```

---

## Task 9: Full-suite verification

**Files:**
- Test: (no new file)

- [ ] **Step 1: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS (all prior tests + the new iOS tests; ~21 new tests).

- [ ] **Step 2: Verify the package imports and doctor lists the iOS tools**

Run:
```bash
.venv/bin/python -c "from centurion.registry import default_registry; from centurion.process import FakeRunner; names=[s.name for s in default_registry(FakeRunner()).doctor()]; assert {'idevice','ideviceinstaller','frida-ios-dump','class-dump'} <= set(names), names; print('iOS adapters present:', sorted(n for n in names if n in {'idevice','ideviceinstaller','frida-ios-dump','class-dump'}))"
```
Expected: prints `iOS adapters present: ['class-dump', 'frida-ios-dump', 'idevice', 'ideviceinstaller']`

- [ ] **Step 3: Verify the iOS Frida scripts ship in the wheel**

Run:
```bash
.venv/bin/python -m build --wheel 2>&1 | tail -3 && unzip -l dist/*.whl | grep -E 'ios_(ssl_unpin|jailbreak_bypass)\.js'
```
Expected: both `centurion/scripts/frida/ios_ssl_unpin.js` and `ios_jailbreak_bypass.js` listed. Then clean up: `rm -rf dist build`.

- [ ] **Step 4: Commit (if any cleanup/no-op changes)**

No code change expected here; if `dist/`/`build/` were created, confirm they are gitignored (they are) and not staged. Nothing to commit if the tree is clean.

---

## Done-When

- `AppleDevice` model exists with `to_dict()`.
- Four iOS adapters (`idevice`, `ideviceinstaller`, `frida-ios-dump`, `class-dump`) exist,
  each unit-tested with `FakeRunner`, and are registered in `default_registry`.
- `read_plist` / `ipa_info` stdlib helpers exist and are unit-tested.
- The two iOS Frida scripts are in the `ScriptLibrary` catalog (`platform="ios"`) and ship
  in the wheel.
- `.venv/bin/python -m pytest -q` is fully green. No new MCP tools or skills (those are 3b).

## Notes

- All `mastg_id` are `None` for now (same convention as dex2jar/strings/mitmproxy); they can
  be filled in later without interface change.
- `frida-ios-dump`'s exact CLI varies by fork; the `dump_command` here uses the common
  `-o <out.ipa> <bundle>` form. If a target environment's fork differs, only `dump_command`
  changes — the Artifact contract stays the same. This is a detect-only wrapper; we never
  auto-install it.
