"""Adapter for the Android Debug Bridge (adb)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...models import Artifact, Category, Platform
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
