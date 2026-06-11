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
