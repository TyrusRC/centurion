"""Adapter for libimobiledevice device enumeration (idevice_id / ideviceinfo)."""

from __future__ import annotations

from ...models import AppleDevice, Category, Platform
from ..base import Adapter


class IdeviceAdapter(Adapter):
    name = "idevice"
    binary = "idevice_id"
    mastg_id = "MASTG-TOOL-0126"  # libimobiledevice suite
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
