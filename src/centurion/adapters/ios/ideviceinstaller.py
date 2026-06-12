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
