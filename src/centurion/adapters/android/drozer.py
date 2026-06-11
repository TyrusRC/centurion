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
