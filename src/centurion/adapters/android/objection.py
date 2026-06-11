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
