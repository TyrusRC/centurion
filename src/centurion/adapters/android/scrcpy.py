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
