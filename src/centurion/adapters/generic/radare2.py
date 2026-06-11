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
