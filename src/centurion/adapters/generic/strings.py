"""Adapter for strings (extract printable strings from binaries — recon)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class StringsAdapter(Adapter):
    name = "strings"
    binary = "strings"
    mastg_id = None  # GNU binutils strings; not a distinct MASTG tool entry
    platform = Platform.GENERIC
    category = Category.RECON

    def install_hint(self) -> str:
        return "Install binutils (provides `strings`): `apt install binutils` or `brew install binutils`"

    def run_command(self, path: str, min_len: int = 8) -> list[str]:
        return ["strings", "-n", str(min_len), path]

    def extract(self, path: str, min_len: int = 8) -> list[str]:
        result = self.runner.run(self.run_command(path, min_len), timeout=120)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
