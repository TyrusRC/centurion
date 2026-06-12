"""Adapter for nm (list symbols from object files / shared libraries — recon).

nm is part of GNU binutils (and shipped by the Apple/LLVM toolchains). MASTG lists it as
0003 (Android) and 0041 (iOS); the underlying tool is the same, so this generic adapter
carries 0003.
"""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class NmAdapter(Adapter):
    name = "nm"
    binary = "nm"
    mastg_id = "MASTG-TOOL-0003"  # nm (0041 is the iOS listing of the same tool)
    platform = Platform.GENERIC
    category = Category.RECON

    def install_hint(self) -> str:
        return "Install nm (GNU binutils): `apt install binutils` or `brew install binutils`"

    def symbols_command(self, path: str, dynamic: bool = True) -> list[str]:
        return ["nm", "-D", path] if dynamic else ["nm", path]

    def parse_symbols(self, stdout: str) -> list[dict]:
        symbols: list[dict] = []
        for line in stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            if len(parts) >= 3:  # "<addr> <type> <name>"
                symbols.append({"address": parts[0], "type": parts[1], "name": parts[2]})
            elif len(parts) == 2:  # undefined: "<type> <name>" (no address)
                symbols.append({"address": None, "type": parts[0], "name": parts[1]})
        return symbols

    def symbols(self, path: str, dynamic: bool = True) -> list[dict]:
        result = self.runner.run(self.symbols_command(path, dynamic), timeout=120)
        return self.parse_symbols(result.stdout)
