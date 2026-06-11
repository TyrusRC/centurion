"""Adapter for tcpdump (packet capture — network analysis)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class TcpdumpAdapter(Adapter):
    name = "tcpdump"
    binary = "tcpdump"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.GENERIC
    category = Category.NETWORK

    def version_command(self) -> list[str]:
        return ["tcpdump", "--version"]

    def install_hint(self) -> str:
        return "Install tcpdump: `apt install tcpdump` or `brew install tcpdump`"

    def capture_command(self, out: str, iface: str = "any", count: int | None = None) -> list[str]:
        cmd = ["tcpdump", "-i", iface, "-w", out]
        if count:
            cmd += ["-c", str(count)]
        return cmd
