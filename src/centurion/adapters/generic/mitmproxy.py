"""Adapter for mitmproxy/mitmdump (HTTP(S) interception — network analysis)."""

from __future__ import annotations

from ...models import Category, Platform
from ..base import Adapter


class MitmproxyAdapter(Adapter):
    name = "mitmproxy"
    binary = "mitmdump"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.GENERIC
    category = Category.NETWORK

    def version_command(self) -> list[str]:
        return ["mitmdump", "--version"]

    def install_hint(self) -> str:
        return "Install mitmproxy: `pip install mitmproxy` or `brew install mitmproxy`"

    def start_command(self, port: int = 8080, flow_out: str | None = None) -> list[str]:
        cmd = ["mitmdump", "-p", str(port)]
        if flow_out:
            cmd += ["-w", flow_out]
        return cmd

    def read_command(self, flow_file: str) -> list[str]:
        return ["mitmdump", "-nr", flow_file, "--flow-detail", "1"]
