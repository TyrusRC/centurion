"""Adapter for Frida (dynamic instrumentation — MASTG-TOOL-0001)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ...models import Category, Platform
from ..base import Adapter


@dataclass
class FridaProcess:
    pid: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FridaAdapter(Adapter):
    name = "frida"
    binary = "frida"
    mastg_id = "MASTG-TOOL-0001"
    platform = Platform.GENERIC
    category = Category.DYNAMIC

    def install_hint(self) -> str:
        return "Install Frida: `pip install frida-tools`"

    def ps_command(self, usb: bool = True) -> list[str]:
        return ["frida-ps", "-U"] if usb else ["frida-ps"]

    def run_script_command(self, target_app: str, script: str, usb: bool = True) -> list[str]:
        cmd = ["frida"]
        if usb:
            cmd.append("-U")
        cmd += ["-f", target_app, "-l", script]
        return cmd

    def parse_ps(self, stdout: str) -> list[FridaProcess]:
        procs: list[FridaProcess] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("PID") or set(line) <= set("- "):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                procs.append(FridaProcess(pid=int(parts[0]), name=parts[1].strip()))
        return procs

    def list_processes(self, usb: bool = True) -> list[FridaProcess]:
        result = self.runner.run(self.ps_command(usb), timeout=30)
        return self.parse_ps(result.stdout)
