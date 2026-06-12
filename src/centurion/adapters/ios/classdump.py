"""Adapter for class-dump (extract Objective-C headers from a Mach-O binary)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class ClassDumpAdapter(Adapter):
    name = "class-dump"
    binary = "class-dump"
    mastg_id = "MASTG-TOOL-0043"  # class-dump
    platform = Platform.IOS
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install class-dump: `brew install class-dump` or from github.com/nygard/class-dump"

    def headers_command(self, binary: str, out_dir: str) -> list[str]:
        return ["class-dump", "-H", "-o", out_dir, binary]

    def headers(self, binary: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.headers_command(binary, out_dir), timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"class-dump failed: {result.stderr.strip()}")
        return Artifact(
            id=f"classdump-{Path(binary).stem}",
            kind="decoded",
            path=out_dir,
            tool="class-dump",
            label=Path(binary).name,
        )
