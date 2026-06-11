"""Adapter for apktool (decode APK resources/manifest — static analysis)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class ApktoolAdapter(Adapter):
    name = "apktool"
    binary = "apktool"
    mastg_id = "MASTG-TOOL-0011"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install apktool: `brew install apktool` or `apt install apktool`"

    def decode_command(self, apk: str, out_dir: str) -> list[str]:
        return ["apktool", "d", "-f", "-o", out_dir, apk]

    def decode(self, apk: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.decode_command(apk, out_dir), timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"apktool failed: {result.stderr.strip()}")
        return Artifact(
            id=f"apktool-{Path(apk).stem}",
            kind="decoded",
            path=out_dir,
            tool="apktool",
            label=Path(apk).name,
        )
