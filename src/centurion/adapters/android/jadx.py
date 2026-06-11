"""Adapter for jadx (Dex/Java decompiler — static analysis)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class JadxAdapter(Adapter):
    name = "jadx"
    binary = "jadx"
    mastg_id = "MASTG-TOOL-0018"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install jadx: `brew install jadx` or download from github.com/skylot/jadx"

    def decompile_command(self, apk: str, out_dir: str) -> list[str]:
        return ["jadx", "--output-dir", out_dir, apk]

    def decompile(self, apk: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.decompile_command(apk, out_dir), timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"jadx failed: {result.stderr.strip()}")
        name = Path(apk).name
        return Artifact(
            id=f"jadx-{Path(apk).stem}",
            kind="decompiled",
            path=out_dir,
            tool="jadx",
            label=name,
        )
