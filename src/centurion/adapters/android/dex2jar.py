"""Adapter for dex2jar (convert .dex/.apk to .jar — static analysis)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class Dex2jarAdapter(Adapter):
    name = "dex2jar"
    binary = "d2j-dex2jar"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install dex2jar: `brew install dex2jar` or `apt install dex2jar`"

    def convert_command(self, input_path: str, out_jar: str) -> list[str]:
        return ["d2j-dex2jar", "-f", "-o", out_jar, input_path]

    def convert(self, input_path: str, out_jar: str) -> Artifact:
        result = self.runner.run(self.convert_command(input_path, out_jar), timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"dex2jar failed: {result.stderr.strip()}")
        return Artifact(
            id=f"dex2jar-{Path(input_path).stem}",
            kind="jar",
            path=out_jar,
            tool="dex2jar",
            label=Path(input_path).name,
        )
