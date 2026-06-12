"""Adapter for frida-ios-dump (pull a decrypted IPA off a jailbroken device)."""

from __future__ import annotations

from pathlib import Path

from ...models import Artifact, Category, Platform
from ..base import Adapter


class FridaIosDumpAdapter(Adapter):
    name = "frida-ios-dump"
    binary = "frida-ios-dump"
    mastg_id = "MASTG-TOOL-0050"  # Frida-ios-dump
    platform = Platform.IOS
    category = Category.DYNAMIC

    def install_hint(self) -> str:
        return (
            "Install frida-ios-dump: see github.com/AloneMonkey/frida-ios-dump. "
            "Requires a jailbroken device running frida-server."
        )

    def dump_command(self, bundle_id: str, out_dir: str) -> list[str]:
        dest = str(Path(out_dir) / f"{bundle_id}.ipa")
        return ["frida-ios-dump", "-o", dest, bundle_id]

    def dump(self, bundle_id: str, out_dir: str) -> Artifact:
        result = self.runner.run(self.dump_command(bundle_id, out_dir), timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"frida-ios-dump failed: {result.stderr.strip()}")
        dest = str(Path(out_dir) / f"{bundle_id}.ipa")
        return Artifact(
            id=f"ipa-{bundle_id}",
            kind="binary",
            path=dest,
            tool="frida-ios-dump",
            label=f"{bundle_id}.ipa",
        )
