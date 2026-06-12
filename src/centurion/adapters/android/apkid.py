"""Adapter for APKiD (Android packer / obfuscator / compiler detection — static).

APKiD identifies the compiler, packer, obfuscator and anti-analysis tricks used to build
an APK/DEX. It emits JSON with ``apkid -j``.
"""

from __future__ import annotations

import json

from ...models import Category, Finding, Platform
from ..base import Adapter


class ApkidAdapter(Adapter):
    name = "apkid"
    binary = "apkid"
    mastg_id = "MASTG-TOOL-0009"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install APKiD: `pip install apkid`"

    def scan_command(self, apk: str) -> list[str]:
        return ["apkid", "-j", apk]

    def parse_scan(self, stdout: str) -> list[Finding]:
        data = json.loads(stdout)
        findings: list[Finding] = []
        for entry in data.get("files", []):
            filename = entry.get("filename", "")
            for category, names in (entry.get("matches") or {}).items():
                for name in names:
                    findings.append(
                        Finding(
                            id=f"apkid:{category}:{name}:{filename}",
                            title=f"{category}: {name}",
                            severity="info",
                            tool="apkid",
                            detail=f"APKiD detected {category} '{name}'",
                            location=filename,
                        )
                    )
        return findings

    def scan(self, apk: str) -> list[Finding]:
        result = self.runner.run(self.scan_command(apk), timeout=300)
        return self.parse_scan(result.stdout)
