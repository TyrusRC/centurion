"""Adapter for apkleaks (scan an APK for URIs, endpoints and secrets — static).

apkleaks writes its results to an output file; with ``--json`` that file is JSON shaped as
``{"package": "...", "results": [{"name": <pattern>, "matches": [<hit>, ...]}, ...]}``.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...models import Category, Finding, Platform
from ..base import Adapter

# Pattern names that denote credential material rather than mere endpoints.
_SECRET_HINTS = ("key", "secret", "token", "password", "credential", "aws", "private")


def _severity_for(name: str) -> str:
    return "medium" if any(h in name.lower() for h in _SECRET_HINTS) else "low"


class ApkleaksAdapter(Adapter):
    name = "apkleaks"
    binary = "apkleaks"
    mastg_id = "MASTG-TOOL-0125"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install apkleaks: `pip install apkleaks`"

    def scan_command(self, apk: str, out_json: str) -> list[str]:
        return ["apkleaks", "-f", apk, "-o", out_json, "--json"]

    def parse_results(self, json_text: str) -> list[Finding]:
        data = json.loads(json_text)
        findings: list[Finding] = []
        for result in data.get("results", []):
            name = result.get("name", "match")
            for hit in result.get("matches", []):
                findings.append(
                    Finding(
                        id=f"apkleaks:{name}:{hit}",
                        title=name,
                        severity=_severity_for(name),
                        tool="apkleaks",
                        detail=hit,
                    )
                )
        return findings

    def scan(self, apk: str, out_json: str) -> list[Finding]:
        self.runner.run(self.scan_command(apk, out_json), timeout=600)
        return self.parse_results(Path(out_json).read_text())
