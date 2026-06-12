"""Adapter for gitleaks (secret scanning over a source/decoded tree — static).

gitleaks v8 scans a directory with ``gitleaks dir <path>`` and writes a JSON report (a list
of finding objects) to ``--report-path``. It exits non-zero when leaks are found, so the
return code is intentionally not treated as an error.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...models import Category, Finding, Platform
from ..base import Adapter


class GitleaksAdapter(Adapter):
    name = "gitleaks"
    binary = "gitleaks"
    mastg_id = "MASTG-TOOL-0144"
    platform = Platform.GENERIC
    category = Category.STATIC

    def version_command(self) -> list[str]:
        return ["gitleaks", "version"]

    def install_hint(self) -> str:
        return "Install gitleaks: `brew install gitleaks` or see github.com/gitleaks/gitleaks/releases"

    def scan_command(self, path: str, report: str) -> list[str]:
        return [
            "gitleaks", "dir", path,
            "--report-format", "json", "--report-path", report, "--no-banner",
        ]

    def parse_report(self, json_text: str) -> list[Finding]:
        data = json.loads(json_text) if json_text.strip() else []
        findings: list[Finding] = []
        for leak in data:
            rule = leak.get("RuleID", "secret")
            file = leak.get("File", "")
            line = leak.get("StartLine")
            findings.append(
                Finding(
                    id=f"gitleaks:{rule}:{file}:{line}",
                    title=leak.get("Description") or rule,
                    severity="high",
                    tool="gitleaks",
                    detail=leak.get("Match", ""),
                    location=f"{file}:{line}" if line else file,
                )
            )
        return findings

    def scan(self, path: str, report: str) -> list[Finding]:
        self.runner.run(self.scan_command(path, report), timeout=600)
        return self.parse_report(Path(report).read_text())
