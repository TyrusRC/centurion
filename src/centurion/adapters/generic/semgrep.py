"""Adapter for semgrep (static analysis with MASTG-derived rules)."""

from __future__ import annotations

import json
from pathlib import Path

from ...models import Category, Finding, Platform
from ..base import Adapter

_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}


def default_rules_path() -> Path:
    return Path.home() / ".centurion" / "rules"


class SemgrepAdapter(Adapter):
    name = "semgrep"
    binary = "semgrep"
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.GENERIC
    category = Category.STATIC

    def install_hint(self) -> str:
        return (
            "Install semgrep: `pip install semgrep`. Then install a ruleset into "
            "~/.centurion/rules (e.g. the OWASP-derived semgrep-rules-android-security)."
        )

    def scan_command(self, target: str, rules: str) -> list[str]:
        return ["semgrep", "--config", rules, "--json", target]

    def parse_scan(self, stdout: str) -> list[Finding]:
        data = json.loads(stdout)
        findings: list[Finding] = []
        for result in data.get("results", []):
            check = result.get("check_id", "semgrep")
            path = result.get("path", "")
            line = result.get("start", {}).get("line")
            extra = result.get("extra", {})
            severity = _SEVERITY.get(str(extra.get("severity", "INFO")).upper(), "info")
            metadata = extra.get("metadata", {}) or {}
            refs = metadata.get("mastg") or metadata.get("owasp-mastg") or []
            findings.append(
                Finding(
                    id=f"{check}:{path}:{line}",
                    title=check,
                    severity=severity,
                    tool="semgrep",
                    detail=extra.get("message", ""),
                    location=f"{path}:{line}" if line else path,
                    mastg_refs=list(refs),
                )
            )
        return findings

    def scan(self, target: str, rules: str | None = None) -> list[Finding]:
        rules_path = rules or str(default_rules_path())
        if not Path(rules_path).exists():
            raise RuntimeError(
                f"semgrep rules not found at '{rules_path}'. Install a ruleset there "
                "or pass an explicit rules path. See `centurion doctor`."
            )
        result = self.runner.run(self.scan_command(target, rules_path), timeout=900)
        return self.parse_scan(result.stdout)
