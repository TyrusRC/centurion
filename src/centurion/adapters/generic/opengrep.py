"""Adapter for Opengrep (open-source Semgrep fork — static analysis with MASTG rules).

Opengrep is CLI- and rule-compatible with Semgrep; it uses a `scan` subcommand and
emits the same JSON result schema.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...models import Category, Finding, Platform
from ..base import Adapter

_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}


def default_rules_path() -> Path:
    return Path.home() / ".centurion" / "rules"


class OpengrepAdapter(Adapter):
    name = "opengrep"
    binary = "opengrep"
    mastg_id = "MASTG-TOOL-0110"  # semgrep (Opengrep is its open-source fork)
    platform = Platform.GENERIC
    category = Category.STATIC

    def install_hint(self) -> str:
        return (
            "Install Opengrep: see github.com/opengrep/opengrep (release binary or install "
            "script). Then install a ruleset into ~/.centurion/rules (the OWASP-derived "
            "semgrep-rules-android-security set is Opengrep-compatible)."
        )

    def scan_command(self, target: str, rules: str) -> list[str]:
        return ["opengrep", "scan", "--config", rules, "--json", target]

    def parse_scan(self, stdout: str) -> list[Finding]:
        data = json.loads(stdout)
        findings: list[Finding] = []
        for result in data.get("results", []):
            check = result.get("check_id", "opengrep")
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
                    tool="opengrep",
                    detail=extra.get("message", ""),
                    location=f"{path}:{line}" if line else path,
                    mastg_refs=list(refs),
                )
            )
        return findings

    def scan(self, target: str, rules: str | None = None) -> list[Finding]:
        if rules:
            # An explicit path the caller named is a real error if it's
            # wrong — surface it, don't silently fall back to something else.
            if not Path(rules).exists():
                raise RuntimeError(
                    f"opengrep rules not found at '{rules}'. Install a ruleset there "
                    "or pass an existing rules path. See `centurion doctor`."
                )
            rules_path = rules
        else:
            rules_path = self._default_rules_path_or_auto()
        result = self.runner.run(self.scan_command(target, rules_path), timeout=900)
        return self.parse_scan(result.stdout)

    def _default_rules_path_or_auto(self) -> str:
        """No explicit rules path given. Prefer the locally installed
        MASTG-curated ruleset; fall back to opengrep's own registry
        auto-config ("auto", the same default plain `opengrep scan` uses)
        when none is installed, instead of refusing to scan at all — a scan
        with the community ruleset is strictly better than no scan."""
        local = default_rules_path()
        if local.exists():
            return str(local)
        return "auto"
