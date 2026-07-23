"""Adapter for mantis (mantis-sast): SAST + LLM-validated findings source.

Centurion ingests mantis's validated findings (its LLM assigns severity) rather
than scoring vulnerabilities itself. The JSON parser is implemented and tested
now; the live invocation is guarded until mantis-sast exposes a stable contract
(recommended: `from mantis_sast import audit; audit(path) -> list[dict]`).
"""

from __future__ import annotations

from ...models import Category, Finding, Platform
from ..base import Adapter

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class MantisAdapter(Adapter):
    name = "mantis"
    binary = "mantis"
    mastg_id = None
    platform = Platform.GENERIC
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install mantis: `pipx install mantis-sast` (see github.com/TyrusRC/mantis)"

    def _parse_mantis_json(self, payload: dict | list) -> list[Finding]:
        results = payload.get("results", []) if isinstance(payload, dict) else payload
        findings: list[Finding] = []
        for i, r in enumerate(results):
            title = r.get("rule") or r.get("title") or "mantis-finding"
            severity = str(r.get("severity", "info")).lower()
            if severity not in _SEVERITIES:
                severity = "info"
            file = r.get("file", "")
            line = r.get("line")
            location = f"{file}:{line}" if file and line is not None else (file or None)
            findings.append(Finding(
                id=f"mantis:{title}:{file}:{line if line is not None else i}",
                title=title,
                severity=severity,
                tool="mantis",
                detail=r.get("detail", ""),
                location=location,
                mastg_refs=list(r.get("mastg", []) or []),
            ))
        return findings

    def audit(self, source_dir: str) -> list[Finding]:
        raise NotImplementedError(
            "mantis lib pending: expose `from mantis_sast import audit` "
            "(or `mantis audit --json`) and wire it here."
        )
