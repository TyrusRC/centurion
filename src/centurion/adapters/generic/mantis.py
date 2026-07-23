"""Adapter for mantis (mantis-sast): SAST + optional LLM-validated findings source.

Centurion ingests mantis's findings rather than scoring vulnerabilities itself.
`audit()` calls mantis's programmatic entry point (`from mantis import audit`)
and maps its native records into Centurion `Finding`s. mantis is an optional
dependency: if it is not installed, `audit()` raises a clear install hint.
"""

from __future__ import annotations

from ...models import Category, Finding, Platform
from ..base import Adapter

# mantis emits scanner-native severities (ERROR/WARNING/INFO); map to Centurion's.
_SEVERITY_MAP = {
    "ERROR": "high", "WARNING": "medium", "INFO": "low",
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low",
}


def _as_list(value) -> list[str]:
    if not value:
        return []
    return [value] if isinstance(value, str) else list(value)


class MantisAdapter(Adapter):
    name = "mantis"
    binary = "mantis"
    mastg_id = None
    platform = Platform.GENERIC
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install mantis: `pipx install mantis-sast` (see github.com/TyrusRC/mantis)"

    def _parse_mantis_json(self, results: list | dict) -> list[Finding]:
        """Map mantis native records into Centurion findings.

        Accepts mantis's `audit()` return (a list of records) or a raw scanner
        payload wrapped in `{"results": [...]}`.
        """
        if isinstance(results, dict):
            results = results.get("results", [])
        findings: list[Finding] = []
        for i, r in enumerate(results):
            rule = r.get("rule_id") or r.get("rule") or r.get("title") or "mantis-finding"
            severity = _SEVERITY_MAP.get(str(r.get("severity", "")).upper(), "info")
            path = r.get("path") or r.get("file") or ""
            line = r.get("start_line", r.get("line"))
            location = f"{path}:{line}" if path and line is not None else (path or None)
            meta = r.get("metadata") or {}
            masvs = _as_list(meta.get("masvs-v2") or meta.get("masvs") or r.get("masvs"))
            detail = (r.get("message") or r.get("detail") or "").strip()
            findings.append(Finding(
                id=f"mantis:{rule}:{path}:{line if line is not None else i}",
                title=rule,
                severity=severity,
                tool="mantis",
                detail=detail,
                location=location,
                mastg_refs=_as_list(r.get("mastg")),
                masvs_refs=masvs,
            ))
        return findings

    def audit(self, source_dir: str, *, llm: bool = False) -> list[Finding]:
        """Run mantis over a source tree and return mapped findings.

        SAST-only by default; pass ``llm=True`` to also run mantis's triage
        (requires a mantis provider config). Raises ``RuntimeError`` if the
        optional ``mantis-sast`` package is not installed.
        """
        try:
            from mantis import audit as _mantis_audit
        except ImportError as exc:
            raise RuntimeError(
                "mantis not installed: `pipx install mantis-sast` "
                "(or `pip install mantis-sast`) to enable mantis findings."
            ) from exc
        return self._parse_mantis_json(_mantis_audit(source_dir, llm=llm))
