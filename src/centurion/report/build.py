# src/centurion/report/build.py
"""Aggregate a workspace session into a render-ready report model."""

from __future__ import annotations

from .. import masvs

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_report(workspace) -> dict:
    session = workspace.load()
    findings = masvs.enrich(session.findings)

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    by_category: dict[str, list[dict]] = {}
    for f in findings:
        controls = f.get("masvs_refs") or []
        category = masvs.category_of(controls[0]) if controls else "Unmapped"
        by_category.setdefault(category, []).append(f)
    for items in by_category.values():
        items.sort(key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "info"), 9))

    coverage = [{"category": c, "count": len(v)} for c, v in sorted(by_category.items())]
    screenshots = [a for a in session.artifacts if a.get("kind") == "screenshot"]

    return {
        "target": session.target,
        "platform": session.platform,
        "device": session.device,
        "severity_counts": severity_counts,
        "findings_by_category": by_category,
        "coverage": coverage,
        "screenshots": screenshots,
        "runs": session.runs,
    }
