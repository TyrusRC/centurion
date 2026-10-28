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

    # OWASP Mobile Top 10 (2024) coverage: tally findings per category, list only
    # those actually hit, ordered M1..M10 (numeric, so M10 sorts after M9).
    top10_hits: dict[str, int] = {}
    for f in masvs.enrich_top10(findings):
        for ref in f.get("mobile_top10") or []:
            top10_hits[ref] = top10_hits.get(ref, 0) + 1
    top10_coverage = [
        {"ref": ref, "name": masvs.MOBILE_TOP10_2024.get(ref, ""), "count": count}
        for ref, count in sorted(top10_hits.items(), key=lambda kv: int(kv[0][1:]))
    ]

    screenshots = [a for a in session.artifacts if a.get("kind") == "screenshot"]

    return {
        "target": session.target,
        "platform": session.platform,
        "device": session.device,
        "severity_counts": severity_counts,
        "findings_by_category": by_category,
        "coverage": coverage,
        "top10_coverage": top10_coverage,
        "screenshots": screenshots,
        "runs": session.runs,
    }
