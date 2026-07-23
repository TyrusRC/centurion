# src/centurion/report/markdown.py
"""Render a report model as Markdown."""

from __future__ import annotations


def render_markdown(model: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Centurion report — {model['target']}")
    lines.append("")
    lines.append(f"- Platform: {model['platform']}")
    lines.append(f"- Device: {model.get('device') or 'n/a'}")
    counts = model["severity_counts"]
    if counts:
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
        lines.append(f"- Findings: {summary}")
    lines.append("")

    lines.append("## MASVS coverage")
    lines.append("")
    if model["coverage"]:
        lines.append("| MASVS category | Findings |")
        lines.append("| --- | --- |")
        for row in model["coverage"]:
            lines.append(f"| {row['category']} | {row['count']} |")
    else:
        lines.append("_No findings recorded._")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for category, items in sorted(model["findings_by_category"].items()):
        lines.append(f"### {category}")
        lines.append("")
        for f in items:
            refs = ", ".join(f.get("masvs_refs") or []) or "—"
            lines.append(f"- **[{f.get('severity', 'info').upper()}] {f['title']}** "
                         f"({f['tool']}, {refs})")
            if f.get("location"):
                lines.append(f"  - Location: `{f['location']}`")
            if f.get("detail"):
                lines.append(f"  - {f['detail']}")
        lines.append("")

    if model["screenshots"]:
        lines.append("## Evidence — screenshots")
        lines.append("")
        for shot in model["screenshots"]:
            lines.append(f"- `{shot['path']}` — {shot.get('label') or shot['id']}")
        lines.append("")

    if model["runs"]:
        lines.append("## Run log")
        lines.append("")
        for run in model["runs"]:
            lines.append(f"- **{run['tool']}** ({run['status']}): "
                         f"`{' '.join(run['command'])}`")
            if run.get("preview"):
                body = "\n".join(f"  {ln}" for ln in run["preview"].strip().splitlines())
                lines.append(f"  ```\n{body}\n  ```")
        lines.append("")

    return "\n".join(lines)
