# src/centurion/report/__init__.py
"""Report generation: aggregate a workspace into Markdown + self-contained HTML."""

from __future__ import annotations

from .build import build_report
from .html import render_html
from .markdown import render_markdown

__all__ = ["build_report", "render_html", "render_markdown", "generate"]


def generate(workspace, fmt: str = "both") -> dict[str, str]:
    model = build_report(workspace)
    out: dict[str, str] = {}
    if fmt in ("md", "markdown", "both"):
        path = workspace.dir / "report.md"
        path.write_text(render_markdown(model))
        out["markdown"] = str(path)
    if fmt in ("html", "both"):
        path = workspace.dir / "report.html"
        path.write_text(render_html(model))
        out["html"] = str(path)
    return out
