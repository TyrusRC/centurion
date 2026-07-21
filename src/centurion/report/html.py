# src/centurion/report/html.py
"""Render a report model as a single self-contained HTML file."""

from __future__ import annotations

import base64
import html
from pathlib import Path


def _img_data_uri(path: str) -> str | None:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii")


def render_html(model: dict) -> str:
    e = html.escape
    parts: list[str] = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append(f"<title>Centurion report — {e(model['target'])}</title>")
    parts.append("<style>body{font-family:system-ui,sans-serif;margin:2rem;}"
                 "table{border-collapse:collapse;}td,th{border:1px solid #ccc;"
                 "padding:4px 8px;}img{max-width:360px;border:1px solid #ccc;}"
                 "pre{background:#f5f5f5;padding:8px;overflow-x:auto;}</style></head><body>")
    parts.append(f"<h1>Centurion report — {e(model['target'])}</h1>")
    parts.append(f"<p>Platform: {e(model['platform'])} · "
                 f"Device: {e(str(model.get('device') or 'n/a'))}</p>")

    parts.append("<h2>MASVS coverage</h2>")
    if model["coverage"]:
        parts.append("<table><tr><th>MASVS category</th><th>Findings</th></tr>")
        for row in model["coverage"]:
            parts.append(f"<tr><td>{e(row['category'])}</td><td>{row['count']}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p><em>No findings recorded.</em></p>")

    parts.append("<h2>Findings</h2>")
    for category, items in sorted(model["findings_by_category"].items()):
        parts.append(f"<h3>{e(category)}</h3><ul>")
        for f in items:
            refs = e(", ".join(f.get("masvs_refs") or []) or "—")
            parts.append(f"<li><strong>[{e(f.get('severity','info').upper())}] "
                         f"{e(f['title'])}</strong> ({e(f['tool'])}, {refs})")
            if f.get("location"):
                parts.append(f"<br><code>{e(f['location'])}</code>")
            if f.get("detail"):
                parts.append(f"<br>{e(f['detail'])}")
            parts.append("</li>")
        parts.append("</ul>")

    shots = model["screenshots"]
    if shots:
        parts.append("<h2>Evidence — screenshots</h2>")
        for shot in shots:
            uri = _img_data_uri(shot["path"])
            if uri is None:
                continue
            caption = e(shot.get("label") or shot["id"])
            parts.append(f"<figure><img src='{uri}'><figcaption>{caption}"
                         f"</figcaption></figure>")

    if model["runs"]:
        parts.append("<h2>Run log</h2>")
        for run in model["runs"]:
            parts.append(f"<p><strong>{e(run['tool'])}</strong> "
                         f"({e(run['status'])}): <code>{e(' '.join(run['command']))}</code></p>")
            if run.get("preview"):
                parts.append(f"<pre>{e(run['preview'].strip())}</pre>")

    parts.append("</body></html>")
    return "".join(parts)
