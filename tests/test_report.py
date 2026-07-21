# tests/test_report.py
from pathlib import Path

from centurion import report
from centurion.session import Workspace


def _seed(tmp_path):
    ws = Workspace(tmp_path, "com.example.app")
    ws.create()
    from centurion.models import Finding, Artifact
    ws.add_finding(Finding(id="otool:no-pie:/a", title="No PIE", severity="medium",
                           tool="otool", detail="no aslr", location="/a"))
    ws.add_finding(Finding(id="gitleaks:key:1", title="AWS key", severity="high",
                           tool="gitleaks", detail="leaked", location="src/x"))
    png = ws.artifacts_dir / "shot.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\nDATA")
    ws.add_artifact(Artifact(id="s1", kind="screenshot", path=str(png),
                             tool="adb", label="home screen"))
    ws.record_run("gitleaks", ["gitleaks", "detect"], "ok", output="found 1 secret")
    return ws


def test_build_report_groups_by_masvs_and_counts_severity(tmp_path):
    model = report.build_report(_seed(tmp_path))
    assert model["target"] == "com.example.app"
    assert model["severity_counts"]["high"] == 1
    assert model["severity_counts"]["medium"] == 1
    assert "MASVS-STORAGE" in model["findings_by_category"]
    assert "MASVS-RESILIENCE" in model["findings_by_category"]


def test_render_markdown_contains_findings_and_coverage(tmp_path):
    md = report.render_markdown(report.build_report(_seed(tmp_path)))
    assert "com.example.app" in md
    assert "AWS key" in md
    assert "MASVS-STORAGE" in md
    assert "found 1 secret" in md  # run evidence preview


def test_render_html_embeds_screenshot_as_base64(tmp_path):
    html = report.render_html(report.build_report(_seed(tmp_path)))
    assert "data:image/png;base64," in html
    assert "home screen" in html
    assert "<html" in html.lower()


def test_render_html_skips_missing_screenshot_file(tmp_path):
    ws = _seed(tmp_path)
    from centurion.models import Artifact
    ws.add_artifact(Artifact(id="s2", kind="screenshot",
                             path=str(tmp_path / "nope.png"), tool="adb"))
    html = report.render_html(report.build_report(ws))  # must not raise
    assert "data:image/png;base64," in html  # the valid one still embedded


def test_generate_writes_both_files(tmp_path):
    ws = _seed(tmp_path)
    out = report.generate(ws, fmt="both")
    assert Path(out["markdown"]).exists()
    assert Path(out["html"]).exists()


def test_build_report_handles_empty_session(tmp_path):
    ws = Workspace(tmp_path, "empty.app")
    ws.create()
    model = report.build_report(ws)
    assert model["findings_by_category"] == {}
    md = report.render_markdown(model)   # must not raise
    assert "empty.app" in md
