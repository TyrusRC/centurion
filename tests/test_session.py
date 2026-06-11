from pathlib import Path

from centurion.models import Artifact, Finding
from centurion.session import Session, Workspace


def test_create_workspace_writes_session_json(tmp_path: Path):
    ws = Workspace(tmp_path, target="Acme Banking", platform="android")
    session = ws.create()

    assert ws.slug == "acme-banking"
    assert ws.dir == tmp_path / "acme-banking"
    assert ws.artifacts_dir.is_dir()
    assert ws.session_file.exists()
    assert session.target == "Acme Banking"
    assert session.platform == "android"
    assert session.runs == []


def test_create_is_idempotent(tmp_path: Path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.record_run("adb", ["adb", "devices"], "ok")
    reopened = ws.create()  # must not clobber
    assert len(reopened.runs) == 1


def test_record_run_appends(tmp_path: Path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.record_run("jadx", ["jadx", "app.apk"], "ok")
    loaded = ws.load()
    assert loaded.runs == [{"tool": "jadx", "command": ["jadx", "app.apk"], "status": "ok"}]


def test_add_artifact(tmp_path: Path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.add_artifact(Artifact(id="a1", kind="decompiled", path="/tmp/out", tool="jadx"))
    loaded = ws.load()
    assert loaded.artifacts[0]["id"] == "a1"
    assert isinstance(loaded, Session)


def test_load_ignores_unknown_fields(tmp_path):
    import json
    ws = Workspace(tmp_path, target="app")
    ws.create()
    data = json.loads(ws.session_file.read_text())
    data["future_field"] = "ignore me"
    ws.session_file.write_text(json.dumps(data))
    loaded = ws.load()  # must not raise
    assert loaded.target == "app"


def test_add_finding(tmp_path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    ws.add_finding(Finding(id="f1", title="Cleartext", severity="high", tool="opengrep"))
    loaded = ws.load()
    assert loaded.findings[0]["id"] == "f1"
    assert loaded.findings[0]["severity"] == "high"


def test_findings_defaults_empty_for_old_sessions(tmp_path):
    import json
    ws = Workspace(tmp_path, target="app")
    ws.create()
    # Simulate an older session.json written before `findings` existed.
    data = json.loads(ws.session_file.read_text())
    data.pop("findings", None)
    ws.session_file.write_text(json.dumps(data))
    loaded = ws.load()
    assert loaded.findings == []
