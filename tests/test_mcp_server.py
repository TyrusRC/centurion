import centurion.mcp.server as server
from centurion.adapters.android.adb import AdbAdapter
from centurion.adapters.android.apktool import ApktoolAdapter
from centurion.adapters.generic.opengrep import OpengrepAdapter
from centurion.process import FakeRunner
from centurion.registry import Registry


def _fake_registry():
    fake = FakeRunner()
    fake.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    fake.register("adb devices -l", stdout="List of devices attached\nemulator-5554\tdevice model:Pixel_6\n")
    return Registry([AdbAdapter(fake)])


def test_server_name():
    assert server.mcp.name == "centurion"


def test_doctor_tool_returns_dicts(monkeypatch):
    monkeypatch.setattr(server, "get_registry", _fake_registry)
    result = server.doctor()
    assert isinstance(result, list)
    assert result[0]["name"] == "adb"
    assert result[0]["installed"] is True


def test_device_list_tool(monkeypatch):
    monkeypatch.setattr(server, "get_registry", _fake_registry)
    result = server.device_list()
    assert result == [{"serial": "emulator-5554", "state": "device", "model": "Pixel_6"}]


def test_get_workspace_creates_under_target(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ws = server.get_workspace("Acme Bank")
    assert ws.slug == "acme-bank"
    assert ws.session_file.exists()


def test_get_process_manager_is_workspace_backed(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    pm = server.get_process_manager("Acme Bank")
    assert pm.list() == []


def test_get_script_library_lists_scripts():
    assert len(server.get_script_library().list()) == 4


def _static_registry(fake):
    return Registry([AdbAdapter(fake), ApktoolAdapter(fake), OpengrepAdapter(fake)])


def test_app_list_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("adb shell pm list packages",
                  stdout="package:com.acme.app\npackage:com.other\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    assert server.app_list() == ["com.acme.app", "com.other"]


def test_app_pull_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("adb shell pm path com.acme.app", stdout="package:/data/app/base.apk\n")
    fake.register("adb pull", stdout="1 file pulled\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    result = server.app_pull("com.acme.app", "Acme")
    assert result["kind"] == "binary"
    assert result["path"].endswith("com.acme.app.apk")
    assert server.get_workspace("Acme").load().artifacts[0]["id"] == "apk-com.acme.app"


def test_static_decode_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("apktool d", stdout="I: Using Apktool\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    result = server.static_decode("/tmp/app.apk", "Acme")
    assert result["kind"] == "decoded"
    assert server.get_workspace("Acme").load().artifacts[0]["tool"] == "apktool"


def test_static_scan_records_findings(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    fake = FakeRunner()
    fake.register("opengrep scan", stdout=(
        '{"results":[{"check_id":"cleartext","path":"a/A.java",'
        '"start":{"line":12},"extra":{"severity":"ERROR","message":"cleartext HTTP"}}]}'
    ))
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    findings = server.static_scan("/tmp/decoded", "Acme", str(rules))
    assert findings[0]["severity"] == "high"
    assert server.get_workspace("Acme").load().findings[0]["title"] == "cleartext"
