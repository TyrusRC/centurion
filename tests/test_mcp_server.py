import centurion.mcp.server as server
from centurion.adapters.android.adb import AdbAdapter
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
