import centurion.cli.app as cli_app
from centurion.adapters.android.adb import AdbAdapter
from centurion.process import FakeRunner
from centurion.registry import Registry
from typer.testing import CliRunner

runner = CliRunner()


def _fake_registry():
    fake = FakeRunner()
    fake.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    fake.register("adb devices -l", stdout="List of devices attached\nemulator-5554\tdevice model:Pixel_6\n")
    return Registry([AdbAdapter(fake)])


def test_doctor_lists_tools(monkeypatch):
    monkeypatch.setattr(cli_app, "get_registry", _fake_registry)
    result = runner.invoke(cli_app.app, ["doctor"])
    assert result.exit_code == 0
    assert "adb" in result.stdout
    assert "MASTG-TOOL-0006" in result.stdout


def test_device_list(monkeypatch):
    monkeypatch.setattr(cli_app, "get_registry", _fake_registry)
    result = runner.invoke(cli_app.app, ["device", "list"])
    assert result.exit_code == 0
    assert "emulator-5554" in result.stdout


def test_version():
    result = runner.invoke(cli_app.app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout
