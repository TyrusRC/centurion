from centurion.adapters.android.adb import AdbAdapter, AndroidDevice
from centurion.models import Artifact
from centurion.process import FakeRunner


def test_adb_detect_parses_version():
    runner = FakeRunner()
    runner.register(
        "adb version",
        stdout="Android Debug Bridge version 1.0.41\nVersion 34.0.4\n",
        path="/usr/bin/adb",
    )
    status = AdbAdapter(runner).detect()
    assert status.installed is True
    assert status.version == "1.0.41"
    assert status.mastg_id == "MASTG-TOOL-0006"
    assert status.platform == "android"


def test_adb_devices_parses_list():
    runner = FakeRunner()
    runner.register(
        "adb devices -l",
        stdout=(
            "List of devices attached\n"
            "emulator-5554          device product:sdk_gphone model:Pixel_6 device:emu64\n"
            "RZ8N12345              device product:p3 model:Pixel_3 device:blueline\n"
            "\n"
        ),
    )
    devices = AdbAdapter(runner).devices()
    assert devices == [
        AndroidDevice(serial="emulator-5554", state="device", model="Pixel_6"),
        AndroidDevice(serial="RZ8N12345", state="device", model="Pixel_3"),
    ]


def test_adb_devices_empty():
    runner = FakeRunner()
    runner.register("adb devices -l", stdout="List of devices attached\n\n")
    assert AdbAdapter(runner).devices() == []


def test_adb_packages_parses_list():
    runner = FakeRunner()
    runner.register(
        "adb shell pm list packages",
        stdout="package:com.acme.bank\npackage:com.android.settings\n",
    )
    assert AdbAdapter(runner).packages() == ["com.acme.bank", "com.android.settings"]


def test_adb_pull_apk_returns_artifact(tmp_path):
    runner = FakeRunner()
    runner.register("adb shell pm path com.acme.bank", stdout="package:/data/app/com.acme.bank/base.apk\n")
    runner.register("adb pull", stdout="1 file pulled\n")
    artifact = AdbAdapter(runner).pull_apk("com.acme.bank", str(tmp_path))
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "binary"
    assert artifact.label == "com.acme.bank.apk"
    assert artifact.path.endswith("com.acme.bank.apk")
    # adb pull was called with the resolved remote path
    assert ["adb", "pull", "/data/app/com.acme.bank/base.apk", artifact.path] in runner.calls


def test_adb_pull_apk_missing_package_raises():
    runner = FakeRunner()
    runner.register("adb shell pm path com.ghost", stdout="\n")
    import pytest
    with pytest.raises(RuntimeError, match="package not found"):
        AdbAdapter(runner).pull_apk("com.ghost", "/tmp")
