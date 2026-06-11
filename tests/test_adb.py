from centurion.adapters.android.adb import AdbAdapter, AndroidDevice
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
