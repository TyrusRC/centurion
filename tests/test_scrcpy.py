from centurion.adapters.android.scrcpy import ScrcpyAdapter
from centurion.process import FakeRunner


def test_scrcpy_detect():
    runner = FakeRunner()
    runner.register("scrcpy --version", stdout="scrcpy 2.4\n", path="/usr/bin/scrcpy")
    status = ScrcpyAdapter(runner).detect()
    assert status.installed is True
    assert status.version == "scrcpy 2.4"
    assert status.category == "device-qa"
    assert status.mastg_id == "MASTG-TOOL-0024"


def test_scrcpy_start_command_no_serial():
    assert ScrcpyAdapter().start_command() == ["scrcpy"]


def test_scrcpy_start_command_with_serial():
    assert ScrcpyAdapter().start_command(serial="emulator-5554") == [
        "scrcpy",
        "--serial",
        "emulator-5554",
    ]
