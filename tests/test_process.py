import pytest

from centurion.process import FakeRunner, RunResult


def test_fakerunner_returns_registered_response():
    runner = FakeRunner()
    runner.register("adb version", stdout="Android Debug Bridge version 1.0.41", path="/usr/bin/adb")

    result = runner.run(["adb", "version"])

    assert isinstance(result, RunResult)
    assert result.returncode == 0
    assert "1.0.41" in result.stdout
    assert runner.calls == [["adb", "version"]]


def test_fakerunner_matches_by_prefix():
    runner = FakeRunner()
    runner.register("adb devices", stdout="List of devices attached\nemulator-5554\tdevice\n")

    result = runner.run(["adb", "devices", "-l"])

    assert "emulator-5554" in result.stdout


def test_fakerunner_unregistered_raises_filenotfound():
    runner = FakeRunner()
    with pytest.raises(FileNotFoundError):
        runner.run(["nope", "--version"])


def test_fakerunner_which():
    runner = FakeRunner()
    runner.register("adb version", path="/usr/bin/adb")
    assert runner.which("adb") == "/usr/bin/adb"
    assert runner.which("ghost") is None
