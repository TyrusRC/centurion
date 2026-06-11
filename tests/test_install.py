from centurion.adapters.android.adb import AdbAdapter
from centurion.install import plan_install
from centurion.process import FakeRunner
from centurion.registry import Registry


def _registry():
    runner = FakeRunner()
    # adb is installed; nothing else registered would be "missing" if present
    runner.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    return Registry([AdbAdapter(runner)])


def test_plan_install_all_returns_only_missing():
    reg = _registry()  # adb present -> nothing missing
    assert plan_install(reg, "all") == []


def test_plan_install_reports_missing_tool():
    reg = Registry([AdbAdapter(FakeRunner())])  # adb not registered -> missing
    missing = plan_install(reg, "android")
    assert [s.name for s in missing] == ["adb"]
    assert missing[0].install_hint is not None


def test_plan_install_unknown_group_is_empty():
    reg = Registry([AdbAdapter(FakeRunner())])
    assert plan_install(reg, "ios") == []  # no ios adapters in Phase 1 registry
