from centurion.adapters.android.adb import AdbAdapter
from centurion.adapters.generic.frida import FridaAdapter
from centurion.install import _selects, plan_install
from centurion.models import ToolStatus
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


def test_selects_network_group_matches_category_not_platform():
    # A network tool: platform generic, category network.
    net = ToolStatus(name="mitmproxy", installed=False, platform="generic", category="network")
    assert _selects(net, "network") is True
    # A generic-platform non-network tool must NOT match the network group.
    other = ToolStatus(name="frida", installed=False, platform="generic", category="dynamic")
    assert _selects(other, "network") is False
