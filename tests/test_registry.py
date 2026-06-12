import pytest

from centurion.adapters.android.adb import AdbAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner
from centurion.registry import Registry, default_registry


def test_registry_register_and_get():
    reg = Registry([AdbAdapter()])
    assert reg.get("adb").name == "adb"
    assert [a.name for a in reg.all()] == ["adb"]


def test_registry_filter_by_platform_and_category():
    reg = Registry([AdbAdapter()])
    assert reg.by_platform(Platform.ANDROID)[0].name == "adb"
    assert reg.by_platform(Platform.IOS) == []
    assert reg.by_category(Category.DEVICE_QA)[0].name == "adb"


def test_registry_doctor_returns_statuses():
    runner = FakeRunner()
    runner.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    reg = Registry([AdbAdapter(runner)])
    statuses = reg.doctor()
    assert len(statuses) == 1
    assert statuses[0].name == "adb"
    assert statuses[0].installed is True


def test_registry_get_unknown_raises_clear_error():
    reg = Registry([])
    with pytest.raises(KeyError, match="No adapter registered for 'ghost'"):
        reg.get("ghost")


def test_default_registry_has_all_adapters():
    names = {a.name for a in default_registry(FakeRunner()).all()}
    assert names == {
        "adb", "scrcpy", "jadx", "frida",
        "apktool", "dex2jar", "apksigner", "opengrep",
        "radare2", "strings", "objection", "drozer",
        "mitmproxy", "tcpdump",
        "idevice", "ideviceinstaller", "frida-ios-dump", "class-dump",
    }


def test_registry_filters_ios_adapters():
    from centurion.models import Platform
    names = {a.name for a in default_registry(FakeRunner()).by_platform(Platform.IOS)}
    assert names == {"idevice", "ideviceinstaller", "frida-ios-dump", "class-dump"}
