from centurion.adapters.ios.idevice import IdeviceAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = IdeviceAdapter()
    assert a.name == "idevice"
    assert a.binary == "idevice_id"
    assert a.platform == Platform.IOS
    assert a.category == Category.DEVICE_QA


def test_devices_parses_udids_with_info():
    fake = FakeRunner()
    fake.register("idevice_id -l", stdout="00008030-AAAA\n00008030-BBBB\n", path="/usr/bin/idevice_id")
    fake.register("ideviceinfo -u 00008030-AAAA -k DeviceName", stdout="Alice iPhone\n")
    fake.register("ideviceinfo -u 00008030-AAAA -k ProductVersion", stdout="16.4\n")
    fake.register("ideviceinfo -u 00008030-BBBB -k DeviceName", stdout="Bob iPad\n")
    fake.register("ideviceinfo -u 00008030-BBBB -k ProductVersion", stdout="17.1\n")
    devices = IdeviceAdapter(fake).devices()
    assert [d.udid for d in devices] == ["00008030-AAAA", "00008030-BBBB"]
    assert devices[0].name == "Alice iPhone"
    assert devices[0].ios_version == "16.4"


def test_devices_empty_when_none_attached():
    fake = FakeRunner()
    fake.register("idevice_id -l", stdout="\n", path="/usr/bin/idevice_id")
    assert IdeviceAdapter(fake).devices() == []


def test_info_returns_keyed_values():
    fake = FakeRunner()
    fake.register("ideviceinfo -u UDID -k DeviceName", stdout="Alice iPhone\n")
    fake.register("ideviceinfo -u UDID -k ProductVersion", stdout="16.4\n")
    info = IdeviceAdapter(fake).info("UDID")
    assert info == {"name": "Alice iPhone", "ios_version": "16.4"}
