from centurion.adapters.ios.ideviceinstaller import IdeviceinstallerAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = IdeviceinstallerAdapter()
    assert a.name == "ideviceinstaller"
    assert a.binary == "ideviceinstaller"
    assert a.platform == Platform.IOS
    assert a.category == Category.DEVICE_QA


def test_apps_parses_bundle_ids():
    # `ideviceinstaller -l` prints a CSV-ish header then "BundleID, Version, Name" rows.
    out = (
        "CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName\n"
        "com.acme.bank, 1.2.0, Acme Bank\n"
        "com.example.notes, 3.0, Notes\n"
    )
    fake = FakeRunner()
    fake.register("ideviceinstaller -l", stdout=out, path="/usr/bin/ideviceinstaller")
    assert IdeviceinstallerAdapter(fake).apps() == ["com.acme.bank", "com.example.notes"]


def test_apps_empty():
    fake = FakeRunner()
    fake.register("ideviceinstaller -l", stdout="CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName\n")
    assert IdeviceinstallerAdapter(fake).apps() == []
