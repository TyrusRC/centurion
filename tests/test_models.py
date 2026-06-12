from centurion.models import (
    Platform, Category, Severity, ToolStatus, Artifact, Finding,
)


def test_toolstatus_to_dict_roundtrip():
    status = ToolStatus(
        name="adb",
        installed=True,
        mastg_id="MASTG-TOOL-0006",
        platform=Platform.ANDROID.value,
        category=Category.DEVICE_QA.value,
        version="1.0.41",
        path="/usr/bin/adb",
        install_hint="brew install android-platform-tools",
    )
    d = status.to_dict()
    assert d["name"] == "adb"
    assert d["installed"] is True
    assert d["mastg_id"] == "MASTG-TOOL-0006"
    assert d["platform"] == "android"


def test_finding_defaults():
    f = Finding(id="f1", title="Cleartext traffic", severity=Severity.HIGH.value, tool="opengrep")
    assert f.detail == ""
    assert f.location is None
    assert f.mastg_refs == []
    assert f.to_dict()["severity"] == "high"


def test_artifact_to_dict():
    a = Artifact(id="jadx-app", kind="decompiled", path="/tmp/out", tool="jadx", label="app.apk")
    assert a.to_dict() == {
        "id": "jadx-app",
        "kind": "decompiled",
        "path": "/tmp/out",
        "tool": "jadx",
        "label": "app.apk",
    }


def test_apple_device_to_dict():
    from centurion.models import AppleDevice
    dev = AppleDevice(udid="00008030-ABC", name="Test iPhone", ios_version="16.4")
    assert dev.to_dict() == {
        "udid": "00008030-ABC",
        "name": "Test iPhone",
        "ios_version": "16.4",
    }


def test_apple_device_defaults():
    from centurion.models import AppleDevice
    dev = AppleDevice(udid="00008030-ABC")
    assert dev.name is None
    assert dev.ios_version is None
