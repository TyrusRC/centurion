from centurion.adapters.android.aapt2 import Aapt2Adapter
from centurion.process import FakeRunner

SAMPLE = """\
package: name='com.acme.bank' versionCode='42' versionName='3.1.0' compileSdkVersion='34'
sdkVersion:'24'
targetSdkVersion:'34'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.CAMERA'
application-label:'Acme Bank'
"""


def test_aapt2_metadata():
    a = Aapt2Adapter()
    assert a.name == "aapt2"
    assert a.mastg_id == "MASTG-TOOL-0124"
    assert a.platform.value == "android"
    assert a.category.value == "static"


def test_aapt2_badging_command():
    assert Aapt2Adapter().badging_command("/tmp/app.apk") == [
        "aapt2", "dump", "badging", "/tmp/app.apk",
    ]


def test_aapt2_parse_badging():
    info = Aapt2Adapter().parse_badging(SAMPLE)
    assert info["package"] == "com.acme.bank"
    assert info["version_code"] == "42"
    assert info["version_name"] == "3.1.0"
    assert info["min_sdk"] == "24"
    assert info["target_sdk"] == "34"
    assert info["permissions"] == [
        "android.permission.INTERNET", "android.permission.CAMERA",
    ]


def test_aapt2_badging_runs():
    fake = FakeRunner()
    fake.register("aapt2 dump badging", stdout=SAMPLE)
    assert Aapt2Adapter(fake).badging("/tmp/app.apk")["package"] == "com.acme.bank"
