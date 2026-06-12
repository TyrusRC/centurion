from centurion.adapters.android.apkid import ApkidAdapter
from centurion.models import Finding
from centurion.process import FakeRunner

SAMPLE_JSON = """\
{"apkid_version": "2.1.5", "files": [
  {"filename": "classes.dex",
   "matches": {"compiler": ["dexlib 2.x"], "anti_vm": ["Build.FINGERPRINT check"]}},
  {"filename": "lib/arm64-v8a/libfoo.so",
   "matches": {"packer": ["Jiagu"]}}
]}
"""


def test_apkid_metadata():
    a = ApkidAdapter()
    assert a.name == "apkid"
    assert a.binary == "apkid"
    assert a.mastg_id == "MASTG-TOOL-0009"
    assert a.platform.value == "android"
    assert a.category.value == "static"


def test_apkid_scan_command():
    assert ApkidAdapter().scan_command("/tmp/app.apk") == ["apkid", "-j", "/tmp/app.apk"]


def test_apkid_parse_scan_flattens_matches():
    findings = ApkidAdapter().parse_scan(SAMPLE_JSON)
    assert len(findings) == 3
    assert all(isinstance(f, Finding) for f in findings)
    assert all(f.tool == "apkid" and f.severity == "info" for f in findings)
    titles = {f.title for f in findings}
    assert "packer: Jiagu" in titles
    assert "compiler: dexlib 2.x" in titles
    packer = next(f for f in findings if f.title == "packer: Jiagu")
    assert packer.location == "lib/arm64-v8a/libfoo.so"


def test_apkid_scan_runs_and_parses():
    fake = FakeRunner()
    fake.register("apkid -j", stdout=SAMPLE_JSON)
    findings = ApkidAdapter(fake).scan("/tmp/app.apk")
    assert {f.title for f in findings} >= {"packer: Jiagu", "anti_vm: Build.FINGERPRINT check"}
