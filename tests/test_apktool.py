import pytest

from centurion.adapters.android.apktool import ApktoolAdapter
from centurion.models import Artifact
from centurion.process import FakeRunner


def test_apktool_detect():
    runner = FakeRunner()
    runner.register("apktool --version", stdout="2.9.3\n", path="/usr/bin/apktool")
    status = ApktoolAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0011"
    assert status.platform == "android"
    assert status.category == "static"


def test_apktool_decode_command():
    assert ApktoolAdapter().decode_command("/tmp/app.apk", "/tmp/out") == [
        "apktool", "d", "-f", "-o", "/tmp/out", "/tmp/app.apk",
    ]


def test_apktool_decode_returns_artifact():
    runner = FakeRunner()
    runner.register("apktool d", stdout="I: Using Apktool 2.9.3\n")
    artifact = ApktoolAdapter(runner).decode("/tmp/app.apk", "/tmp/out")
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "decoded"
    assert artifact.tool == "apktool"
    assert artifact.path == "/tmp/out"
    assert artifact.label == "app.apk"


def test_apktool_decode_raises_on_failure():
    runner = FakeRunner()
    runner.register("apktool d", returncode=1, stderr="brut.androlib.AndrolibException: bad apk\n")
    with pytest.raises(RuntimeError, match="bad apk"):
        ApktoolAdapter(runner).decode("/tmp/app.apk", "/tmp/out")
