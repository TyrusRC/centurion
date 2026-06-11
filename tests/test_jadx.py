import pytest

from centurion.adapters.android.jadx import JadxAdapter
from centurion.models import Artifact
from centurion.process import FakeRunner


def test_jadx_detect():
    runner = FakeRunner()
    runner.register("jadx --version", stdout="1.5.0\n", path="/usr/bin/jadx")
    status = JadxAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0018"
    assert status.category == "static"


def test_jadx_decompile_command():
    cmd = JadxAdapter().decompile_command("/tmp/app.apk", "/tmp/out")
    assert cmd == ["jadx", "--output-dir", "/tmp/out", "/tmp/app.apk"]


def test_jadx_decompile_returns_artifact():
    runner = FakeRunner()
    runner.register("jadx --output-dir", stdout="INFO - done\n")
    artifact = JadxAdapter(runner).decompile("/tmp/app.apk", "/tmp/out")
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "decompiled"
    assert artifact.path == "/tmp/out"
    assert artifact.tool == "jadx"
    assert artifact.label == "app.apk"


def test_jadx_decompile_raises_on_failure():
    runner = FakeRunner()
    runner.register("jadx --output-dir", returncode=1, stderr="ERROR - bad apk\n")
    with pytest.raises(RuntimeError, match="bad apk"):
        JadxAdapter(runner).decompile("/tmp/app.apk", "/tmp/out")
