import pytest

from centurion.adapters.android.dex2jar import Dex2jarAdapter
from centurion.models import Artifact
from centurion.process import FakeRunner


def test_dex2jar_detect_via_path():
    runner = FakeRunner()
    # dex2jar may exit non-zero on --version, but presence on PATH means installed.
    runner.register("d2j-dex2jar --version", returncode=1, stderr="usage: d2j-dex2jar\n", path="/usr/bin/d2j-dex2jar")
    status = Dex2jarAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "android"
    assert status.category == "static"
    assert status.mastg_id is None


def test_dex2jar_convert_command():
    assert Dex2jarAdapter().convert_command("/tmp/app.apk", "/tmp/app.jar") == [
        "d2j-dex2jar", "-f", "-o", "/tmp/app.jar", "/tmp/app.apk",
    ]


def test_dex2jar_convert_returns_artifact():
    runner = FakeRunner()
    runner.register("d2j-dex2jar -f", stdout="dex2jar /tmp/app.apk -> /tmp/app.jar\n")
    artifact = Dex2jarAdapter(runner).convert("/tmp/app.apk", "/tmp/app.jar")
    assert isinstance(artifact, Artifact)
    assert artifact.kind == "jar"
    assert artifact.tool == "dex2jar"
    assert artifact.path == "/tmp/app.jar"
    assert artifact.label == "app.apk"


def test_dex2jar_convert_raises_on_failure():
    runner = FakeRunner()
    runner.register("d2j-dex2jar -f", returncode=1, stderr="translate error\n")
    with pytest.raises(RuntimeError, match="translate error"):
        Dex2jarAdapter(runner).convert("/tmp/app.apk", "/tmp/app.jar")
