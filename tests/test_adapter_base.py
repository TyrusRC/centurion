from centurion.adapters.base import Adapter
from centurion.models import Platform, Category
from centurion.process import FakeRunner


class DummyAdapter(Adapter):
    name = "dummy"
    binary = "dummy"
    mastg_id = "MASTG-TOOL-9999"
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "pip install dummy"


def test_detect_installed_parses_version():
    runner = FakeRunner()
    runner.register("dummy --version", stdout="dummy 2.3.4\n", path="/usr/bin/dummy")
    status = DummyAdapter(runner).detect()
    assert status.installed is True
    assert status.version == "dummy 2.3.4"
    assert status.path == "/usr/bin/dummy"
    assert status.mastg_id == "MASTG-TOOL-9999"
    assert status.platform == "android"
    assert status.category == "static"
    assert status.install_hint == "pip install dummy"


def test_detect_missing_tool_reports_not_installed():
    runner = FakeRunner()  # nothing registered -> run() raises FileNotFoundError
    status = DummyAdapter(runner).detect()
    assert status.installed is False
    assert status.version is None
    assert status.path is None
    assert status.install_hint == "pip install dummy"
