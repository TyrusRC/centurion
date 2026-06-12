from centurion.adapters.generic.radare2 import Radare2Adapter
from centurion.process import FakeRunner


def test_radare2_detect():
    runner = FakeRunner()
    runner.register("r2 -version", stdout="radare2 5.8.8 0 @ linux-x86-64\n", path="/usr/bin/r2")
    status = Radare2Adapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0028"
    assert status.category == "recon"


def test_radare2_strings_command():
    assert Radare2Adapter().strings_command("/tmp/lib.so") == ["rabin2", "-z", "/tmp/lib.so"]


def test_radare2_info_command():
    assert Radare2Adapter().info_command("/tmp/lib.so") == ["rabin2", "-I", "/tmp/lib.so"]


def test_info_returns_stdout():
    from centurion.adapters.generic.radare2 import Radare2Adapter
    from centurion.process import FakeRunner
    fake = FakeRunner()
    fake.register("rabin2 -I", stdout="arch     arm\nbits     64\n")
    info = Radare2Adapter(fake).info("/tmp/libfoo.so")
    assert "arch" in info
