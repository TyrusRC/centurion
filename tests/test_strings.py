from centurion.adapters.generic.strings import StringsAdapter
from centurion.process import FakeRunner


def test_strings_detect():
    runner = FakeRunner()
    runner.register("strings --version", stdout="strings (GNU Binutils) 2.40\n", path="/usr/bin/strings")
    status = StringsAdapter(runner).detect()
    assert status.installed is True
    assert status.category == "recon"
    assert status.mastg_id is None


def test_strings_command_default_min_len():
    assert StringsAdapter().run_command("/tmp/lib.so") == ["strings", "-n", "8", "/tmp/lib.so"]


def test_strings_extract_filters_blank_lines():
    runner = FakeRunner()
    runner.register("strings -n", stdout="https://api.example.com\n\nAES/CBC/PKCS5Padding\n")
    out = StringsAdapter(runner).extract("/tmp/lib.so")
    assert out == ["https://api.example.com", "AES/CBC/PKCS5Padding"]
