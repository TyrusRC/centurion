from centurion.adapters.generic.nm import NmAdapter
from centurion.process import FakeRunner

SAMPLE = """\
0000000000001100 T JNI_OnLoad
0000000000001234 t local_helper
                 U malloc
"""


def test_nm_metadata():
    a = NmAdapter()
    assert a.name == "nm"
    assert a.mastg_id == "MASTG-TOOL-0003"
    assert a.platform.value == "generic"
    assert a.category.value == "recon"


def test_nm_symbols_command_dynamic_default():
    assert NmAdapter().symbols_command("/tmp/lib.so") == ["nm", "-D", "/tmp/lib.so"]
    assert NmAdapter().symbols_command("/tmp/lib.so", dynamic=False) == ["nm", "/tmp/lib.so"]


def test_nm_parse_symbols_handles_undefined():
    syms = NmAdapter().parse_symbols(SAMPLE)
    assert {"address": "0000000000001100", "type": "T", "name": "JNI_OnLoad"} in syms
    undef = next(s for s in syms if s["name"] == "malloc")
    assert undef["address"] is None
    assert undef["type"] == "U"


def test_nm_symbols_runs():
    fake = FakeRunner()
    fake.register("nm -D", stdout=SAMPLE)
    names = [s["name"] for s in NmAdapter(fake).symbols("/tmp/lib.so")]
    assert "JNI_OnLoad" in names and "malloc" in names
