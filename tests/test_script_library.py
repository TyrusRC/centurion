from pathlib import Path

from centurion.scripts import ScriptLibrary


def test_lists_all_bundled_scripts():
    lib = ScriptLibrary()
    names = {s.name for s in lib.list()}
    assert names == {"ssl_unpin", "root_bypass", "debugger_bypass", "dump_class_hooks"}


def test_each_script_has_description_and_platform():
    lib = ScriptLibrary()
    info = {s.name: s for s in lib.list()}
    assert info["ssl_unpin"].platform == "android"
    assert "pinning" in info["ssl_unpin"].description.lower()


def test_get_resolves_a_real_readable_file():
    lib = ScriptLibrary()
    info = lib.get("ssl_unpin")
    assert Path(info.path).is_file()
    assert "AUTHORIZED TESTING ONLY" in Path(info.path).read_text()


def test_get_unknown_raises():
    lib = ScriptLibrary()
    try:
        lib.get("does_not_exist")
        assert False, "expected KeyError"
    except KeyError as e:
        assert "does_not_exist" in str(e)
