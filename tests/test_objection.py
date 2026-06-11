from centurion.adapters.android.objection import ObjectionAdapter
from centurion.process import FakeRunner


def test_objection_detect():
    runner = FakeRunner()
    runner.register("objection version", stdout="objection: 1.11.0\n", path="/usr/bin/objection")
    status = ObjectionAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0029"
    assert status.category == "dynamic"


def test_objection_explore_command_with_startup_commands():
    cmd = ObjectionAdapter().explore_command(
        "com.acme.bank",
        ["android sslpinning disable", "android root disable"],
    )
    assert cmd == [
        "objection", "-g", "com.acme.bank", "explore",
        "--startup-command", "android sslpinning disable",
        "--startup-command", "android root disable",
    ]


def test_objection_run_returns_stdout():
    runner = FakeRunner()
    runner.register("objection -g com.acme.bank explore", stdout="pinning disabled\n")
    out = ObjectionAdapter(runner).run("com.acme.bank", ["android sslpinning disable"])
    assert "pinning disabled" in out
