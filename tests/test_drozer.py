from centurion.adapters.android.drozer import DrozerAdapter
from centurion.process import FakeRunner


def test_drozer_detect_via_path():
    runner = FakeRunner()
    runner.register("drozer --version", returncode=1, stderr="usage: drozer\n", path="/usr/bin/drozer")
    status = DrozerAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0015"
    assert status.category == "dynamic"


def test_drozer_module_command_with_args():
    assert DrozerAdapter().module_command("app.package.attacksurface", "com.acme.bank") == [
        "drozer", "console", "connect", "-c", "run app.package.attacksurface com.acme.bank",
    ]


def test_drozer_module_command_no_args():
    assert DrozerAdapter().module_command("app.package.list") == [
        "drozer", "console", "connect", "-c", "run app.package.list",
    ]


def test_drozer_run_module_returns_stdout():
    runner = FakeRunner()
    runner.register("drozer console connect", stdout="Attack surface:\n  3 activities exported\n")
    out = DrozerAdapter(runner).run_module("app.package.attacksurface", "com.acme.bank")
    assert "3 activities exported" in out
