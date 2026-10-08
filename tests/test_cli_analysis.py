from typer.testing import CliRunner

import centurion.cli.app as appmod
from centurion.cli.app import app
from centurion.process import FakeRunner
from centurion.registry import default_registry

runner = CliRunner()


def test_cli_analysis_commands_missing_tool_show_hint(monkeypatch):
    reg = default_registry(FakeRunner())  # nothing installed
    monkeypatch.setattr(appmod, "get_registry", lambda: reg)
    for args in (["scan", "/tmp"], ["decompile", "/x.apk", "-o", "/tmp/o"],
                 ["decode", "/x.apk", "-o", "/tmp/o"]):
        res = runner.invoke(app, args)
        assert res.exit_code == 2, f"{args} -> {res.exit_code}"
        assert "not installed" in res.stdout


def test_cli_analysis_commands_registered():
    names = {c.callback.__name__ for c in app.registered_commands}
    assert {"decompile", "decode", "scan"} <= names
