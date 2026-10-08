import centurion.mcp.server as srv
from centurion.process import FakeRunner
from centurion.registry import default_registry


def test_orphaned_adapters_now_have_mcp_tools():
    # The 5 previously-unreachable adapters are now exposed as MCP tools.
    for tool in ("static_decompile", "apk_verify_signature", "dex_to_jar",
                 "drozer_run", "mantis_scan"):
        assert hasattr(srv, tool), f"missing MCP tool: {tool}"


def test_missing_tool_returns_install_hint_not_traceback(monkeypatch):
    # FakeRunner raises FileNotFoundError for unregistered commands, so detect()
    # reports not-installed and the tool must return the hint, never raise.
    reg = default_registry(FakeRunner())
    monkeypatch.setattr(srv, "get_registry", lambda: reg)

    out = srv.apk_verify_signature("/nope.apk")
    assert out.get("error") and out.get("install_hint")

    out2 = srv.mantis_scan("/src", "/tmp/centurion-test-target")
    assert out2.get("error") and out2.get("install_hint")

    out3 = srv.drozer_run("app.package.info", "/tmp/centurion-test-target")
    assert out3.get("error") and out3.get("install_hint")


def test_install_plan_tool():
    out = srv.install_plan("ios")
    assert isinstance(out, list)
    # every entry is a ToolStatus dict with an install hint for missing tools
    assert all("name" in s for s in out)
