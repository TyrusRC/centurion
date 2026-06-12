import centurion.mcp.server as server
from centurion.adapters.android.adb import AdbAdapter
from centurion.adapters.android.apktool import ApktoolAdapter
from centurion.adapters.android.objection import ObjectionAdapter
from centurion.adapters.generic.frida import FridaAdapter
from centurion.adapters.generic.mitmproxy import MitmproxyAdapter
from centurion.adapters.generic.opengrep import OpengrepAdapter
from centurion.adapters.generic.strings import StringsAdapter
from centurion.adapters.generic.radare2 import Radare2Adapter
from centurion.adapters.ios.idevice import IdeviceAdapter
from centurion.adapters.ios.ideviceinstaller import IdeviceinstallerAdapter
from centurion.adapters.ios.frida_ios_dump import FridaIosDumpAdapter
from centurion.models import Finding
from centurion.process import FakeRunner, WorkspaceProcessManager
from centurion.registry import Registry


def _fake_registry():
    fake = FakeRunner()
    fake.register("adb version", stdout="Android Debug Bridge version 1.0.41\n", path="/usr/bin/adb")
    fake.register("adb devices -l", stdout="List of devices attached\nemulator-5554\tdevice model:Pixel_6\n")
    return Registry([AdbAdapter(fake)])


def test_server_name():
    assert server.mcp.name == "centurion"


def test_doctor_tool_returns_dicts(monkeypatch):
    monkeypatch.setattr(server, "get_registry", _fake_registry)
    result = server.doctor()
    assert isinstance(result, list)
    assert result[0]["name"] == "adb"
    assert result[0]["installed"] is True


def test_device_list_tool(monkeypatch):
    monkeypatch.setattr(server, "get_registry", _fake_registry)
    result = server.device_list()
    assert result == [{"serial": "emulator-5554", "state": "device", "model": "Pixel_6"}]


def test_get_workspace_creates_under_target(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ws = server.get_workspace("Acme Bank")
    assert ws.slug == "acme-bank"
    assert ws.session_file.exists()


def test_get_process_manager_is_workspace_backed(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    pm = server.get_process_manager("Acme Bank")
    assert pm.list() == []


def test_get_script_library_lists_scripts():
    assert len(server.get_script_library().list()) == 6


def _static_registry(fake):
    return Registry([AdbAdapter(fake), ApktoolAdapter(fake), OpengrepAdapter(fake)])


def test_app_list_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("adb shell pm list packages",
                  stdout="package:com.acme.app\npackage:com.other\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    assert server.app_list() == ["com.acme.app", "com.other"]


def test_app_pull_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("adb shell pm path com.acme.app", stdout="package:/data/app/base.apk\n")
    fake.register("adb pull", stdout="1 file pulled\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    result = server.app_pull("com.acme.app", "Acme")
    assert result["kind"] == "binary"
    assert result["path"].endswith("com.acme.app.apk")
    assert server.get_workspace("Acme").load().artifacts[0]["id"] == "apk-com.acme.app"


def test_static_decode_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("apktool d", stdout="I: Using Apktool\n")
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    result = server.static_decode("/tmp/app.apk", "Acme")
    assert result["kind"] == "decoded"
    assert server.get_workspace("Acme").load().artifacts[0]["tool"] == "apktool"


def test_static_scan_records_findings(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    fake = FakeRunner()
    fake.register("opengrep scan", stdout=(
        '{"results":[{"check_id":"cleartext","path":"a/A.java",'
        '"start":{"line":12},"extra":{"severity":"ERROR","message":"cleartext HTTP"}}]}'
    ))
    monkeypatch.setattr(server, "get_registry", lambda: _static_registry(fake))
    findings = server.static_scan("/tmp/decoded", "Acme", str(rules))
    assert findings[0]["severity"] == "high"
    assert server.get_workspace("Acme").load().findings[0]["title"] == "cleartext"


def test_objection_run_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("objection -g com.acme.app explore",
                  stdout="android hooking ... done\n")
    monkeypatch.setattr(server, "get_registry",
                        lambda: Registry([ObjectionAdapter(fake)]))
    out = server.objection_run("com.acme.app", ["android hooking list classes"])
    assert "done" in out


def test_frida_list_scripts_tool():
    names = {s["name"] for s in server.frida_list_scripts()}
    assert "ssl_unpin" in names


def test_frida_run_named_script_starts_process(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)

    class FakeProc:
        pid = 4321

    monkeypatch.setattr(server, "get_process_manager",
                        lambda target: WorkspaceProcessManager(
                            server.get_workspace(target), spawn=lambda cmd: FakeProc()))
    result = server.frida_run_named_script("com.acme.app", "ssl_unpin", "Acme")
    assert result["handle"] == "frida-com.acme.app"
    assert result["pid"] == 4321
    assert any("ssl_unpin.js" in part for part in result["command"])


def test_ssl_unpin_is_named_script_shortcut(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)

    class FakeProc:
        pid = 99

    monkeypatch.setattr(server, "get_process_manager",
                        lambda target: WorkspaceProcessManager(
                            server.get_workspace(target), spawn=lambda cmd: FakeProc()))
    result = server.ssl_unpin("com.acme.app", "Acme")
    assert any("ssl_unpin.js" in part for part in result["command"])


def test_proxy_start_and_stop(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)

    class FakeProc:
        pid = 555

    monkeypatch.setattr(server, "get_registry", lambda: Registry([MitmproxyAdapter(FakeRunner())]))
    monkeypatch.setattr(server, "get_process_manager",
                        lambda target: WorkspaceProcessManager(
                            server.get_workspace(target), spawn=lambda cmd: FakeProc(),
                            kill=lambda pid: None))
    started = server.proxy_start("Acme", 8080)
    assert started["handle"] == "proxy"
    assert started["pid"] == 555
    assert server.proxy_stop("Acme") == {"stopped": True}


def test_proxy_flows_reads_flow_file(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("mitmdump -nr", stdout="GET https://api.acme.com/x\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([MitmproxyAdapter(fake)]))
    flows = server.proxy_flows("Acme")
    assert flows == [{"method": "GET", "url": "https://api.acme.com/x"}]


def test_recon_strings_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("strings -n 8", stdout="hardcoded_api_key\nshort\nanother_long_str\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([StringsAdapter(fake)]))
    out = server.recon_strings("/tmp/libfoo.so")
    assert "hardcoded_api_key" in out


def test_recon_radare2_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("rabin2 -I", stdout="arch arm\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([Radare2Adapter(fake)]))
    assert "arch" in server.recon_radare2("/tmp/libfoo.so")["info"]


def test_findings_list_tool(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ws = server.get_workspace("Acme")
    ws.add_finding(Finding(id="f1", title="Cleartext", severity="high", tool="opengrep"))
    assert server.findings_list("Acme")[0]["id"] == "f1"


def test_scripts_resource_lists_bundled():
    data = server.scripts_resource()
    assert {s["name"] for s in data} >= {"ssl_unpin", "root_bypass"}


def test_findings_resource(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    ws = server.get_workspace("Acme")
    ws.add_finding(Finding(id="f9", title="X", severity="low", tool="opengrep"))
    assert server.findings_resource("Acme")[0]["id"] == "f9"


def test_processes_resource(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    server.get_workspace("Acme")  # create
    assert server.processes_resource("Acme") == []


def test_all_documented_tools_are_defined():
    expected = {
        "doctor", "device_list", "app_list", "app_pull", "static_decode",
        "static_scan", "objection_run", "frida_list_scripts",
        "frida_run_named_script", "frida_run_script", "ssl_unpin",
        "proxy_start", "proxy_stop", "proxy_flows", "recon_strings",
        "recon_radare2", "findings_list",
    }
    for name in expected:
        assert callable(getattr(server, name)), f"missing MCP tool: {name}"


def test_skills_and_agents_reference_only_shipped_tools():
    import re
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    shipped = {
        "doctor", "device_list", "app_list", "app_pull", "static_decode",
        "static_scan", "objection_run", "frida_list_scripts",
        "frida_run_named_script", "frida_run_script", "ssl_unpin",
        "proxy_start", "proxy_stop", "proxy_flows", "recon_strings",
        "recon_radare2", "findings_list",
    }
    md_files = list((repo / ".claude" / "skills").rglob("*.md"))
    md_files += list((repo / ".claude" / "agents").rglob("*.md"))
    assert md_files, "no skill/agent markdown found"
    # Tool references are written as `tool_name(` (a backtick-quoted call).
    pattern = re.compile(r"`([a-z_][a-z0-9_]*)\(")
    referenced = set()
    for md in md_files:
        referenced |= set(pattern.findall(md.read_text()))
    unknown = referenced - shipped
    assert not unknown, f"skills/agents reference unshipped tools: {sorted(unknown)}"


def test_ios_device_list_tool(monkeypatch):
    fake = FakeRunner()
    fake.register("idevice_id -l", stdout="00008030-AAAA\n", path="/usr/bin/idevice_id")
    fake.register("ideviceinfo -u 00008030-AAAA -k DeviceName", stdout="Alice iPhone\n")
    fake.register("ideviceinfo -u 00008030-AAAA -k ProductVersion", stdout="16.4\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([IdeviceAdapter(fake)]))
    assert server.ios_device_list() == [
        {"udid": "00008030-AAAA", "name": "Alice iPhone", "ios_version": "16.4"}
    ]


def test_ios_app_list_tool(monkeypatch):
    out = (
        "CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName\n"
        "com.acme.bank, 1.0, Acme Bank\n"
    )
    fake = FakeRunner()
    fake.register("ideviceinstaller -l", stdout=out, path="/usr/bin/ideviceinstaller")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([IdeviceinstallerAdapter(fake)]))
    assert server.ios_app_list() == ["com.acme.bank"]


def test_ios_app_pull_records_artifact(tmp_path, monkeypatch):
    import centurion.session as session_mod
    monkeypatch.setattr(session_mod, "default_root", lambda: tmp_path)
    fake = FakeRunner()
    fake.register("frida-ios-dump", stdout="Done\n")
    monkeypatch.setattr(server, "get_registry", lambda: Registry([FridaIosDumpAdapter(fake)]))
    result = server.ios_app_pull("com.acme.bank", "AcmeIOS")
    assert result["kind"] == "binary"
    assert result["path"].endswith("com.acme.bank.ipa")
    assert server.get_workspace("AcmeIOS").load().artifacts[0]["id"] == "ipa-com.acme.bank"
