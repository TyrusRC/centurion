"""FastMCP server exposing Centurion tools to Claude Code over stdio."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .. import session as session
from ..process import WorkspaceProcessManager
from ..registry import Registry, default_registry
from ..scripts import ScriptLibrary

mcp = FastMCP("centurion")


def get_registry() -> Registry:
    """Factory so tests can monkeypatch with a FakeRunner-backed registry."""
    return default_registry()


def get_workspace(target: str):
    """Resolve (creating if needed) the per-target workspace."""
    ws = session.Workspace(session.default_root(), target)
    ws.create()
    return ws


def get_process_manager(target: str) -> WorkspaceProcessManager:
    """Durable process manager backed by the target workspace."""
    return WorkspaceProcessManager(get_workspace(target))


def get_script_library() -> ScriptLibrary:
    return ScriptLibrary()


@mcp.tool()
def doctor() -> list[dict]:
    """List every wrapped tool with installation status (name, MASTG id, version)."""
    return [s.to_dict() for s in get_registry().doctor()]


@mcp.tool()
def device_list() -> list[dict]:
    """List connected Android devices (serial, state, model)."""
    adb = get_registry().get("adb")
    return [d.to_dict() for d in adb.devices()]


@mcp.tool()
def app_list() -> list[str]:
    """List installed package names on the connected Android device."""
    return get_registry().get("adb").packages()


@mcp.tool()
def app_pull(package: str, target: str) -> dict:
    """Pull a package's base APK into the target workspace; records an artifact."""
    ws = get_workspace(target)
    artifact = get_registry().get("adb").pull_apk(package, str(ws.artifacts_dir))
    ws.add_artifact(artifact)
    return artifact.to_dict()


@mcp.tool()
def static_decode(apk: str, target: str) -> dict:
    """Decode an APK's manifest/resources with apktool; records an artifact."""
    ws = get_workspace(target)
    out_dir = str(ws.artifacts_dir / "decoded")
    artifact = get_registry().get("apktool").decode(apk, out_dir)
    ws.add_artifact(artifact)
    return artifact.to_dict()


@mcp.tool()
def static_scan(path: str, target: str, rules: str | None = None) -> list[dict]:
    """Scan a decoded/source tree with Opengrep; records and returns findings."""
    ws = get_workspace(target)
    findings = get_registry().get("opengrep").scan(path, rules)
    for finding in findings:
        ws.add_finding(finding)
    return [f.to_dict() for f in findings]


@mcp.tool()
def objection_run(package: str, commands: list[str]) -> str:
    """Run objection startup commands against a package; returns raw output."""
    return get_registry().get("objection").run(package, commands)


@mcp.tool()
def frida_list_scripts() -> list[dict]:
    """List the bundled, vetted Frida scripts (name, description, platform)."""
    return [s.__dict__ for s in get_script_library().list()]


@mcp.tool()
def frida_run_named_script(target_app: str, script: str, target: str) -> dict:
    """Spawn target_app under Frida with a bundled script; durable process handle."""
    script_path = get_script_library().path(script)
    command = get_registry().get("frida").run_script_command(target_app, script_path)
    proc = get_process_manager(target).start(f"frida-{target_app}", command)
    return proc.to_dict()


@mcp.tool()
def frida_run_script(target_app: str, script_path: str, target: str) -> dict:
    """Spawn target_app under Frida with an arbitrary script (raw passthrough)."""
    command = get_registry().get("frida").run_script_command(target_app, script_path)
    proc = get_process_manager(target).start(f"frida-{target_app}", command)
    return proc.to_dict()


@mcp.tool()
def ssl_unpin(target_app: str, target: str) -> dict:
    """Shortcut: run the bundled ssl_unpin script against target_app."""
    return frida_run_named_script(target_app, "ssl_unpin", target)


def _flow_file(target: str) -> str:
    return str(get_workspace(target).artifacts_dir / "flows.mitm")


@mcp.tool()
def proxy_start(target: str, port: int = 8080) -> dict:
    """Start mitmdump (durable handle 'proxy'), writing flows into the workspace."""
    adapter = get_registry().get("mitmproxy")
    command = adapter.start_command(port=port, flow_out=_flow_file(target))
    proc = get_process_manager(target).start("proxy", command)
    return proc.to_dict()


@mcp.tool()
def proxy_stop(target: str) -> dict:
    """Stop the running mitmdump proxy for the target."""
    return {"stopped": get_process_manager(target).stop("proxy")}


@mcp.tool()
def proxy_flows(target: str) -> list[dict]:
    """Summarize captured flows (method + URL) from the workspace flow file."""
    adapter = get_registry().get("mitmproxy")
    result = adapter.runner.run(adapter.read_command(_flow_file(target)), timeout=120)
    return adapter.parse_flows(result.stdout)


@mcp.tool()
def recon_strings(path: str, min_len: int = 8) -> list[str]:
    """Extract printable strings (>= min_len) from a binary."""
    return get_registry().get("strings").extract(path, min_len)


@mcp.tool()
def recon_radare2(path: str) -> dict:
    """Return rabin2 binary info for a target file."""
    return {"info": get_registry().get("radare2").info(path)}


@mcp.tool()
def findings_list(target: str) -> list[dict]:
    """List recorded findings for the target workspace (for triage)."""
    return get_workspace(target).load().findings


@mcp.tool()
def ios_device_list() -> list[dict]:
    """List connected iOS devices (udid, name, ios_version)."""
    return [d.to_dict() for d in get_registry().get("idevice").devices()]


@mcp.tool()
def ios_app_list() -> list[str]:
    """List installed app bundle IDs on the connected iOS device."""
    return get_registry().get("ideviceinstaller").apps()


@mcp.tool()
def ios_app_pull(bundle_id: str, target: str) -> dict:
    """Pull a decrypted IPA (frida-ios-dump) into the workspace; records an artifact."""
    ws = get_workspace(target)
    artifact = get_registry().get("frida-ios-dump").dump(bundle_id, str(ws.artifacts_dir))
    ws.add_artifact(artifact)
    return artifact.to_dict()


@mcp.resource("centurion://scripts")
def scripts_resource() -> list[dict]:
    """The bundled Frida script catalog."""
    return [s.__dict__ for s in get_script_library().list()]


@mcp.resource("centurion://findings/{target}")
def findings_resource(target: str) -> list[dict]:
    """Recorded findings for a target workspace."""
    return get_workspace(target).load().findings


@mcp.resource("centurion://processes/{target}")
def processes_resource(target: str) -> list[dict]:
    """Durable long-running process handles for a target workspace."""
    return get_process_manager(target).list()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
