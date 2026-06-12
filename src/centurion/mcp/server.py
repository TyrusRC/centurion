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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
