"""FastMCP server exposing Centurion tools to Claude Code over stdio."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .. import masvs
from .. import report
from .. import session as session
from ..ios.ipa import ipa_info, read_plist
from ..models import Finding
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
    import json
    ws.record_run("opengrep", ["opengrep", "scan", path], "ok",
                  output=json.dumps([f.to_dict() for f in findings], indent=2))
    return [f.to_dict() for f in findings]


@mcp.tool()
def objection_run(package: str, commands: list[str], target: str) -> str:
    """Run objection startup commands against a package; returns raw output."""
    output = get_registry().get("objection").run(package, commands)
    get_workspace(target).record_run("objection", ["objection", *commands], "ok", output=output)
    _auto_screenshot(target, f"after objection: {package}")
    return output


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
    _auto_screenshot(target, f"after frida:{script}")
    return proc.to_dict()


@mcp.tool()
def frida_run_script(target_app: str, script_path: str, target: str) -> dict:
    """Spawn target_app under Frida with an arbitrary script (raw passthrough)."""
    command = get_registry().get("frida").run_script_command(target_app, script_path)
    proc = get_process_manager(target).start(f"frida-{target_app}", command)
    _auto_screenshot(target, "after frida:custom-script")
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
    """List MASVS-enriched findings for the target workspace (for triage)."""
    return masvs.enrich(get_workspace(target).load().findings)


@mcp.tool()
def report_generate(target: str, format: str = "both") -> dict:
    """Render the target workspace into a Markdown + self-contained HTML report."""
    return report.generate(get_workspace(target), fmt=format)


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


@mcp.tool()
def ios_plist(path: str) -> dict:
    """Parse an iOS plist (binary or XML) into a dict."""
    return read_plist(path)


@mcp.tool()
def ios_static_ipa(ipa: str, target: str) -> dict:
    """Summarize an IPA's Info.plist; records an ATS finding if the app opts out of
    App Transport Security. Returns the summary (bundle id, min OS, URL schemes, ATS)."""
    ws = get_workspace(target)
    summary = ipa_info(ipa)
    if summary.get("ats_allows_arbitrary_loads"):
        ws.add_finding(
            Finding(
                id=f"ats-{summary.get('bundle_id') or ipa}",
                title="App Transport Security disabled (NSAllowsArbitraryLoads)",
                severity="medium",
                tool="ios-static-ipa",
                detail="Info.plist sets NSAllowsArbitraryLoads=true, permitting cleartext HTTP.",
                location=summary.get("info_plist"),
            )
        )
    return summary


@mcp.tool()
def ios_classdump(binary: str, target: str) -> dict:
    """Dump Objective-C headers from a Mach-O binary with class-dump; records an artifact."""
    ws = get_workspace(target)
    out_dir = str(ws.artifacts_dir / "headers")
    artifact = get_registry().get("class-dump").headers(binary, out_dir)
    ws.add_artifact(artifact)
    return artifact.to_dict()


@mcp.tool()
def apkid_scan(apk: str, target: str) -> list[dict]:
    """Detect the APK's packer/obfuscator/compiler with APKiD; records info findings."""
    ws = get_workspace(target)
    findings = get_registry().get("apkid").scan(apk)
    for finding in findings:
        ws.add_finding(finding)
    return [f.to_dict() for f in findings]


@mcp.tool()
def apkleaks_scan(apk: str, target: str) -> list[dict]:
    """Scan an APK for endpoints and secrets with apkleaks; records findings."""
    ws = get_workspace(target)
    out_json = str(ws.artifacts_dir / "apkleaks.json")
    findings = get_registry().get("apkleaks").scan(apk, out_json)
    for finding in findings:
        ws.add_finding(finding)
    return [f.to_dict() for f in findings]


@mcp.tool()
def secrets_scan(path: str, target: str) -> list[dict]:
    """Scan a decoded/source tree for secrets with gitleaks; records findings."""
    ws = get_workspace(target)
    report = str(ws.artifacts_dir / "gitleaks.json")
    findings = get_registry().get("gitleaks").scan(path, report)
    for finding in findings:
        ws.add_finding(finding)
    return [f.to_dict() for f in findings]


@mcp.tool()
def apk_badging(apk: str) -> dict:
    """Dump an APK's package name, version and requested permissions with aapt2."""
    return get_registry().get("aapt2").badging(apk)


@mcp.tool()
def recon_symbols(path: str, dynamic: bool = True) -> list[dict]:
    """List symbols from a binary/shared library with nm (dynamic table by default)."""
    return get_registry().get("nm").symbols(path, dynamic)


@mcp.tool()
def ios_binary_info(binary: str, target: str) -> dict:
    """Report Mach-O hardening (PIE/encryption/stack-canary/ARC/libs) with otool;
    records findings for missing PIE, an unencrypted binary, or a missing stack canary."""
    ws = get_workspace(target)
    adapter = get_registry().get("otool")
    info = adapter.hardening(binary)
    for finding in adapter.hardening_findings(binary, info):
        ws.add_finding(finding)
    return info


@mcp.tool()
def ios_entitlements(binary: str) -> dict:
    """Dump code-signing entitlements from a Mach-O binary with ldid."""
    return get_registry().get("ldid").entitlements(binary)


@mcp.tool()
def ios_relay(local_port: int, device_port: int, target: str) -> dict:
    """Start an iproxy USB TCP relay (durable handle 'iproxy-<local>'); e.g. 2222->22 for SSH."""
    command = get_registry().get("idevice").relay_command(local_port, device_port)
    proc = get_process_manager(target).start(f"iproxy-{local_port}", command)
    return proc.to_dict()


@mcp.tool()
def screenshot(target: str, label: str | None = None) -> dict:
    """Capture an Android device screenshot into the workspace as evidence."""
    ws = get_workspace(target)
    name = f"screenshot-{len(ws.load().artifacts) + 1}"
    artifact = get_registry().get("adb").screenshot(
        str(ws.artifacts_dir), name=name, label=label
    )
    ws.add_artifact(artifact)
    return artifact.to_dict()


@mcp.tool()
def ios_screenshot(target: str, label: str | None = None) -> dict:
    """Capture an iOS device screenshot into the workspace as evidence."""
    ws = get_workspace(target)
    name = f"screenshot-{len(ws.load().artifacts) + 1}"
    artifact = get_registry().get("idevice").screenshot(
        str(ws.artifacts_dir), name=name, label=label
    )
    ws.add_artifact(artifact)
    return artifact.to_dict()


def _auto_screenshot(target: str, label: str) -> dict | None:
    """Best-effort evidence capture after a dynamic run. Never raises."""
    try:
        return screenshot(target, label=label)
    except Exception:
        return None


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


def _ensure(name: str):
    """Return (adapter, None) if installed, else (adapter, a hint dict).

    Keeps the README's "missing tool -> install hint" promise on the runtime
    path instead of leaking a raw FileNotFoundError to the MCP client.
    """
    adapter = get_registry().get(name)
    status = adapter.detect()
    if not status.installed:
        return adapter, {"error": f"{name} not installed",
                         "install_hint": status.install_hint}
    return adapter, None


@mcp.tool()
def static_decompile(apk: str, target: str) -> dict:
    """Decompile an APK's DEX to Java source with jadx; records an artifact."""
    from pathlib import Path
    adapter, miss = _ensure("jadx")
    if miss:
        return miss
    ws = get_workspace(target)
    art = adapter.decompile(apk, str(ws.artifacts_dir / f"jadx-{Path(apk).stem}"))
    ws.add_artifact(art)
    return art.to_dict()


@mcp.tool()
def apk_verify_signature(apk: str) -> dict:
    """Verify an APK's signing blocks (v1-v4) with apksigner."""
    adapter, miss = _ensure("apksigner")
    if miss:
        return miss
    return adapter.verify(apk).to_dict()


@mcp.tool()
def dex_to_jar(input_path: str, target: str) -> dict:
    """Convert a DEX/APK to a JAR with dex2jar; records an artifact."""
    from pathlib import Path
    adapter, miss = _ensure("dex2jar")
    if miss:
        return miss
    ws = get_workspace(target)
    out_jar = str(ws.artifacts_dir / (Path(input_path).stem + ".jar"))
    art = adapter.convert(input_path, out_jar)
    ws.add_artifact(art)
    return art.to_dict()


@mcp.tool()
def drozer_run(module: str, target: str, args: str = "") -> dict:
    """Run a drozer module against the connected device; returns its output."""
    adapter, miss = _ensure("drozer")
    if miss:
        return miss
    out = adapter.run_module(module, args)
    get_workspace(target).record_run("drozer", ["drozer", "run", module], "ok", output=out)
    return {"module": module, "output": out}


@mcp.tool()
def mantis_scan(source_dir: str, target: str, llm: bool = False) -> dict:
    """Run mantis (SAST) over a source/decompiled tree; records + returns findings.

    The mobile use case: point this at jadx/apktool output to statically audit the
    recovered code. SAST-only by default; `llm=True` adds mantis's LLM triage."""
    adapter, miss = _ensure("mantis")
    if miss:
        return miss
    findings = adapter.audit(source_dir, llm=llm)
    ws = get_workspace(target)
    for f in findings:
        ws.add_finding(f)
    return {"count": len(findings), "findings": [f.to_dict() for f in findings]}


@mcp.tool()
def install_plan(group: str = "all") -> list[dict]:
    """List the tools in a group (android|ios|static|dynamic|network|recon|all) that
    are not yet installed, each with its install hint — the grouped equivalent of the
    CLI `install` command."""
    from ..install import plan_install
    return [s.to_dict() for s in plan_install(get_registry(), group)]
