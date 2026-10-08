"""Typer CLI for daily-workflow use."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..install import plan_install
from ..registry import Registry, default_registry

app = typer.Typer(help="Centurion — mobile QA + pentest toolkit.")
device_app = typer.Typer(help="Device commands.")
app.add_typer(device_app, name="device")

console = Console()


def get_registry() -> Registry:
    """Factory so tests can monkeypatch with a FakeRunner-backed registry."""
    return default_registry()


@app.command()
def version() -> None:
    """Print the Centurion version."""
    console.print(f"centurion {__version__}")


@app.command()
def doctor() -> None:
    """Show every wrapped tool and whether it is installed."""
    table = Table("Tool", "MASTG", "Platform", "Category", "Installed", "Version")
    for status in get_registry().doctor():
        table.add_row(
            status.name,
            status.mastg_id or "-",
            status.platform or "-",
            status.category or "-",
            "yes" if status.installed else "no",
            status.version or "-",
        )
    console.print(table)


@app.command()
def install(
    group: str = typer.Option(
        "all",
        "--group",
        help="Tool group: all | android | ios | generic | network | static | dynamic | device-qa | recon",
    ),
) -> None:
    """List tools in a group that are not yet installed, with install hints."""
    missing = plan_install(get_registry(), group)
    if not missing:
        console.print(f"All tools in group '{group}' are already installed.")
        return
    console.print(f"Missing tools in group '{group}':")
    for status in missing:
        console.print(f"  {status.name}: {status.install_hint}")


@app.command()
def screenshot(
    target: str,
    label: str = typer.Option(None),
    ios: bool = typer.Option(False),
) -> None:
    """Capture a device screenshot into the target workspace."""
    from .. import session as _session

    ws = _session.Workspace(_session.default_root(), target)
    ws.create()
    tool = "idevice" if ios else "adb"
    name = f"screenshot-{len(ws.load().artifacts) + 1}"
    artifact = get_registry().get(tool).screenshot(str(ws.artifacts_dir), name=name, label=label)
    ws.add_artifact(artifact)
    typer.echo(artifact.path)


@app.command()
def report(
    target: str,
    format: str = typer.Option("both", help="both|md|html"),
) -> None:
    """Generate the Markdown + HTML report for a target workspace."""
    from .. import report as _report, session as _session

    ws = _session.Workspace(_session.default_root(), target)
    ws.create()
    out = _report.generate(ws, fmt=format)
    for kind, path in out.items():
        typer.echo(f"{kind}: {path}")


@device_app.command("list")
def device_list() -> None:
    """List connected Android devices."""
    table = Table("Serial", "State", "Model")
    adb = get_registry().get("adb")
    for dev in adb.devices():
        table.add_row(dev.serial, dev.state, dev.model or "-")
    console.print(table)


if __name__ == "__main__":
    app()


def _cli_tool_or_exit(name: str):
    adapter = get_registry().get(name)
    status = adapter.detect()
    if not status.installed:
        console.print(f"[red]{name} not installed.[/red] {status.install_hint}")
        raise typer.Exit(2)
    return adapter


@app.command()
def decompile(apk: str, out: str = typer.Option(..., "-o", "--out")) -> None:
    """Decompile an APK's DEX to Java source with jadx."""
    art = _cli_tool_or_exit("jadx").decompile(apk, out)
    console.print(f"decompiled -> {art.path}")


@app.command()
def decode(apk: str, out: str = typer.Option(..., "-o", "--out")) -> None:
    """Decode an APK's manifest/resources with apktool."""
    art = _cli_tool_or_exit("apktool").decode(apk, out)
    console.print(f"decoded -> {art.path}")


@app.command()
def scan(path: str, rules: str = typer.Option(None, "--rules")) -> None:
    """Scan a decoded/source tree for issues with opengrep."""
    findings = _cli_tool_or_exit("opengrep").scan(path, rules)
    table = Table("Severity", "Rule", "Location")
    for f in findings:
        table.add_row(f.severity, f.title, f.location or "-")
    console.print(table)
    console.print(f"{len(findings)} finding(s)")
