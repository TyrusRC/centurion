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
