"""Bundled, vetted Frida scripts and the registry that exposes them.

All scripts are original and labelled for authorized testing only.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources


@dataclass
class ScriptInfo:
    name: str
    description: str
    platform: str
    path: str


_CATALOG = {
    "ssl_unpin": ("Bypass common TLS certificate pinning (TrustManager + OkHttp)", "android"),
    "root_bypass": ("Hide common root indicators from File.exists checks", "android"),
    "debugger_bypass": ("Force isDebuggerConnected to report false", "android"),
    "dump_class_hooks": ("Enumerate declared methods of a target class", "android"),
}


class ScriptLibrary:
    """Lists and resolves the bundled Frida scripts via importlib.resources."""

    _package = "centurion.scripts.frida"

    def list(self) -> list[ScriptInfo]:
        return [self.get(name) for name in _CATALOG]

    def get(self, name: str) -> ScriptInfo:
        if name not in _CATALOG:
            raise KeyError(f"No bundled script named '{name}'")
        description, platform = _CATALOG[name]
        path = resources.files(self._package).joinpath(f"{name}.js")
        return ScriptInfo(name=name, description=description, platform=platform, path=str(path))

    def path(self, name: str) -> str:
        return self.get(name).path
