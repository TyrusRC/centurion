"""Adapter registry: discovery, filtering, and the MASTG mapping."""

from __future__ import annotations

from .adapters.base import Adapter
from .models import Category, Platform, ToolStatus
from .process import Runner


class Registry:
    def __init__(self, adapters: list[Adapter] | None = None) -> None:
        self._adapters: dict[str, Adapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: Adapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> Adapter:
        try:
            return self._adapters[name]
        except KeyError:
            raise KeyError(f"No adapter registered for '{name}'") from None

    def all(self) -> list[Adapter]:
        return list(self._adapters.values())

    def by_platform(self, platform: Platform) -> list[Adapter]:
        return [a for a in self._adapters.values() if a.platform == platform]

    def by_category(self, category: Category) -> list[Adapter]:
        return [a for a in self._adapters.values() if a.category == category]

    def doctor(self) -> list[ToolStatus]:
        return [a.detect() for a in self._adapters.values()]


def default_registry(runner: Runner | None = None) -> Registry:
    """Build the registry with all currently-implemented adapters."""
    from .adapters.android.adb import AdbAdapter
    from .adapters.android.apksigner import ApksignerAdapter
    from .adapters.android.apktool import ApktoolAdapter
    from .adapters.android.dex2jar import Dex2jarAdapter
    from .adapters.android.drozer import DrozerAdapter
    from .adapters.android.jadx import JadxAdapter
    from .adapters.android.objection import ObjectionAdapter
    from .adapters.android.scrcpy import ScrcpyAdapter
    from .adapters.generic.frida import FridaAdapter
    from .adapters.generic.mitmproxy import MitmproxyAdapter
    from .adapters.generic.radare2 import Radare2Adapter
    from .adapters.generic.opengrep import OpengrepAdapter
    from .adapters.generic.strings import StringsAdapter
    from .adapters.generic.tcpdump import TcpdumpAdapter

    return Registry(
        [
            AdbAdapter(runner),
            ScrcpyAdapter(runner),
            JadxAdapter(runner),
            FridaAdapter(runner),
            ApktoolAdapter(runner),
            Dex2jarAdapter(runner),
            ApksignerAdapter(runner),
            OpengrepAdapter(runner),
            Radare2Adapter(runner),
            StringsAdapter(runner),
            ObjectionAdapter(runner),
            DrozerAdapter(runner),
            MitmproxyAdapter(runner),
            TcpdumpAdapter(runner),
        ]
    )
