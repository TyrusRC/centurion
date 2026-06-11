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
    """Build the registry with all Phase 1 adapters."""
    from .adapters.android.adb import AdbAdapter
    from .adapters.android.jadx import JadxAdapter
    from .adapters.android.scrcpy import ScrcpyAdapter
    from .adapters.generic.frida import FridaAdapter

    return Registry(
        [
            AdbAdapter(runner),
            ScrcpyAdapter(runner),
            JadxAdapter(runner),
            FridaAdapter(runner),
        ]
    )
