"""Install planning: choose which tools a group selects, return the missing ones."""

from __future__ import annotations

from .models import ToolStatus
from .registry import Registry

_PLATFORMS = {"android", "ios", "generic", "network"}
_CATEGORIES = {"device-qa", "static", "dynamic", "network", "recon"}


def _selects(status: ToolStatus, group: str) -> bool:
    if group == "all":
        return True
    if group in _CATEGORIES:
        return status.category == group
    if group in _PLATFORMS:
        return status.platform == group
    return False


def plan_install(registry: Registry, group: str) -> list[ToolStatus]:
    """Return ToolStatus entries in `group` that are not yet installed."""
    return [s for s in registry.doctor() if _selects(s, group) and not s.installed]
