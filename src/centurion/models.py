"""Structured data models shared across Centurion."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    GENERIC = "generic"
    NETWORK = "network"


class Category(str, Enum):
    DEVICE_QA = "device-qa"
    STATIC = "static"
    DYNAMIC = "dynamic"
    NETWORK = "network"
    RECON = "recon"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolStatus:
    name: str
    installed: bool
    mastg_id: str | None = None
    platform: str | None = None
    category: str | None = None
    version: str | None = None
    path: str | None = None
    install_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Artifact:
    id: str
    kind: str  # decompiled | pcap | frida-log | screenshot | binary
    path: str
    tool: str
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AppleDevice:
    udid: str
    name: str | None = None
    ios_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    tool: str
    detail: str = ""
    location: str | None = None
    mastg_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
