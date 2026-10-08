"""Adapter for apksigner (verify APK signing schemes — static analysis)."""

from __future__ import annotations

import re

from dataclasses import asdict, dataclass
from typing import Any

from ...models import Category, Platform
from ..base import Adapter


_SCHEME_RE = re.compile(r"using (v\d) scheme[^:]*:\s*(true|false)", re.I)


@dataclass
class SignatureInfo:
    v1: bool
    v2: bool
    v3: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApksignerAdapter(Adapter):
    name = "apksigner"
    binary = "apksigner"
    mastg_id = "MASTG-TOOL-0123"  # apksigner
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install apksigner (Android SDK build-tools): `sdkmanager 'build-tools;34.0.0'`"

    def verify_command(self, apk: str) -> list[str]:
        return ["apksigner", "verify", "--print-certs", "-v", apk]

    def parse_verify(self, stdout: str) -> SignatureInfo:
        # apksigner prints e.g. "Verified using v2 scheme (APK Signature Scheme v2): true".
        # Extract the boolean per scheme defensively (value after the colon), rather than
        # matching the whole line's suffix.
        found = {m.group(1).lower(): m.group(2).lower() == "true"
                 for m in _SCHEME_RE.finditer(stdout)}
        return SignatureInfo(v1=found.get("v1", False), v2=found.get("v2", False),
                             v3=found.get("v3", False))

    def verify(self, apk: str) -> SignatureInfo:
        result = self.runner.run(self.verify_command(apk), timeout=60)
        return self.parse_verify(result.stdout)
