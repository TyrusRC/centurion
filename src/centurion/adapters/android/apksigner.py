"""Adapter for apksigner (verify APK signing schemes — static analysis)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ...models import Category, Platform
from ..base import Adapter


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
    mastg_id = None  # MASTG id not yet confirmed
    platform = Platform.ANDROID
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install apksigner (Android SDK build-tools): `sdkmanager 'build-tools;34.0.0'`"

    def verify_command(self, apk: str) -> list[str]:
        return ["apksigner", "verify", "--print-certs", "-v", apk]

    def parse_verify(self, stdout: str) -> SignatureInfo:
        def verified(scheme: str) -> bool:
            for line in stdout.splitlines():
                low = line.strip().lower()
                if f"using {scheme} scheme" in low:
                    return low.endswith("true")
            return False

        return SignatureInfo(v1=verified("v1"), v2=verified("v2"), v3=verified("v3"))

    def verify(self, apk: str) -> SignatureInfo:
        result = self.runner.run(self.verify_command(apk), timeout=60)
        return self.parse_verify(result.stdout)
