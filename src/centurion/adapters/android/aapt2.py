"""Adapter for aapt2 (Android Asset Packaging Tool — dump APK badging, static).

``aapt2 dump badging <apk>`` prints the package name/version, SDK levels and the requested
permissions without a full decode.
"""

from __future__ import annotations

import re

from ...models import Category, Platform
from ..base import Adapter

_PKG = re.compile(r"package: name='([^']*)'(?:.*versionCode='([^']*)')?(?:.*versionName='([^']*)')?")
_SDK = re.compile(r"sdkVersion:'([^']*)'")
_TARGET = re.compile(r"targetSdkVersion:'([^']*)'")
_PERM = re.compile(r"uses-permission: name='([^']*)'")


class Aapt2Adapter(Adapter):
    name = "aapt2"
    binary = "aapt2"
    mastg_id = "MASTG-TOOL-0124"
    platform = Platform.ANDROID
    category = Category.STATIC

    def version_command(self) -> list[str]:
        return ["aapt2", "version"]

    def install_hint(self) -> str:
        return "Install aapt2 (Android SDK build-tools): `sdkmanager 'build-tools;34.0.0'`"

    def badging_command(self, apk: str) -> list[str]:
        return ["aapt2", "dump", "badging", apk]

    def parse_badging(self, stdout: str) -> dict:
        pkg = _PKG.search(stdout)
        sdk = _SDK.search(stdout)
        target = _TARGET.search(stdout)
        return {
            "package": pkg.group(1) if pkg else None,
            "version_code": pkg.group(2) if pkg else None,
            "version_name": pkg.group(3) if pkg else None,
            "min_sdk": sdk.group(1) if sdk else None,
            "target_sdk": target.group(1) if target else None,
            "permissions": _PERM.findall(stdout),
        }

    def badging(self, apk: str) -> dict:
        result = self.runner.run(self.badging_command(apk), timeout=120)
        return self.parse_badging(result.stdout)
