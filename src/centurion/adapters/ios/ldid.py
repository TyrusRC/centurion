"""Adapter for ldid (dump code-signing entitlements from a Mach-O binary — iOS static).

``ldid -e <binary>`` prints the binary's entitlements as an XML plist, which we parse into a
dict so callers can inspect get-task-allow, app groups, keychain access groups, etc.
"""

from __future__ import annotations

import plistlib

from ...models import Category, Platform
from ..base import Adapter


class LdidAdapter(Adapter):
    name = "ldid"
    binary = "ldid"
    mastg_id = "MASTG-TOOL-0111"
    platform = Platform.IOS
    category = Category.STATIC

    def install_hint(self) -> str:
        return "Install ldid: `brew install ldid` (or build from github.com/ProcursusTeam/ldid)"

    def entitlements_command(self, binary: str) -> list[str]:
        return ["ldid", "-e", binary]

    def parse_entitlements(self, stdout: str) -> dict:
        text = stdout.strip()
        if not text:
            return {}
        try:
            return plistlib.loads(text.encode())
        except plistlib.InvalidFileException:
            return {}

    def entitlements(self, binary: str) -> dict:
        result = self.runner.run(self.entitlements_command(binary), timeout=60)
        return self.parse_entitlements(result.stdout)
