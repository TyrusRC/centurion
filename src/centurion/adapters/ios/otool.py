"""Adapter for otool (Mach-O binary inspection — iOS static hardening checks).

Reports the protections an iOS app binary was built with: PIE/ASLR (``otool -hv`` header
flags), FairPlay encryption (``otool -l`` LC_ENCRYPTION_INFO ``cryptid``), stack canary and
ARC (``otool -Iv`` imported symbols), and linked libraries (``otool -L``). This mirrors the
"binary protections" view offered by MobSF and objection's ``ios info binary``.
"""

from __future__ import annotations

import re

from ...models import Category, Finding, Platform
from ..base import Adapter

_CRYPTID = re.compile(r"cryptid\s+(\d+)")


class OtoolAdapter(Adapter):
    name = "otool"
    binary = "otool"
    mastg_id = "MASTG-TOOL-0060"
    platform = Platform.IOS
    category = Category.STATIC

    def version_command(self) -> list[str]:
        return ["otool", "--version"]

    def install_hint(self) -> str:
        return (
            "Install otool (macOS Xcode command line tools): `xcode-select --install`; "
            "on Linux use cctools / `llvm-otool`."
        )

    def header_command(self, binary: str) -> list[str]:
        return ["otool", "-hv", binary]

    def load_commands_command(self, binary: str) -> list[str]:
        return ["otool", "-l", binary]

    def symbols_command(self, binary: str) -> list[str]:
        return ["otool", "-Iv", binary]

    def libraries_command(self, binary: str) -> list[str]:
        return ["otool", "-L", binary]

    def parse_pie(self, header_stdout: str) -> bool:
        return "PIE" in header_stdout

    def parse_encrypted(self, load_commands_stdout: str) -> bool:
        return any(int(m) > 0 for m in _CRYPTID.findall(load_commands_stdout))

    def parse_symbol_protections(self, symbols_stdout: str) -> dict:
        return {
            "stack_canary": "stack_chk" in symbols_stdout,
            "arc": "_objc_release" in symbols_stdout
            or "_objc_autoreleaseReturnValue" in symbols_stdout,
        }

    def parse_libraries(self, libraries_stdout: str) -> list[str]:
        libs: list[str] = []
        for line in libraries_stdout.splitlines():
            if line.startswith(("\t", " ")) and line.strip():
                libs.append(line.strip().split(" (", 1)[0])
        return libs

    def hardening(self, binary: str) -> dict:
        header = self.runner.run(self.header_command(binary), timeout=120).stdout
        load_cmds = self.runner.run(self.load_commands_command(binary), timeout=120).stdout
        symbols = self.runner.run(self.symbols_command(binary), timeout=120).stdout
        libs = self.runner.run(self.libraries_command(binary), timeout=120).stdout
        info = {
            "pie": self.parse_pie(header),
            "encrypted": self.parse_encrypted(load_cmds),
            "libraries": self.parse_libraries(libs),
        }
        info.update(self.parse_symbol_protections(symbols))
        return info

    def hardening_findings(self, binary: str, info: dict) -> list[Finding]:
        findings: list[Finding] = []
        if not info.get("pie"):
            findings.append(
                Finding(
                    id=f"otool:no-pie:{binary}", title="Binary not built with PIE/ASLR",
                    severity="medium", tool="otool",
                    detail="Mach-O header lacks the PIE flag; load address is not randomized.",
                    location=binary,
                )
            )
        if not info.get("encrypted"):
            findings.append(
                Finding(
                    id=f"otool:not-encrypted:{binary}", title="App binary is not encrypted",
                    severity="low", tool="otool",
                    detail="No LC_ENCRYPTION_INFO with cryptid>0; the binary is already decrypted.",
                    location=binary,
                )
            )
        if not info.get("stack_canary"):
            findings.append(
                Finding(
                    id=f"otool:no-canary:{binary}", title="No stack canary",
                    severity="low", tool="otool",
                    detail="No __stack_chk symbols found; stack-smashing protection may be absent.",
                    location=binary,
                )
            )
        return findings
