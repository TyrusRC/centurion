"""Base class every tool adapter inherits from."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Category, Platform, ToolStatus
from ..process import RealRunner, RunResult, Runner


class Adapter(ABC):
    # Subclasses set these as class attributes.
    name: str
    binary: str
    mastg_id: str | None = None
    platform: Platform = Platform.GENERIC
    category: Category = Category.RECON

    def __init__(self, runner: Runner | None = None) -> None:
        self.runner = runner or RealRunner()

    def version_command(self) -> list[str]:
        return [self.binary, "--version"]

    def parse_version(self, result: RunResult) -> str | None:
        out = (result.stdout or result.stderr).strip()
        return out.splitlines()[0] if out else None

    @abstractmethod
    def install_hint(self) -> str:
        """Human-readable instruction for installing this tool."""

    def detect(self) -> ToolStatus:
        try:
            result = self.runner.run(self.version_command(), timeout=10)
        except FileNotFoundError:
            return self._status(installed=False)

        path = self.runner.which(self.binary)
        installed = path is not None or result.returncode == 0
        return self._status(
            installed=installed,
            version=self.parse_version(result) if installed else None,
            path=path,
        )

    def _status(
        self,
        *,
        installed: bool,
        version: str | None = None,
        path: str | None = None,
    ) -> ToolStatus:
        return ToolStatus(
            name=self.name,
            installed=installed,
            mastg_id=self.mastg_id,
            platform=self.platform.value,
            category=self.category.value,
            version=version,
            path=path,
            install_hint=self.install_hint(),
        )
