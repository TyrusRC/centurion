"""Subprocess execution abstraction.

Everything that shells out goes through a Runner so adapters can be unit-tested
with canned output and never touch a real device.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass
class RunResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    def run(self, args: list[str], *, timeout: float | None = None) -> RunResult: ...

    def which(self, binary: str) -> str | None: ...


class RealRunner:
    """Runs commands for real via subprocess."""

    def run(self, args: list[str], *, timeout: float | None = None) -> RunResult:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return RunResult(list(args), proc.returncode, proc.stdout, proc.stderr)

    def which(self, binary: str) -> str | None:
        return shutil.which(binary)


class FakeRunner:
    """Test double. Register canned responses keyed by command-line prefix."""

    def __init__(self) -> None:
        self._responses: dict[str, RunResult] = {}
        self._paths: dict[str, str] = {}
        self.calls: list[list[str]] = []

    def register(
        self,
        prefix: str,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        path: str | None = None,
    ) -> None:
        self._responses[prefix] = RunResult([], returncode, stdout, stderr)
        if path is not None:
            self._paths[prefix.split()[0]] = path

    def run(self, args: list[str], *, timeout: float | None = None) -> RunResult:
        self.calls.append(list(args))
        key = " ".join(args)
        for prefix, resp in self._responses.items():
            if key.startswith(prefix):
                return RunResult(list(args), resp.returncode, resp.stdout, resp.stderr)
        raise FileNotFoundError(args[0])

    def which(self, binary: str) -> str | None:
        return self._paths.get(binary)
