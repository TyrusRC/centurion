"""Subprocess execution abstraction.

Everything that shells out goes through a Runner so adapters can be unit-tested
with canned output and never touch a real device.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Callable, Protocol


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


@dataclass
class ManagedProcess:
    handle: str
    pid: int
    command: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _real_spawn(command: list[str]):
    return subprocess.Popen(command)


class ProcessManager:
    """Tracks long-running background tools (scrcpy, mitmproxy, frida-server)."""

    def __init__(self, spawn: Callable[[list[str]], Any] | None = None) -> None:
        self._spawn = spawn or _real_spawn
        self._procs: dict[str, Any] = {}

    def start(self, handle: str, command: list[str]) -> ManagedProcess:
        existing = self._procs.get(handle)
        if existing is not None:
            existing.terminate()
        proc = self._spawn(command)
        self._procs[handle] = proc
        return ManagedProcess(handle=handle, pid=proc.pid, command=list(command))

    def stop(self, handle: str) -> bool:
        proc = self._procs.get(handle)
        if proc is None:
            return False
        proc.terminate()
        del self._procs[handle]
        return True

    def list(self) -> list[str]:
        return list(self._procs)


def _real_kill(pid: int) -> None:
    os.kill(pid, signal.SIGTERM)


class WorkspaceProcessManager:
    """Tracks long-running tools, persisting handles to the workspace session
    so they survive across separate MCP server invocations (no daemon)."""

    def __init__(
        self,
        workspace,
        spawn: Callable[[list[str]], Any] | None = None,
        kill: Callable[[int], None] | None = None,
    ) -> None:
        self._workspace = workspace
        self._spawn = spawn or _real_spawn
        self._kill = kill or _real_kill

    def start(self, handle: str, command: list[str]) -> ManagedProcess:
        existing = self._find(handle)
        # Spawn the replacement first: if it fails, the existing process and the
        # persisted handle are left untouched rather than orphaned.
        proc = self._spawn(command)
        if existing is not None:
            self._kill(existing["pid"])
        session = self._workspace.load()
        session.processes = [p for p in session.processes if p["handle"] != handle]
        session.processes.append({"handle": handle, "pid": proc.pid, "command": list(command)})
        self._workspace.save(session)
        return ManagedProcess(handle=handle, pid=proc.pid, command=list(command))

    def stop(self, handle: str) -> bool:
        entry = self._find(handle)
        if entry is None:
            return False
        self._kill(entry["pid"])
        session = self._workspace.load()
        session.processes = [p for p in session.processes if p["handle"] != handle]
        self._workspace.save(session)
        return True

    def list(self) -> list[dict]:
        return self._workspace.load().processes

    def _find(self, handle: str) -> dict | None:
        for entry in self._workspace.load().processes:
            if entry["handle"] == handle:
                return entry
        return None
