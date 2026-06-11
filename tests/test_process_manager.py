import pytest

from centurion.process import ManagedProcess, ProcessManager, WorkspaceProcessManager
from centurion.session import Workspace


class FakeProc:
    def __init__(self, pid):
        self.pid = pid
        self.terminated = False

    def terminate(self):
        self.terminated = True


def test_start_registers_process():
    spawned = {}

    def fake_spawn(command):
        proc = FakeProc(pid=4242)
        spawned["proc"] = proc
        spawned["command"] = command
        return proc

    pm = ProcessManager(spawn=fake_spawn)
    managed = pm.start("scrcpy", ["scrcpy", "--serial", "x"])

    assert isinstance(managed, ManagedProcess)
    assert managed.handle == "scrcpy"
    assert managed.pid == 4242
    assert managed.command == ["scrcpy", "--serial", "x"]
    assert pm.list() == ["scrcpy"]


def test_stop_terminates_and_removes():
    proc = FakeProc(pid=1)
    pm = ProcessManager(spawn=lambda command: proc)
    pm.start("scrcpy", ["scrcpy"])

    assert pm.stop("scrcpy") is True
    assert proc.terminated is True
    assert pm.list() == []


def test_stop_unknown_handle_returns_false():
    pm = ProcessManager(spawn=lambda command: FakeProc(pid=1))
    assert pm.stop("ghost") is False


def test_start_same_handle_terminates_previous():
    procs = []

    def spawn(command):
        p = FakeProc(pid=len(procs) + 1)
        procs.append(p)
        return p

    pm = ProcessManager(spawn=spawn)
    pm.start("scrcpy", ["scrcpy"])
    pm.start("scrcpy", ["scrcpy"])  # reuse handle

    assert procs[0].terminated is True   # first one was terminated
    assert procs[1].terminated is False  # second is live
    assert pm.list() == ["scrcpy"]


def _ws(tmp_path):
    ws = Workspace(tmp_path, target="app")
    ws.create()
    return ws


def test_workspace_pm_start_persists_handle(tmp_path):
    ws = _ws(tmp_path)
    pm = WorkspaceProcessManager(ws, spawn=lambda command: FakeProc(pid=999), kill=lambda pid: None)
    managed = pm.start("proxy", ["mitmdump", "-p", "8080"])
    assert managed.pid == 999
    # Persisted to session.json, visible to a fresh manager (simulates new MCP process).
    fresh = WorkspaceProcessManager(ws, spawn=lambda c: FakeProc(pid=1), kill=lambda pid: None)
    assert fresh.list() == [{"handle": "proxy", "pid": 999, "command": ["mitmdump", "-p", "8080"]}]


def test_workspace_pm_stop_signals_and_removes(tmp_path):
    ws = _ws(tmp_path)
    killed = []
    pm = WorkspaceProcessManager(ws, spawn=lambda c: FakeProc(pid=42), kill=lambda pid: killed.append(pid))
    pm.start("proxy", ["mitmdump"])
    assert pm.stop("proxy") is True
    assert killed == [42]
    assert pm.list() == []


def test_workspace_pm_stop_unknown_returns_false(tmp_path):
    ws = _ws(tmp_path)
    pm = WorkspaceProcessManager(ws, spawn=lambda c: FakeProc(pid=1), kill=lambda pid: None)
    assert pm.stop("ghost") is False


def test_workspace_pm_reusing_handle_signals_previous(tmp_path):
    ws = _ws(tmp_path)
    killed = []
    pids = iter([10, 11])
    pm = WorkspaceProcessManager(
        ws,
        spawn=lambda c: FakeProc(pid=next(pids)),
        kill=lambda pid: killed.append(pid),
    )
    pm.start("proxy", ["mitmdump"])
    pm.start("proxy", ["mitmdump"])  # reuse handle -> previous pid signalled
    assert killed == [10]
    assert pm.list() == [{"handle": "proxy", "pid": 11, "command": ["mitmdump"]}]


def test_workspace_pm_failed_respawn_preserves_existing(tmp_path):
    ws = _ws(tmp_path)
    killed = []
    calls = {"n": 0}

    def spawn(command):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeProc(pid=5)
        raise FileNotFoundError("mitmdump")

    pm = WorkspaceProcessManager(ws, spawn=spawn, kill=lambda pid: killed.append(pid))
    pm.start("proxy", ["mitmdump"])
    # A failed respawn must not kill the existing process nor corrupt the handle.
    with pytest.raises(FileNotFoundError):
        pm.start("proxy", ["mitmdump"])
    assert killed == []
    assert pm.list() == [{"handle": "proxy", "pid": 5, "command": ["mitmdump"]}]
