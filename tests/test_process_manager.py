from centurion.process import ManagedProcess, ProcessManager


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
