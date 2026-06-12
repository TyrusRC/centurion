from centurion.adapters.generic.frida import FridaAdapter, FridaProcess
from centurion.process import FakeRunner
from centurion.registry import default_registry


def test_frida_detect():
    runner = FakeRunner()
    runner.register("frida --version", stdout="16.2.1\n", path="/usr/bin/frida")
    status = FridaAdapter(runner).detect()
    assert status.installed is True
    assert status.mastg_id == "MASTG-TOOL-0031"
    assert status.category == "dynamic"
    assert status.platform == "generic"


def test_frida_ps_command_usb():
    assert FridaAdapter().ps_command(usb=True) == ["frida-ps", "-U"]
    assert FridaAdapter().ps_command(usb=False) == ["frida-ps"]


def test_frida_parse_ps_list():
    runner = FakeRunner()
    runner.register(
        "frida-ps -U",
        stdout=(
            "  PID  Name\n"
            "-----  ----------------\n"
            " 1234  com.acme.bank\n"
            " 5678  System UI\n"
        ),
    )
    procs = FridaAdapter(runner).list_processes(usb=True)
    assert procs == [
        FridaProcess(pid=1234, name="com.acme.bank"),
        FridaProcess(pid=5678, name="System UI"),
    ]


def test_default_registry_has_all_phase1_adapters():
    runner = FakeRunner()
    names = {a.name for a in default_registry(runner).all()}
    assert {"adb", "scrcpy", "jadx", "frida"}.issubset(names)


def test_run_script_command_attaches_over_usb():
    from centurion.adapters.generic.frida import FridaAdapter
    cmd = FridaAdapter().run_script_command("com.acme.app", "/tmp/ssl_unpin.js")
    assert cmd == ["frida", "-U", "-f", "com.acme.app", "-l", "/tmp/ssl_unpin.js"]
