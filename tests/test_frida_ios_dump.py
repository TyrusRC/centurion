from centurion.adapters.ios.frida_ios_dump import FridaIosDumpAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = FridaIosDumpAdapter()
    assert a.name == "frida-ios-dump"
    assert a.binary == "frida-ios-dump"
    assert a.platform == Platform.IOS
    assert a.category == Category.DYNAMIC


def test_dump_command():
    a = FridaIosDumpAdapter()
    cmd = a.dump_command("com.acme.bank", "/tmp/out")
    assert cmd == ["frida-ios-dump", "-o", "/tmp/out/com.acme.bank.ipa", "com.acme.bank"]


def test_dump_returns_artifact():
    fake = FakeRunner()
    fake.register("frida-ios-dump", stdout="Generating dump... Done\n")
    artifact = FridaIosDumpAdapter(fake).dump("com.acme.bank", "/tmp/out")
    assert artifact.kind == "binary"
    assert artifact.tool == "frida-ios-dump"
    assert artifact.path == "/tmp/out/com.acme.bank.ipa"
    assert artifact.id == "ipa-com.acme.bank"


def test_dump_raises_on_failure():
    fake = FakeRunner()
    fake.register("frida-ios-dump", returncode=1, stderr="Failed to connect to frida-server\n")
    try:
        FridaIosDumpAdapter(fake).dump("com.acme.bank", "/tmp/out")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "frida-server" in str(e)
