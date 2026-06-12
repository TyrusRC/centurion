from centurion.adapters.ios.classdump import ClassDumpAdapter
from centurion.models import Category, Platform
from centurion.process import FakeRunner


def test_metadata():
    a = ClassDumpAdapter()
    assert a.name == "class-dump"
    assert a.binary == "class-dump"
    assert a.platform == Platform.IOS
    assert a.category == Category.STATIC


def test_headers_command():
    a = ClassDumpAdapter()
    assert a.headers_command("/tmp/App", "/tmp/hdr") == ["class-dump", "-H", "-o", "/tmp/hdr", "/tmp/App"]


def test_headers_returns_artifact():
    fake = FakeRunner()
    fake.register("class-dump -H -o /tmp/hdr /tmp/App", stdout="")
    artifact = ClassDumpAdapter(fake).headers("/tmp/App", "/tmp/hdr")
    assert artifact.kind == "decoded"
    assert artifact.tool == "class-dump"
    assert artifact.path == "/tmp/hdr"
    assert artifact.id == "classdump-App"


def test_headers_raises_on_failure():
    fake = FakeRunner()
    fake.register("class-dump", returncode=1, stderr="not an Objective-C binary\n")
    try:
        ClassDumpAdapter(fake).headers("/tmp/App", "/tmp/hdr")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "Objective-C" in str(e)
