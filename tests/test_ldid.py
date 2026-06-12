import plistlib

from centurion.adapters.ios.ldid import LdidAdapter
from centurion.process import FakeRunner

ENTITLEMENTS = plistlib.dumps(
    {"application-identifier": "ABCDE.com.acme.bank", "get-task-allow": False},
    fmt=plistlib.FMT_XML,
).decode()


def test_ldid_metadata():
    a = LdidAdapter()
    assert a.name == "ldid"
    assert a.mastg_id == "MASTG-TOOL-0111"
    assert a.platform.value == "ios"
    assert a.category.value == "static"


def test_ldid_entitlements_command():
    assert LdidAdapter().entitlements_command("/tmp/Acme") == ["ldid", "-e", "/tmp/Acme"]


def test_ldid_parse_entitlements():
    ents = LdidAdapter().parse_entitlements(ENTITLEMENTS)
    assert ents["application-identifier"] == "ABCDE.com.acme.bank"
    assert ents["get-task-allow"] is False


def test_ldid_parse_empty_and_invalid():
    assert LdidAdapter().parse_entitlements("") == {}
    assert LdidAdapter().parse_entitlements("not a plist") == {}


def test_ldid_entitlements_runs():
    fake = FakeRunner()
    fake.register("ldid -e", stdout=ENTITLEMENTS)
    assert LdidAdapter(fake).entitlements("/tmp/Acme")["get-task-allow"] is False
