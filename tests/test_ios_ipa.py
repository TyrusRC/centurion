import plistlib
import zipfile
from pathlib import Path

from centurion.ios.ipa import read_plist, ipa_info


def test_read_plist_binary(tmp_path: Path):
    p = tmp_path / "Info.plist"
    p.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.acme.bank"}, fmt=plistlib.FMT_BINARY))
    assert read_plist(str(p))["CFBundleIdentifier"] == "com.acme.bank"


def test_read_plist_xml(tmp_path: Path):
    p = tmp_path / "Info.plist"
    p.write_bytes(plistlib.dumps({"MinimumOSVersion": "15.0"}, fmt=plistlib.FMT_XML))
    assert read_plist(str(p))["MinimumOSVersion"] == "15.0"


def test_ipa_info_extracts_app_plist(tmp_path: Path):
    ipa = tmp_path / "app.ipa"
    info = {"CFBundleIdentifier": "com.acme.bank", "MinimumOSVersion": "15.0"}
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/Acme.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_XML))
        zf.writestr("Payload/Acme.app/Acme", b"\xca\xfe\xba\xbe")  # fake Mach-O
    result = ipa_info(str(ipa))
    assert result["bundle_id"] == "com.acme.bank"
    assert result["minimum_os"] == "15.0"
    assert result["app_path"] == "Payload/Acme.app"


def test_ipa_info_raises_without_payload(tmp_path: Path):
    ipa = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("not_payload/x.txt", "nope")
    try:
        ipa_info(str(ipa))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "Info.plist" in str(e)


def test_ipa_info_tolerates_non_dict_ats(tmp_path: Path):
    ipa = tmp_path / "app.ipa"
    info = {"CFBundleIdentifier": "com.acme.bank", "NSAppTransportSecurity": "garbage"}
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/Acme.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_XML))
    result = ipa_info(str(ipa))
    assert result["ats_allows_arbitrary_loads"] is False
