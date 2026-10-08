from centurion.adapters.ios.ldid import LdidAdapter
from centurion.adapters.ios.otool import OtoolAdapter
from centurion.process import RunResult


class _WhichRunner:
    def __init__(self, present):
        self.present = set(present)

    def run(self, args, *, timeout=None):
        return RunResult(list(args), 0, "", "")

    def which(self, binary):
        return ("/usr/bin/" + binary) if binary in self.present else None


def test_otool_falls_back_to_llvm_otool_on_linux():
    a = OtoolAdapter(_WhichRunner(["llvm-otool"]))  # real otool absent
    assert a.binary == "llvm-otool"
    assert a.header_command("/bin/app")[0] == "llvm-otool"
    assert a.version_command()[0] == "llvm-otool"


def test_otool_prefers_real_otool_when_present():
    a = OtoolAdapter(_WhichRunner(["otool", "llvm-otool"]))
    assert a.binary == "otool"


def test_ldid_parse_tolerates_non_plist_and_bad_xml():
    assert LdidAdapter().parse_entitlements("ldid: cannot open file") == {}
    assert LdidAdapter().parse_entitlements("<plist garbage without close") == {}
    assert LdidAdapter().parse_entitlements("") == {}
