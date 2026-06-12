from centurion.adapters.ios.otool import OtoolAdapter
from centurion.models import Finding
from centurion.process import FakeRunner

HEADER_PIE = "Mach header\n  magic cputype ... flags\n  MH_MAGIC_64 ARM64 ... NOUNDEFS DYLDLINK TWOLEVEL PIE\n"
HEADER_NOPIE = "Mach header\n  MH_MAGIC_64 ARM64 ... NOUNDEFS DYLDLINK TWOLEVEL\n"
LOADCMDS_ENC = "Load command 12\n  cmd LC_ENCRYPTION_INFO_64\n  cryptoff 16384\n  cryptid 1\n"
LOADCMDS_DEC = "Load command 12\n  cmd LC_ENCRYPTION_INFO_64\n  cryptoff 16384\n  cryptid 0\n"
SYMS = "0x0 ___stack_chk_guard\n0x8 _objc_release\n"
LIBS = "/tmp/Acme:\n\t/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0)\n\t@rpath/libswiftCore.dylib (compatibility version 1.0.0)\n"


def test_otool_metadata():
    a = OtoolAdapter()
    assert a.name == "otool"
    assert a.mastg_id == "MASTG-TOOL-0060"
    assert a.platform.value == "ios"
    assert a.category.value == "static"


def test_otool_command_builders():
    a = OtoolAdapter()
    assert a.header_command("/b") == ["otool", "-hv", "/b"]
    assert a.load_commands_command("/b") == ["otool", "-l", "/b"]
    assert a.symbols_command("/b") == ["otool", "-Iv", "/b"]
    assert a.libraries_command("/b") == ["otool", "-L", "/b"]


def test_otool_parsers():
    a = OtoolAdapter()
    assert a.parse_pie(HEADER_PIE) is True
    assert a.parse_pie(HEADER_NOPIE) is False
    assert a.parse_encrypted(LOADCMDS_ENC) is True
    assert a.parse_encrypted(LOADCMDS_DEC) is False
    prot = a.parse_symbol_protections(SYMS)
    assert prot == {"stack_canary": True, "arc": True}
    assert a.parse_libraries(LIBS) == [
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "@rpath/libswiftCore.dylib",
    ]


def test_otool_hardening_aggregates():
    fake = FakeRunner()
    fake.register("otool -hv", stdout=HEADER_NOPIE)
    fake.register("otool -l", stdout=LOADCMDS_DEC)
    fake.register("otool -Iv", stdout=SYMS)
    fake.register("otool -L", stdout=LIBS)
    info = OtoolAdapter(fake).hardening("/tmp/Acme")
    assert info["pie"] is False
    assert info["encrypted"] is False
    assert info["stack_canary"] is True
    assert "@rpath/libswiftCore.dylib" in info["libraries"]


def test_otool_hardening_findings():
    a = OtoolAdapter()
    info = {"pie": False, "encrypted": False, "stack_canary": False, "libraries": []}
    findings = a.hardening_findings("/tmp/Acme", info)
    assert all(isinstance(f, Finding) and f.tool == "otool" for f in findings)
    titles = {f.title for f in findings}
    assert "Binary not built with PIE/ASLR" in titles
    assert "No stack canary" in titles
    # A fully-hardened, encrypted binary yields no findings.
    assert a.hardening_findings("/b", {"pie": True, "encrypted": True, "stack_canary": True}) == []
