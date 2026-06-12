from centurion.adapters.android.apkleaks import ApkleaksAdapter
from centurion.models import Finding
from centurion.process import FakeRunner

SAMPLE_JSON = """\
{"package": "com.acme.app", "results": [
  {"name": "LinkFinder", "matches": ["https://api.acme.com/v1", "/internal/health"]},
  {"name": "AWS API Key", "matches": ["AKIAIOSFODNN7EXAMPLE"]}
]}
"""


def test_apkleaks_metadata():
    a = ApkleaksAdapter()
    assert a.name == "apkleaks"
    assert a.mastg_id == "MASTG-TOOL-0125"
    assert a.platform.value == "android"
    assert a.category.value == "static"


def test_apkleaks_scan_command():
    assert ApkleaksAdapter().scan_command("/tmp/app.apk", "/tmp/out.json") == [
        "apkleaks", "-f", "/tmp/app.apk", "-o", "/tmp/out.json", "--json",
    ]


def test_apkleaks_parse_results_severity():
    findings = ApkleaksAdapter().parse_results(SAMPLE_JSON)
    assert len(findings) == 3
    assert all(isinstance(f, Finding) and f.tool == "apkleaks" for f in findings)
    secret = next(f for f in findings if f.title == "AWS API Key")
    assert secret.severity == "medium"  # key -> credential material
    link = next(f for f in findings if f.detail == "https://api.acme.com/v1")
    assert link.severity == "low"


def test_apkleaks_scan_reads_output_file(tmp_path):
    out = tmp_path / "out.json"
    out.write_text(SAMPLE_JSON)
    fake = FakeRunner()
    fake.register("apkleaks -f", stdout="written to out.json\n")
    findings = ApkleaksAdapter(fake).scan("/tmp/app.apk", str(out))
    assert {f.title for f in findings} == {"LinkFinder", "AWS API Key"}
    assert fake.calls[0][:2] == ["apkleaks", "-f"]
