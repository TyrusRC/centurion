from centurion.adapters.generic.gitleaks import GitleaksAdapter
from centurion.models import Finding
from centurion.process import FakeRunner

SAMPLE_JSON = """\
[
  {"RuleID": "aws-access-key", "Description": "AWS Access Key", "File": "src/Config.java",
   "StartLine": 12, "Match": "AKIAIOSFODNN7EXAMPLE"},
  {"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "res/strings.xml",
   "StartLine": 3, "Match": "api_key = 0xdeadbeef"}
]
"""


def test_gitleaks_metadata():
    a = GitleaksAdapter()
    assert a.name == "gitleaks"
    assert a.mastg_id == "MASTG-TOOL-0144"
    assert a.platform.value == "generic"
    assert a.category.value == "static"


def test_gitleaks_scan_command():
    assert GitleaksAdapter().scan_command("/tmp/src", "/tmp/r.json") == [
        "gitleaks", "dir", "/tmp/src",
        "--report-format", "json", "--report-path", "/tmp/r.json", "--no-banner",
    ]


def test_gitleaks_parse_report():
    findings = GitleaksAdapter().parse_report(SAMPLE_JSON)
    assert len(findings) == 2
    assert all(isinstance(f, Finding) and f.severity == "high" for f in findings)
    assert findings[0].title == "AWS Access Key"
    assert findings[0].location == "src/Config.java:12"


def test_gitleaks_parse_empty_report():
    assert GitleaksAdapter().parse_report("") == []
    assert GitleaksAdapter().parse_report("[]") == []


def test_gitleaks_scan_reads_report(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(SAMPLE_JSON)
    fake = FakeRunner()
    fake.register("gitleaks dir", returncode=1, stdout="")  # non-zero when leaks found
    findings = GitleaksAdapter(fake).scan("/tmp/src", str(report))
    assert [f.title for f in findings] == ["AWS Access Key", "Generic API Key"]
