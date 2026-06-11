import pytest

from centurion.adapters.generic.opengrep import OpengrepAdapter, default_rules_path
from centurion.models import Finding
from centurion.process import FakeRunner

SAMPLE_JSON = """\
{"results": [
  {"check_id": "android.cleartext", "path": "app/Main.java",
   "start": {"line": 42},
   "extra": {"message": "Cleartext HTTP traffic", "severity": "WARNING",
             "metadata": {"mastg": ["MASTG-TEST-0066"]}}},
  {"check_id": "android.weak-crypto", "path": "app/Crypto.java",
   "start": {"line": 7},
   "extra": {"message": "Weak cipher", "severity": "ERROR", "metadata": {}}}
], "errors": []}
"""


def test_opengrep_detect():
    runner = FakeRunner()
    runner.register("opengrep --version", stdout="1.2.0\n", path="/usr/bin/opengrep")
    status = OpengrepAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "generic"
    assert status.category == "static"


def test_opengrep_scan_command_uses_scan_subcommand():
    assert OpengrepAdapter().scan_command("/tmp/src", "/tmp/rules") == [
        "opengrep", "scan", "--config", "/tmp/rules", "--json", "/tmp/src",
    ]


def test_opengrep_parse_scan_maps_severity_and_refs():
    findings = OpengrepAdapter().parse_scan(SAMPLE_JSON)
    assert len(findings) == 2
    assert isinstance(findings[0], Finding)
    assert findings[0].tool == "opengrep"
    assert findings[0].title == "android.cleartext"
    assert findings[0].severity == "medium"  # WARNING -> medium
    assert findings[0].location == "app/Main.java:42"
    assert findings[0].mastg_refs == ["MASTG-TEST-0066"]
    assert findings[1].severity == "high"  # ERROR -> high


def test_opengrep_scan_missing_rules_raises(tmp_path):
    runner = FakeRunner()
    missing = str(tmp_path / "no-rules")
    with pytest.raises(RuntimeError, match="rules"):
        OpengrepAdapter(runner).scan("/tmp/src", rules=missing)


def test_opengrep_scan_runs_and_parses(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    runner = FakeRunner()
    runner.register("opengrep scan --config", stdout=SAMPLE_JSON)
    findings = OpengrepAdapter(runner).scan("/tmp/src", rules=str(rules))
    assert [f.title for f in findings] == ["android.cleartext", "android.weak-crypto"]


def test_default_rules_path_under_centurion_home():
    assert default_rules_path().name == "rules"
    assert ".centurion" in str(default_rules_path())
