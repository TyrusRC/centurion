import sys
import types

import pytest

from centurion.adapters.generic.mantis import MantisAdapter
from centurion.process import FakeRunner


def test_parse_mantis_json_maps_native_records():
    # mantis's native `audit()` shape: rule_id / severity ERROR/WARNING/INFO /
    # path + start_line / message / metadata{masvs-v2}.
    records = [{
        "rule_id": "hardcoded-key", "severity": "ERROR", "path": "a/B.java",
        "start_line": 42, "message": "AWS key in source",
        "metadata": {"cwe": "CWE-798", "masvs-v2": ["MASVS-STORAGE-1"]},
        "verdict": None,
    }]
    findings = MantisAdapter(FakeRunner())._parse_mantis_json(records)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "hardcoded-key"
    assert f.severity == "high"          # ERROR -> high
    assert f.tool == "mantis"
    assert f.location == "a/B.java:42"
    assert f.masvs_refs == ["MASVS-STORAGE-1"]


def test_parse_mantis_json_defaults_and_severity_fallback():
    findings = MantisAdapter(FakeRunner())._parse_mantis_json(
        [{"rule_id": "x", "severity": "WARNING", "path": "y"}]
    )
    assert findings[0].severity == "medium"   # WARNING -> medium
    assert findings[0].location == "y"        # no line -> bare path
    assert findings[0].masvs_refs == []


def test_audit_maps_from_installed_mantis(monkeypatch):
    """When mantis is importable, audit() calls it and maps the records."""
    fake_mantis = types.ModuleType("mantis")
    captured = {}

    def fake_audit(path, *, llm=False):
        captured["path"] = path
        captured["llm"] = llm
        return [{"rule_id": "cmd-inj", "severity": "ERROR",
                 "path": "app/run.py", "start_line": 7, "message": "shell=True"}]

    fake_mantis.audit = fake_audit
    monkeypatch.setitem(sys.modules, "mantis", fake_mantis)

    findings = MantisAdapter(FakeRunner()).audit("/some/src")
    assert captured == {"path": "/some/src", "llm": False}
    assert findings[0].title == "cmd-inj"
    assert findings[0].location == "app/run.py:7"


def test_audit_raises_clear_error_when_mantis_missing(monkeypatch):
    """Without mantis-sast installed, audit() raises a clear install hint."""
    monkeypatch.setitem(sys.modules, "mantis", None)  # forces ImportError
    with pytest.raises(RuntimeError, match="mantis not installed"):
        MantisAdapter(FakeRunner()).audit("/some/src")


def test_mantis_registered_in_registry():
    # NOTE: registration lives in default_registry(runner), NOT Registry.__init__
    # (which takes a list of adapters). Do not use Registry(FakeRunner()).
    from centurion.registry import default_registry
    reg = default_registry(FakeRunner())
    assert reg.get("mantis").name == "mantis"
