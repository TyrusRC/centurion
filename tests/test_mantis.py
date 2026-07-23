import pytest

from centurion.adapters.generic.mantis import MantisAdapter
from centurion.process import FakeRunner


def test_parse_mantis_json_maps_results_to_findings():
    payload = {"results": [
        {"rule": "hardcoded-key", "severity": "high", "file": "a/B.java",
         "line": 42, "detail": "AWS key in source", "mastg": ["MASTG-TEST-0003"]},
    ]}
    findings = MantisAdapter(FakeRunner())._parse_mantis_json(payload)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "hardcoded-key"
    assert f.severity == "high"
    assert f.tool == "mantis"
    assert f.location == "a/B.java:42"
    assert f.mastg_refs == ["MASTG-TEST-0003"]


def test_parse_mantis_json_accepts_bare_list_and_defaults():
    findings = MantisAdapter(FakeRunner())._parse_mantis_json(
        [{"title": "x", "severity": "MEDIUM", "file": "y"}]
    )
    assert findings[0].severity == "medium"
    assert findings[0].location == "y"
    assert findings[0].mastg_refs == []


def test_audit_is_guarded_until_lib_lands():
    with pytest.raises(NotImplementedError, match="mantis lib pending"):
        MantisAdapter(FakeRunner()).audit("/some/src")


def test_mantis_registered_in_registry():
    # NOTE: registration lives in default_registry(runner), NOT Registry.__init__
    # (which takes a list of adapters). Do not use Registry(FakeRunner()).
    from centurion.registry import default_registry
    reg = default_registry(FakeRunner())
    assert reg.get("mantis").name == "mantis"
