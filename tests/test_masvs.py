from centurion import masvs


def test_masvs_for_maps_mastg_test_refs():
    finding = {"id": "rule:a.java:10", "tool": "opengrep",
               "mastg_refs": ["MASTG-TEST-0011"]}
    assert masvs.masvs_for(finding) == ["MASVS-CRYPTO-1"]


def test_masvs_for_falls_back_to_tool_default():
    finding = {"id": "otool:no-pie:/bin/app", "tool": "otool", "mastg_refs": []}
    assert masvs.masvs_for(finding) == ["MASVS-RESILIENCE-1"]


def test_masvs_for_secret_scanners_map_to_storage():
    for tool in ("gitleaks", "apkleaks"):
        finding = {"id": f"{tool}:secret:1", "tool": tool, "mastg_refs": []}
        assert masvs.masvs_for(finding) == ["MASVS-STORAGE-1"]


def test_masvs_for_unknown_finding_is_empty():
    assert masvs.masvs_for({"id": "x:y", "tool": "mystery", "mastg_refs": []}) == []


def test_enrich_adds_masvs_refs_without_mutating_input():
    src = [{"id": "otool:no-pie:/a", "tool": "otool", "mastg_refs": []}]
    out = masvs.enrich(src)
    assert out[0]["masvs_refs"] == ["MASVS-RESILIENCE-1"]
    assert "masvs_refs" not in src[0]  # input untouched


def test_category_of_strips_control_number():
    assert masvs.category_of("MASVS-CRYPTO-1") == "MASVS-CRYPTO"
