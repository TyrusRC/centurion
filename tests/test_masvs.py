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


# ── OWASP Mobile Top 10 (2024) mapping ──────────────────────────────

def test_mobile_top10_via_mastg_ref():
    # MASTG-TEST-0014 -> MASVS-NETWORK-1 -> M5 (Insecure Communication)
    finding = {"id": "rule:a:1", "tool": "opengrep", "mastg_refs": ["MASTG-TEST-0014"]}
    assert masvs.mobile_top10_for(finding) == ["M5"]


def test_mobile_top10_routes_through_tool_default_masvs():
    # gitleaks has a MASVS default (STORAGE-1), so it routes via MASVS -> M9,
    # not through the tool fallback table.
    finding = {"id": "gitleaks:k:1", "tool": "gitleaks", "mastg_refs": []}
    assert masvs.mobile_top10_for(finding) == ["M9"]
    otool = {"id": "otool:no-pie:/a", "tool": "otool", "mastg_refs": []}
    assert masvs.mobile_top10_for(otool) == ["M7"]


def test_mobile_top10_tool_fallback_when_no_masvs():
    # drozer has no MASVS default, so the tool fallback table applies.
    assert masvs.mobile_top10_for({"id": "drozer:x", "tool": "drozer"}) == ["M8"]
    assert masvs.mobile_top10_for({"id": "objection:x", "tool": "objection"}) == ["M3"]


def test_mobile_top10_unknown_is_empty():
    assert masvs.mobile_top10_for({"id": "x:y", "tool": "mystery"}) == []


def test_enrich_top10_adds_refs_and_labels_without_mutating_input():
    src = [{"id": "gitleaks:k:1", "tool": "gitleaks", "mastg_refs": []}]
    out = masvs.enrich_top10(src)
    assert out[0]["mobile_top10"] == ["M9"]
    assert out[0]["mobile_top10_labels"] == ["M9: Insecure Data Storage"]
    assert "mobile_top10" not in src[0]  # input untouched
