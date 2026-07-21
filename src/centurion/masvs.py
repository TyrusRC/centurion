"""MASVS control mapping and finding enrichment.

Two layers: findings that carry MASTG-TEST refs (opengrep, from ruleset
metadata) map through MASTG_TEST_TO_MASVS; everything else falls back to a
per-tool / per-finding-id-prefix default. Enrichment is applied at read time
so stored findings stay raw and the tables can improve without rescanning.
"""

from __future__ import annotations

# MASTG-TEST id -> MASVS v2 control. Extend as rulesets emit more refs.
MASTG_TEST_TO_MASVS: dict[str, str] = {
    "MASTG-TEST-0011": "MASVS-CRYPTO-1",   # weak/insecure crypto primitives
    "MASTG-TEST-0012": "MASVS-CRYPTO-2",   # bad key management
    "MASTG-TEST-0014": "MASVS-NETWORK-1",  # cleartext / insecure transport
    "MASTG-TEST-0017": "MASVS-NETWORK-2",  # missing cert/host validation
    "MASTG-TEST-0003": "MASVS-STORAGE-1",  # sensitive data in local storage
    "MASTG-TEST-0004": "MASVS-STORAGE-1",  # sensitive data in logs
    "MASTG-TEST-0025": "MASVS-PLATFORM-1", # exported IPC / component exposure
    "MASTG-TEST-0031": "MASVS-CODE-3",     # webview / injection
}

# Fallback for findings without MASTG refs, matched by finding-id prefix first
# (most specific), then by tool name.
TOOL_DEFAULT_MASVS: dict[str, str] = {
    # id-prefix matches (checked first)
    "otool:no-pie": "MASVS-RESILIENCE-1",
    "otool:not-encrypted": "MASVS-RESILIENCE-1",
    "otool:no-canary": "MASVS-RESILIENCE-1",
    # tool matches
    "gitleaks": "MASVS-STORAGE-1",
    "apkleaks": "MASVS-STORAGE-1",
    "apkid": "MASVS-RESILIENCE-1",
}


def masvs_for(finding: dict) -> list[str]:
    controls: list[str] = []
    for ref in finding.get("mastg_refs") or []:
        control = MASTG_TEST_TO_MASVS.get(ref)
        if control and control not in controls:
            controls.append(control)
    if controls:
        return controls
    fid = finding.get("id", "")
    for prefix, control in TOOL_DEFAULT_MASVS.items():
        if ":" in prefix and fid.startswith(prefix):
            return [control]
    tool_default = TOOL_DEFAULT_MASVS.get(finding.get("tool", ""))
    return [tool_default] if tool_default else []


def enrich(findings: list[dict]) -> list[dict]:
    return [{**f, "masvs_refs": masvs_for(f)} for f in findings]


def category_of(control: str) -> str:
    # "MASVS-CRYPTO-1" -> "MASVS-CRYPTO"
    return control.rsplit("-", 1)[0] if control else control
