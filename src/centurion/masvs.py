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


# ── OWASP Mobile Top 10 (2024) ──────────────────────────────────────

MOBILE_TOP10_2024: dict[str, str] = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

# MASVS category → Mobile Top 10 mapping.
_MASVS_TO_TOP10: dict[str, str] = {
    "MASVS-AUTH": "M3",
    "MASVS-STORAGE": "M9",
    "MASVS-CRYPTO": "M10",
    "MASVS-NETWORK": "M5",
    "MASVS-PLATFORM": "M4",
    "MASVS-CODE": "M8",
    "MASVS-RESILIENCE": "M7",
    "MASVS-PRIVACY": "M6",
}

# Tool/finding-id patterns → Mobile Top 10 (when no MASVS ref available).
_TOOL_TO_TOP10: dict[str, str] = {
    "gitleaks": "M1",
    "apkleaks": "M1",
    "apkid": "M2",
    "otool:no-pie": "M7",
    "otool:not-encrypted": "M7",
    "otool:no-canary": "M7",
    "drozer": "M8",
    "objection": "M3",
    "frida": "M3",
    "mitmproxy": "M5",
    "tcpdump": "M5",
    "mantis": "M4",
}


def mobile_top10_for(finding: dict) -> list[str]:
    """Map a finding to OWASP Mobile Top 10 2024 category numbers."""
    categories: list[str] = []

    # Route via MASVS refs first.
    for control in masvs_for(finding):
        cat = category_of(control)
        m = _MASVS_TO_TOP10.get(cat)
        if m and m not in categories:
            categories.append(m)
    if categories:
        return categories

    # Fallback: tool or finding-id prefix.
    fid = finding.get("id", "")
    for prefix, m in _TOOL_TO_TOP10.items():
        if ":" in prefix and fid.startswith(prefix):
            return [m]
    tool = finding.get("tool", "")
    m = _TOOL_TO_TOP10.get(tool)
    return [m] if m else []


def enrich_top10(findings: list[dict]) -> list[dict]:
    """Annotate each finding with its OWASP Mobile Top 10 2024 refs."""
    result = []
    for f in findings:
        refs = mobile_top10_for(f)
        labels = [f"{m}: {MOBILE_TOP10_2024.get(m, '')}" for m in refs]
        result.append({**f, "mobile_top10": refs, "mobile_top10_labels": labels})
    return result
