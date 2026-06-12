"""Stdlib-only iOS helpers: plist parsing and IPA introspection.

Neither wraps an external tool — `plistlib` reads binary and XML plists, and `zipfile`
unpacks the IPA archive (an IPA is a zip). Kept out of the adapter layer for that reason.
"""

from __future__ import annotations

import plistlib
import zipfile


def read_plist(path: str) -> dict:
    """Parse a binary or XML plist file into a dict."""
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def ipa_info(ipa_path: str) -> dict:
    """Extract the app's Info.plist from an .ipa and summarize key fields."""
    with zipfile.ZipFile(ipa_path) as zf:
        plist_name = next(
            (
                n
                for n in zf.namelist()
                if n.startswith("Payload/")
                and n.endswith(".app/Info.plist")
                and n.count("/") == 2
            ),
            None,
        )
        if plist_name is None:
            raise ValueError(f"no Payload/*.app/Info.plist found in {ipa_path}")
        info = plistlib.loads(zf.read(plist_name))
    app_path = plist_name.rsplit("/", 1)[0]
    return {
        "bundle_id": info.get("CFBundleIdentifier"),
        "minimum_os": info.get("MinimumOSVersion"),
        "url_schemes": _url_schemes(info),
        "ats_allows_arbitrary_loads": (
            info.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoads", False)
        ),
        "app_path": app_path,
        "info_plist": plist_name,
    }


def _url_schemes(info: dict) -> list[str]:
    schemes: list[str] = []
    for entry in info.get("CFBundleURLTypes", []) or []:
        schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    return schemes
