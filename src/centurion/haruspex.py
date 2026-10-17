"""Native Haruspex triage for centurion (mobile toolkit).

FAIL-OPEN read-time annotator: scores each already-persisted finding for how likely it is
a real, reportable issue (0..1) via a local Haruspex /v1/evaluate engine, and ranks the
list highest-likelihood first to fight triage fatigue. Advisory only — it never drops a
finding (they stay in session.json), never re-severities one, and never gates which checks
run. A missed finding is the cardinal harm.

Standalone: set CENTURION_HARUSPEX_URL to any /v1/evaluate endpoint (keyless on loopback);
unset or unreachable -> findings returned unchanged.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

_Q = {
    "type": "boolean",
    "instructions": "Is this a real, reportable security finding?",
    "criteria": {"true": "a real, exploitable vulnerability or risk", "false": "informational / not reportable alone"},
}


def base_url() -> str:
    return os.environ.get("CENTURION_HARUSPEX_URL", "").strip()


def _adjudicate(state: str, endpoint: str, timeout: int = 30) -> float | None:
    if not state:
        return None
    body = json.dumps({"model": "haruspex", "state": state, "questions": {"q": _Q}}).encode()
    req = urllib.request.Request(endpoint.rstrip("/") + "/v1/evaluate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ans = json.loads(r.read()).get("answers", {}).get("q", {})
        p = ans.get("probability")
        return float(p) if p is not None else None
    except Exception:  # noqa: BLE001 - fail-open: any failure = no opinion
        return None


def triage(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate + rank findings by Haruspex true-positive likelihood. Never drops one.
    Engine unset/unreachable -> returns the list unchanged."""
    ep = base_url()
    if not ep or not findings:
        return findings
    scored: list[tuple[float, dict]] = []
    for d in findings:
        state = " — ".join(str(x) for x in (d.get("title"), d.get("location"), d.get("detail")) if x)
        p = _adjudicate(state, ep)
        if p is not None:
            d["haruspex_real_prob"] = p
            if p < 0.5:
                d["haruspex_triage"] = "review"
        scored.append((p if p is not None else -1.0, d))
    scored.sort(key=lambda t: -t[0])  # stable: highest TP-likelihood first, nothing removed
    return [d for _, d in scored]
