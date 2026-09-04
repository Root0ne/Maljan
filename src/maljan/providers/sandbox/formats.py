"""Name the sandbox format behind an already-parsed report payload.

Used by the upload provider (Task 15) to decide which normaliser handles an
attached report, and by the Triage adapter (Task 16) to confirm what it just
fetched. Kept a pure function over a plain ``dict`` — no I/O, no provider
imports — so both call sites can use it without a dependency on each other.
"""

from __future__ import annotations

from typing import Any, Literal

Format = Literal["cape2", "cuckoo", "triage", "unknown"]


def sniff_format(payload: dict[str, Any]) -> Format:
    """Name the sandbox that produced ``payload``, most specific first.

    Triage first: its overview carries ``analysis`` plus ``tasks``, which no
    CAPE report has. CAPE next: ``CAPE`` as a top-level key, or a version string
    naming it. Cuckoo last, as the generic ``info`` + ``behavior`` shape CAPE
    inherited from it — so it can only be reached once CAPE has been ruled out.
    """
    if not isinstance(payload, dict) or not payload:
        return "unknown"
    analysis = payload.get("analysis")
    if isinstance(analysis, dict) and isinstance(payload.get("tasks"), list):
        return "triage"
    if isinstance(payload.get("CAPE"), (dict, list)):
        return "cape2"
    info_field = payload.get("info")
    info = info_field if isinstance(info_field, dict) else {}
    version = str(info.get("version") or "")
    if "cape" in version.lower():
        return "cape2"
    if isinstance(payload.get("behavior"), dict) and info:
        return "cuckoo"
    return "unknown"
