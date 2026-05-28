"""Post-pipeline false-positive linter (Wave 4, 2026-05-28).

The 2026-05-23 zararli.apk audit found that the pipeline's deterministic
layers + LLM narratives could agree on a confidently-wrong story (six
Windows / macOS / cloud TTPs on an APK, defensive recommendations to
"block PowerShell"). Wave 4's structural fixes (Sigma/YARA platform
filters, cascade source-layer override, indicator denylists) close the
direct path, but every refactor can regress.

The FP linter is the belt-and-braces safety net. It runs after the
cascade + NarrativeAgent have populated the MalwareReport and emits one
or more :class:`FPWarning` rows for any anomaly:

* **C1** capability_matrix entry whose technique platform doesn't
  intersect the sample's canonical platform (should be impossible after
  Step 4; the linter calls it out anyway).
* **C2** ``defensive_recommendations[].action`` mentions a technique ID
  that's not in the capability matrix (NarrativeAgent hallucination).
* **C3** ``executive_summary`` mentions a platform-specific concept
  (PowerShell, RDP, macOS, raw disk, cloud auth) that doesn't apply to
  the sample (narrative cascade FP).
* **C4** total ``file:name`` indicators above ``MAX_FILE_NAME_INDICATORS``
  (Step 5 cap escaped).
* **C5** family attribution set with ``family_grounded=false`` (D11
  zeroes confidence; the linter calls it out so a downstream consumer
  doesn't read the string and assume it's verified).

Results land in ``run_summary.fp_warnings`` so the API + UI can render
an audit banner without re-running the pipeline.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from maljan.agents._indicator_denylists import MAX_FILE_NAME_INDICATORS


@dataclass(frozen=True)
class FPWarning:
    """One linter finding. Serialised under ``run_summary.fp_warnings``."""

    rule: str  # "C1" / "C2" / "C3" / "C4" / "C5"
    severity: str  # "warn" / "error"
    message: str
    field: str | None = None  # dotted path into the report, when applicable

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Heuristic: only flag executive-summary mentions of these concepts on
# samples that genuinely can't host them. Per-platform dicts so a
# Windows sample's exec summary mentioning PowerShell stays unflagged.
_PLATFORM_INCOMPATIBLE_TERMS: dict[str, frozenset[str]] = {
    "android": frozenset({"powershell", "rdp", "raw disk", "macos", "cloud auth", "azure"}),
    "ios": frozenset({"powershell", "rdp", "raw disk", "macos", "cloud auth", "azure"}),
    "linux": frozenset({"powershell", "macos", "cloud auth", "azure"}),
    "macos": frozenset({"powershell", "rdp", "cloud auth", "azure"}),
    "windows": frozenset({"macos", "cloud auth", "azure"}),
}

_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def lint_report(report: Any, sample_platform: str | None) -> list[FPWarning]:
    """Walk the populated :class:`MalwareReport` and emit FP warnings."""
    warnings: list[FPWarning] = []
    sp = (sample_platform or "").strip().lower()

    capability_ids = _capability_technique_ids(report)

    # C1 — platform-mismatched capability_matrix entries.
    if sp and sp != "unknown":
        for cell in getattr(report, "capability_matrix", None) or []:
            tid = getattr(cell, "technique_id", None)
            # Populated only when the builder filled it.
            cell_platforms = getattr(cell, "platforms", None)
            if not cell_platforms:
                continue
            norm = {str(p).lower() for p in cell_platforms}
            if "any" in norm or sp in norm:
                continue
            warnings.append(
                FPWarning(
                    rule="C1",
                    severity="warn",
                    message=(
                        f"Capability {tid} survived cascade but its declared "
                        f"platforms {sorted(norm)} don't include sample={sp}."
                    ),
                    field=f"capability_matrix.{tid}",
                )
            )

    # C2 — defense recommendations citing TTPs not in capability matrix.
    for i, rec in enumerate(getattr(report, "defensive_recommendations", None) or []):
        text_blob = " ".join(
            str(getattr(rec, attr, "") or "") for attr in ("action", "rationale", "category")
        )
        for tid in set(_TID_RE.findall(text_blob)):
            if tid not in capability_ids:
                warnings.append(
                    FPWarning(
                        rule="C2",
                        severity="warn",
                        message=(
                            f"defensive_recommendations[{i}] references {tid} which is not "
                            f"in capability_matrix — NarrativeAgent likely hallucinated."
                        ),
                        field=f"defensive_recommendations[{i}]",
                    )
                )

    # C3 — executive_summary mentions platform-incompatible concepts.
    exec_summary = (getattr(report, "executive_summary", None) or "").lower()
    if sp and sp in _PLATFORM_INCOMPATIBLE_TERMS:
        for term in _PLATFORM_INCOMPATIBLE_TERMS[sp]:
            if term in exec_summary:
                warnings.append(
                    FPWarning(
                        rule="C3",
                        severity="warn",
                        message=(
                            f"executive_summary mentions '{term}' but sample platform is "
                            f"{sp}; likely narrative cascade FP."
                        ),
                        field="executive_summary",
                    )
                )

    # C4 — indicator file:name overflow.
    file_name_count = _count_file_name_indicators(report)
    if file_name_count > MAX_FILE_NAME_INDICATORS:
        warnings.append(
            FPWarning(
                rule="C4",
                severity="warn",
                message=(
                    f"{file_name_count} file:name indicators present "
                    f"(threshold {MAX_FILE_NAME_INDICATORS}). The J-02 cap may not be running."
                ),
                field="stix_bundle_extended.objects[indicator]",
            )
        )

    # C5 — family is set but ungrounded.
    attribution = getattr(report, "attribution", None)
    if attribution is not None:
        family = getattr(attribution, "family", None)
        grounded = getattr(attribution, "family_grounded", True)
        if family and grounded is False:
            warnings.append(
                FPWarning(
                    rule="C5",
                    severity="warn",
                    message=(
                        f"Family attribution '{family}' is ungrounded "
                        f"(family_grounded=false); confidence already zeroed."
                    ),
                    field="attribution.family",
                )
            )

    return warnings


def _capability_technique_ids(report: Any) -> set[str]:
    out: set[str] = set()
    for cell in getattr(report, "capability_matrix", None) or []:
        tid = getattr(cell, "technique_id", None)
        if tid:
            out.add(str(tid))
    return out


def _count_file_name_indicators(report: Any) -> int:
    bundle = getattr(report, "stix_bundle_extended", None)
    if not isinstance(bundle, dict):
        return 0
    objects = bundle.get("objects") or []
    if not isinstance(objects, list):
        return 0
    count = 0
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        if isinstance(pattern, str) and pattern.lstrip().startswith("[file:name"):
            count += 1
    return count
