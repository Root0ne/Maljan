"""Post-pipeline false-positive linter.

An audit found that the pipeline could agree with itself on a confidently-wrong
story (TTPs from the wrong platform attached to a sample, defensive
recommendations to "block PowerShell" that did not apply). Nothing here
corrects any of it — the linter reports, and the report carries what it says.

It runs after the NarrativeAgent has populated the MalwareReport and emits one
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
* **C5** family attribution set with ``family_grounded=false`` — the judge
  named a family and cited no evidence ids for it.
* **C6** a claim or finding that carries neither an evidence id nor a tool
  entry behind it.
* **C7** a technique id the ATT&CK catalogue does not have, kept on a claim
  after the analyst was told and given a retry.

Results land in ``run_summary.fp_warnings`` so the API + UI can render
an audit banner without re-running the pipeline.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from maljan.agents._indicator_denylists import (
    MAX_FILE_NAME_INDICATORS,
    MAX_TOTAL_INDICATORS,
)


@dataclass(frozen=True)
class FPWarning:
    """One linter finding. Serialised under ``run_summary.fp_warnings``.

    ``explanation`` is a structured root-cause sentence that names the
    upstream guardrail responsible for the warning. A test gate asserts
    every warning carries a non-empty ``explanation`` so the UI
    surfaces actionable text instead of raw rule-engine output.
    """

    rule: str  # "C1" .. "C7"
    severity: str  # "warn" / "error"
    message: str
    field: str | None = None  # dotted path into the report, when applicable
    explanation: str | None = None  # structured root-cause prose

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Heuristic: only flag executive-summary mentions of these concepts on
# samples that genuinely can't host them. Per-platform dicts so a
# Windows sample's exec summary mentioning PowerShell stays unflagged.
# Each value names the concepts that platform cannot host, so an executive
# summary that mentions one on that sample is worth a warning.
_PLATFORM_INCOMPATIBLE_TERMS: dict[str, frozenset[str]] = {
    "linux": frozenset({"powershell", "macos", "cloud auth", "azure"}),
    "windows": frozenset({"macos", "cloud auth", "azure"}),
    "macos": frozenset({"powershell", "windows registry", "cloud auth", "azure"}),
    "android": frozenset({"powershell", "windows registry", "macos", "cloud auth", "azure"}),
    "ios": frozenset({"powershell", "windows registry", "cloud auth", "azure"}),
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
                    explanation=(
                        "The TTP cascade is expected to drop "
                        "platform-mismatched claims via "
                        "_is_claim_platform_compatible. This warning means a "
                        "claim slipped through with rule_platforms intact — "
                        "investigate whether the Sigma/YARA source layer "
                        "populated platforms but the cascade trusted a "
                        "different signal (e.g. MITRE catalog overlap)."
                    ),
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
                        explanation=(
                            "NarrativeAgent freely cites TTPs in its prose; "
                            "the cascade is the source of truth. When a "
                            "recommendation names a TID absent from "
                            "capability_matrix, treat the recommendation as "
                            "advisory only — the underlying capability was "
                            "either dropped (platform mismatch) or never "
                            "claimed by any analyst."
                        ),
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
                        explanation=(
                            f"NarrativeAgent emitted a platform-specific "
                            f"concept ('{term}') that cannot apply to a {sp} "
                            f"sample. This was the failure mode of the "
                            f"2026-05-23 cross-platform narrative audit; treat the "
                            f"entire executive summary sentence with skepticism and "
                            f"prefer the deterministic capability_matrix."
                        ),
                    )
                )

    # C4 — indicator file:name overflow OR total-indicator overflow.
    file_name_count = _count_file_name_indicators(report)
    total_count = _count_total_indicators(report)
    if file_name_count > MAX_FILE_NAME_INDICATORS:
        warnings.append(
            FPWarning(
                rule="C4",
                severity="warn",
                message=(
                    f"{file_name_count} file:name indicators present "
                    f"(threshold {MAX_FILE_NAME_INDICATORS}). The judge "
                    "renderer's cap may not be running."
                ),
                field="stix_bundle_extended.objects[indicator]",
                explanation=(
                    "file:name indicators are capped in the STIX bundle to keep "
                    "low-signal IOCs from drowning the high-signal ones. When "
                    "this fires, the cap in the extended renderer "
                    "(``_accept_string_ioc``) either did not run or the bundle "
                    "was rebuilt downstream without re-applying the limit."
                ),
            )
        )
    if total_count > MAX_TOTAL_INDICATORS:
        warnings.append(
            FPWarning(
                rule="C4",
                severity="warn",
                message=(
                    f"{total_count} total indicators present "
                    f"(threshold {MAX_TOTAL_INDICATORS}). The hard cap should "
                    f"have collapsed lower-signal kinds."
                ),
                field="stix_bundle_extended.objects[indicator]",
                explanation=(
                    "The STIX bundle's total indicator count is hard-capped "
                    "to keep downstream consumers (SIEM ingest, MISP "
                    "export) tractable. When this fires the priority order "
                    "(hashes > network IOCs > file:name) wasn't applied at "
                    "the renderer."
                ),
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
                        f"Family attribution '{family}' cites no evidence ids "
                        f"(family_grounded=false)."
                    ),
                    field="attribution.family",
                    explanation=(
                        "The judge named this family and cited no ledger entry "
                        "for it. The name is kept rather than deleted — a "
                        "flagged attribution is more useful than a silently "
                        "zeroed one — and the UI renders it as unverified."
                    ),
                )
            )

    # C6 — a claim or finding standing on nothing citable.
    ungrounded = _ungrounded_claim_count(report)
    if ungrounded:
        warnings.append(
            FPWarning(
                rule="C6",
                severity="warn",
                message=(
                    f"{ungrounded} claim(s) or finding(s) carry no evidence id and no "
                    f"tool entry; nothing in the ledger can be opened to check them."
                ),
                field="run_summary.evidence",
                explanation=(
                    "Every tool call a run makes is written to the evidence "
                    "ledger with a citable id. A claim that names none of them "
                    "and was not produced by a tool is the analyst's assertion "
                    "alone, which is allowed but should be visible as such."
                ),
            )
        )

    # C7 — a technique id that survived the validation retry unresolved.
    invalid = _invalid_technique_ids(report)
    if invalid:
        warnings.append(
            FPWarning(
                rule="C7",
                severity="warn",
                message=(
                    f"{len(invalid)} technique id(s) are not in the ATT&CK catalogue: "
                    f"{', '.join(sorted(invalid))}."
                ),
                field="run_summary.validation",
                explanation=(
                    "The producer was shown the problem and given one turn to "
                    "fix it, and kept the id. It is reported rather than "
                    "substituted, so the report says what the analyst said and "
                    "says that it does not resolve."
                ),
            )
        )

    return warnings


def _ungrounded_claim_count(report: Any) -> int:
    """Report sections and TTP rows with nothing citable behind them.

    A section that can name a ledger entry, an agent finding or an artifact is
    grounded (``ledger_report.section_is_grounded``); a TTP row is grounded when
    some source contributed it or some claim quoted it. Anything else was
    written by the pipeline about itself.
    """
    from maljan.reporting.ledger_report import section_is_grounded

    count = 0
    for section in getattr(report, "sections", None) or []:
        try:
            if not section_is_grounded(section):
                count += 1
        except Exception:  # noqa: BLE001 — a linter never fails a report
            continue
    for mapping in getattr(report, "ttp_mappings", None) or []:
        if not getattr(mapping, "contributing_layers", None) and not getattr(
            mapping, "evidence_quotes", None
        ):
            count += 1
    return count


def _invalid_technique_ids(report: Any) -> set[str]:
    """Technique ids the validation loop could not get resolved."""
    found: set[str] = set()
    for row in (getattr(report, "run_summary", None) or {}).get("validation", {}).get(
        "unresolved", []
    ) or []:
        if isinstance(row, dict) and row.get("code") == "attck.unknown_id":
            for token in _TID_RE.findall(str(row.get("message") or "")):
                found.add(token)
                break
    return found


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


def _count_total_indicators(report: Any) -> int:
    """Total count of STIX ``indicator`` SDOs in the bundle."""
    bundle = getattr(report, "stix_bundle_extended", None)
    if not isinstance(bundle, dict):
        return 0
    objects = bundle.get("objects") or []
    if not isinstance(objects, list):
        return 0
    return sum(1 for obj in objects if isinstance(obj, dict) and obj.get("type") == "indicator")
