"""The tiny stored run the replay's tests read, and what each producer raises over it."""

from __future__ import annotations

from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "replay" / "tiny"

# What each producer raises over the tiny run under today's rules.
EXPECTED_TOTALS: dict[str, dict[str, int]] = {
    "answers": {
        "attck.absence_claim": 1,
        "attck.unknown_id": 1,
        "isr.claim_without_confidence": 1,
        "isr.technique_line_unread": 1,
        "isr.ungrounded_technique": 1,
    },
    "claims_in_force": {"attck.absence_claim": 1, "attck.claim_does_not_describe": 1},
    "judge": {
        "stix.credit_without_claim": 1,
        "stix.ungrounded_indicator": 1,
        "stix.unknown_technique": 1,
    },
    "narrative": {
        "narrative.schema": 1,
        "narrative.ungrounded_finding": 1,
        "narrative.unpublished_technique": 1,
    },
    "composer": {"report.citation_not_evidence": 1},
    "tool": {"tool.argument_names_its_parameter": 1},
    "fp_linter": {"C7": 1},
}
