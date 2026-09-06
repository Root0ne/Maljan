"""The run summary's key set is a contract, so it is pinned.

CORE-3 (dev audit 2026-09-06): ``RunSummary.to_dict()`` is what the API
stores, what the report renders and what every evaluation script reads back
out of a stored run, and nothing pinned its shape. A key renamed or dropped in
passing would keep every existing test green and quietly break a consumer that
is not in this repository at all -- an old stored summary read by new code, or
a paper table built from a field that stopped being written.

The golden is the key set alone, not the values: what a run measures is
allowed to change from one run to the next, but what it is *called* is not.
The summary below is a default-profile run with every optional section
populated, so the golden covers the widest shape ``to_dict`` can return.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from maljan.analysis.run_summary import RunSummary, RunSummaryBuilder
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "run_summary_keys.json"


def _claim(technique_id: str, confidence: float) -> ClaimEvidence:
    return ClaimEvidence(
        claim=f"claim for {technique_id}",
        evidence_ref="ref",
        confidence=confidence,
        technique_id=technique_id,
    )


def _isr(agent_id: str, domain: str) -> AgentISR:
    return AgentISR(
        agent_id=agent_id,
        domain=domain,  # type: ignore[arg-type]
        claims=[_claim("T1055", 0.8)],
        dissent_items=[],
        revision_round=1,
    )


def _default_profile_summary() -> RunSummary:
    """A default-profile run with every optional section filled in."""
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    class _Validation:
        total_claims = 5
        valid_ids = 4
        invalid_ids = 1
        low_alignment = 1
        hallucination_rate = 0.2

    analysts = ["static", "dynamic", "network"]
    isr_reports = {key: _isr(key, key) for key in analysts}

    builder = RunSummaryBuilder(start_time=time.time() - 1.0)
    builder.set_sample("abc123", "evil.exe")
    builder.set_verdict("Malware", 12)
    builder.set_negotiation(
        {
            "file_hash": "abc123",
            "file_name": "evil.exe",
            "iteration_count": 2,
            "is_consensus": True,
            "confidence_history": [0.7, 0.85, 0.91],
            "sycophancy_detected": False,
            "discussion_history": [],
            "_max_iterations": 5,
        }
    )
    builder.set_isr_stats(isr_reports)
    builder.set_validation_summary(_Validation())
    builder.set_cascade_summary(TTPCascadeEngine().compute(isr_reports))
    builder.set_platform_filter_summary(1, 2, "windows")
    builder.set_profile("default", analysts, [])
    builder.set_degraded_mode(False, [])
    builder.set_failed_analysts([])
    builder.set_token_usage(
        {
            "input_tokens": 10,
            "output_tokens": 20,
            "total_tokens": 30,
            "llm_calls": 3,
            "estimated_calls": 0,
        }
    )
    builder.set_truncation(
        {
            "tool_output_calls": 4,
            "tool_output_over_limit": 1,
            "tool_output_summarised": 1,
            "tool_output_hard_truncated": 0,
            "tool_output_chars_dropped": 12,
            "react_invocations": 3,
            "react_step_cap_hits": 0,
            "judge_invocations": 1,
            "judge_token_cap_hits": 0,
            "integrity_invocations": 1,
            "integrity_objects_removed": 0,
            "integrity_dropped": {"indicator": 0},
        }
    )
    return builder.build()


# Two of the maps in the summary are keyed by data rather than by schema --
# one technique layer per layer that produced a technique, one integrity
# counter per object kind that was dropped. Their contents are a property of
# the run, not of the format, so they are pinned as present and opaque.
_DATA_KEYED = frozenset({"techniques_by_layer", "truncation.integrity_dropped"})


def _key_shape(value: Any, path: str = "") -> Any:
    """Keys all the way down; a list contributes the shape of its first item."""
    if path in _DATA_KEYED:
        return "<data-keyed map>"
    if isinstance(value, dict):
        return {
            key: _key_shape(value[key], f"{path}.{key}" if path else key) for key in sorted(value)
        }
    if isinstance(value, list):
        return [_key_shape(value[0], f"{path}[]")] if value else []
    return None


def test_the_run_summary_key_set_matches_the_golden():
    shape = _key_shape(_default_profile_summary().to_dict())
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert shape == expected, (
        "RunSummary.to_dict() changed shape. If the change is intended, update "
        f"{GOLDEN.name} in the same commit and say in the message which consumer "
        "of the stored summary was checked."
    )


def test_the_summary_is_still_json_serializable():
    json.dumps(_default_profile_summary().to_dict())
