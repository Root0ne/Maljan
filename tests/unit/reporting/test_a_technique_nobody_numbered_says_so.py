"""A technique nobody put a number on is published without one.

The matrix took the highest number any source gave a technique and 0.0 when
none did, so the report printed ``conf=0.00`` for a technique the judge named
with no number — a confidence of zero is a statement nobody made. On a
Suspicious or Benign verdict it is the rule rather than the exception: the
bundle carries no malware object, so the judge has nothing to hang a numbered
``uses`` edge on, and every technique it names alone arrives with no number.
Now the confidence is absent, and every surface prints "not given".
"""

from __future__ import annotations

import pytest

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.narrative_agent import build_prompt_text
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _bundle(verdict: str) -> dict:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Inhibit System Recovery",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1490"}],
            }
        ],
        "x_maljan_assessment": {"verdict": verdict, "confidence": 0.7},
    }


@pytest.mark.parametrize("verdict", ["Suspicious", "Benign", "Malware"])
def test_the_matrix_states_no_number(verdict: str) -> None:
    cells, mappings = build_capability_matrix(stix_output=_bundle(verdict), isr_reports=None)

    assert [c.confidence for c in cells] == [None]
    assert [m.confidence for m in mappings] == [None]


@pytest.mark.parametrize("verdict", ["Suspicious", "Benign"])
def test_the_report_and_the_narrative_prompt_print_not_given(verdict: str) -> None:
    report = MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output=_bundle(verdict),
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.7,
        judge_assessment=None,
        malware_category="dropper",
        evidence_ledger=[],
    ).build_deterministic()

    markdown = MarkdownRenderer().render(report)
    prompt = build_prompt_text(report)

    assert "T1490" in markdown
    assert "conf=not given" in markdown
    assert "0.00" not in markdown.split("## MITRE ATT&CK Matrix", 1)[1].split("\n## ", 1)[0]
    assert "conf=not given" in prompt


def test_a_number_somebody_gave_is_still_printed() -> None:
    bundle = _bundle("Malware")
    bundle["objects"] += [
        {"type": "malware", "id": "malware--1", "name": "x", "is_family": False},
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "uses",
            "source_ref": "malware--1",
            "target_ref": "attack-pattern--1",
            "x_maljan_confidence": 0.6,
        },
    ]

    _cells, mappings = build_capability_matrix(stix_output=bundle, isr_reports=None)

    assert [m.confidence for m in mappings] == [0.6]
