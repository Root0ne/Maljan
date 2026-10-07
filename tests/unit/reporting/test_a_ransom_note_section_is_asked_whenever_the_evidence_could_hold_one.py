"""The ransom-note section is asked for whenever the run's evidence could hold a note.

A narrower reading — a claim or a strings answer naming "ransom", or a
ransomware category — skipped a real note: a run whose strings say "YOUR
FILES ARE ENCRYPTED … HOW_TO_DECRYPT.txt" and whose judge wrote no category
never names "ransom". The bundle stays non-empty whenever the strings tools
answered or the capability profile was measured, and the report model says
when there is no note; an empty answer costs one short call.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.evidence_bundles import bundle_for, is_empty
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity, StaticAnalysis
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NOTE = (
    "YOUR FILES ARE ENCRYPTED. To decrypt them send 0.1 BTC to the address below.\n"
    "HOW_TO_DECRYPT.txt"
)


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        static=StaticAnalysis(api_capabilities={"crypto": 6, "files": 9}),
        **over,
    )


def _isr(text: str) -> dict[str, Any]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[ClaimEvidence(claim=text, evidence_ref="[ev_0002]", confidence=0.8)],
        )
    }


def test_a_ransomware_run_with_no_category_and_no_ransom_word_is_asked() -> None:
    strings = {"static": [{"tool_name": "list_strings", "output": NOTE}]}
    claim = (
        "The sample encrypts user documents with AES-256 and writes HOW_TO_DECRYPT.txt to "
        "every folder, demanding payment in bitcoin."
    )

    bundle = bundle_for("ransom_note", _report(), strings, _isr(claim))

    assert not is_empty(bundle)
    assert [o["tool"] for o in bundle["tool_outputs"]] == ["list_strings"]


def test_the_measured_profile_alone_asks_for_it() -> None:
    bundle = bundle_for("ransom_note", _report(), {}, _isr("It beacons home."))

    assert not is_empty(bundle)
