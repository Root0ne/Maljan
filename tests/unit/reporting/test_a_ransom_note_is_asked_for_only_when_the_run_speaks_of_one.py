"""The ransom-note section is asked for only when something in the run speaks of one.

Its bundle held the strings tools' answers and the capability profile, which
every PE run has, so every run asked the report model for a ransom note and
printed none. It is asked for when a claim names a ransom note, a strings
answer holds the words of one, or the judge's category is ransomware.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.evidence_bundles import bundle_for, is_empty
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)

STRINGS = {"static": [{"tool_name": "list_strings", "output": "GetProcAddress\nkernel32.dll"}]}


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        static=StaticAnalysis(api_capabilities={"network": 4, "crypto": 2}),
        **over,
    )


def _isr(*claims: str) -> dict[str, Any]:
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(claim=text, evidence_ref="[ev_0002]", confidence=0.8)
                for text in claims
            ],
        )
    }


def test_a_run_that_never_speaks_of_a_note_is_not_asked() -> None:
    report = _report(malware_category="loader")
    isrs = _isr("The sample annotated nothing; it noted the host name.", "It beacons home.")

    assert is_empty(bundle_for("ransom_note", report, STRINGS, isrs))


def test_a_claim_naming_a_note_asks_for_it() -> None:
    bundle = bundle_for(
        "ransom_note", _report(), STRINGS, _isr("The sample drops a ransom note on the desktop.")
    )

    assert not is_empty(bundle)
    assert len(bundle["claims"]) == 1
    assert bundle["tool_outputs"] == []


def test_a_strings_answer_holding_a_note_s_words_asks_for_it() -> None:
    strings = {"static": [{"tool_name": "list_strings", "output": "README_FOR_DECRYPT.txt"}]}
    bundle = bundle_for("ransom_note", _report(), strings, _isr("It beacons home."))

    assert not is_empty(bundle)
    assert [o["tool"] for o in bundle["tool_outputs"]] == ["list_strings"]


def test_a_ransomware_category_asks_for_it() -> None:
    bundle = bundle_for(
        "ransom_note", _report(malware_category="ransomware"), STRINGS, _isr("It encrypts.")
    )

    assert bundle["facts"] == {"category": "ransomware"}
    assert not is_empty(bundle)
