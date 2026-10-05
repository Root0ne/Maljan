"""A recommendation acts only on the indicators this run publishes.

A local run's IOC table refused an address ("no: the sandbox report does not
say which process made the flows to it") and its hunting notes and P0
recommendation told the reader to block that address anyway: nothing checked
the recommendations against the publish decision. A recommendation that names
a value the run does not publish is now asked about once, with the table's
own answer; what the model answers stands, and a value it keeps is recorded
beside the recommendation.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    UNPUBLISHED_RECOMMENDATION_CODE,
    recommendation_indicator_violations,
)
from maljan.reporting.models import (
    ConsolidatedIOC,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from maljan.reporting.narrative_agent import NarrativeAgent, published_answers

PUBLISHED = "gate.example.com"
REFUSED = "198.51.100.7"
REFUSAL = "no: the sandbox report does not say which process made the flows to it"


def _report() -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        consolidated_iocs=[
            ConsolidatedIOC(
                type="Domain",
                kind="domain",
                value=PUBLISHED,
                source="sandbox",
                published="yes: the sandbox recorded it",
                is_network=True,
            ),
            ConsolidatedIOC(
                type="IPv4",
                kind="ip",
                value=REFUSED,
                source="sandbox",
                published=REFUSAL,
                is_network=True,
            ),
        ],
    )
    report.ttp_mappings = [TTPMapping(technique_id="T1071.001", technique_name="Web Protocols")]
    return report


def _recommendations(*actions: str) -> dict[str, Any]:
    return {
        "defensive_recommendations": [
            {
                "category": "firewall",
                "action": action,
                "rationale": "The sample talks to its server.",
                "priority": "P0",
                "detection": "Sysmon event 3 to the host.",
            }
            for action in actions
        ]
    }


class TestTheCheck:
    def test_a_refused_value_is_asked_about_with_the_tables_answer(self) -> None:
        (found,) = recommendation_indicator_violations(
            _recommendations(f"Block {PUBLISHED} and {REFUSED} at the perimeter."),
            published_answers(_report()),
        )

        assert found.code == UNPUBLISHED_RECOMMENDATION_CODE
        assert REFUSED in found.message and REFUSAL in found.message
        assert PUBLISHED not in found.message
        assert found.path == "defensive_recommendations.0"

    def test_a_published_value_and_its_url_are_not_asked_about(self) -> None:
        payload = _recommendations(f"Block https://{PUBLISHED}/live/ and {PUBLISHED}.")

        assert recommendation_indicator_violations(payload, published_answers(_report())) == []

    def test_a_defanged_refused_value_is_read(self) -> None:
        payload = _recommendations("Block 198.51.100[.]7.")

        assert recommendation_indicator_violations(payload, published_answers(_report()))

    def test_a_value_no_row_holds_is_asked_about_as_not_published(self) -> None:
        (found,) = recommendation_indicator_violations(
            _recommendations("Block other.example.net."), published_answers(_report())
        )

        assert "no row of this run's IOC table holds it" in found.message

    def test_the_hunting_note_is_read_too(self) -> None:
        payload = _recommendations("Hunt for beacons.")
        payload["defensive_recommendations"][0]["detection"] = f"Traffic to {REFUSED}."

        assert recommendation_indicator_violations(payload, published_answers(_report()))

    def test_a_kept_value_ships_with_the_finding(self) -> None:
        assert UNPUBLISHED_RECOMMENDATION_CODE in KEPT_WITH_A_FINDING


def _answer(action: str) -> str:
    return json.dumps(
        {
            "executive_summary": "The sample is a loader that reaches its server over HTTPS "
            "and should be contained on every host it reached, with its domain blocked.",
            "key_findings": [
                {"text": "It resolves its imports at run time.", "evidence_ids": []},
                {"text": "It reaches its server over HTTPS (T1071.001).", "evidence_ids": []},
            ],
            "defensive_recommendations": [
                {
                    "category": "firewall",
                    "action": action,
                    "rationale": "The sample talks to its server.",
                    "priority": "P0",
                    "technique_id": "T1071.001",
                    "detection": "Sysmon event 3 to the host.",
                },
                {
                    "category": "edr_hunting",
                    "action": "Alert on the loader's process tree.",
                    "rationale": "It starts from a script host.",
                    "priority": "P1",
                    "detection": "Sysmon event 1 for the script host.",
                },
                {
                    "category": "other",
                    "action": "Reimage the hosts it ran on.",
                    "rationale": "It persists.",
                    "priority": "P2",
                    "detection": "Process creation of the loader.",
                },
            ],
        }
    )


@pytest.mark.asyncio
async def test_the_narrative_is_asked_once_and_its_answer_stands() -> None:
    llm = MagicMock()
    structured = MagicMock()
    structured.ainvoke = AsyncMock(side_effect=Exception("no schema"))
    llm.with_structured_output.return_value = structured
    llm.ainvoke = AsyncMock(
        side_effect=[
            MagicMock(content=_answer(f"Block {REFUSED} and {PUBLISHED}.")),
            MagicMock(content=_answer(f"Block {PUBLISHED}.")),
        ]
    )

    out = await NarrativeAgent(llm=llm).generate(_report())

    assert out is not None
    assert out.defensive_recommendations[0].action == f"Block {PUBLISHED}."
    feedback = str(llm.ainvoke.await_args_list[1].args[0][-1].content)
    assert f"[{UNPUBLISHED_RECOMMENDATION_CODE}]" in feedback


def test_a_reference_host_no_row_holds_is_not_asked_about() -> None:
    payload = _recommendations("Apply the vendor's guidance at learn.microsoft.com.")

    assert recommendation_indicator_violations(payload, published_answers(_report())) == []


def test_a_reference_host_the_table_refuses_is_still_asked_about() -> None:
    report = _report()
    report.consolidated_iocs.append(
        ConsolidatedIOC(
            type="Domain",
            kind="domain",
            value="learn.microsoft.com",
            source="sandbox",
            published="no: a well-known benign name the sandbox's guest resolved",
            is_network=True,
        )
    )
    payload = _recommendations("Block learn.microsoft.com.")

    assert recommendation_indicator_violations(payload, published_answers(report))
