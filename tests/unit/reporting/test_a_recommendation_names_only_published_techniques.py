"""A recommendation names only the techniques this run publishes, or is asked once.

The hunting notes and the recommendations print a technique beside each
action, and nothing checked those ids against the report's ATT&CK table: an id
no analyst claimed and the table does not carry was printed as the technique an
action acts on. Each id a recommendation names that the run does not publish is
now asked about once, as an unpublished indicator is; what the model answers
stands, and an id it keeps is recorded.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    UNPUBLISHED_RECOMMENDATION_TECHNIQUE_CODE,
    recommendation_technique_violations,
)
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity, TTPMapping
from maljan.reporting.narrative_agent import NarrativeAgent, published_technique_ids

PUBLISHED = ["T1071.001", "T1105"]


def _report() -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
    )
    report.ttp_mappings = [
        TTPMapping(technique_id="T1071.001", technique_name="Web Protocols"),
        TTPMapping(technique_id="T1105", technique_name="Ingress Tool Transfer"),
    ]
    return report


def _row(technique: str = "", **over: str) -> dict[str, Any]:
    return {
        "category": "edr_hunting",
        "action": "Alert on the loader's process tree.",
        "rationale": "It starts from a script host.",
        "priority": "P1",
        "technique_id": technique,
        "detection": "Sysmon event 1 for the script host.",
        **over,
    }


class TestTheCheck:
    def test_an_unpublished_technique_column_is_asked_about(self) -> None:
        (found,) = recommendation_technique_violations(
            {"defensive_recommendations": [_row("T1105"), _row("T1059.003")]}, PUBLISHED
        )

        assert found.code == UNPUBLISHED_RECOMMENDATION_TECHNIQUE_CODE
        assert found.path == "defensive_recommendations.1"
        assert "recommendation 2 names a technique this run does not publish: T1059.003." in (
            found.message
        )

    def test_an_id_in_the_hunting_note_is_read_too(self) -> None:
        row = _row("T1105", detection="Sysmon event 1 for the shell (T1059.003).")
        (found,) = recommendation_technique_violations(
            {"defensive_recommendations": [row]}, PUBLISHED
        )

        assert "T1059.003" in found.message
        assert "T1105" not in found.message

    def test_published_ids_and_no_id_are_not_asked_about(self) -> None:
        payload = {
            "defensive_recommendations": [_row("t1071.001"), _row(""), _row("T1105")],
        }

        assert recommendation_technique_violations(payload, PUBLISHED) == []

    def test_with_no_list_nothing_is_read(self) -> None:
        payload = {"defensive_recommendations": [_row("T1059.003")]}

        assert recommendation_technique_violations(payload, None) == []

    def test_a_kept_id_ships_with_the_finding(self) -> None:
        assert UNPUBLISHED_RECOMMENDATION_TECHNIQUE_CODE in KEPT_WITH_A_FINDING

    def test_the_published_list_is_the_attck_table(self) -> None:
        assert published_technique_ids(_report()) == PUBLISHED


def _answer(technique: str) -> str:
    return json.dumps(
        {
            "executive_summary": "The sample is a loader that reaches its server over HTTPS "
            "and should be contained on every host it reached, with its domain blocked.",
            "key_findings": [
                {"text": "It resolves its imports at run time.", "evidence_ids": []},
                {"text": "It reaches its server over HTTPS (T1071.001).", "evidence_ids": []},
            ],
            "defensive_recommendations": [
                _row(technique, priority="P0", category="firewall"),
                _row("T1071.001"),
                _row("", priority="P2", category="other"),
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
            MagicMock(content=_answer("T1059.003")),
            MagicMock(content=_answer("T1105")),
        ]
    )

    out = await NarrativeAgent(llm=llm).generate(_report())

    assert out is not None
    assert out.defensive_recommendations[0].technique_id == "T1105"
    feedback = str(llm.ainvoke.await_args_list[1].args[0][-1].content)
    assert f"[{UNPUBLISHED_RECOMMENDATION_TECHNIQUE_CODE}]" in feedback
