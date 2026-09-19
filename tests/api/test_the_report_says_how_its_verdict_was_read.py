"""A client can tell a verdict the judge stated from one it did not.

Three of the four readings publish the inconclusive verdict, which is one of
the same three words a judge may state. A consumer of ``GET /reports/{id}``
therefore saw ``verdict: "Suspicious"`` with ``overall_confidence: null`` and
had to read ``degradation_reasons`` — a list of sentences — to learn whether
the judge had concluded Suspicious or whether its conclusion could not be read.
Two different facts about the sample, one value, told apart only by prose.

``verdict_reading`` is that distinction as one word, lifted out of the run
summary the pipeline already writes. A report stored before it existed carries
none, and a client that finds none draws nothing new.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.reports import _detail
from maljan.pipeline.outcome import (
    VERDICT_READ_FALLBACK,
    VERDICT_READ_STATED,
    VERDICT_READ_UNRECOGNISED,
    VERDICT_READ_UNSTATED,
    verdict_reading,
)
from maljan.schemas.stix_models import Bundle

READINGS = (
    VERDICT_READ_STATED,
    VERDICT_READ_UNRECOGNISED,
    VERDICT_READ_UNSTATED,
    VERDICT_READ_FALLBACK,
)


def _report_row(run_summary: dict[str, Any] | None) -> Any:
    """An ``AnalysisReport`` row as the response model reads one.

    A namespace rather than a mock, so the row has exactly the columns the
    table has: a mock answers every attribute, including the one this test is
    about, and the stored row does not have it at all.
    """
    return SimpleNamespace(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        verdict="Suspicious",
        overall_confidence=None,
        malware_category=None,
        stix_bundle=None,
        mitre_techniques=None,
        agent_reports=None,
        negotiation_log=None,
        run_summary=run_summary,
        malware_report=None,
        agent_findings=[],
        transcript=[],
        created_at="2026-09-19T00:00:00+00:00",
    )


def _bundle(assessment: dict[str, Any] | None, **top: Any) -> Bundle:
    payload: dict[str, Any] = {"objects": [], **top}
    if assessment is not None:
        payload["x_maljan_assessment"] = assessment
    return Bundle.model_validate(payload)


class TestWhatThePipelineRecords:
    def test_a_verdict_the_judge_stated(self) -> None:
        assert verdict_reading(_bundle({"verdict": "Benign"})) == VERDICT_READ_STATED

    def test_a_word_it_could_not_read(self) -> None:
        assert verdict_reading(_bundle({"verdict": "Malicious"})) == VERDICT_READ_UNRECOGNISED

    def test_no_verdict_at_all(self) -> None:
        assert verdict_reading(_bundle({"confidence": 0.5})) == VERDICT_READ_UNSTATED
        assert verdict_reading(_bundle(None)) == VERDICT_READ_UNSTATED

    def test_an_answer_that_was_not_a_bundle(self) -> None:
        bundle = _bundle(
            {"verdict": "Malware"},
            x_maljan_fallback_verdict={"decision": "Suspicious", "source": "extracted"},
        )

        assert verdict_reading(bundle) == VERDICT_READ_FALLBACK

    def test_it_agrees_with_the_verdict_beside_it(self) -> None:
        """The same order ``decide_from_bundle`` reads them in."""
        from maljan.pipeline.outcome import INCONCLUSIVE_VERDICT, decide_from_bundle

        for assessment, reading in (
            ({"verdict": "Benign"}, VERDICT_READ_STATED),
            ({"verdict": "Malicious"}, VERDICT_READ_UNRECOGNISED),
            ({"confidence": 0.5}, VERDICT_READ_UNSTATED),
        ):
            bundle = _bundle(assessment)
            decided = decide_from_bundle(bundle)
            assert verdict_reading(bundle) == reading
            if reading != VERDICT_READ_STATED:
                assert decided == INCONCLUSIVE_VERDICT or decided in ("Malware", "Benign")


class TestWhatTheApiSends:
    @pytest.mark.asyncio
    async def test_the_reading_reaches_the_response(self) -> None:
        svc = MagicMock(spec_set=["get_report"])
        svc.get_report = AsyncMock()

        for reading in READINGS:
            detail = await _detail(svc, _report_row({"verdict_reading": reading}))
            assert detail.verdict_reading == reading, reading

    @pytest.mark.asyncio
    async def test_a_report_stored_before_it_existed_carries_none(self) -> None:
        svc = MagicMock(spec_set=["get_report"])

        for summary in (None, {}, {"validation": {"retries": 0}}):
            detail = await _detail(svc, _report_row(summary))
            assert detail.verdict_reading is None, summary

    @pytest.mark.asyncio
    async def test_a_value_that_is_not_a_word_is_not_sent(self) -> None:
        svc = MagicMock(spec_set=["get_report"])

        for value in ("", None, 7, ["stated"]):
            detail = await _detail(svc, _report_row({"verdict_reading": value}))
            assert detail.verdict_reading is None, value

    @pytest.mark.asyncio
    async def test_the_verdict_and_the_confidence_are_unchanged_by_it(self) -> None:
        svc = MagicMock(spec_set=["get_report"])

        detail = await _detail(svc, _report_row({"verdict_reading": VERDICT_READ_UNRECOGNISED}))

        assert detail.verdict == "Suspicious"
        assert detail.overall_confidence is None
