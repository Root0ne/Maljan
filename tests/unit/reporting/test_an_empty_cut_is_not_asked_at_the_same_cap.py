"""A section cut at its cap with no text is asked again only with more room.

In a run held by the spend ceiling, six report sections came back cut at their
output cap with 0 characters: a reasoning model at its highest effort spent
the whole allowance thinking. The composer asked each one again at the same
cap, and its log said the window had set the cap when the spend ceiling had.
A cut with no text is now asked again only when the second call would have
more room; otherwise the section is recorded as not written, with the limit
that applied and where it came from, and the log names that limit.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from maljan.core.spend import SpendMeter
from maljan.core.token_ledger import TokenLedger
from maljan.reporting.composer import COMPOSED_SECTIONS, ReportComposer, _HostIdentifiersOut

_WHOLE = (
    '{"identifiers": [{"kind": "File name", "value": "state.example.bin", '
    '"purpose": "", "evidence_refs": ["ev_0001"]}]}'
)


class _Answers:
    model_name = "priced-model"

    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)
        self.caps: list[Any] = []

    async def ainvoke(self, messages: Any, **kwargs: Any) -> AIMessage:
        self.caps.append(kwargs.get("max_tokens"))
        return self.answers.pop(0)


def _empty_cut(tokens: int) -> AIMessage:
    return AIMessage(
        content="",
        response_metadata={"finish_reason": "length"},
        usage_metadata={"input_tokens": 100, "output_tokens": tokens, "total_tokens": 0},
    )


def _whole() -> AIMessage:
    return AIMessage(content=_WHOLE, response_metadata={"finish_reason": "stop"})


def _compose(llm: _Answers, ledger: TokenLedger | None, **settings: Any) -> ReportComposer:
    composer = ReportComposer(
        llm=llm,  # type: ignore[arg-type]
        section_max_tokens=8192,
        token_ledger=ledger,
        model_label="priced-model",
        **settings,
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "maljan.reporting.composer.structured_output_supported_for_llm", lambda _l: False
        )
        composer._last = asyncio.run(  # type: ignore[attr-defined]
            composer._invoke(
                [HumanMessage(content="x")], _HostIdentifiersOut, section="host_identifiers"
            )
        )
    return composer


def _held_meter() -> SpendMeter:
    """A ceiling that pays for about 2,000 output tokens, with a 1,000-token answer measured."""
    meter = SpendMeter(
        0.03,
        {"priced-model": {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}},
        table={},
    )
    meter.settle({"input_tokens": 0, "output_tokens": 1_000}, "priced-model")
    return meter


class TestAnEmptyCutAtTheSpendHold:
    def test_is_not_asked_again_and_is_recorded_as_not_written(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        meter = _held_meter()
        llm = _Answers(_empty_cut(2_000), _whole())

        with caplog.at_level(logging.INFO, logger="maljan"):
            composer = _compose(llm, TokenLedger(spend=meter))

        assert composer._last is None  # type: ignore[attr-defined]
        assert len(llm.caps) == 1, "no second call at the same cap"
        (held,) = llm.caps
        assert held is not None and held < 8192
        (reason,) = composer.degradations
        assert reason.startswith("report section 'host_identifiers' is not written:")
        assert "no text written" in reason and "the spend ceiling's hold" in reason
        said = [r.getMessage() for r in caplog.records if "may write" in r.getMessage()]
        assert said and "the spend ceiling's hold" in said[0]
        assert "window" not in said[0]

    def test_at_the_section_s_own_budget_it_names_that_budget(self) -> None:
        # No ceiling and no window: the second call would have the same
        # budget, so it is not asked again, and the budget is the limit named.
        llm = _Answers(_empty_cut(8192), _whole())
        composer = _compose(llm, None)
        assert len(llm.caps) == 1
        (reason,) = composer.degradations
        assert "its output budget of 8192 tokens" in reason

    def test_a_cut_with_text_is_still_asked_once_for_a_shorter_answer(self) -> None:
        cut = AIMessage(
            content='{"identifiers": [{"kind": "Str',
            response_metadata={"finish_reason": "length"},
        )
        llm = _Answers(cut, _whole())
        composer = _compose(llm, None)
        assert len(llm.caps) == 2
        assert composer.degradations == []


class TestTheSectionsArePlannedForTheSpend:
    def test_the_list_is_every_section_compose_writes(self) -> None:
        asked: list[str] = []

        async def _author(self: Any, section: str, *args: Any, **kwargs: Any) -> None:
            asked.append(section)

        from maljan.reporting.models import MalwareReport

        composer = ReportComposer(llm=None, per_section_timeout=5)  # type: ignore[arg-type]
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ReportComposer, "_author", _author)
            asyncio.run(composer.compose(MalwareReport.model_construct()))
        assert tuple(asked) == COMPOSED_SECTIONS
