"""The judge's prompts are sized from its window, not cut at fixed lengths.

Each analyst's report reached the verdict cut to 500 characters, the evidence
summary to 2,000, the negotiation history to 800 and every remembered case's
summary to 200 — on a DeepSeek window of a million tokens, with the judge
shown the first paragraph of every report and the conclusion of none. Every
part is whole now when the window, less the judge's output cap, holds it;
when it does not, the largest parts are shortened first, the prompt says so,
and the run records it as a degradation.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import (
    PROMPT_SHORTENED_NOTICE,
    JudgeAgent,
    fit_prompt_parts,
    verdict_reports_text,
)
from maljan.utils.marked_cut import CUT_MARK

LONG_REPORT = "The loader decrypts its payload. " * 200 + "CONCLUSION: it injects into explorer."
SUMMARY = "EVIDENCE SUMMARY\n" + "\n".join(f"T{1000 + i}: static (0.7)" for i in range(300))


def _judge(seen: list[str], window_tokens: int | None) -> JudgeAgent:
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge.verdict_prompt_notice = ""
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]
    budget = (
        None
        if window_tokens is None
        else SimpleNamespace(
            derives=True, chars_per_token=4, window=SimpleNamespace(tokens=window_tokens)
        )
    )
    judge._context_budget = lambda: budget  # type: ignore[method-assign]

    class _Model:
        async def ainvoke(self, messages: Any, **_: Any) -> Any:
            seen.append("\n".join(str(getattr(m, "content", m)) for m in messages))
            return MagicMock(
                content='{"type": "bundle", "objects": [], "x_maljan_assessment": '
                '{"severity": {"rating": "Low", "rationale": "thin"}, "confidence": 0.2}}'
            )

    judge.llm = _Model()
    return judge


def _verdict(judge: JudgeAgent, history: list[Any] | None = None) -> None:
    asyncio.run(
        judge.give_verdict(
            reports={"static": LONG_REPORT, "dynamic": "It writes a run key."},
            history=history or [],
            isr_reports={},
            evidence_summary=SUMMARY,
        )
    )


class TestThePartsAreWhole:
    def test_every_report_and_the_evidence_summary_whole(self) -> None:
        text = verdict_reports_text({"static": LONG_REPORT}, {}, SUMMARY)
        assert LONG_REPORT in text and SUMMARY in text

    def test_the_verdict_prompt_is_whole_when_the_window_holds_it(self) -> None:
        seen: list[str] = []
        judge = _judge(seen, window_tokens=1_000_000)
        history = [f"round {i}: " + "the agents disagree about the loader. " * 20 for i in range(5)]

        _verdict(judge, history)

        assert LONG_REPORT in seen[0], "the conclusion at the end of the report reached it"
        assert SUMMARY in seen[0]
        assert str(history) in seen[0]
        assert judge.verdict_prompt_notice == ""
        assert "did not fit" not in seen[0]

    def test_no_known_window_is_everything_whole(self) -> None:
        seen: list[str] = []
        judge = _judge(seen, window_tokens=None)

        _verdict(judge)

        assert LONG_REPORT in seen[0] and judge.verdict_prompt_notice == ""


class TestAWindowThatCannotHoldIt:
    def test_the_largest_parts_are_shortened_first_and_the_prompt_says_so(self) -> None:
        seen: list[str] = []
        # A window whose room, less the output cap, cannot hold both long parts.
        judge = _judge(seen, window_tokens=0)
        judge._question_room = lambda fixed, cap: 6_000  # type: ignore[method-assign]

        _verdict(judge)

        notice = judge.verdict_prompt_notice
        assert notice.startswith("NOTE: this prompt did not fit this model's window whole.")
        assert notice in seen[0], "the model is told"
        assert "It writes a run key." in seen[0], "a short part is never cut for a long one"
        assert LONG_REPORT not in seen[0] and CUT_MARK in seen[0]
        assert "static report" in notice and "evidence summary" in notice

    def test_the_shortening_is_largest_first_to_one_width(self) -> None:
        parts = {"a": "x" * 1000, "b": "y" * 300, "c": "z" * 50}

        fitted, notice = fit_prompt_parts(parts, 700)

        # 700 holds c and b whole; a gets what is left.
        assert fitted["c"] == parts["c"] and fitted["b"] == parts["b"]
        assert len(fitted["a"]) == 350 and fitted["a"].endswith(CUT_MARK)
        assert notice == PROMPT_SHORTENED_NOTICE.format(cut=1, total=3, names="a", width=350)

        fitted, notice = fit_prompt_parts(parts, 400)

        # 400 holds c whole; a and b share the rest at one width.
        assert fitted["c"] == parts["c"]
        assert len(fitted["a"]) == len(fitted["b"]) == 175
        assert notice == PROMPT_SHORTENED_NOTICE.format(cut=2, total=3, names="a, b", width=175)

    def test_parts_that_fit_come_back_whole_and_unannounced(self) -> None:
        parts = {"a": "x" * 10, "b": "y" * 10}
        assert fit_prompt_parts(parts, 20) == (parts, "")
        assert fit_prompt_parts(parts, None) == (parts, "")
