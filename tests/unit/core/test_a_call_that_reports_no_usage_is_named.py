"""A model call whose provider reported no usage is named, and the run summary says how many.

A paid run's summary read "not reported for 1 of them" and nothing said which
call that was. The ledger now keeps the agent, the call and the model of every
call that reported nothing, and the summary names them beside the count —
which is a count of calls, never a guessed number of tokens.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import TOOL_LOOP_TURN_CALL, BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder, tokens_sentence
from maljan.core.token_ledger import TokenLedger, record_response_usage

_REPORTED = {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}


def _silent() -> AIMessage:
    return AIMessage(content="an answer with no usage block")


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: object, **kwargs: object) -> str:  # pragma: no cover - unused
        return ""


class TestTheLedgerNamesTheCall:
    def test_a_call_that_reported_nothing_is_recorded_by_agent_call_and_model(self) -> None:
        ledger = TokenLedger()
        record_response_usage(ledger, _silent(), agent="static_r2", model="m1", call="verdict")
        record_response_usage(
            ledger, AIMessage(content="x", usage_metadata=dict(_REPORTED)), agent="static"
        )

        snapshot = ledger.snapshot()

        assert snapshot["unreported_calls"] == 1
        assert snapshot["unreported"] == [{"agent": "static_r2", "call": "verdict", "model": "m1"}]
        assert snapshot["input_tokens"] == 10

    def test_a_run_whose_calls_all_reported_carries_no_rows(self) -> None:
        ledger = TokenLedger()
        record_response_usage(ledger, AIMessage(content="x", usage_metadata=dict(_REPORTED)))

        assert "unreported" not in ledger.snapshot()

    def test_a_tool_loop_turn_is_named_as_one(self) -> None:
        ledger = TokenLedger()
        analyst = _Analyst(llm=MagicMock(), name="static_r2")
        analyst.token_ledger = ledger

        analyst._record_turns_taken({"messages": [_silent()]}, 0)

        assert [row["call"] for row in ledger.snapshot()["unreported"]] == [TOOL_LOOP_TURN_CALL]


class TestTheRunSummarySaysIt:
    def _tokens(self, ledger: TokenLedger) -> dict:
        return (
            RunSummaryBuilder(start_time=0.0)
            .set_token_usage(ledger.snapshot())
            .build()
            .to_dict()["tokens"]
        )

    def test_the_count_and_the_calls_are_in_the_summary(self) -> None:
        ledger = TokenLedger()
        ledger.add(dict(_REPORTED), agent="static", model="m1")
        ledger.add(None, agent="static_r2", model="m1", call=TOOL_LOOP_TURN_CALL)

        tokens = self._tokens(ledger)

        assert tokens["unreported_calls"] == 1
        assert tokens["unreported"] == [
            {"agent": "static_r2", "call": TOOL_LOOP_TURN_CALL, "model": "m1"}
        ]
        assert "not reported for 1 of them (static_r2: tool loop turn on m1)" in tokens["sentence"]

    def test_repeated_calls_are_said_once_with_their_count(self) -> None:
        ledger = TokenLedger()
        ledger.add(dict(_REPORTED), agent="static", model="m1")
        for _ in range(3):
            ledger.add(None, agent="judge", model="m2", call="verdict")

        assert (
            "not reported for 3 of them (judge: verdict on m2 ×3)"
            in (self._tokens(ledger)["sentence"])
        )

    def test_a_summary_stored_without_rows_says_the_count_alone(self) -> None:
        sentence = tokens_sentence(
            {"llm_calls": 2, "unreported_calls": 1, "input_tokens": 5, "output_tokens": 1}
        )

        assert sentence is not None
        assert sentence.endswith("not reported for 1 of them.")
