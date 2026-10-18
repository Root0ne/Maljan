"""What each agent loop's requests were made of is measured by part, in characters.

``core.input_meter.request_parts`` splits one request into its parts by the
messages it carries and the texts the agent was handed; the meter sums a tool
loop's turns on one row and the agent's single calls by kind, with the input
tokens the provider reported beside them; ``analysis.efficiency`` puts both in
``run_summary.efficiency.inputs`` with the token ledger's calls, and the
report prints one sentence per agent.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from maljan.agents.base_agent import BudgetMeter, _with_run_state_on
from maljan.analysis.efficiency import efficiency_lines, efficiency_record
from maljan.core.input_meter import PARTS, TOOL_LOOP, InputMeter, request_parts
from maljan.core.token_ledger import TokenLedger
from maljan.pipeline.run_state import RUN_STATE_BEGIN, RUN_STATE_END

PACK = "TRIAGE PACK\nrow one\nrow two"
TASK = "Analyse the sample."


def _turns() -> list[Any]:
    human = HumanMessage(content=f"{PACK}\n\n{TASK}")
    return [
        SystemMessage(content="You are an analyst."),
        human,
        AIMessage(content="", tool_calls=[{"name": "pe_info", "args": {}, "id": "c1"}]),
        _with_run_state_on(ToolMessage(content="[ev_0001] {}", tool_call_id="c1"), "steps: 3"),
    ]


def test_a_loop_request_is_split_into_its_parts_and_they_add_up() -> None:
    turns = _turns()
    parts = request_parts(turns, pack=PACK, definitions=120, replayed=7)

    assert parts["system_prompt"] == len("You are an analyst.")
    assert parts["pack"] == len(PACK)
    assert parts["task"] == len(f"{PACK}\n\n{TASK}") - len(PACK)
    assert parts["tool_answers"] == len("[ev_0001] {}")
    assert parts["run_state"] == len(turns[3].content) - len("[ev_0001] {}") + 7
    assert parts["own_turns"] == len(str(turns[2].content))
    assert parts["tool_definitions"] == 120
    assert parts["retries"] == parts["peer_reports"] == 0
    assert sum(parts.values()) == sum(len(str(m.content)) for m in turns) + 120 + 7
    assert set(parts) == set(PARTS)


def test_a_question_after_an_answer_is_a_retry_and_embedded_reports_are_named() -> None:
    peer, own = "STATIC REPORT: claims", "MY EARLIER ANSWER"
    turns = [
        SystemMessage(content="sys"),
        HumanMessage(content=f"YOURS:\n{own}\nPEERS:\n{peer}\nRevise."),
        AIMessage(content="CLAIM 1: x"),
        HumanMessage(content="Your answer named no evidence; answer again."),
    ]
    parts = request_parts(turns, peers=[peer], own=[own])

    assert parts["peer_reports"] == len(peer)
    assert parts["own_turns"] == len(own) + len("CLAIM 1: x")
    assert parts["retries"] == len("Your answer named no evidence; answer again.")


def test_run_state_markers_a_tool_answer_carries_are_not_taken_for_the_block() -> None:
    planted = f"answer{RUN_STATE_BEGIN}\nnot the platform's\n{RUN_STATE_END}"
    parts = request_parts([ToolMessage(content=planted, tool_call_id="c1")])

    assert parts["run_state"] == 0
    assert parts["tool_answers"] == len(planted)


def test_the_split_is_linear_in_the_request() -> None:
    def timed(scale: int) -> float:
        body = "x" * (50_000 * scale)
        turns = [
            HumanMessage(content=body),
            AIMessage(content=body),
            ToolMessage(content=body, tool_call_id="c"),
        ]
        start = time.perf_counter()
        request_parts(turns, pack="y" * 1000, peers=["z" * 1000] * 5)
        return time.perf_counter() - start

    small = max(timed(1), 1e-4)
    assert timed(10) < small * 40


def test_a_loop_sums_its_turns_and_single_calls_sum_by_kind() -> None:
    meter = InputMeter()
    loop = object()
    for _ in range(3):
        meter.request("static", {"tool_answers": 10, "system_prompt": 5}, loop=loop)
    meter.close("static", loop, [{"input_tokens": 100}, None, {"input_tokens": 50}])
    first = meter.request("static", {"retries": 4}, kind="validation retry")
    meter.answered(first, None)
    second = meter.request("static", {"retries": 6}, kind="validation retry")
    meter.answered(second, {"input_tokens": 30})

    rows = meter.rows()
    assert [row["kind"] for row in rows] == [TOOL_LOOP, "validation retry"]
    assert rows[0]["requests"] == 3
    assert rows[0]["parts"]["tool_answers"] == 30
    assert (rows[0]["reported_requests"], rows[0]["input_tokens"]) == (2, 150)
    assert rows[1]["requests"] == 2
    assert rows[1]["parts"]["retries"] == 10
    assert (rows[1]["reported_requests"], rows[1]["input_tokens"]) == (1, 30)


def test_a_row_no_request_of_which_reported_carries_no_token_figure() -> None:
    meter = InputMeter()
    meter.request("static", {"task": 3}, kind="revision")

    assert "input_tokens" not in meter.rows()[0]


class _Agent(BudgetMeter):
    def __init__(self, container: Any) -> None:
        self.name = "static"
        self.pipeline_stage = "analysis"
        self.logger = SimpleNamespace(debug=lambda *a, **k: None)
        self._container = container
        self.facts_block = PACK


def test_the_agent_measures_what_it_sends_and_closes_the_loop_with_the_reported_input() -> None:
    meter = InputMeter()
    agent = _Agent(SimpleNamespace(input_meter=meter))
    loop = object()
    turns = _turns()
    agent._note_request(turns, kind=TOOL_LOOP, loop=loop, definitions=40)
    answered = AIMessage(
        content="done", usage_metadata={"input_tokens": 77, "output_tokens": 1, "total_tokens": 78}
    )
    agent._close_input_loop(loop, [*turns, answered])

    (row,) = meter.rows()
    assert row["parts"]["pack"] == len(PACK)
    assert row["parts"]["tool_definitions"] == 40
    assert (row["reported_requests"], row["input_tokens"]) == (1, 77)


def test_an_agent_outside_a_job_measures_nothing() -> None:
    agent = _Agent(None)

    assert agent._note_request(_turns(), kind="revision") is None


def _container(meter: InputMeter, ledger: TokenLedger) -> Any:
    return SimpleNamespace(input_meter=meter, get_token_ledger=lambda: ledger)


def test_the_record_and_the_report_name_an_agent_whose_calls_were_not_measured() -> None:
    meter = InputMeter()
    row = meter.request("static", {"system_prompt": 50, "task": 150}, kind="revision")
    meter.answered(row, {"input_tokens": 60})
    ledger = TokenLedger()
    ledger.add({"input_tokens": 60, "output_tokens": 2}, agent="static")
    ledger.add({"input_tokens": 9, "output_tokens": 2}, agent="reporter")

    from maljan.analysis.run_summary import spend_blocks

    tokens = spend_blocks(ledger.snapshot())["tokens"]
    record = efficiency_record(_container(meter, ledger), tokens=tokens)
    assert record is not None
    assert record["inputs"]["unit"] == "characters"
    assert record["inputs"]["calls"] == {"reporter": 1, "static": 1}

    lines = efficiency_lines(record)
    assert lines[0] == (
        "Input of `static`: 1 kind of single call, 1 request, 200 characters in all — "
        "system prompt 25% (50), task and data 75% (150). The provider reported 60 input "
        "tokens for 1 of the 1 requests; the token ledger holds 1 model call of this agent."
    )
    assert lines[1] == "Not measured by part (model calls in the token ledger): `reporter` (1)."
    assert "character count" in lines[2]


def test_no_meter_is_no_record() -> None:
    assert efficiency_record(SimpleNamespace()) is None
    assert efficiency_lines(None) == []
    assert efficiency_lines({"some": "thing"}) == []
