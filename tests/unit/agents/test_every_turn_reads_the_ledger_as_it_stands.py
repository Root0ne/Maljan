"""Every turn an analyst sends reads the run-state block as of that turn.

The node renders the block once, from the run's state, when it briefs the
agent. The agent's own calls of the node are filed after that, so a block
reused for the turns after the loop told a revising reverser "ledger: 137
entries (ev_0001–ev_0131)" while the answer it was asked to fix cited the
fifteen reads it had just made (ev_0142–ev_0165), and it withdrew them as
entries that could not be checked. Each turn now renders the block again from
the briefed state with the entries the agent filed since appended: inside the
loop, and on every turn after it (the nudge, the forced synthesis, a
validation retry, a drops question).
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from maljan.agents.base_agent import BaseAnalyst, current_run_state, prompt_to_messages
from maljan.pipeline.nodes import brief_agent
from maljan.pipeline.run_state import RUN_STATE_BEGIN, RUN_STATE_END, render_run_state
from maljan.pipeline.triage_pack import PIPELINE
from maljan.schemas.evidence import build_entry, format_entry_id
from tests.linear_cost import TIME_RATIO_LIMIT, calls, cpu_seconds

REPORT = "CLAIM: it decodes\nEVIDENCE: ev_0004\nCONFIDENCE: 0.6\nTECHNIQUE: T1140\n"


def _entry(seq: int, agent: str = PIPELINE, *, ok: bool = True, tool: str = "identify_file") -> Any:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=agent,
        tool=tool,
        args={},
        server=agent,
        output='{"file_type": "pe", "platform": "windows", "size": 10}' if ok else "",
        ok=ok,
        error=None if ok else "the call failed",
    )


def _state(count: int = 3) -> dict[str, Any]:
    return {
        "file_hash": "a" * 64,
        "evidence_ledger": [_entry(n).model_dump(mode="json") for n in range(1, count + 1)],
        "stage_results": {},
    }


class _LLM:
    def __init__(self) -> None:
        self.seen: list[list[Any]] = []

    def invoke(self, messages: Any, **_: Any) -> AIMessage:
        self.seen.append(list(messages))
        return AIMessage(content=REPORT)

    async def ainvoke(self, messages: Any, **_: Any) -> AIMessage:
        return self.invoke(messages)


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="reverser")

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _briefed(state: dict[str, Any]) -> _Analyst:
    container = MagicMock()
    container.config.reporting.upstream_findings_max_chars = 6000
    agent = _Analyst(_LLM())
    brief_agent(agent, state, container)
    return agent


def _block(messages: list[Any]) -> str:
    text = str(messages[-1].content)
    assert text.endswith(RUN_STATE_END)
    return text[text.rindex(RUN_STATE_BEGIN) :]


class TestTheBlockIsRenderedForTheTurn:
    def test_the_node_hands_the_agent_the_state_it_rendered_from(self) -> None:
        state = _state()
        agent = _briefed(state)
        assert agent.run_state_source is state
        assert "ledger: 3 entries (ev_0001–ev_0003)" in agent.run_state_block

    def test_with_no_entry_of_its_own_the_block_is_the_briefed_one(self) -> None:
        agent = _briefed(_state())
        assert current_run_state(agent) == agent.run_state_block

    def test_the_entries_filed_after_the_briefing_are_in_the_ledger_line(self) -> None:
        agent = _briefed(_state())
        agent._evidence_entries = [_entry(7, "reverser"), _entry(8, "reverser", ok=False)]
        now = current_run_state(agent)
        assert "ledger: 5 entries (ev_0001–ev_0008)" in now
        assert "tools failed: identify_file (reverser)" in now

    def test_a_loop_s_live_entries_count_too(self) -> None:
        agent = _briefed(_state())
        agent._live_map_entries = [_entry(4, "reverser")]
        block = _block(agent.frame_messages(prompt_to_messages([("human", "Go on.")])))
        assert "ledger: 4 entries (ev_0001–ev_0004)" in block

    def test_an_entry_already_in_the_state_is_counted_once(self) -> None:
        state = _state()
        agent = _briefed(state)
        agent._evidence_entries = [_entry(3), _entry(4, "reverser")]
        agent._live_map_entries = [_entry(4, "reverser")]
        assert "ledger: 4 entries (ev_0001–ev_0004)" in current_run_state(agent)

    def test_an_agent_briefed_without_the_state_reads_its_block(self) -> None:
        agent = SimpleNamespace(run_state_block="ledger: 2 entries", _evidence_entries=[_entry(9)])
        assert current_run_state(agent) == "ledger: 2 entries"
        assert current_run_state(SimpleNamespace()) == ""

    def test_a_state_that_cannot_be_rendered_leaves_the_briefed_block(self) -> None:
        agent = _briefed(_state())
        agent.run_state_source = {"evidence_ledger": object()}
        agent._evidence_entries = [_entry(4, "reverser")]
        assert current_run_state(agent) == agent.run_state_block


class TestATurnAfterTheLoop:
    def test_the_validation_retry_reads_the_entries_the_answer_cites(
        self, monkeypatch: Any
    ) -> None:
        from maljan.pipeline.validation import Violation
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        told = [Violation(code="isr.ungrounded_technique", message="cite ev_0004")]
        answers = iter([told, told, []])
        monkeypatch.setattr(
            "maljan.pipeline.validation.validate_isr", lambda *_a, **_k: next(answers, [])
        )
        agent = _briefed(_state())
        # The loop filed two reads after the briefing; the answer cites them.
        agent._evidence_entries = [_entry(4, "reverser"), _entry(5, "reverser")]
        agent._system_prompt = lambda _default, tools=None: "You are a reverser."  # type: ignore[method-assign]
        sent: list[list[Any]] = []

        def _capture(turns: list[Any], timeout: int, **_: Any) -> AIMessage:
            sent.append(list(turns))
            return AIMessage(content=REPORT)

        agent._invoke_llm_with_timeout = _capture  # type: ignore[method-assign]
        isr = AgentISR(
            agent_id="reverser",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="c", evidence_ref="ev_0005", confidence=0.5, technique_id="T1140"
                )
            ],
        )
        agent._validate_isr(isr, "the raw data")
        assert sent
        carried = [
            str(m.content)
            for turns in sent
            for m in turns
            if isinstance(m, HumanMessage) and RUN_STATE_BEGIN in str(m.content)
        ]
        assert carried
        assert all("ledger: 5 entries (ev_0001–ev_0005)" in text for text in carried)
        assert not any("ledger: 3 entries" in text for text in carried)


class TestLinearTime:
    @pytest.mark.parametrize("own", [50, 500])
    def test_four_times_the_ledger_costs_under_eight_times_the_time(self, own: int) -> None:
        def reader(rows: int) -> Callable[[], Any]:
            state = _state(rows)
            agent = SimpleNamespace(
                run_state_block=render_run_state(state),
                run_state_source=state,
                _evidence_entries=[_entry(rows + n, "reverser") for n in range(1, own + 1)],
                _live_map_entries=None,
            )
            return lambda: current_run_state(agent)

        small, large = reader(2_000), reader(8_000)
        # CPU time, best of five, over inputs that take milliseconds: a
        # millisecond wall-clock sample was swamped by one cyclic-GC pass over
        # the heap a long suite builds, and by a busy machine.
        assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
        assert calls(large) < calls(small) * 5
