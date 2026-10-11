"""Sycophancy is a rise in likeness beyond shared sources, told to the mediator and never enforced.

A revision is flagged only when, with the words of every ledger entry or
sandbox item it and the peer both cite left out of both, its similarity to a
peer's answer is above the threshold and above its own answer's before the
round, and only when it added no citation and made no tool call. Two answers
alike because they restate the same rows are not flagged. A flag is recorded
on the round, put to the next mediation as a fact, and never overrides a
consensus or widens a round that asks only the analysts the mediator named.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.pipeline.nodes import make_negotiation_node
from maljan.pipeline.state import AgentArgument
from maljan.pipeline.sycophancy_detector import (
    convergence_flags,
    convergence_sentence,
    flagged_analysts,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

ROW = (
    "the pack row lists seven decoded command lines for host discovery, a scheduled task "
    "named helper, two candidate hosts and a staging path under the temporary folder"
)
PEER = (
    "The sample builds a beacon from the host name, mixes it with a fixed key, rotates the "
    "result twice, appends a counter, and posts it to the second candidate host each minute."
)
OWN = (
    "The decoder at the routine walks the table, xors each byte with a rolling key, and "
    "returns a buffer the caller frees; nothing else in the routine is reached."
)


def _isr(name: str, text: str, ref: str = "[ev_0001]") -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.7)],
    )


TEXTS = {"ev_0001": ROW, "ev_0002": "another entry"}


class TestTheFlag:
    def test_a_move_towards_a_peer_beyond_the_shared_row_is_flagged(self) -> None:
        before = {"a": _isr("a", OWN), "b": _isr("b", PEER)}
        after = {"a": _isr("a", PEER), "b": _isr("b", PEER)}

        flags = convergence_flags(before, after, ["a"], {}, TEXTS)

        assert [(f["agent"], f["towards"]) for f in flags] == [("a", "b")]
        assert flags[0]["after"] > 0.9 > flags[0]["before"]

    def test_answers_alike_only_in_the_row_both_cite_are_not_flagged(self) -> None:
        before = {"a": _isr("a", OWN), "b": _isr("b", f"{ROW}. {PEER}")}
        after = {"a": _isr("a", f"{ROW}. {OWN}"), "b": _isr("b", f"{ROW}. {PEER}")}

        assert convergence_flags(before, after, ["a"], {}, TEXTS) == []

    def test_answers_alike_before_the_round_are_not_flagged(self) -> None:
        before = {"a": _isr("a", PEER), "b": _isr("b", PEER)}
        after = {"a": _isr("a", PEER), "b": _isr("b", PEER)}

        assert convergence_flags(before, after, ["a"], {}, TEXTS) == []

    def test_a_revision_that_added_a_citation_is_not_flagged(self) -> None:
        before = {"a": _isr("a", OWN), "b": _isr("b", PEER)}
        after = {"a": _isr("a", PEER, "[ev_0001] [ev_0002]"), "b": _isr("b", PEER)}

        assert convergence_flags(before, after, ["a"], {}, TEXTS) == []

    def test_a_revision_that_made_a_tool_call_is_not_flagged(self) -> None:
        before = {"a": _isr("a", OWN), "b": _isr("b", PEER)}
        after = {"a": _isr("a", PEER), "b": _isr("b", PEER)}

        assert convergence_flags(before, after, ["a"], {"a": 1}, TEXTS) == []

    def test_an_analyst_not_revised_is_not_judged(self) -> None:
        before = {"a": _isr("a", OWN), "b": _isr("b", PEER)}
        after = {"a": _isr("a", PEER), "b": _isr("b", PEER)}

        assert convergence_flags(before, after, [], {}, TEXTS) == []

    def test_the_sentence_and_the_names(self) -> None:
        flags = [{"agent": "a", "towards": "b", "before": 0.4, "after": 0.95}]

        said = convergence_sentence(flags)

        assert "a moved towards b (similarity 0.40 to 0.95)" in said
        assert "it decides nothing" in said
        assert flagged_analysts(flags) == {"a", "b"}
        assert convergence_sentence([]) == ""

    def test_many_peers_are_read_in_linear_time(self) -> None:
        timings = []
        for n in (20, 200):
            before = {f"p{i}": _isr(f"p{i}", f"{PEER} {i}") for i in range(n)}
            before["a"] = _isr("a", OWN)
            after = dict(before)
            after["a"] = _isr("a", PEER)
            start = time.perf_counter()
            convergence_flags(before, after, ["a"], {}, TEXTS)
            timings.append(time.perf_counter() - start)
        assert timings[1] < timings[0] * 10 * 4 + 0.5


def _negotiate(record: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = ["a", "b"]
    judge = MagicMock()
    judge.mediate = AsyncMock(
        return_value=(
            AgentArgument(agent_name="Mediator", finding="ok", confidence_score=0.9),
            True,
        )
    )
    container.get_judge_agent.return_value = judge
    state = {
        "iteration_count": 1,
        "reports": {"a": PEER, "b": PEER},
        "isr_reports": {"a": _isr("a", PEER), "b": _isr("b", PEER)},
        "revision_rounds": [record],
        "discussion_history": [AgentArgument(agent_name="Mediator", finding="revise")],
        "confidence_history": [0.5],
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes.pack_text", lambda *a: "PACK")
        mp.setattr("maljan.pipeline.nodes.render_run_state", lambda *a: "")
        update = asyncio.run(make_negotiation_node(container)(state))
    return update, judge


RECORD = {"round": 1, "stage": "debate", "made": 1, "identical": False, "revised": ["a"]}
FLAG = {"agent": "a", "towards": "b", "before": 0.4, "after": 0.95}


class TestTheMediatorIsTold:
    def test_a_recorded_flag_is_put_to_the_mediation_as_a_fact(self) -> None:
        update, judge = _negotiate({**RECORD, "converged": [FLAG]})

        facts = judge.mediate.call_args.kwargs["facts_block"]
        assert facts.startswith("PACK")
        assert convergence_sentence([FLAG]) in facts
        assert update["sycophancy_detected"] is True

    def test_no_flag_tells_nothing(self) -> None:
        update, judge = _negotiate({**RECORD, "converged": []})

        assert judge.mediate.call_args.kwargs["facts_block"] == "PACK"
        assert update["sycophancy_detected"] is False
