"""A revision's answer passes the checks a first answer passes, and a smaller one is said.

A revision round's answer went straight from the parser into the answer in
force: no validation turn, so no claim-count question, no confidence question
and no technique-line question was ever put to it. One analyst's 38-claim
first answer was replaced by a revision of which the reader read 3 (15 of its
18 CONFIDENCE lines ended in a full stop), and nothing in the run said so.

Now a revision is asked the same questions once, in the same turn, and what is
still unread after it is stated as its unread reason. A revision the model
made with fewer claims still replaces the answer in force, since the model
decides what its answer is, and the run summary states the replacement with
both counts.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.nodes import make_revision_node, revision_replacement_sentence
from maljan.pipeline.validation import CLAIM_WITHOUT_CONFIDENCE_CODE
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

REVISION = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "claims"
    / "revision_with_full_stop_confidences.txt"
).read_text(encoding="utf-8")

TWO_CLAIMS_ONE_UNREADABLE = (
    "CLAIM: The file keeps its settings in an encoded table.\n"
    "EVIDENCE: [ev_0001]\n"
    "CONFIDENCE: 0.8\n"
    "---\n"
    "CLAIM: The file reads the table at start.\n"
    "EVIDENCE: [ev_0002]\n"
    "CONFIDENCE: high\n"
)
TWO_CLAIMS_READABLE = TWO_CLAIMS_ONE_UNREADABLE.replace("CONFIDENCE: high", "CONFIDENCE: 0.7.")


class _Answers:
    """A model that answers each call from a queue and records what it was sent."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.sent: list[list[Any]] = []

    def invoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        self.sent.append(list(messages))
        return AIMessage(content=self.answers.pop(0))

    async def ainvoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        return self.invoke(messages)


class _Reviser(BaseAnalyst):
    """An analyst whose revision is the text it is handed; its model answers the checks."""

    revision_text = ""

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:
        return self.revision_text


def _reviser(revision: str, answers: list[str]) -> tuple[_Reviser, _Answers]:
    llm = _Answers(answers)
    analyst = _Reviser(llm=llm, name="reverser")  # type: ignore[arg-type]
    analyst.revision_text = revision
    return analyst, llm


def _revise(analyst: _Reviser) -> tuple[str, AgentISR]:
    with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
        return analyst.safe_revise_isr("the evidence", "own report", {}, "feedback", 1)


class TestTheValidationTurnAsksARevision:
    def test_an_unreadable_confidence_is_asked_about_and_the_answer_is_read(self) -> None:
        analyst, llm = _reviser(TWO_CLAIMS_ONE_UNREADABLE, [TWO_CLAIMS_READABLE])

        _text, isr = _revise(analyst)

        assert len(llm.sent) == 1
        assert "'high'" in str(llm.sent[0][-1].content)
        assert [c.confidence for c in isr.claims] == [0.8, 0.7]
        assert isr.claims_unread_reason == ""
        assert analyst.validation_fed_back.get(CLAIM_WITHOUT_CONFIDENCE_CODE) == 1

    def test_a_revision_still_short_after_the_question_states_its_unread_reason(self) -> None:
        analyst, _llm = _reviser(TWO_CLAIMS_ONE_UNREADABLE, [TWO_CLAIMS_ONE_UNREADABLE])

        _text, isr = _revise(analyst)

        assert len(isr.claims) == 1
        assert "began 2 claim(s)" in isr.claims_unread_reason
        assert "'high'" in isr.claims_unread_reason
        assert CLAIM_WITHOUT_CONFIDENCE_CODE in {v.code for v in analyst.validation_findings}

    def test_a_stale_first_loop_deadline_does_not_keep_the_question_from_being_asked(
        self,
    ) -> None:
        analyst, llm = _reviser(TWO_CLAIMS_ONE_UNREADABLE, [TWO_CLAIMS_READABLE])
        # The first answer's loop ended long ago; the revision made no loop.
        analyst._last_loop_deadline = time.monotonic() - 3_600.0

        with patch("maljan.agents.base_agent.loop_limits", return_value=(3_600.0, None)):
            _text, isr = _revise(analyst)

        assert len(llm.sent) == 1
        assert len(isr.claims) == 2

    def test_the_first_answer_s_nudge_is_not_the_revision_s(self) -> None:
        analyst, llm = _reviser(TWO_CLAIMS_ONE_UNREADABLE, [TWO_CLAIMS_READABLE])
        analyst._answer_unstructured = True

        _text, isr = _revise(analyst)

        assert len(llm.sent) == 1
        assert len(isr.claims) == 2

    def test_the_eighteen_claim_revision_reads_eighteen(self) -> None:
        # Its multi-id technique lines are asked about too: the answer given
        # back is the same, and every claim still stands.
        analyst, _llm = _reviser(REVISION, [REVISION])

        _text, isr = _revise(analyst)

        assert len(isr.claims) == 18
        assert isr.claims_unread_reason == ""


def _claims(count: int) -> list[ClaimEvidence]:
    return [
        ClaimEvidence(claim=f"finding {n}", evidence_ref="[ev_0001]", confidence=0.8)
        for n in range(1, count + 1)
    ]


def _node_run(in_force: AgentISR, revision: AgentISR) -> dict[str, Any]:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["reverser"]
    container.analyst_keys.return_value = ["reverser"]
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    agent = MagicMock()
    agent.safe_revise_isr.return_value = ("the revision", revision)
    container.get_agent.return_value = agent
    container.load_chunked.return_value = [MagicMock(content="data")]
    container.load_data.return_value = "data"
    node = make_revision_node(container)
    state = {
        "file_hash": "abc",
        "iteration_count": 1,
        "discussion_history": [],
        "reports": {"reverser": "first answer"},
        "isr_reports": {"reverser": in_force},
    }
    return asyncio.run(node(state))


class TestARevisionWithFewerClaimsStandsAndIsSaid:
    def test_the_thirty_eight_claim_answer_replaced_by_the_revision_is_stated(self) -> None:
        in_force = AgentISR(agent_id="reverser", domain="static", claims=_claims(38))
        analyst, _llm = _reviser(REVISION, [REVISION])
        _text, revision = _revise(analyst)

        out = _node_run(in_force, revision)

        # The model's revision is the answer in force.
        assert len(out["isr_reports"]["reverser"].claims) == 18
        assert out["revision_replacements"] == [
            "The reverser analyst's round-1 revision replaced 38 claim(s) with 18."
        ]

    def test_a_revision_that_keeps_or_adds_claims_is_not_a_replacement_to_state(self) -> None:
        in_force = AgentISR(agent_id="reverser", domain="static", claims=_claims(3))
        revision = AgentISR(agent_id="reverser", domain="static", claims=_claims(3))

        out = _node_run(in_force, revision)

        assert "revision_replacements" not in out
        assert revision_replacement_sentence("x", 1, in_force, revision) == ""

    def test_the_run_summary_states_the_replacement(self) -> None:
        sentence = "The reverser analyst's round-1 revision replaced 38 claim(s) with 3."
        summary = (
            RunSummaryBuilder(start_time=time.time())
            .set_negotiation({"iteration_count": 1, "revision_replacements": [sentence]}, 2)
            .build()
        )

        assert summary.to_dict()["negotiation"]["revision_replacements"] == [sentence]
        assert sentence in summary.to_markdown()
