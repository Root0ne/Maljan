"""A revision and the next mediation are shown the ledger entries their contested lines cite.

The revision shows them after the mediator's feedback, each whole, in the
input room the raw data leaves: the raw data is never shortened for them,
an entry that does not fit is named by id, and the entries shown are grounds
for the revision's checks as its raw data is. The mediation shows the round's
facts after the ledger's counts and the entries after them, in the room its
reports and history leave.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.judge_agent import CONTRADICTIONS_BLOCK_QUESTION, JudgeAgent
from maljan.llm.context_window import ANSWER_SHARE, ContextBudget
from maljan.pipeline.debate_facts import (
    DEBATE_ENTRIES_HEAD,
    DEBATE_ENTRIES_UNFIT,
    LINE_MARK_RULE,
    MEDIATION_ENTRIES_HEAD,
    MEDIATION_ENTRIES_UNFIT,
)
from maljan.schemas.isr_models import AgentISR

ENTRIES = {
    "ev_0011": "[ev_0011] decompile:\nvoid f5750() { key(); }",
    "ev_0012": "[ev_0012] decompile:\n" + "x" * 4000,
}


class _Analyst(BaseAnalyst):
    def __init__(self, room: int | None) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self.room = room
        self.feedback = ""
        self.data = ""
        self.grounds: list[str] = []

    def analyze(self, data: str) -> str:  # pragma: no cover
        return ""

    def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover
        return ""

    def _input_room_chars(self, text: str) -> int | None:
        return self.room

    def revise_isr(self, data: str, own: str, peers: dict, feedback: str, rnd: int = 1) -> Any:
        self.data, self.feedback = data, feedback
        return "CLAIM: x", AgentISR(agent_id="static", domain="static", claims=[])

    def _apply_consistency_gate(self, isr: AgentISR, evidence: str) -> AgentISR:
        self.grounds.append(evidence)
        return isr

    def _validate_isr(self, isr: AgentISR, evidence: str) -> AgentISR:
        self.grounds.append(evidence)
        return isr


def _revise(room: int | None, entries: dict[str, str] | None = ENTRIES) -> _Analyst:
    analyst = _Analyst(room)
    analyst.safe_revise_isr("raw data", "own", {"p": "peer"}, "feedback", 2, cited_entries=entries)
    return analyst


class TestTheRevision:
    def test_with_no_room_known_every_entry_follows_the_feedback(self) -> None:
        analyst = _revise(None)

        assert analyst.feedback.startswith(f"feedback\n\n{DEBATE_ENTRIES_HEAD}")
        assert ENTRIES["ev_0011"] in analyst.feedback
        assert ENTRIES["ev_0012"] in analyst.feedback
        assert analyst.revision_entries_shown == ("ev_0011", "ev_0012")

    def test_the_raw_data_keeps_its_room_and_a_large_entry_is_named(self) -> None:
        beside = len("own") + len("feedback") + len("peer")
        room = beside + len("raw data") + 600

        analyst = _revise(room)

        assert analyst.data == "raw data"
        assert ENTRIES["ev_0011"] in analyst.feedback
        assert f"{DEBATE_ENTRIES_UNFIT} ev_0012." in analyst.feedback
        assert analyst.revision_entries_shown == ("ev_0011",)

    def test_no_room_left_beside_the_raw_data_shows_none(self) -> None:
        room = len("own") + len("feedback") + len("peer") + len("raw data")

        analyst = _revise(room)

        assert analyst.data == "raw data"
        assert analyst.feedback == "feedback"
        assert analyst.revision_entries_shown == ()

    def test_the_entries_shown_are_grounds_for_the_checks(self) -> None:
        analyst = _revise(None)

        assert analyst.grounds and all(ENTRIES["ev_0011"] in g for g in analyst.grounds)
        assert all(g.startswith("raw data") for g in analyst.grounds)

    def test_no_entries_is_the_revision_as_it_was(self) -> None:
        analyst = _revise(None, entries=None)

        assert analyst.feedback == "feedback"
        assert analyst.grounds == ["raw data", "raw data"]
        assert analyst.revision_entries_shown == ()


def _judge(seen: list[str]) -> JudgeAgent:
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]

    class _Model:
        async def ainvoke(self, messages: Any, **_k: Any) -> Any:
            seen.append("\n".join(str(getattr(m, "content", m)) for m in messages))
            return MagicMock(content="CONTRADICTIONS: NONE\nagreement_confidence: 0.9")

    judge.llm = _Model()
    return judge


ROUND_FACTS = (
    f'The run\'s record of the last revision round:\n- L1 "x": named static.\n{LINE_MARK_RULE}'
)


def _budget(tool_chars: int, per_token: float = 3.0) -> Any:
    budget = MagicMock(spec=ContextBudget)
    budget.derives = True
    budget.chars_per_token = per_token
    budget.tool_budget_chars.return_value = tool_chars
    return budget


def _mediate(room: int | None, budget: Any = None, cap: int = 0, **extra: Any) -> str:
    seen: list[str] = []
    with (
        patch.object(JudgeAgent, "_question_room", return_value=room),
        patch.object(JudgeAgent, "_context_budget", return_value=budget),
        patch.object(JudgeAgent, "_built_cap_tokens", return_value=cap),
    ):
        asyncio.run(
            _judge(seen).mediate(
                reports={"static": "text"},
                history=[],
                isr_reports={},
                reputation_asked=True,
                **extra,
            )
        )
    return seen[0]


class TestTheMediation:
    def test_the_round_s_facts_and_the_entries_come_before_the_closing(self) -> None:
        prompt = _mediate(None, round_facts=ROUND_FACTS, cited_entries=ENTRIES)

        facts_at = prompt.index(ROUND_FACTS)
        entries_at = prompt.index(MEDIATION_ENTRIES_HEAD)
        assert prompt.index("Previous Discussion:") < facts_at < entries_at
        assert entries_at < prompt.index("End with the CONTRADICTIONS: block")
        assert ENTRIES["ev_0012"] in prompt

    def test_the_entries_take_only_what_the_reports_and_history_leave(self) -> None:
        reports_and_history = len("text") + len("[]")
        room = reports_and_history + len(CONTRADICTIONS_BLOCK_QUESTION) + 700
        prompt = _mediate(room, cited_entries=ENTRIES)

        assert ENTRIES["ev_0011"] in prompt
        assert f"{MEDIATION_ENTRIES_UNFIT} ev_0012." in prompt

    def test_the_follow_up_and_the_tool_loop_keep_their_room(self) -> None:
        reports_and_history = len("text") + len("[]")
        tool_chars, cap, per_token = 80_000, 1_000, 3.0
        reserve = (
            len(CONTRADICTIONS_BLOCK_QUESTION)
            + int(tool_chars * ANSWER_SHARE)
            + int(cap * per_token)
        )
        budget = _budget(tool_chars, per_token)

        without = _mediate(reports_and_history + 700, budget, cap, cited_entries=ENTRIES)
        beside = _mediate(reports_and_history + reserve + 700, budget, cap, cited_entries=ENTRIES)

        # Room enough for the entry alone is not room once the turns after it are kept.
        assert MEDIATION_ENTRIES_HEAD not in without
        assert ENTRIES["ev_0011"] in beside
        assert f"{MEDIATION_ENTRIES_UNFIT} ev_0012." in beside

    def test_the_reserve_is_the_question_with_no_budget_known(self) -> None:
        judge = _judge([])
        with patch.object(JudgeAgent, "_context_budget", return_value=None):
            assert judge._mediation_entries_reserve() == len(CONTRADICTIONS_BLOCK_QUESTION)

    def test_a_first_mediation_reads_as_it_did(self) -> None:
        prompt = _mediate(None)

        assert MEDIATION_ENTRIES_HEAD not in prompt
        assert LINE_MARK_RULE not in prompt
