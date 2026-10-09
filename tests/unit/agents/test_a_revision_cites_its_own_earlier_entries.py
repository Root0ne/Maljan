"""A revision may cite the ledger entries its own earlier rounds produced.

The analysis node drains each analyst's entries onto the job's ledger once its
work is done: the state's ledger channel is append-only, and an entry left in
the analyst's buffer would be written again by the next node that drains it.
The validator built what an analyst may cite from that buffer alone, so a
revision that repeated a correctly grounded technique claim, citing the
round-0 entry it was read from, was told the technique cited nothing from the
run, cost a validation turn, and was asked to withdraw a true finding.

The ids of what an analyst handed over stay with it for the rest of the job;
the entries themselves, and their output, are not sent again. Another
analyst's entries are never among them.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import UNGROUNDED_TECHNIQUE_CODE
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


class _Analyst(BaseAnalyst):
    def analyze(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        raise NotImplementedError

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        raise NotImplementedError


def _agent(name: str, entries: list[str], answers: list[str] | None = None, job: str = "j1") -> Any:
    agent = _Analyst.__new__(_Analyst)
    agent.name = name
    agent.logger = MagicMock()
    agent._job_id = job
    agent._drained_ids_job = ""
    agent._drained_ids = []
    agent.validation_findings = []
    agent.validation_retries = 0
    agent.validation_fed_back = {}
    agent._findings_buffer = []
    agent._artifacts_buffer = []
    agent._evidence_entries = [
        LedgerEntry(id=entry, agent=name, tool="pe_info") for entry in entries
    ]
    # The triage pack's entry, shown to every agent: what keeps an analyst
    # whose own buffer is empty from being exempt from the question.
    agent.pack_ledger_ids = ["ev_0100"]
    agent._answers = list(answers or [])
    agent._system_prompt = lambda _evidence, tools=None: "you are an analyst"  # type: ignore[method-assign]
    agent._truncate_input = lambda text, *a, **k: text  # type: ignore[method-assign]
    agent._capture_findings = lambda text: text  # type: ignore[method-assign]

    def _invoke(turns: Any, timeout: int, **_: Any) -> Any:
        return MagicMock(content=agent._answers.pop(0))

    agent._invoke_llm_with_timeout = _invoke  # type: ignore[method-assign]

    def _parse(text: str, revision_round: int = 0) -> AgentISR:
        evidence = text.split("EVIDENCE:", 1)[1].split("\n", 1)[0].strip()
        return _isr(name, evidence)

    agent._text_to_isr = _parse  # type: ignore[method-assign]
    return agent


def _isr(name: str, evidence: str) -> AgentISR:
    claim = ClaimEvidence(
        claim="it injects code", evidence_ref=evidence, confidence=0.4, technique_id="T1055"
    )
    return AgentISR(agent_id=name, domain="static", claims=[claim], revision_round=1)


def _answer(evidence: str) -> str:
    return f"CLAIM: it injects code\nEVIDENCE: {evidence}\nCONFIDENCE: 0.4\nTECHNIQUE: T1055\n"


def _validate(agent: Any, isr: AgentISR) -> AgentISR:
    with patch("maljan.agents.base_agent.get_settings") as settings:
        settings.return_value.react_agent_timeout = 60
        settings.return_value.react_agent_timeout_overrides = {}
        return agent._validate_isr(isr, "the evidence the analyst read")


def _ungrounded(agent: Any) -> int:
    return int(agent.validation_fed_back.get(UNGROUNDED_TECHNIQUE_CODE, 0))


class TestARevisionCitesItsOwnRoundZero:
    def test_a_round_zero_entry_is_still_citable_after_the_drain(self) -> None:
        agent = _agent("static", ["ev_0001", "ev_0002"], answers=[_answer("ev_0002 again")])
        assert [entry.id for entry in agent.drain_evidence_entries()] == ["ev_0001", "ev_0002"]

        _validate(agent, _isr("static", "ev_0002 lists VirtualAllocEx"))

        assert len(agent._answers) == 1, "no validation turn was asked"
        assert _ungrounded(agent) == 0
        assert agent.validation_retries == 0
        assert agent.validation_findings == []

    def test_entries_of_every_earlier_drain_of_the_job_are_citable(self) -> None:
        agent = _agent("static", ["ev_0001"], answers=[_answer("ev_0001 again")])
        agent.drain_evidence_entries()
        agent._evidence_entries = [LedgerEntry(id="ev_0007", agent="static", tool="strings")]
        agent.drain_evidence_entries()

        _validate(agent, _isr("static", "ev_0001 imports"))

        assert len(agent._answers) == 1, "no validation turn was asked"
        assert _ungrounded(agent) == 0

    def test_the_drain_still_hands_each_entry_over_once(self) -> None:
        agent = _agent("static", ["ev_0001"])

        assert len(agent.drain_evidence_entries()) == 1
        assert agent.drain_evidence_entries() == []

    def test_a_revision_that_cites_nothing_is_still_asked(self) -> None:
        agent = _agent("static", ["ev_0001"], answers=[_answer("ev_0001 lists it")])
        agent.drain_evidence_entries()

        revised = _validate(agent, _isr("static", "speculative"))

        assert _ungrounded(agent) == 1
        assert "ev_0001" in revised.claims[0].evidence_ref


class TestNoLeakBetweenAnalysts:
    def test_another_analyst_s_entry_is_not_a_citation(self) -> None:
        other = _agent("dynamic", ["ev_0005"])
        other.drain_evidence_entries()
        agent = _agent("static", ["ev_0001"], answers=[_answer("ev_0005 shows it")])
        agent.drain_evidence_entries()

        _validate(agent, _isr("static", "ev_0005 shows it"))

        assert _ungrounded(agent) == 1
        assert [row.code for row in agent.validation_findings] == [UNGROUNDED_TECHNIQUE_CODE]

    def test_an_earlier_job_s_entries_are_not_carried_into_the_next(self) -> None:
        agent = _agent("static", ["ev_0001"], answers=[_answer("ev_0001 again")], job="j1")
        agent.drain_evidence_entries()
        agent._job_id = "j2"
        agent._evidence_entries = [LedgerEntry(id="ev_0009", agent="static", tool="strings")]

        _validate(agent, _isr("static", "ev_0001 from the last job"))

        assert _ungrounded(agent) == 1
