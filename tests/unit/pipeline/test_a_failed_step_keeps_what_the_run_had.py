"""A step that fails keeps what the run already had.

Three paths each dropped something the run had already established:

* a judge that raised replaced the run's degradation reasons with its own
  failure alone, wrote no run summary (the stages, the spend and the coverage
  of the run were absent without notice), and filed its failure as an agent
  note beside ``ran: true`` rather than as the stage's failure;
* the report node handed the narrative and the composer the state's ledger ids
  only, so a section citing an entry the report node itself added (one no node
  drained, or the static provider's) had its citation refused;
* a lead that crashed with ``ValueError`` or ``RuntimeError`` took the answers
  its specialists had already given down with it, which the other failure
  paths promote.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

from maljan.core.config import Settings
from maljan.pipeline.nodes import citable_ids, make_judge_node, make_stage_agent_node
from maljan.pipeline.outcome import VERDICT_READ_FALLBACK
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import ANALYSIS_STAGE
from tests.unit.pipeline.test_a_fallback_verdict_assesses_nothing import _Container, _state
from tests.unit.pipeline.test_evidence_ledger_channel import _analysis_state, _Analyst, _Chunk
from tests.unit.pipeline.test_evidence_ledger_channel import _container as _analyst_container

TRIAGE_REASON = "the triage pack could not read the sample's sections"


def _failed_judge(stage: Any = None) -> dict[str, Any]:
    container = _Container(EvidenceCounter())
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(side_effect=TimeoutError("waited 1800s"))
    state = _state()
    state["triage_facts"] = {"degradation_reasons": [TRIAGE_REASON]}
    state["file_hash"] = "a" * 64
    return asyncio.run(make_judge_node(container, stage=stage)(state))


class TestAFailedJudgeKeepsTheRunsReasons:
    def test_the_reasons_gathered_before_it_failed_stay(self) -> None:
        reasons = _failed_judge()["degradation_reasons"]

        assert TRIAGE_REASON in reasons
        assert reasons[-1] == "judge failed (TimeoutError)"
        assert reasons.count("judge failed (TimeoutError)") == 1

    def test_the_run_summary_is_still_written(self) -> None:
        update = _failed_judge()
        summary = update["run_summary"]

        assert summary is not None
        assert summary["final_decision"] == "Suspicious"
        assert summary["degraded_mode"] is True
        assert summary["degradation_reasons"] == update["degradation_reasons"]
        assert summary["verdict_reading"] == VERDICT_READ_FALLBACK
        assert summary["file_hash"] == "a" * 64

    def test_the_verdict_stage_is_said_to_have_failed(self) -> None:
        settings = Settings(_env_file=None)
        stage = settings.agents.profiles["default"].stage("verdict")

        record = _failed_judge(stage)["stage_results"]["verdict"]

        assert record["ran"] is True
        assert record["failure"] is True
        assert record["reason"] == "judge failed (TimeoutError)"
        assert "agent_reasons" not in record

    def test_reasons_survive_a_judge_that_could_not_be_built(self) -> None:
        container = _Container(EvidenceCounter())
        container.server_degradation_reasons = lambda: ["the CAPE server rested"]  # type: ignore[method-assign]

        def _no_judge(role: str = "judge") -> Any:
            raise RuntimeError("no judge model configured")

        container.get_judge_agent = _no_judge  # type: ignore[method-assign]
        state = _state()
        state["triage_facts"] = {"degradation_reasons": [TRIAGE_REASON]}

        update = asyncio.run(make_judge_node(container)(state))

        assert update["degradation_reasons"] == [
            TRIAGE_REASON,
            "the CAPE server rested",
            "judge failed (RuntimeError)",
        ]


class TestTheReportCitesWhatItAdded:
    def test_an_entry_the_report_node_added_is_citable(self) -> None:
        state: dict[str, Any] = {"evidence_ledger": [{"id": "ev_0001"}, {"id": "ev_0002"}]}
        added = [SimpleNamespace(id="ev_0001"), SimpleNamespace(id="ev_0003")]

        assert citable_ids(state, added) == ["ev_0001", "ev_0002", "ev_0003"]  # type: ignore[arg-type]

    def test_with_nothing_added_it_is_the_state_s_ledger(self) -> None:
        state: dict[str, Any] = {"evidence_ledger": [{"id": "ev_0002"}, {"id": "ev_0001"}]}

        assert citable_ids(state) == ["ev_0002", "ev_0001"]  # type: ignore[arg-type]


class TestACrashedLeadKeepsItsSpecialistsAnswers:
    def test_the_answered_asks_are_promoted(self) -> None:
        agent = _Analyst("static", EvidenceCounter())
        answer = AgentISR(
            agent_id="deep_static",
            domain="static",
            claims=[
                ClaimEvidence(claim="Imports VirtualAllocEx", evidence_ref="ev", confidence=0.7)
            ],
        )
        agent.answered_asks = lambda: [answer]  # type: ignore[attr-defined]

        def _crash(_data: str) -> AgentISR:
            raise RuntimeError("segfault in the loader")

        agent.safe_analyze_isr = _crash  # type: ignore[method-assign]
        container = _analyst_container({"static": agent}, {"static": [_Chunk("PE32.")]})

        update = make_stage_agent_node(ANALYSIS_STAGE, "static", container)(_analysis_state())

        assert "crashed" in update["reports"]["static"]
        assert update["isr_reports"]["deep_static#1"] is answer
        assert update["reports"]["deep_static#1"] == answer.to_text_summary()
