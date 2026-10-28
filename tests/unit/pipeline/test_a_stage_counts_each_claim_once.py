"""A stage's claim count counts a claim mapped to several techniques once (T-425).

An analyst's block whose TECHNIQUE line listed several ids is read as one
claim per id. The stage record a condition reads (``stages.<key>.claim_count``)
counted those copies, so one claim with three techniques was three claims.
It now counts claim blocks (``validation.count_claim_blocks``), as the run
summary's row and the judge's ISR line do. A stored run keeps the count it
stored: nothing recomputes it from the stored claims.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.conditions import StageResult
from maljan.pipeline.nodes import make_stage_agent_node, stage_context
from maljan.reporting.follow_up import stored_run
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import ANALYSIS_STAGE
from tests.unit.analysis.test_one_claim_is_counted_once_everywhere import _split_isr
from tests.unit.pipeline.test_evidence_ledger_channel import (
    _analysis_state,
    _Analyst,
    _Chunk,
    _container,
)
from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import (
    _payload,
    _rows,
)


class _SplitAnswer(_Analyst):
    """An analyst whose answer is one claim with three techniques and one other claim."""

    def __init__(self, isr: AgentISR) -> None:
        super().__init__("static", EvidenceCounter())
        self.answer = isr

    def _isr(self) -> AgentISR:
        return self.answer


def _stage_entry(isr: AgentISR) -> dict[str, Any]:
    container = _container({"static": _SplitAnswer(isr)}, {"static": [_Chunk("PE32.")]})
    update = make_stage_agent_node(ANALYSIS_STAGE, "static", container)(_analysis_state())
    (entry,) = update["stage_results"].values()
    return entry


class TestTheStageRecordCountsClaimBlocks:
    def test_a_claim_with_three_techniques_and_one_other_is_two_claims(self) -> None:
        isr = _split_isr()
        assert len(isr.claims) == 4
        assert _stage_entry(isr)["claim_count"] == 2

    def test_a_split_claim_built_without_the_reader_is_one_claim(self) -> None:
        assert _stage_entry(_split_isr(read=False))["claim_count"] == 2

    def test_its_techniques_are_still_every_id(self) -> None:
        assert _stage_entry(_split_isr())["technique_ids"] == ["T1082", "T1016", "T1033", "T1057"]


class TestAStoredStageKeepsItsCount:
    def test_a_stored_stage_row_keeps_the_count_it_stored(self) -> None:
        # Stored by a run before the count was by block: four copies, as stored.
        findings = [
            {
                "agent_name": "static",
                "domain": "static",
                "claims": [c.model_dump(mode="json") for c in _split_isr().claims],
                "dissent_items": [],
            }
        ]
        run = stored_run(
            _payload(),
            _rows(),
            findings,
            {"stages": [{"key": "static", "ran": True, "claim_count": 4}]},
        )
        assert len(run.isr_reports["static"].claims) == 4
        assert run.state["stage_results"]["static"]["claim_count"] == 4
        assert stage_context(run.state).stages["static"].claim_count == 4

    def test_a_stage_result_reads_back_its_stored_value(self) -> None:
        stored = {"ran": True, "claim_count": 4, "technique_ids": ["T1082"]}
        assert StageResult.from_dict(stored).claim_count == 4
        assert StageResult.from_dict(stored).to_dict()["claim_count"] == 4


def test_a_claim_with_one_technique_is_one_claim() -> None:
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim="runs from memory", evidence_ref="[ev_0002]", confidence=0.8)],
    )
    assert _stage_entry(isr)["claim_count"] == 1
