"""What degrades a run is decided at the judge node, over everything it adds.

A failed optional pack tool leaves its token on the record and does not flip
``degraded_mode``; a failed identity entry does. Asserted at the node, not on
the helper alone, because the node adds reasons of its own on the way and
the assertion has to survive them: this fixture neutralises each one.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

from maljan.agents.judge_agent import JudgeVerdict
from maljan.core.token_ledger import TokenLedger
from maljan.core.truncation_ledger import TruncationLedger
from maljan.pipeline.nodes import make_judge_node
from maljan.schemas.evidence import EvidenceCounter, build_entry, format_entry_id
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle
from tests.stages import paper_profile
from tests.unit.pipeline.test_evidence_ledger_channel import _JudgeContainer


class _Container(_JudgeContainer):
    def server_degradation_reasons(self) -> list[str]:
        return []

    def active_profile(self) -> Any:
        return paper_profile(["static"])

    def get_token_ledger(self) -> TokenLedger:
        return TokenLedger()

    def get_truncation_ledger(self) -> TruncationLedger:
        return TruncationLedger()


def _capa_entry() -> Any:
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "ledger" / "capa.json"
    return build_entry(
        entry_id=format_entry_id(1),
        seq=1,
        agent="pipeline",
        tool="capa",
        args={},
        server="pipeline",
        output=fixture.read_text(encoding="utf-8"),
        stage="triage_pack",
    )


def _state(pack_reasons: list[str]) -> dict[str, Any]:
    claim = ClaimEvidence(
        claim="Allocates and writes memory in a remote process",
        evidence_ref="[ev_0001] capa: inject code",
        confidence=0.8,
        technique_id="T1055",
    )
    return {
        "iteration_count": 1,
        "reports": {"static": "static findings"},
        "isr_reports": {"static": AgentISR(agent_id="static", domain="static", claims=[claim])},
        "evidence_ledger": [_capa_entry()],
        "sandbox_report": {"signatures": []},
        "sample_path": None,
        "triage_facts": {"degradation_reasons": pack_reasons},
        "validation_findings": {},
        "validation_not_run": [],
    }


def _run(state: dict[str, Any]) -> dict[str, Any]:
    container = _Container(EvidenceCounter())
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(
        return_value=JudgeVerdict(bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={})
    )
    return asyncio.run(make_judge_node(container)(state))


class TestACapaFailureAlone:
    def test_the_token_is_on_the_record_and_the_run_is_not_degraded(self) -> None:
        update = _run(_state(["triage.capa_failed"]))
        assert "triage.capa_failed" in update["degradation_reasons"]
        assert update["degraded_mode"] is False
        summary = update["run_summary"]
        assert summary["degraded_mode"] is False
        assert "triage.capa_failed" in summary["degradation_reasons"]

    def test_a_failed_identity_entry_degrades_the_run(self) -> None:
        update = _run(_state(["triage.identify_file_failed"]))
        assert update["degraded_mode"] is True
        assert update["run_summary"]["degraded_mode"] is True


class TestTheJudgeRecordsItsOwnUncheckedIds:
    def test_an_unreadable_catalogue_is_a_not_run_check_at_the_judge_too(self, monkeypatch) -> None:
        from maljan.pipeline import nodes

        class _NoCatalogue:
            @staticmethod
            def catalogue_available() -> bool:
                return False

        monkeypatch.setattr(nodes, "_knowledge_module", lambda: _NoCatalogue())
        update = _run(_state([]))
        summary = update["run_summary"]
        assert "attck.unknown_id" in summary["validation"]["not_run"]
        assert any(
            reason.startswith("the ATT&CK catalogue could not be read")
            for reason in update["degradation_reasons"]
        )


class TestTheZeroCorroborationNoteCountsClaims:
    def test_rule_only_tags_are_stated_apart_from_the_claimed_count(self) -> None:
        """capa and YARA firing richly on benign software used to read as
        thirty-three techniques; the count is the analysts' claims, and the
        rule-only tags are a sentence of their own."""
        import json

        state = _state([])
        capa = {
            "capabilities": [
                {"rule": "a", "namespace": "", "attck": ["X [T1027]"], "mbc": [], "match_count": 1},
                {"rule": "b", "namespace": "", "attck": ["X [T1497]"], "mbc": [], "match_count": 1},
            ]
        }
        entry = _capa_entry().model_copy(update={"output": json.dumps(capa), "structured": capa})
        state["evidence_ledger"] = [entry]
        update = _run(state)
        reasons = update["degradation_reasons"]
        assert "zero cross-layer corroboration (1 claimed technique)" in reasons
        assert "2 rule matches carry technique tags no analyst claimed" in reasons
        assert not any("single-layer" in r for r in reasons)
