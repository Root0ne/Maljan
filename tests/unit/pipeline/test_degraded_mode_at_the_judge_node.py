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

    def server_rests(self) -> list[dict]:
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


class _TeamContainer(_Container):
    """The paper's three analysts, each a role of its own name."""

    def analyst_keys(self) -> list[str]:
        return ["static", "dynamic", "network"]

    def active_profile(self) -> Any:
        return paper_profile(["static", "dynamic", "network"])

    def agent_role(self, key: str) -> str:
        return key


class TestASkippedAnalystIsSaidToBeSkipped:
    """An analyst skipped for want of sandbox data did not run, and the reason says so."""

    def _reasons(self, dynamic_claims: bool) -> list[str]:
        state = _state([])
        claimed = state["isr_reports"]["static"]
        dynamic = AgentISR(agent_id="dynamic", domain="dynamic", claims=[])
        if dynamic_claims:
            dynamic = AgentISR(agent_id="dynamic", domain="dynamic", claims=list(claimed.claims))
        network = AgentISR(agent_id="network", domain="network", claims=[])
        state["isr_reports"] = {"static": claimed, "dynamic": dynamic, "network": network}
        state["reports"] = {**state["reports"], "dynamic": "", "network": ""}
        # The mock sandbox's stand-in for a detonation that never ran.
        state["sandbox_report"] = {"synthetic": True, "signatures": []}
        container = _TeamContainer(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        return list(asyncio.run(make_judge_node(container)(state))["degradation_reasons"])

    def test_the_reason_names_them_skipped_for_no_sandbox_data(self) -> None:
        reasons = self._reasons(dynamic_claims=False)
        assert "analysts skipped (no sandbox data): dynamic, network" in reasons
        assert not any(r.startswith("analysts produced no claims:") for r in reasons)

    def test_an_analyst_that_claimed_is_not_named(self) -> None:
        reasons = self._reasons(dynamic_claims=True)
        assert "analysts skipped (no sandbox data): network" in reasons


class TestANoteOnPartOfAnAnswer:
    """An unread claim beside claims read is listed and does not degrade the run."""

    SENTENCE = (
        "The static analyst's answer began 2 claim(s), and 1 were read; 1 could not be "
        "read as a claim and are not in its findings."
    )

    def _judged(self) -> tuple[dict[str, Any], str]:
        state = _state([])
        isr = state["isr_reports"]["static"]
        isr.note_claims_unread(self.SENTENCE)
        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        update = asyncio.run(make_judge_node(container)(state))
        return update, str(judge.give_verdict.call_args.kwargs.get("degradation_note") or "")

    def test_the_run_is_not_degraded_and_the_note_is_listed(self) -> None:
        update, _note = self._judged()

        assert self.SENTENCE in update["degradation_reasons"]
        assert update["degraded_mode"] is False
        assert update["run_summary"]["degraded_mode"] is False

    def test_the_judge_is_told_it_is_a_note_not_a_missing_tool(self) -> None:
        _update, note = self._judged()

        assert self.SENTENCE in note
        assert "degraded" not in note
        assert "claims it read standing" in note
        assert "missing tool" not in note


class _RememberingContainer(_Container):
    """A container with a memory store, and a report stage that runs or not."""

    def __init__(self, counter: EvidenceCounter, *, reporting: bool) -> None:
        super().__init__(counter)
        from maljan.memory.in_memory_store import InMemoryStore

        self._store = InMemoryStore()
        self.pending_memory_case: Any = None
        self.config.reporting.enabled = reporting

    def get_memory_store(self) -> Any:
        return self._store


def _thin_in_claims() -> dict[str, Any]:
    """One claimed technique, which no second source names."""
    import json

    state = _state([])
    empty = {"capabilities": []}
    entry = _capa_entry().model_copy(update={"output": json.dumps(empty), "structured": empty})
    state["evidence_ledger"] = [entry]
    return state


def _judged(state: dict[str, Any], *, reporting: bool, objects: list[dict]) -> Any:
    container = _RememberingContainer(EvidenceCounter(), reporting=reporting)
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(
        return_value=JudgeVerdict(
            bundle=Bundle.model_validate({"objects": objects}),
            violations=[],
            retries=0,
            fed_back={},
        )
    )
    asyncio.run(make_judge_node(container)(state))
    return container.pending_memory_case


def _technique(tid: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": tid,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


class TestThePublishedGateDecides:
    """The case is judged on what the run published, not on what was claimed."""

    def test_a_run_thin_in_claims_is_held_for_the_report_node(self) -> None:
        case = _judged(_thin_in_claims(), reporting=True, objects=[])

        assert case is not None, "the report node's published gate decides"
        assert case.technique_ids == ["T1055"]

    def test_without_a_report_node_the_case_holds_the_published_ids(self) -> None:
        case = _judged(
            _thin_in_claims(),
            reporting=False,
            objects=[_technique("T1055"), _technique("T1027")],
        )

        assert case is not None
        assert case.technique_ids == ["T1055", "T1027"]
        assert case.total_techniques == 2

    def test_without_a_report_node_a_thin_publication_is_not_stored(self) -> None:
        case = _judged(_thin_in_claims(), reporting=False, objects=[_technique("T1055")])

        assert case is None


def test_a_bundle_that_could_not_be_read_keeps_the_claimed_ids_and_says_so() -> None:
    from maljan.memory.long_term_memory import StoredCase
    from maljan.pipeline.nodes import case_for_the_judge_alone

    claimed = StoredCase(
        sample_id="s", summary_text="t", technique_ids=["T1055", "T1027"], total_techniques=2
    )

    case, note = case_for_the_judge_alone(claimed, None, {}, [])

    assert case is claimed
    assert "claimed" in note


def test_a_profile_that_cannot_be_read_is_said(caplog: Any) -> None:
    import logging
    from unittest.mock import MagicMock

    from maljan.pipeline.nodes import a_report_node_follows

    container = MagicMock()
    container.config.reporting.enabled = True
    container.active_profile.side_effect = RuntimeError("no profile")

    with caplog.at_level(logging.WARNING):
        assert a_report_node_follows(container) is True

    assert any("report node" in record.getMessage() for record in caplog.records)
