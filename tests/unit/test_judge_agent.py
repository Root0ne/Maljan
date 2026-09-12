"""Tests for the JudgeAgent standalone class.

JudgeAgent is NOT a BaseAnalyst subclass — it has two distinct responsibilities:
  1. mediate()     — finds contradictions, returns (AgentArgument, is_consensus)
  2. give_verdict() — produces a STIX 2.1 Bundle

All tests use a mocked LLM to avoid real API calls.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from maljan.agents.judge_agent import CONSENSUS_THRESHOLD, JudgeAgent
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.pipeline.state import AgentArgument


@pytest.fixture
def mock_llm() -> MagicMock:
    """Mocked LLM that supports with_structured_output and LangChain pipe chains."""
    return MagicMock()


@pytest.fixture
def sample_reports() -> dict[str, str]:
    return {
        "static": "Found CryptAcquireContext and CreateRemoteThread.",
        "dynamic": "Process injection into explorer.exe detected.",
        "network": "Periodic HTTPS beacon to 185.220.101.45:443.",
    }


@pytest.fixture
def sample_history() -> list[AgentArgument]:
    return []


class TestJudgeAgentInit:
    """JudgeAgent is a standalone class — no BaseAnalyst inheritance."""

    def test_is_not_base_analyst(self) -> None:
        from maljan.agents.base_agent import BaseAnalyst

        llm = MagicMock()
        judge = JudgeAgent(llm=llm)
        assert not isinstance(judge, BaseAnalyst)

    def test_stores_llm(self) -> None:
        llm = MagicMock()
        judge = JudgeAgent(llm=llm)
        assert judge.llm is llm

    def test_has_logger(self) -> None:
        judge = JudgeAgent(llm=MagicMock())
        assert judge.logger is not None


class TestJudgeAgentMediate:
    """Tests for the mediate() method."""

    def test_mediate_returns_tuple(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        verdict = MediatorVerdict(
            contradictions=["Agent A says X, Agent B says Y"],
            resolution_summary="Partial agreement found.",
            confidence=0.5,
        )
        judge = JudgeAgent(llm=mock_llm)

        with (
            patch.object(judge, "_initialize_mcp_client"),
            patch.object(judge, "execute_tool_loop", return_value="Mediation result text."),
            patch.object(judge, "_fallback_mediate", return_value=verdict),
        ):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            result = asyncio.run(judge.mediate(sample_reports, sample_history))

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_mediate_returns_agent_argument_and_bool(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        verdict = MediatorVerdict(
            contradictions=[],
            resolution_summary="All experts agree.",
            confidence=0.95,
        )
        judge = JudgeAgent(llm=mock_llm)

        with (
            patch.object(judge, "_initialize_mcp_client"),
            patch.object(judge, "execute_tool_loop", return_value="Mediation result text."),
            patch.object(judge, "_fallback_mediate", return_value=verdict),
        ):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            argument, is_consensus = asyncio.run(judge.mediate(sample_reports, sample_history))

        assert isinstance(argument, AgentArgument)
        assert argument.agent_name == "Mediator"
        assert isinstance(is_consensus, bool)

    def test_consensus_above_threshold(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        """confidence >= CONSENSUS_THRESHOLD => is_consensus is True."""
        verdict = MediatorVerdict(
            contradictions=[],
            resolution_summary="Full agreement.",
            confidence=CONSENSUS_THRESHOLD,
        )
        judge = JudgeAgent(llm=mock_llm)

        with (
            patch.object(judge, "_initialize_mcp_client"),
            patch.object(judge, "execute_tool_loop", return_value="Full agreement."),
            patch.object(judge, "_fallback_mediate", return_value=verdict),
        ):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            _, is_consensus = asyncio.run(judge.mediate(sample_reports, sample_history))

        assert is_consensus is True

    def test_no_consensus_below_threshold(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        """confidence < CONSENSUS_THRESHOLD => is_consensus is False."""
        verdict = MediatorVerdict(
            contradictions=["Major contradiction"],
            resolution_summary="Unresolved.",
            confidence=CONSENSUS_THRESHOLD - 0.01,
        )
        judge = JudgeAgent(llm=mock_llm)

        with (
            patch.object(judge, "_initialize_mcp_client"),
            patch.object(judge, "execute_tool_loop", return_value="Unresolved."),
            patch.object(judge, "_fallback_mediate", return_value=verdict),
        ):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            _, is_consensus = asyncio.run(judge.mediate(sample_reports, sample_history))

        assert is_consensus is False

    def test_mediate_generic_any_agent_count(self, mock_llm: MagicMock) -> None:
        """mediate() accepts any number of reports without modification."""
        verdict = MediatorVerdict(contradictions=[], resolution_summary="Ok.", confidence=0.9)
        # 5 agents instead of 3 — method should not care
        reports = {f"agent_{i}": f"Report from agent {i}" for i in range(5)}
        judge = JudgeAgent(llm=mock_llm)

        with (
            patch.object(judge, "_initialize_mcp_client"),
            patch.object(judge, "execute_tool_loop", return_value="Ok."),
            patch.object(judge, "_fallback_mediate", return_value=verdict),
        ):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            argument, is_consensus = asyncio.run(judge.mediate(reports, []))

        assert argument.agent_name == "Mediator"
        assert is_consensus is True

    def test_confidence_score_stored_in_argument(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        expected_confidence = 0.72
        verdict = MediatorVerdict(
            contradictions=[], resolution_summary="Partial.", confidence=expected_confidence
        )
        judge = JudgeAgent(llm=mock_llm)

        with (
            patch.object(judge, "_initialize_mcp_client"),
            patch.object(judge, "execute_tool_loop", return_value="Partial."),
            patch.object(judge, "_fallback_mediate", return_value=verdict),
        ):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            argument, _ = asyncio.run(judge.mediate(sample_reports, sample_history))

        assert argument.confidence_score == pytest.approx(expected_confidence)

    def test_fallback_when_structured_output_fails(
        self, sample_reports: dict, sample_history: list
    ) -> None:
        """When structured output raises, fallback should produce a MediatorVerdict."""
        llm = MagicMock()
        judge = JudgeAgent(llm=llm)

        verdict = MediatorVerdict(
            contradictions=[],
            resolution_summary="Confidence: 0.6",
            confidence=0.6,
        )

        with (
            patch.object(judge, "_initialize_mcp_client"),
            patch.object(judge, "execute_tool_loop", return_value="Confidence: 0.6"),
            patch.object(judge, "_fallback_mediate", return_value=verdict),
        ):
            llm.with_structured_output.side_effect = Exception("Provider not supported")
            # Should not raise — fallback activates
            argument, _ = asyncio.run(judge.mediate(sample_reports, sample_history))

        assert argument.agent_name == "Mediator"


class TestJudgeAgentExtractConfidence:
    """Tests for the private text-based confidence extractor (fallback path)."""

    def test_extracts_valid_float(self) -> None:
        text = "The confidence score is: 0.78\nAll experts agree."
        result = JudgeAgent._extract_confidence_from_text(text)
        assert result == pytest.approx(0.78)

    # 2026-08-07: the next three used to assert clamping and a 0.5 default.
    # Both were changed deliberately, because together they shipped a false
    # consensus: clamping accepted *any* number on the line, so
    # "Confidence: 0.95 (based on 3 agents)" scanned in reverse, hit the 3,
    # clamped it to 1.0 and ended the negotiation on a number that was never a
    # score. Clamping is what made the wrong token look legitimate, so a value
    # outside [0,1] is now evidence the model ignored the contract rather than
    # something to be repaired into range. And the 0.5 default was
    # indistinguishable from a real 0.5 while sitting permanently below
    # CONSENSUS_THRESHOLD, so no run could ever converge.
    # See tests/unit/agents/test_mediator_confidence_extraction.py.

    def test_rejects_above_one_instead_of_clamping(self) -> None:
        assert JudgeAgent._extract_confidence_from_text("confidence: 1.5") is None

    def test_rejects_below_zero_instead_of_clamping(self) -> None:
        assert JudgeAgent._extract_confidence_from_text("confidence: -0.3") is None

    def test_returns_none_when_not_found(self) -> None:
        assert JudgeAgent._extract_confidence_from_text("No score mentioned here.") is None


class TestFallbackBundleFailsClosed:
    """The degraded path must emit less than the working one, not more.

    The fallback builder used to union two sets of technique identifiers: the
    ones analysts had claimed against cited evidence, and every identifier
    matching ``T\\d{4}`` anywhere in the model's raw response. Both were emitted
    as ``attack-pattern`` objects in one bundle. The scraped ones are real
    ATT&CK identifiers that no evidence source claimed, so a schema check passes
    them and an analyst cannot tell them from techniques three layers agreed on.

    These tests exist because that guarantee was stated in a comment and pinned
    by nothing.
    """

    @pytest.fixture
    def judge(self) -> JudgeAgent:
        return JudgeAgent(llm=MagicMock())

    @staticmethod
    def _isr(*technique_ids: str):
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        return {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim=f"claim for {tid}",
                        evidence_ref="import table @ 0x401000",
                        confidence=0.9,
                        technique_id=tid,
                    )
                    for tid in technique_ids
                ],
            )
        }

    @staticmethod
    def _emitted(bundle) -> set[str]:
        return {
            o["name"] for o in bundle.model_dump()["objects"] if o.get("type") == "attack-pattern"
        }

    def test_an_identifier_only_the_model_named_is_not_emitted(self, judge) -> None:
        bundle = judge._fallback_bundle_from_text(
            "The sample performs T1055.001 and also T1486.",
            {},
            self._isr("T1055.001"),
        )
        assert self._emitted(bundle) == {"T1055.001"}, (
            "T1486 was named by the model and by no evidence claim; the degraded "
            "path must not put it in front of an analyst"
        )

    def test_the_evidence_claims_still_reach_the_bundle(self, judge) -> None:
        bundle = judge._fallback_bundle_from_text("[TIMEOUT]", {}, self._isr("T1055.001", "T1027"))
        assert self._emitted(bundle) == {"T1055.001", "T1027"}

    def test_what_was_dropped_is_recorded_rather_than_discarded(self, judge) -> None:
        malware = next(
            o
            for o in judge._fallback_bundle_from_text(
                "T1486 and T1490 look likely.", {}, self._isr("T1055.001")
            ).model_dump()["objects"]
            if o["type"] == "malware"
        )
        assert malware["x_maljan_model_only_technique_ids"] == ["T1486", "T1490"]
        assert malware["x_maljan_degraded_path"] is True

    def test_no_empty_custom_property_when_nothing_was_dropped(self, judge) -> None:
        malware = next(
            o
            for o in judge._fallback_bundle_from_text(
                "T1055.001 only.", {}, self._isr("T1055.001")
            ).model_dump()["objects"]
            if o["type"] == "malware"
        )
        assert "x_maljan_model_only_technique_ids" not in malware, (
            "an empty array serialised as present is one of the two conformance "
            "defects an external validator found in this emitter"
        )


class TestJudgeToolCallsAreCitable:
    """The judge calls tools too, and a verdict that leans on one must be checkable.

    Threat intel on a disputed indicator and the knowledge lookups are exactly
    the calls a reader would want to resolve, and they went through an executor
    with no recorder attached, so they were neither citable nor counted.
    """

    @staticmethod
    def _tool():
        from langchain_core.tools import StructuredTool

        def reputation(indicator: str) -> dict:
            """Look up an indicator's reputation."""
            return {"indicator": indicator, "malicious": 7}

        return StructuredTool.from_function(func=reputation, name="reputation")

    def _run(self, judge: JudgeAgent) -> str:
        from langchain_core.messages import AIMessage

        async def _ainvoke(payload, config=None):
            # The executor is the seam the loop calls the tool through; the
            # recorder wraps whichever tools it is handed.
            for wrapped in captured[0]:
                wrapped.invoke({"indicator": "c2.evil.tld"})
            return {"messages": [AIMessage(content="Verdict: Malware.")]}

        captured: list = []

        def _create(llm, tools):
            captured.append(tools)
            executor = MagicMock()
            executor.ainvoke = _ainvoke
            return executor

        with patch("langgraph.prebuilt.create_react_agent", _create):
            return asyncio.run(
                judge.execute_tool_loop([("system", "mediate"), ("human", "reports")])
            )

    def test_a_judge_tool_call_becomes_a_ledger_entry(self, mock_llm: MagicMock) -> None:
        judge = JudgeAgent(llm=mock_llm)
        judge.tools = [self._tool()]

        assert self._run(judge) == "Verdict: Malware."

        entries = judge.drain_evidence_entries()
        assert [e.tool for e in entries] == ["reputation"]
        assert entries[0].agent == "judge"
        assert entries[0].structured == {"indicator": "c2.evil.tld", "malicious": 7}

    def test_the_ids_continue_the_job_s_sequence(self, mock_llm: MagicMock) -> None:
        from maljan.schemas.evidence import EvidenceCounter

        counter = EvidenceCounter()
        counter.next_id()
        counter.next_id()

        judge = JudgeAgent(llm=mock_llm)
        judge.tools = [self._tool()]
        judge.evidence_counter = counter
        self._run(judge)

        assert [e.id for e in judge.drain_evidence_entries()] == ["ev_0003"]

    def test_two_mediation_rounds_both_reach_the_drain(self, mock_llm: MagicMock) -> None:
        judge = JudgeAgent(llm=mock_llm)
        judge.tools = [self._tool()]
        self._run(judge)
        self._run(judge)

        entries = judge.drain_evidence_entries()
        assert [e.id for e in entries] == ["ev_0001", "ev_0002"]
        assert judge.drain_evidence_entries() == []

    def test_a_judge_with_no_tools_records_nothing(self, mock_llm: MagicMock) -> None:
        judge = JudgeAgent(llm=mock_llm)
        assert judge.drain_evidence_entries() == []
