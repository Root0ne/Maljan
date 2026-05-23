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

    def test_clamps_above_one(self) -> None:
        text = "confidence: 1.5"
        result = JudgeAgent._extract_confidence_from_text(text)
        assert result == 1.0

    def test_clamps_below_zero(self) -> None:
        text = "confidence: -0.3"
        result = JudgeAgent._extract_confidence_from_text(text)
        assert result == 0.0

    def test_defaults_to_0_5_when_not_found(self) -> None:
        result = JudgeAgent._extract_confidence_from_text("No score mentioned here.")
        assert result == 0.5


class TestBuildCTIBlock:
    """Coverage for the sandbox-CTI prompt-section helper."""

    def test_returns_empty_for_none(self) -> None:
        from maljan.agents.judge_agent import _build_cti_block

        assert _build_cti_block(None) == ""

    def test_returns_empty_for_empty_dict(self) -> None:
        from maljan.agents.judge_agent import _build_cti_block

        assert _build_cti_block({}) == ""

    def test_returns_empty_when_all_lists_empty(self) -> None:
        from maljan.agents.judge_agent import _build_cti_block

        cti = {
            "family": [],
            "ttp": [],
            "tags": [],
            "c2": {"urls": [], "domains": [], "ips": []},
            "mutexes": [],
            "keys": [],
            "credentials": [],
            "dropped_files": [],
            "dropper_urls": [],
            "ransom_notes": [],
            "network": {
                "dns_queries": [],
                "http_urls": [],
                "domains": [],
                "ips": [],
                "tls_ja3": [],
                "tls_sni": [],
            },
            "indicators": [],
            "yara_rules": [],
            "score": None,
        }
        assert _build_cti_block(cti) == ""

    def test_renders_all_populated_sections(self) -> None:
        from maljan.agents.judge_agent import _build_cti_block

        cti = {
            "family": ["emotet"],
            "ttp": ["T1055", "T1059.001"],
            "tags": ["malware:trojan"],
            "score": 10,
            "c2": {
                "urls": ["http://evil.example/c2"],
                "domains": ["evil.example"],
                "ips": ["1.2.3.4"],
            },
            "mutexes": ["GlobalMutex_xyz"],
            "keys": [{"kind": "AES", "key": "deadbeef", "value": None}],
            "credentials": [{"protocol": "ftp", "host": "ftp.evil.example"}],
            "dropped_files": [{"name": "payload.bin", "sha256": "f" * 64}],
            "dropper_urls": [{"type": "exe", "url": "http://stager.example/p"}],
            "ransom_notes": [{"family": "ransom"}],
            "network": {
                "dns_queries": ["evil.example"],
                "http_urls": ["http://evil.example/x"],
                "domains": ["evil.example"],
                "ips": ["1.2.3.4"],
                "tls_ja3": ["abc"],
                "tls_sni": ["evil.example"],
            },
            "indicators": [{"ioc": "evil.example", "description": "C2 contacted"}],
            "yara_rules": ["emotet_c2"],
        }
        out = _build_cti_block(cti)
        assert out.startswith("=== SANDBOX_CTI")
        assert out.rstrip().endswith("=== END SANDBOX_CTI ===")
        assert "sandbox_score: 10/10" in out
        assert "family: ['emotet']" in out
        assert "mitre_ttp: ['T1055', 'T1059.001']" in out
        assert "http://evil.example/c2" in out
        assert "GlobalMutex_xyz" in out
        assert "credentials_count: 1" in out
        assert "payload.bin" in out
        assert "fffffffffffffff" in out  # truncated sha256 visible
        assert "stager.example" in out
        assert "ransom_notes: 1 extracted" in out
        assert "tls_sni: ['evil.example']" in out
        assert "yara_rules: ['emotet_c2']" in out
        assert "sandbox_indicators: ['evil.example']" in out

    def test_truncates_long_lists(self) -> None:
        from maljan.agents.judge_agent import _build_cti_block

        cti = {
            "ttp": [f"T{i:04d}" for i in range(50)],
            "c2": {"domains": [f"evil-{i}.example" for i in range(30)], "urls": [], "ips": []},
        }
        out = _build_cti_block(cti)
        # ttp helper caps at 12; the 13th and 30th must not appear verbatim.
        assert "'T0011'" in out
        assert "'T0012'" not in out
        # c2 domain helper caps at 8.
        assert "evil-7.example" in out
        assert "evil-8.example" not in out


class TestCTIReachesVerdictPrompt:
    """Integration check: CTI passed to give_verdict() lands in the prompt
    that reaches the LLM. We intercept the ChatPromptTemplate.from_messages
    call to capture the formatted text."""

    def test_cti_block_present_in_human_message(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        captured: dict[str, str] = {}

        class _FakeChain:
            async def ainvoke(self, kwargs: dict) -> object:
                captured["reports"] = str(kwargs.get("reports", ""))

                class _R:
                    content = "{}"  # invalid JSON triggers text fallback

                return _R()

        class _FakePrompt:
            def __or__(self, _llm: object) -> _FakeChain:
                return _FakeChain()

        cti_block = {
            "family": ["emotet"],
            "ttp": ["T1055"],
            "c2": {"urls": [], "domains": ["evil.example"], "ips": ["1.2.3.4"]},
            "mutexes": ["GlobalMutex_xyz"],
            "score": 9,
        }

        judge = JudgeAgent(llm=MagicMock())
        with patch(
            "maljan.agents.judge_agent.ChatPromptTemplate.from_messages",
            return_value=_FakePrompt(),
        ):
            asyncio.run(
                judge.give_verdict(
                    reports={"static": "x"},
                    history=[],
                    cti_block=cti_block,
                )
            )

        assert "reports" in captured
        # CTI block must surface in the prompt text exactly as rendered by
        # _build_cti_block — sandbox_score / family / c2 / mutex lines.
        text = captured["reports"]
        assert "SANDBOX_CTI" in text
        assert "sandbox_score: 9/10" in text
        assert "family: ['emotet']" in text
        assert "evil.example" in text
        assert "1.2.3.4" in text
        assert "GlobalMutex_xyz" in text

    def test_no_cti_block_means_no_section(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        captured: dict[str, str] = {}

        class _FakeChain:
            async def ainvoke(self, kwargs: dict) -> object:
                captured["reports"] = str(kwargs.get("reports", ""))

                class _R:
                    content = "{}"

                return _R()

        class _FakePrompt:
            def __or__(self, _llm: object) -> _FakeChain:
                return _FakeChain()

        judge = JudgeAgent(llm=MagicMock())
        with patch(
            "maljan.agents.judge_agent.ChatPromptTemplate.from_messages",
            return_value=_FakePrompt(),
        ):
            asyncio.run(
                judge.give_verdict(
                    reports={"static": "x"},
                    history=[],
                    cti_block=None,
                )
            )
        assert "reports" in captured
        # Without CTI, the SANDBOX_CTI header MUST NOT appear in the prompt.
        assert "SANDBOX_CTI" not in captured["reports"]
