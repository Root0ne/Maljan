"""Unit tests for the sycophancy detector."""

from __future__ import annotations

from maljan.pipeline.sycophancy_detector import (
    DEVIL_ADVOCATE_DIRECTIVE,
    build_revision_directive,
    detect_sycophancy,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _make_isr(agent_id: str, domain: str, claim_text: str, confidence: float = 0.8) -> AgentISR:
    return AgentISR(
        agent_id=agent_id,
        domain=domain,  # type: ignore[arg-type]
        claims=[
            ClaimEvidence(
                claim=claim_text,
                evidence_ref=f"evidence from {agent_id}",
                confidence=confidence,
            )
        ],
        dissent_items=[],
        revision_round=1,
    )


class TestDetectSycophancy:
    def test_identical_summaries_detected(self) -> None:
        """Two ISRs with near-identical claim text are flagged at a lower threshold.

        Because to_text_summary() includes agent_id and domain in the header,
        two ISRs for different agents will never be 100% cosine-identical even
        when their claims are the same. We use threshold=0.70 to reflect realistic
        sycophancy detection in production (heavily overlapping content).
        """
        isr_a = _make_isr("static", "static", "Encrypts files using AES-256 via CryptoAPI calls")
        isr_b = _make_isr("dynamic", "dynamic", "Encrypts files using AES-256 via CryptoAPI calls")
        # ``iteration=1+`` is required — round 0 never triggers, by design.
        assert detect_sycophancy([isr_a, isr_b], threshold=0.70, iteration=1) is True

    def test_distinct_summaries_not_detected(self) -> None:
        """ISRs from completely different analysis domains should not be flagged."""
        isr_static = _make_isr(
            "static",
            "static",
            "Imports VirtualAllocEx WriteProcessMemory CreateRemoteThread for injection",
        )
        isr_network = _make_isr(
            "network",
            "network",
            "Outbound DNS queries to randomised subdomains port 53 exfiltration pattern",
        )
        assert detect_sycophancy([isr_static, isr_network]) is False

    def test_single_isr_never_detected(self) -> None:
        """Sycophancy requires at least two agents."""
        isr = _make_isr("static", "static", "some claim")
        assert detect_sycophancy([isr]) is False

    def test_empty_list_never_detected(self) -> None:
        assert detect_sycophancy([]) is False

    def test_custom_threshold_permissive(self) -> None:
        """With threshold=1.0 (exact match only), nearly identical texts pass."""
        isr_a = _make_isr("static", "static", "encrypts files via aes")
        isr_b = _make_isr("dynamic", "dynamic", "encrypts files via aes mode")
        # threshold=1.0 means only perfect cosine=1.0 is flagged
        assert detect_sycophancy([isr_a, isr_b], threshold=1.0) is False

    def test_three_agents_any_pair_triggers(self) -> None:
        """If any pair has heavily overlapping content, the function returns True."""
        claim = "Encrypts files with AES-256 symmetric encryption key"
        isr_a = _make_isr("static", "static", claim)
        isr_b = _make_isr("dynamic", "dynamic", claim)
        isr_c = _make_isr("network", "network", "Beaconing to TOR hidden service exfiltrating data")
        assert detect_sycophancy([isr_a, isr_b, isr_c], threshold=0.70, iteration=1) is True


class TestBuildRevisionDirective:
    def test_no_sycophancy_returns_mediator_feedback(self) -> None:
        feedback = "Contradiction: static says no network, dynamic says C2."
        result = build_revision_directive(False, feedback)
        assert result == feedback
        assert DEVIL_ADVOCATE_DIRECTIVE not in result

    def test_sycophancy_prepends_directive(self) -> None:
        feedback = "Please revise."
        result = build_revision_directive(True, feedback)
        assert result.startswith(DEVIL_ADVOCATE_DIRECTIVE)
        assert "Please revise." in result

    def test_sycophancy_empty_feedback(self) -> None:
        result = build_revision_directive(True, "")
        assert DEVIL_ADVOCATE_DIRECTIVE in result

    def test_no_sycophancy_empty_feedback(self) -> None:
        result = build_revision_directive(False, "")
        assert result == ""
