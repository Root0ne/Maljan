"""The live transcript feed — what each pipeline node reports while it runs.

Before this existed a run was opaque: the worker announced which agents were
*about* to start and then said nothing for half an hour. These tests pin the
two properties that make the feed safe to leave switched on in production:

* **It cannot break a run.** A sink that raises, a malformed claim, no sink at
  all — none of it may propagate. Losing a progress line is an annoyance;
  losing a 30-minute analysis to a telemetry bug is not.
* **Failures are reported, not swallowed.** The paths that matter most to a
  watching operator are the ones where an analyst produced nothing or died, so
  those emit too, with a status that says which.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.pipeline.events import (
    AGENT_MESSAGE,
    claims_to_payload,
    emit,
    emit_agent_message,
)
from maljan.pipeline.nodes import (
    make_analyst_node,
    make_negotiation_node,
    make_revision_node,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


class Recorder:
    """Collects everything a node emits."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def messages(self) -> list[dict[str, Any]]:
        return [d for t, d in self.events if t == AGENT_MESSAGE]


def _container(sink: Any, agents: list[str] | None = None) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = sink
    container.agent_registry.list_agents.return_value = agents or ["network"]
    return container


class TestEmitIsHarmless:
    def test_no_sink_is_a_no_op(self) -> None:
        emit(None, "anything", {"a": 1})  # must not raise

    def test_a_raising_sink_never_propagates(self) -> None:
        def boom(_type: str, _data: dict[str, Any]) -> None:
            raise RuntimeError("redis is down")

        emit(boom, "x", {})  # must not raise
        emit_agent_message(boom, speaker="s", role="analyst", text="t")


class TestAgentMessagePayload:
    def test_optional_fields_are_omitted_when_absent(self) -> None:
        rec = Recorder()
        emit_agent_message(rec, speaker="static", role="analyst", text="hi")
        ((event_type, payload),) = rec.events
        assert event_type == AGENT_MESSAGE
        assert payload == {
            "speaker": "static",
            "role": "analyst",
            "round": 0,
            "status": "complete",
            "text": "hi",
        }

    def test_confidence_claims_and_dissent_round_trip(self) -> None:
        rec = Recorder()
        emit_agent_message(
            rec,
            speaker="network",
            role="reviser",
            text="revised",
            round_index=2,
            status="no_data",
            confidence=0.8125,
            claims=[{"claim": "c"}],
            dissent=["disputed"],
        )
        payload = rec.messages()[0]
        assert payload["round"] == 2
        assert payload["status"] == "no_data"
        assert payload["confidence"] == pytest.approx(0.8125)
        assert payload["claims"] == [{"claim": "c"}]
        assert payload["dissent"] == ["disputed"]


class TestClaimsToPayload:
    def test_extracts_the_transcript_fields(self) -> None:
        claims = [
            ClaimEvidence(
                claim="Injects into explorer.exe",
                evidence_ref="API: VirtualAllocEx @ 0x401234",
                confidence=0.9,
                technique_id="T1055",
            )
        ]
        assert claims_to_payload(claims) == [
            {
                "claim": "Injects into explorer.exe",
                "evidence_ref": "API: VirtualAllocEx @ 0x401234",
                "confidence": 0.9,
                "technique_id": "T1055",
            }
        ]

    def test_capped_so_one_agent_cannot_flood_the_replay_stream(self) -> None:
        claims = [
            ClaimEvidence(claim=f"c{i}", evidence_ref="ref", confidence=0.5) for i in range(50)
        ]
        assert len(claims_to_payload(claims)) == 12

    def test_headline_collapses_model_whitespace(self) -> None:
        """Claim text arrives with newlines and markdown; the headline is one line."""
        from maljan.pipeline.events import summarize_claims

        claims = [
            ClaimEvidence(
                claim="Windows PE binary\n\n**Key observations:**\n1. packed",
                evidence_ref="ref",
                confidence=0.5,
            )
        ]
        text = summarize_claims(claims, speaker="static")
        assert "\n" not in text
        assert text == (
            "1 evidence-backed claim from the static layer. "
            "Leading: Windows PE binary **Key observations:** 1. packed"
        )

    def test_headline_without_claims_names_the_layer(self) -> None:
        from maljan.pipeline.events import summarize_claims

        assert summarize_claims([], speaker="dynamic") == "dynamic: no claims produced."

    def test_none_and_malformed_entries_are_tolerated(self) -> None:
        assert claims_to_payload(None) == []
        # A bare object with no attributes stringifies to empty fields rather
        # than exploding — one bad claim must not drop its siblings.
        good = ClaimEvidence(claim="real", evidence_ref="ref", confidence=0.5)
        out = claims_to_payload([object(), good])
        assert any(c["claim"] == "real" for c in out)


class TestAnalystNodeEmits:
    def test_no_data_path_reports_itself(self) -> None:
        """A skipped analyst is the case an operator most needs to see."""
        rec = Recorder()
        container = _container(rec)
        container.load_chunked.return_value = []
        container.get_agent.return_value = MagicMock()

        node = make_analyst_node("network", container)
        node({"file_hash": "a" * 64})

        # It announces that it started, then that it had nothing to work with.
        assert ("agent_progress", {"agent": "network", "phase": "analyzing"}) in rec.events
        message = rec.messages()[0]
        assert message["speaker"] == "network"
        assert message["role"] == "analyst"
        assert message["status"] == "no_data"
        assert "no network data available" in message["text"]

    def test_a_crash_is_reported_as_failed(self) -> None:
        rec = Recorder()
        container = _container(rec)
        container.get_agent.side_effect = RuntimeError("ghidra died")

        node = make_analyst_node("network", container)
        node({"file_hash": "a" * 64})

        message = rec.messages()[0]
        assert message["status"] == "failed"
        assert "ghidra died" in message["text"]

    def test_claims_reach_the_transcript(self) -> None:
        rec = Recorder()
        container = _container(rec)
        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[
                ClaimEvidence(
                    claim="Beacons to c2.example",
                    evidence_ref="PCAP frame 42",
                    confidence=0.77,
                    technique_id="T1071",
                )
            ],
        )
        agent = MagicMock()
        agent.safe_analyze_isr.return_value = isr
        agent.safe_analyze_isr_chunked.return_value = isr
        agent.get_last_tool_evidence.return_value = []
        container.get_agent.return_value = agent
        container.load_chunked.return_value = [MagicMock(content="chunk")]

        node = make_analyst_node("network", container)
        node({"file_hash": "a" * 64})

        message = rec.messages()[0]
        assert message["status"] == "complete"
        assert message["claims"][0]["technique_id"] == "T1071"
        assert message["claims"][0]["evidence_ref"] == "PCAP frame 42"
        # Headline, not the raw ISR dump. The full text restated every claim
        # inline, so the panel showed the same findings twice — once as a wall
        # of prose and once structured underneath.
        assert message["text"] == (
            "1 evidence-backed claim from the network layer. Leading: Beacons to c2.example"
        )


class TestStageNodesEmit:
    def test_mediator_speaks_on_success(self) -> None:
        rec = Recorder()
        container = _container(rec)
        argument = MagicMock(agent_name="Mediator", finding="Agents agree.", confidence_score=0.7)
        judge = MagicMock()
        judge.mediate = AsyncMock(return_value=(argument, True))
        container.get_judge_agent.return_value = judge

        node = make_negotiation_node(container)
        asyncio.run(node({"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}))

        message = rec.messages()[0]
        assert message["speaker"] == "Mediator"
        assert message["role"] == "negotiator"
        assert message["text"] == "Agents agree."
        assert message["round"] == 2

    def test_mediator_failure_is_visible_not_silent(self) -> None:
        rec = Recorder()
        container = _container(rec)
        judge = MagicMock()
        judge.mediate = AsyncMock(side_effect=TimeoutError())
        container.get_judge_agent.return_value = judge

        node = make_negotiation_node(container)
        asyncio.run(node({"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}))

        message = rec.messages()[0]
        assert message["status"] == "timeout"
        assert "[ERROR]" in message["text"]

    def test_revision_reports_each_agent(self) -> None:
        rec = Recorder()
        container = _container(rec, agents=["network"])
        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[ClaimEvidence(claim="c", evidence_ref="r", confidence=0.5)],
            dissent_items=["still disagree with static"],
        )
        agent = MagicMock()
        agent.safe_revise_isr.return_value = ("revised text", isr)
        container.get_agent.return_value = agent

        node = make_revision_node(container)
        asyncio.run(node({"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}))

        message = rec.messages()[0]
        assert message["role"] == "reviser"
        # The headline, not the full revised ISR text — the structured claims
        # carry the detail, and the persisted view summarises identically.
        assert message["text"] == "1 evidence-backed claim from the network layer. Leading: c"
        assert message["dissent"] == ["still disagree with static"]
