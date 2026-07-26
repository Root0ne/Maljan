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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from maljan.pipeline.events import (
    AGENT_MESSAGE,
    REPORT_CHAR_LIMIT,
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


class TestProseTravelsWithTheMessage:
    """The agent's written report rides alongside the headline, not inside it.

    Two separate reasons this field exists, and both are load-bearing:

    * The prose is what a human actually reads. It reached the database as
      ``agent_reports`` and the UI could only render it as a JSON blob, so in
      practice nobody saw it.
    * The *revised* prose reached nothing at all. ``revised_reports`` was a
      pipeline-state key the worker never persisted, so what an agent wrote
      after being contradicted existed only for the duration of the run.

    It stays out of ``text`` deliberately — see ``summarize_claims``. The
    headline is the message; this is the attachment.
    """

    def test_analyst_carries_its_report(self) -> None:
        rec = Recorder()
        container = _container(rec)
        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[ClaimEvidence(claim="c", evidence_ref="r", confidence=0.5)],
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
        # The node's own ``report`` variable — ``isr.to_text_summary()`` — which
        # is exactly the prose that used to reach the database as
        # ``agent_reports`` and be rendered as escaped JSON.
        assert message["report"] == isr.to_text_summary()
        # The headline is still the headline, and still not the prose.
        assert message["text"].startswith("1 evidence-backed claim")
        assert message["report"] != message["text"]

    def test_revision_carries_the_rewritten_report(self) -> None:
        rec = Recorder()
        container = _container(rec, agents=["network"])
        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[ClaimEvidence(claim="c", evidence_ref="r", confidence=0.5)],
        )
        agent = MagicMock()
        agent.safe_revise_isr.return_value = ("the rewritten write-up", isr)
        container.get_agent.return_value = agent

        node = make_revision_node(container)
        asyncio.run(node({"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}))

        message = rec.messages()[0]
        assert message["report"] == "the rewritten write-up"

    def test_absent_report_omits_the_field(self) -> None:
        """Same rule as confidence/claims/dissent: no value, no key."""
        rec = Recorder()
        emit_agent_message(rec, speaker="Mediator", role="negotiator", text="hm")
        assert "report" not in rec.messages()[0]

    def test_an_oversized_report_is_capped_and_says_so(self) -> None:
        """A verbose analyst must not evict the rest of the run.

        These events are mirrored into a Redis Stream capped at 1000 entries and
        fanned out to every connected browser, so an unbounded field is a way
        for one message to cost every other message its replay. Truncation is
        announced rather than silent — a reader must not mistake the cut for the
        end of the report.
        """
        rec = Recorder()
        emit_agent_message(
            rec,
            speaker="static",
            role="analyst",
            text="headline",
            report="x" * (REPORT_CHAR_LIMIT + 500),
        )
        message = rec.messages()[0]
        assert len(message["report"]) == REPORT_CHAR_LIMIT
        assert message["report_truncated"] is True

    def test_a_report_within_the_cap_is_not_flagged(self) -> None:
        rec = Recorder()
        emit_agent_message(rec, speaker="static", role="analyst", text="headline", report="short")
        assert "report_truncated" not in rec.messages()[0]


class TestSycophancyAndJudgeSpeak:
    """The two messages nothing covered, and one of them is the whole point.

    The sycophancy detector is the pipeline's own scepticism made visible — it
    is the reason a fourth round exists. It was emitted and never persisted, so
    a day later a manufactured consensus was indistinguishable from an earned
    one. Now that it is recorded, the emission itself needs pinning.
    """

    def test_the_detector_announces_the_intervention(self) -> None:
        rec = Recorder()
        container = _container(rec)
        argument = MagicMock(agent_name="Mediator", finding="All agree.", confidence_score=0.9)
        judge = MagicMock()
        judge.mediate = AsyncMock(return_value=(argument, True))
        container.get_judge_agent.return_value = judge

        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[ClaimEvidence(claim="identical", evidence_ref="r", confidence=0.9)],
        )
        node = make_negotiation_node(container)
        with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=True):
            asyncio.run(
                node(
                    {
                        "iteration_count": 2,
                        "reports": {"network": "f"},
                        "isr_reports": {"network": isr},
                    }
                )
            )

        speakers = [m["speaker"] for m in rec.messages()]
        assert "Sycophancy detector" in speakers
        notice = next(m for m in rec.messages() if m["speaker"] == "Sycophancy detector")
        assert notice["role"] == "system"
        assert "without new evidence" in notice["text"]

    def test_no_detector_message_when_agreement_is_earned(self) -> None:
        rec = Recorder()
        container = _container(rec)
        argument = MagicMock(agent_name="Mediator", finding="All agree.", confidence_score=0.9)
        judge = MagicMock()
        judge.mediate = AsyncMock(return_value=(argument, True))
        container.get_judge_agent.return_value = judge

        node = make_negotiation_node(container)
        with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False):
            asyncio.run(
                node({"iteration_count": 2, "reports": {"network": "f"}, "isr_reports": {}})
            )

        assert [m["speaker"] for m in rec.messages()] == ["Mediator"]
