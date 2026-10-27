"""The mediator, the verdict and the next revision read each analyst's answer in force.

A stored run's revision round kept an analyst's validation retry (27 claims)
while the report the next mediations, the verdict and the technique question
read was the first answer the revision wrote (12 claims, no text shared): the
revision node stored the written answer as the report. It stores the answer
in force now (``base_agent.answer_in_force_text``), so the mediator reads it
once, the verdict reads the claims in force, and a peer's next revision is
relayed the same text the mediator numbered its lines against.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from maljan.agents.base_agent import WRITTEN_BESIDES_CLAIMS, BaseAnalyst
from maljan.agents.judge_agent import mediation_reports_text, verdict_reports_text
from maljan.pipeline.events import REPORT_CHAR_LIMIT, emit_agent_message
from maljan.pipeline.nodes import (
    RETRY_WORDS_HEAD,
    WRITTEN_ANSWER_HEAD,
    RevisionInput,
    make_revision_node,
    written_record,
)
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding
from tests.stages import paper_profile

NAMES = ["static", "network"]
REBUTTAL = "Network claim 2 says 0x6a1f is unused; ev_0025 lists its caller at 0x6a10."
WRITTEN = (
    "CLAIM 1: The first answer's only claim.\nCONFIDENCE: 0.6\nEVIDENCE: [ev_0138]\n\n"
    f"DISPUTES:\n- {REBUTTAL}"
)


def _claim(text: str, ev: str) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ev, confidence=0.7)


KEPT = [
    _claim("The retry's first claim: 81 strings decode at 0xae78.", "[ev_0021]"),
    _claim("The retry's second claim: the C2 path is /live/.", "[ev_0019]"),
]


FINDING = Finding(title="Mutex guards one instance", detail="CreateMutexW at 0x3935.")


class _Analyst(BaseAnalyst):
    """An analyst whose validation turn keeps a retry (``static``) or the answer (``network``)."""

    def __init__(self, name: str) -> None:
        super().__init__(llm=MagicMock(), name=name)
        self.own: list[str] = []
        self.peers: list[dict[str, str]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover
        return ""

    def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover
        return ""

    def revise_isr(self, data: str, own: str, peers: dict, feedback: str, rnd: int = 1) -> Any:
        self.own.append(own)
        self.peers.append(dict(peers))
        isr = AgentISR(
            agent_id=self.name,
            domain=self.name,
            claims=[_claim("The first answer's only claim.", "[ev_0138]")],
            revision_round=rnd,
        )
        isr.note_answer_text(WRITTEN)
        return WRITTEN, isr

    def _apply_consistency_gate(self, isr: AgentISR, evidence: str) -> AgentISR:
        return isr

    def _validate_isr(self, isr: AgentISR, evidence: str) -> AgentISR:
        if self.name != "static":
            return isr
        kept = AgentISR(
            agent_id=self.name,
            domain=self.name,
            claims=list(KEPT),
            revision_round=isr.revision_round,
        )
        kept.findings = [FINDING]
        kept.note_answer_text("the retry's own words")
        return kept


def _container(
    agents: dict[str, _Analyst], events: list[dict[str, Any]] | None = None
) -> MagicMock:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda kind, data: (
        events.append(data) if events is not None and kind == "agent_message" else None
    )
    container.analyst_keys.return_value = list(agents)
    container.agent_role.side_effect = lambda n: n
    container.active_profile.return_value = paper_profile(list(agents))
    container.config.llm.parallel_analysts = False
    container.get_agent.side_effect = lambda n: agents[n]
    return container


def _round(
    agents: dict[str, _Analyst],
    state: dict[str, Any],
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    with (
        patch(
            "maljan.pipeline.nodes._revision_input",
            lambda _state, _container, _name: RevisionInput(text="data"),
        ),
        patch("maljan.pipeline.nodes.brief_agent", lambda *_a, **_k: None),
    ):
        return asyncio.run(make_revision_node(_container(agents, events))(state))


def _state(**extra: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "iteration_count": 2,
        "reports": {name: f"{name} round-0 summary" for name in NAMES},
        "revised_reports": {},
        "isr_reports": {},
        "discussion_history": [AgentArgument(agent_name="Mediator", finding="revise")],
    }
    state.update(extra)
    return state


class TestTheAnswerInForceIsWhatEveryoneReads:
    def test_the_report_stored_is_the_kept_retry_s_claims(self) -> None:
        agents = {name: _Analyst(name) for name in NAMES}

        update = _round(agents, _state())

        static = update["revised_reports"]["static"]
        assert static.startswith(update["isr_reports"]["static"].to_text_summary())
        assert FINDING.title in static
        assert KEPT[0].claim in static and KEPT[1].claim in static
        assert "The first answer's only claim." not in static
        # An answer the turn left as written is reported as written.
        assert update["revised_reports"]["network"] == WRITTEN

    def test_the_mediator_reads_each_claim_in_force_once_and_not_the_replaced_answer(self) -> None:
        agents = {name: _Analyst(name) for name in NAMES}
        update = _round(agents, _state())

        text = mediation_reports_text(update["revised_reports"], update["isr_reports"])

        assert text.count(KEPT[0].claim) == 1 and text.count(KEPT[1].claim) == 1
        assert text.count(FINDING.title) == 1 and text.count(FINDING.detail) == 1
        assert "[ISR] [STATIC ANALYST" not in text
        assert "--- STATIC ANALYST ---" in text
        assert "the retry's own words" not in text

    def test_the_verdict_reads_the_claims_in_force(self) -> None:
        agents = {name: _Analyst(name) for name in NAMES}
        update = _round(agents, _state())

        text = verdict_reports_text(update["revised_reports"], update["isr_reports"])

        assert "Claim 1: " + KEPT[0].claim in text
        assert "Claim 2: " + KEPT[1].claim in text

    def test_the_next_revision_is_relayed_the_text_the_mediator_numbered(self) -> None:
        agents = {name: _Analyst(name) for name in NAMES}
        first = _round(agents, _state())

        _round(
            agents,
            _state(
                iteration_count=3,
                revised_reports=first["revised_reports"],
                isr_reports=first["isr_reports"],
            ),
        )

        mediator_read = mediation_reports_text(first["revised_reports"], first["isr_reports"])
        assert agents["static"].own[-1] == first["revised_reports"]["static"]
        assert agents["network"].peers[-1]["static"] == first["revised_reports"]["static"]
        assert f"Claim 2: {KEPT[1].claim}" in agents["static"].own[-1]
        assert f"Claim 2: {KEPT[1].claim}" in mediator_read


class TestTheRecordKeepsWhatWasWritten:
    def test_the_reviser_event_carries_the_written_answer_and_the_kept_retry_s_words(
        self,
    ) -> None:
        agents = {name: _Analyst(name) for name in NAMES}
        events: list[dict[str, Any]] = []

        _round(agents, _state(), events)

        said = {e["speaker"]: e.get("report", "") for e in events if e.get("role") == "reviser"}
        assert said["static"] == (
            f"{RETRY_WORDS_HEAD}\nthe retry's own words\n\n{WRITTEN_ANSWER_HEAD}\n{WRITTEN}"
        )
        assert said["network"] == WRITTEN

    def test_the_report_in_force_keeps_the_revision_s_rebuttal_not_its_replaced_claim(
        self,
    ) -> None:
        agents = {name: _Analyst(name) for name in NAMES}

        update = _round(agents, _state())

        static = update["revised_reports"]["static"]
        besides = static.split(f"\n{WRITTEN_BESIDES_CLAIMS}\n", 1)[1]
        assert REBUTTAL in besides
        assert "The first answer's only claim." not in static
        assert static.count(REBUTTAL) == 1

    def test_the_mediator_reads_the_rebuttal_once(self) -> None:
        agents = {name: _Analyst(name) for name in NAMES}
        update = _round(agents, _state())

        text = mediation_reports_text(update["revised_reports"], update["isr_reports"])

        # Once in the static report in force, once in the network answer as written.
        assert text.count(REBUTTAL) == 2


class TestTheSummaryIsNeverShownTwice:
    def test_a_mark_set_after_the_round_leaves_no_isr_duplicate(self) -> None:
        agents = {name: _Analyst(name) for name in NAMES}
        update = _round(agents, _state())
        # A mark the platform sets on a claim in force after the round.
        claim = update["isr_reports"]["static"].claims[0]
        claim.technique_id = "T9999"
        claim.technique_id_valid = False

        text = mediation_reports_text(update["revised_reports"], update["isr_reports"])

        assert "[ISR] [STATIC ANALYST" not in text
        assert text.count(KEPT[0].claim) == 1
        assert "T9999" in text

    def test_the_verdict_reads_the_mark_too(self) -> None:
        agents = {name: _Analyst(name) for name in NAMES}
        update = _round(agents, _state())
        update["isr_reports"]["static"].claims[0].technique_id = "T9999"

        text = verdict_reports_text(update["revised_reports"], update["isr_reports"])

        assert "T9999" in text and text.count(KEPT[0].claim) == 1

    def test_the_retry_s_words_survive_the_record_s_cut(self) -> None:
        events: list[dict[str, Any]] = []
        long_written = "CLAIM 1: x\nCONFIDENCE: 0.5\nEVIDENCE: [ev_0001]\n" + "y" * (
            REPORT_CHAR_LIMIT * 2
        )

        emit_agent_message(
            lambda _kind, data: events.append(data),
            speaker="static",
            role="reviser",
            text="t",
            report=written_record(long_written, "the retry's own words"),
        )

        assert events[0]["report_truncated"] is True
        assert "the retry's own words" in events[0]["report"]

    def test_a_record_with_no_retry_is_the_written_answer(self) -> None:
        assert written_record(WRITTEN) == WRITTEN
