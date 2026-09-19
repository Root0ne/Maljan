"""Who a line is attributed to, as the console reads it.

The conversation view builds its participants from the speakers of the feed,
joined to the roster on the agent key. Two things follow, and neither was true
before these tests:

* An agent that the team composed speaks under **its key**, with the label its
  operator gave it travelling beside the key. The judge used to speak as
  ``"Judge"`` with no label, which does not join to the roster's ``judge`` — so
  a run drew two judges, one from the roster and one from its own verdict.
* A watcher the team did not compose — the mediator, the sycophancy detector —
  is **not a participant**. It speaks as the room and names itself in the line,
  so the console draws a notice rather than adding somebody to a roster the
  operator never wrote.

The failure paths carry one more rule: an event names the class of an
exception and never its message. The log keeps the words for an operator; the
feed goes to every reader of the run, and an exception's text can carry a path,
a host or a credential.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from maljan.agents.judge_agent import JudgeVerdict
from maljan.core.config import JUDGE_AGENT_KEY, Settings
from maljan.core.token_ledger import TokenLedger
from maljan.core.truncation_ledger import TruncationLedger
from maljan.pipeline.nodes import (
    ROOM_SPEAKER,
    make_judge_node,
    make_negotiation_node,
    make_revision_node,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle
from tests.stages import paper_profile
from tests.unit.pipeline.test_evidence_ledger_channel import _JudgeContainer
from tests.unit.pipeline.test_pipeline_events import Recorder, _container


class _Container(_JudgeContainer):
    """The judge node's container, with real settings so labels are real."""

    def __init__(self, sink: Any) -> None:
        super().__init__(EvidenceCounter())
        self.config = Settings()
        self.event_sink = sink

    def server_degradation_reasons(self) -> list[str]:
        return []

    def active_profile(self) -> Any:
        return paper_profile(["static"])

    def get_token_ledger(self) -> TokenLedger:
        return TokenLedger()

    def get_truncation_ledger(self) -> TruncationLedger:
        return TruncationLedger()


def _state() -> dict[str, Any]:
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
        "evidence_ledger": [],
        "sandbox_report": {"signatures": []},
        "sample_path": None,
        "triage_facts": {},
        "validation_findings": {},
        "validation_not_run": [],
    }


def _run_judge(sink: Recorder, verdict: Any) -> None:
    container = _Container(sink)
    judge = container.get_judge_agent(role="judge")
    if isinstance(verdict, BaseException):
        judge.give_verdict = AsyncMock(side_effect=verdict)
    else:
        judge.give_verdict = AsyncMock(return_value=verdict)
    asyncio.run(make_judge_node(container)(_state()))


def _verdict() -> JudgeVerdict:
    return JudgeVerdict(bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={})


class TestTheJudgeSpeaksAsItself:
    def test_the_verdict_carries_the_key_and_the_label(self) -> None:
        rec = Recorder()
        _run_judge(rec, _verdict())

        verdict = next(m for m in rec.messages() if m["kind"] == "verdict")
        # The key the roster lists it under, so the two are one participant.
        assert verdict["speaker"] == JUDGE_AGENT_KEY
        assert verdict["display_name"] == "Judge"
        assert verdict["role"] == "judge"

    def test_the_label_is_the_one_the_operator_typed(self) -> None:
        rec = Recorder()
        container = _Container(rec)
        container.config.agents.definitions[JUDGE_AGENT_KEY].label = "Arbiter"
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(return_value=_verdict())
        asyncio.run(make_judge_node(container)(_state()))

        verdict = next(m for m in rec.messages() if m["kind"] == "verdict")
        assert verdict["speaker"] == JUDGE_AGENT_KEY
        assert verdict["display_name"] == "Arbiter"

    def test_a_failed_verdict_names_the_class_and_not_the_message(self) -> None:
        rec = Recorder()
        _run_judge(rec, RuntimeError("connect to https://user:hunter2@host/v1 failed"))

        failure = next(m for m in rec.messages() if m["status"] == "failed")
        assert failure["speaker"] == JUDGE_AGENT_KEY
        assert failure["display_name"] == "Judge"
        assert "RuntimeError" in failure["text"]
        assert "hunter2" not in failure["text"]
        assert "host/v1" not in failure["text"]


class TestAWatcherIsNotAParticipant:
    def _negotiate(self, sink: Recorder, *, syco: bool, fail: bool = False) -> None:
        container = _container(sink)
        argument = MagicMock(agent_name="Mediator", finding="All agree.", confidence_score=0.9)
        judge = MagicMock()
        judge.mediate = (
            AsyncMock(side_effect=RuntimeError("socket /tmp/secret.sock refused"))
            if fail
            else AsyncMock(return_value=(argument, True))
        )
        container.get_judge_agent.return_value = judge
        # The detector only looks at a round that produced claims, so the
        # sycophancy branch needs one to be reachable at all.
        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[ClaimEvidence(claim="identical", evidence_ref="r", confidence=0.9)],
        )
        node = make_negotiation_node(container)
        with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=syco):
            asyncio.run(
                node(
                    {
                        "iteration_count": 2,
                        "reports": {"network": "f"},
                        "isr_reports": {"network": isr},
                    }
                )
            )

    def test_the_mediator_speaks_as_the_room_and_names_itself(self) -> None:
        rec = Recorder()
        self._negotiate(rec, syco=False)

        message = rec.messages()[0]
        assert message["speaker"] == ROOM_SPEAKER
        assert message["kind"] == "system"
        assert message["text"].startswith("Mediator: ")

    def test_the_detector_speaks_as_the_room_and_names_itself(self) -> None:
        rec = Recorder()
        self._negotiate(rec, syco=True)

        notice = rec.messages()[1]
        assert notice["speaker"] == ROOM_SPEAKER
        assert notice["kind"] == "system"
        assert notice["text"].startswith("Sycophancy detector: ")

    def test_no_watcher_is_ever_drawn_as_a_team_member(self) -> None:
        rec = Recorder()
        self._negotiate(rec, syco=True)

        speakers = {m["speaker"] for m in rec.messages()}
        assert speakers == {ROOM_SPEAKER}

    def test_a_failed_mediation_names_the_class_and_not_the_message(self) -> None:
        rec = Recorder()
        self._negotiate(rec, syco=False, fail=True)

        message = rec.messages()[0]
        assert message["speaker"] == ROOM_SPEAKER
        assert message["kind"] == "system"
        assert "[ERROR]" in message["text"]
        assert "RuntimeError" in message["text"]
        assert "secret.sock" not in message["text"]


class TestAFailedRevisionNamesItsException:
    """The third failure path, held to the rule the other two already keep.

    A revision that dies is published to every reader of the run, and the
    exception it died of is whatever the tool, the transport or the model
    server put in it — a socket path, a host, a bearer token. The class of it
    says as much as a reader of the console can act on; the operator's log
    keeps the words.
    """

    def _revise(self, sink: Recorder, error: BaseException, *, parallel: bool) -> dict[str, Any]:
        container = _container(sink, agents=["static"])
        container.config.llm.parallel_analysts = parallel
        container.load_chunked.side_effect = RuntimeError("force the load_data fallback")
        container.load_data.return_value = "raw analysis data"
        agent = MagicMock()
        # `safe_revise_isr` is synchronous; the node runs it on a thread.
        agent.safe_revise_isr = MagicMock(side_effect=error)
        container.get_agent.return_value = agent
        return asyncio.run(
            make_revision_node(container)(
                {"iteration_count": 1, "reports": {"static": "the first report"}}
            )
        )

    def test_the_class_is_named_and_the_message_is_not(self) -> None:
        rec = Recorder()
        self._revise(
            rec,
            ConnectionError("POST https://user:hunter2@llm.internal/v1 refused"),
            parallel=True,
        )

        failure = next(m for m in rec.messages() if m["status"] == "failed")
        assert failure["speaker"] == "static"
        assert "ConnectionError" in failure["text"]
        assert "hunter2" not in failure["text"]
        assert "llm.internal" not in failure["text"]

    def test_the_sequential_path_says_the_same_thing(self) -> None:
        # The two branches build the failure list differently — gather returns
        # the exception, the loop catches it — and both reach this line.
        rec = Recorder()
        self._revise(rec, RuntimeError("socket /tmp/secret.sock refused"), parallel=False)

        failure = next(m for m in rec.messages() if m["status"] == "failed")
        assert "RuntimeError" in failure["text"]
        assert "secret.sock" not in failure["text"]

    def test_the_analyst_keeps_the_report_it_had(self) -> None:
        rec = Recorder()
        result = self._revise(rec, RuntimeError("boom"), parallel=True)

        assert result["revised_reports"]["static"] == "the first report"
