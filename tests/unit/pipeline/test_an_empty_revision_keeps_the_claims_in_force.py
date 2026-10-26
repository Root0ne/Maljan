"""A revision that wrote no claim keeps the claims in force, whatever its retry wrote.

A revision round's answer that carries no claim line and no structured report
made no decision about the claims in force, and they stand. The revision node
used to read that from the answer the validation turn left, so a retry the
turn asked for after the empty revision, a turn with no tools, turned it into
an answer of its own claims first, and that answer then replaced every claim
in force, the ones the analyst had kept when asked among them.

Now the revision path records that the revision itself wrote no claim before
the validation turn runs, and the node reads that. The claims in force stand,
every one; what the retry wrote is added beside them, each claim marked with
the round whose retry added it, and a claim the answer in force already holds
is not written twice. A revision that wrote claims of its own is the
analyst's answer and still replaces the one in force. Every value is
synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import (
    NO_STRUCTURED_REPORT_STATUS,
    WRITTEN_BESIDES_CLAIMS,
    BaseAnalyst,
)
from maljan.pipeline.nodes import (
    RevisionInput,
    answer_with_retry_additions,
    make_revision_node,
    retry_additions_report,
    retry_additions_text,
    revision_decided_nothing,
)
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding
from tests.stages import paper_profile

NAMES = ["reverser", "dynamic"]


def _claim(text: str, ev: str = "[ev_0001]", technique: str | None = None) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ev, confidence=0.8, technique_id=technique)


DISPATCH = _claim(
    "Command dispatch: the reply parser at 0x541c hands each command id to the switch at "
    "0x3cf4, whose case 0x11 removes the install and exits.",
    "[ev_0068]",
)
TIMING = _claim(
    "Beacon timing: the loop at 0x5750 sleeps 450 to 599 seconds between requests.", "[ev_0063]"
)
INSTALL = _claim(
    "The install routine 0x33ac copies the file under the user's profile and relaunches it.",
    "[ev_0068]",
    "T1547.001",
)


def _in_force(name: str) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[DISPATCH, TIMING, INSTALL],
        findings=[Finding(title="Install path", detail="read in round 0")],
    )


def _empty_revision_retried(name: str, *claims: ClaimEvidence) -> AgentISR:
    """What the revision path returns after an empty revision whose retry wrote ``claims``."""
    isr = AgentISR(agent_id=name, domain=name, claims=list(claims), revision_round=2)
    isr.note_revision_wrote_no_claim()
    return isr


RETRY_NEW = _claim("A second user agent string is decoded at 0xff40.", "[ev_0020]")


def _container(outcomes: dict[str, Any]) -> MagicMock:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = list(outcomes)
    container.agent_role.side_effect = lambda n: n
    container.active_profile.return_value = paper_profile(list(outcomes))
    container.config.llm.parallel_analysts = False
    agents: dict[str, Any] = {}
    for name, outcome in outcomes.items():
        agent = MagicMock()
        agent.safe_revise_isr.return_value = outcome
        agent.drain_evidence_entries.return_value = []
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    return container


def _revise(outcomes: dict[str, Any], in_force: dict[str, AgentISR]) -> dict[str, Any]:
    state = {
        "iteration_count": 2,
        "reports": {name: f"{name} first answer" for name in outcomes},
        "revised_reports": {},
        "isr_reports": dict(in_force),
        "discussion_history": [AgentArgument(agent_name="Mediator", finding="revise")],
    }
    container = _container(outcomes)
    with patch(
        "maljan.pipeline.nodes._revision_input",
        lambda _state, _container, _name: RevisionInput(text="data"),
    ):
        return asyncio.run(make_revision_node(container)(state))


class TestTheRevisionNode:
    def test_a_retry_after_an_empty_revision_adds_and_replaces_nothing(self) -> None:
        in_force = {name: _in_force(name) for name in NAMES}
        # The retry wrote one claim again word for word and one new claim.
        outcomes = {
            name: ("prose with no claim line", _empty_revision_retried(name, TIMING, RETRY_NEW))
            for name in NAMES
        }

        update = _revise(outcomes, in_force)

        for name in NAMES:
            after = update["isr_reports"][name]
            assert after.claims[:3] == [DISPATCH, TIMING, INSTALL]
            assert [c.claim for c in after.claims[3:]] == [RETRY_NEW.claim]
            assert after.claims[3].added_by_retry_in_round == 2
            assert all(c.added_by_retry_in_round is None for c in after.claims[:3])
            assert [f.title for f in after.findings] == ["Install path"]
            # The report is built from the answer in force with the claims
            # added: each claim once, the added one numbered on and marked,
            # the line saying so, then what the answer in force wrote besides.
            report = update["revised_reports"][name]
            assert report.startswith(after.to_text_summary())
            assert after.rendered_summary == after.to_text_summary()
            assert "Claim 4 above was added by the round-2 validation retry" in report
            assert report.count(RETRY_NEW.claim) == 1
            assert "(added by a tool-less retry, round 2)" in report
            assert report.count(TIMING.claim) == 1
            assert report.endswith(f"{WRITTEN_BESIDES_CLAIMS}\n{name} first answer")
            # The answer it was built from is unchanged.
            assert len(in_force[name].claims) == 3
        [record] = update["revision_rounds"]
        assert record["retry_added"] == {"reverser": 1, "dynamic": 1}
        assert record["made"] == 2
        assert record["identical"] is False
        assert record["reworded"] is False
        assert "dropped_claims" not in update
        assert "revision_replacements" not in update

    def test_a_retry_that_writes_only_claims_in_force_leaves_the_answer_standing(self) -> None:
        in_force = {"reverser": _in_force("reverser")}
        outcomes = {"reverser": ("prose", _empty_revision_retried("reverser", DISPATCH))}

        update = _revise(outcomes, in_force)

        assert update["isr_reports"]["reverser"] is in_force["reverser"]
        [record] = update["revision_rounds"]
        assert record["made"] == 0
        assert record["not_revised"] == {"reverser": "its answer carried no structured report"}

    def test_an_empty_revision_with_no_retry_leaves_the_answer_standing(self) -> None:
        in_force = {"reverser": _in_force("reverser")}
        empty = AgentISR(agent_id="reverser", domain="reverser", status=NO_STRUCTURED_REPORT_STATUS)
        update = _revise({"reverser": ("prose", empty)}, in_force)

        assert update["isr_reports"]["reverser"] is in_force["reverser"]

    def test_an_agent_that_records_nothing_is_read_from_the_answer_it_returned(self) -> None:
        # A revision path that never notes the flag still returns the empty,
        # unstructured answer itself: that is read as before.
        empty = AgentISR(agent_id="x", domain="x", status=NO_STRUCTURED_REPORT_STATUS)
        assert revision_decided_nothing(empty) is True
        assert revision_decided_nothing(AgentISR(agent_id="x", domain="x", claims=[TIMING])) is (
            False
        )
        assert revision_decided_nothing(_empty_revision_retried("x", TIMING)) is True

    def test_a_revision_that_wrote_claims_still_replaces_the_answer(self) -> None:
        in_force = {"reverser": _in_force("reverser")}
        revision = AgentISR(agent_id="reverser", domain="reverser", claims=[RETRY_NEW])

        update = _revise({"reverser": ("CLAIM: ...", revision)}, in_force)

        assert update["isr_reports"]["reverser"] is revision
        assert update["revision_replacements"] == [
            "The reverser analyst's round-2 revision replaced 3 claim(s) with 1."
        ]

    def test_with_nothing_in_force_the_retry_claims_carry_their_provenance(self) -> None:
        empty_in_force = {"reverser": AgentISR(agent_id="reverser", domain="reverser")}
        outcomes = {"reverser": ("prose", _empty_revision_retried("reverser", RETRY_NEW))}

        update = _revise(outcomes, empty_in_force)

        [claim] = update["isr_reports"]["reverser"].claims
        assert claim.claim == RETRY_NEW.claim
        assert claim.added_by_retry_in_round == 2


class TestTheAdditions:
    def test_new_findings_are_added_and_the_revision_disputes_are_kept(self) -> None:
        in_force = _in_force("reverser")
        retried = _empty_revision_retried("reverser", RETRY_NEW)
        retried.findings = [
            Finding(title="install path", detail="the same title"),
            Finding(title="Second user agent", detail="new"),
        ]
        in_force.dissent_items = ["the peer's beacon interval"]
        retried.dissent_items = ["the peer's beacon interval", "the peer's export count"]

        combined = answer_with_retry_additions(in_force, retried, 2)

        assert [f.title for f in combined.findings] == ["Install path", "Second user agent"]
        # The disputes in force, then the revision's new ones.
        assert combined.dissent_items == [
            "the peer's beacon interval",
            "the peer's export count",
        ]
        assert in_force.dissent_items == ["the peer's beacon interval"]
        assert combined.revision_round == 2

    def test_a_restatement_in_substance_is_not_added_twice_and_is_counted(
        self, caplog: Any
    ) -> None:
        import logging

        # The same values, entries and technique, worded otherwise.
        reworded = _claim(
            "Beacon timing: the loop at 0x5750 sleeps between requests 450 to 599 seconds.",
            "[ev_0063]",
        )
        # The same sentence citing another entry is another claim.
        other_entry = _claim(TIMING.claim, "[ev_0120]")
        with caplog.at_level(logging.INFO, logger="maljan"):
            combined = answer_with_retry_additions(
                _in_force("reverser"), _empty_revision_retried("reverser", reworded, other_entry), 2
            )

        assert [c.evidence_ref for c in combined.claims[3:]] == ["[ev_0120]"]
        assert "1 claim(s) of the round-2 validation retry state a claim in force again" in (
            caplog.text
        )

    def test_the_provenance_is_serialised_only_when_set(self) -> None:
        assert "added_by_retry_in_round" not in TIMING.model_dump()
        marked = TIMING.model_copy()
        marked.added_by_retry_in_round = 3
        assert marked.model_dump()["added_by_retry_in_round"] == 3


class _Answers:
    """A model that answers each call from a queue."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)

    def invoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        return AIMessage(content=self.answers.pop(0))

    async def ainvoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        return self.invoke(messages)


class _Reviser(BaseAnalyst):
    revision_text = ""

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:
        return self.revision_text


class TestTheRevisionPathRecordsIt:
    def _revise(self, revision: str, answers: list[str]) -> AgentISR:
        analyst = _Reviser(llm=_Answers(answers), name="reverser")  # type: ignore[arg-type]
        analyst.revision_text = revision
        with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
            _text, isr = analyst.safe_revise_isr("the evidence", "own report", {}, "feedback", 2)
        return isr

    def test_an_empty_revision_retried_into_claims_is_recorded(self) -> None:
        isr = self._revise(
            "I re-read the switch and the loop; the earlier reading stands.",
            [
                "CLAIM: A second user agent string is decoded at 0xff40.\n"
                "EVIDENCE: [ev_0020]\nCONFIDENCE: 0.7\n"
            ],
        )

        assert [c.claim for c in isr.claims] == [RETRY_NEW.claim]
        assert isr.revision_wrote_no_claim is True

    def test_claim_blocks_the_parser_could_not_read_are_claims_the_revision_wrote(self) -> None:
        # Two blocks with no confidence, then one it cannot read: the
        # revision began claims, and the retry that reads them is its answer.
        well_formed = (
            "CLAIM: The loop at 0x5750 sleeps 450 to 599 seconds.\n"
            "EVIDENCE: [ev_0063]\nCONFIDENCE: 0.8\n\n"
            "CLAIM: A second user agent string is decoded at 0xff40.\n"
            "EVIDENCE: [ev_0020]\nCONFIDENCE: 0.7\n"
        )
        no_confidence = well_formed.replace("CONFIDENCE: 0.8\n", "").replace(
            "CONFIDENCE: 0.7\n", ""
        )
        unreadable = well_formed.replace("CONFIDENCE: 0.8", "CONFIDENCE: high").replace(
            "CONFIDENCE: 0.7", "CONFIDENCE: high"
        )
        for revision in (no_confidence, unreadable):
            isr = self._revise(revision, [well_formed, well_formed])
            assert len(isr.claims) == 2
            assert isr.revision_wrote_no_claim is False

            update = _revise({"reverser": (revision, isr)}, {"reverser": _in_force("reverser")})

            assert update["isr_reports"]["reverser"] is isr
            assert update["revision_replacements"] == [
                "The reverser analyst's round-2 revision replaced 3 claim(s) with 2."
            ]
            assert "retry_added" not in update["revision_rounds"][0]

    def test_a_revision_with_claims_is_not_recorded(self) -> None:
        isr = self._revise(
            "CLAIM: A second user agent string is decoded at 0xff40.\n"
            "EVIDENCE: [ev_0020]\nCONFIDENCE: 0.7\n",
            [],
        )

        assert isr.revision_wrote_no_claim is False


class TestTheAdditionsReport:
    def test_after_a_rendered_summary_the_tail_is_kept_and_no_claim_is_shown_twice(
        self,
    ) -> None:
        prior = _in_force("reverser")
        summary = prior.to_text_summary()
        prior.note_rendered_summary(summary)
        tail = "\n  Findings:\n    - Install path: read in round 0"
        combined = answer_with_retry_additions(
            prior, _empty_revision_retried("reverser", RETRY_NEW), 2
        )

        report = retry_additions_report(summary + tail, prior, combined, 1, 2)

        assert report == (
            f"{combined.to_text_summary()}\n{retry_additions_text(combined, 1, 2)}{tail}"
        )
        assert report.count(RETRY_NEW.claim) == 1 and report.count(DISPATCH.claim) == 1

    def test_after_written_text_its_other_sections_and_the_findings_follow(self) -> None:
        prior = _in_force("reverser")
        written = (
            f"CLAIM 1: {DISPATCH.claim}\nEVIDENCE: [ev_0068]\nCONFIDENCE: 0.8\n\n"
            "DISPUTES:\n- Dynamic claim 2 reads the sleep as fixed; ev_0063 shows a range."
        )
        combined = answer_with_retry_additions(
            prior, _empty_revision_retried("reverser", RETRY_NEW), 2
        )

        report = retry_additions_report(written, prior, combined, 1, 2)

        assert report.startswith(combined.to_text_summary())
        assert "  Findings:\n    - Install path: read in round 0" in report
        assert retry_additions_text(combined, 1, 2) in report
        assert report.endswith(
            f"{WRITTEN_BESIDES_CLAIMS}\nDISPUTES:\n- Dynamic claim 2 reads the sleep as "
            "fixed; ev_0063 shows a range."
        )
        assert report.count(DISPATCH.claim) == 1

    def test_the_line_names_the_added_claims_by_their_numbers(self) -> None:
        combined = AgentISR(agent_id="x", domain="x", claims=[DISPATCH, TIMING, INSTALL])

        assert retry_additions_text(combined, 1, 3).startswith("Claim 3 above was")
        assert retry_additions_text(combined, 2, 3).startswith("Claims 2 to 3 above were")
