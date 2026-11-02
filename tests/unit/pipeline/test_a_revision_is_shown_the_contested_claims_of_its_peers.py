"""A named revision is shown, of each peer, the claims its contested lines name.

The mediator writes each contested line as ``[analysts: A, B] <text>
[blocking|not blocking: reason]`` and cites the claims it means by number
("STATIC Claims 1 and 3"). A revision round that asks the analysts the lines
name shows each of them the peers those lines name; of each such peer it
quotes the named claims from the answer in force the mediator read, numbered
by claim block as every summary numbers them, with the peer's disputes that
name the analyst, under a heading that says which claims are quoted and that
the whole report is not shown.

The whole report is shown instead, per peer, and a sentence on the round's
record says why, when a line names the peer with no claim number for it (or
one too long to read), when a number is past the claims of its answer in
force, or when that answer is not held. The analyst's own report stays whole,
the merge by claim number is untouched, and a whole report is headed and
passed byte for byte as before.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import _REVISION_ISR_FORMAT, revision_messages
from maljan.pipeline.debate_facts import (
    ContestedRef,
    ShownReport,
    claims_named_by_lines,
    contested_input,
    contested_refs,
    peer_report_heading,
    peers_shown_record,
)
from maljan.pipeline.nodes import RevisionInput, make_revision_node
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["static", "all_tools_static_r2", "dynamic", "network"]


def _isr(name: str, *claims: str, disputes: tuple[str, ...] = (), round_: int = 0) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        revision_round=round_,
        claims=[
            ClaimEvidence(claim=c, evidence_ref=f"[ev_00{i + 10}]", confidence=0.8)
            for i, c in enumerate(claims)
        ],
        dissent_items=list(disputes),
    )


IN_FORCE = {
    "static": _isr(
        "static",
        "Reads the flag at 0x40.",
        "Opens a key.",
        "Writes a file.",
        disputes=("DYNAMIC Claim 1 has no mutex call.", "NETWORK Claim 1 is wording only."),
    ),
    "all_tools_static_r2": _isr("all_tools_static_r2", "Lists exports.", "No check at 0x40."),
    "dynamic": _isr("dynamic", "Creates a mutex."),
    "network": _isr("network", "The host is live."),
}
REPORTS = {name: f"{name} report in force, every claim and section of it" for name in NAMES}
LINE = (
    "[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claims 1 and 3 [ev_0007]. "
    "[blocking: the ledger refutes it]"
)


def _finding(*lines: str) -> str:
    return (
        f"The reports agree on the loader.\n\nContradictions: {'; '.join(lines)}\nConfidence: 0.6"
    )


def _shown(line: str, name: str = "dynamic", **kw: Any) -> dict[str, str]:
    kw.setdefault("isrs", IN_FORCE)
    _feedback, peers = contested_input(name, _finding(line), [line], NAMES, REPORTS, **kw)
    return peers


# ---------------------------------------------------------------------------
# The references a line makes
# ---------------------------------------------------------------------------


class TestContestedRefs:
    def test_a_line_is_read_into_typed_references(self) -> None:
        (ref,) = contested_refs([LINE], NAMES)

        assert ref == ContestedRef(
            line=1,
            blocking=True,
            analysts=("dynamic",),
            claims=(("dynamic", 1), ("static", 1), ("static", 3)),
            entries=("ev_0007",),
            question=(
                "[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claims 1 and 3 [ev_0007]. "
                "[blocking: the ledger refutes it]"
            ),
        )
        assert ref.claims_of("static") == (1, 3)

    def test_lines_count_from_one_and_carry_their_mark(self) -> None:
        lines = [LINE, "[analysts: network] NETWORK Claim 1 is moot. [not blocking: wording]"]

        refs = contested_refs(lines, NAMES)

        assert [(r.line, r.blocking) for r in refs] == [(1, True), (2, False)]

    def test_the_field_analysts_claims_are_the_merge_s_claims(self) -> None:
        lines = [LINE, "[analysts: static] STATIC Claim 2 and DYNAMIC Claim 1. [blocking: x]"]

        named = claims_named_by_lines(lines, NAMES)
        refs = contested_refs(lines, NAMES)

        for ref in refs:
            for analyst in ref.analysts:
                assert set(ref.claims_of(analyst)) == {
                    n
                    for n, rows in named.get(analyst, {}).items()
                    if ref.line in {r[0] for r in rows}
                }

    def test_a_claim_number_too_long_is_never_converted(self) -> None:
        line = f"[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claim {'9' * 5000}."

        (ref,) = contested_refs([line], NAMES)

        assert ref.unplaced == ("static",)
        assert ref.claims_of("static") == ()


# ---------------------------------------------------------------------------
# The excerpt and its layout
# ---------------------------------------------------------------------------


EXCERPT = (
    "STATIC REPORT (claims 1, 3 quoted; the whole report is not shown):\n"
    "  Claim 1: Reads the flag at 0x40. | Evidence: [ev_0010] | Confidence: 0.80\n"
    "  Claim 3: Writes a file. | Evidence: [ev_0012] | Confidence: 0.80\n"
    "  Disputes naming the dynamic analyst:\n"
    "    - DYNAMIC Claim 1 has no mutex call."
)


class TestTheExcerpt:
    def test_the_excerpt_prompt_is_laid_out_as_its_golden(self) -> None:
        peers = _shown(LINE)

        human = revision_messages("SYS", "RAW", "OWN", peers, "FB", isr=True)[1][1]

        assert human == (
            f"YOUR ORIGINAL REPORT:\nOWN\n\nPEER REPORTS:\n{EXCERPT}\n\n"
            f"MEDIATOR FEEDBACK:\nFB\n\nRAW DATA:\nRAW\n\n{_REVISION_ISR_FORMAT}"
        )

    def test_the_whole_report_prompt_is_byte_identical_to_a_plain_report(self) -> None:
        shown = ShownReport(REPORTS["static"], (), len(REPORTS["static"]), "a note")
        plain = {"static": REPORTS["static"]}

        assert revision_messages("SYS", "RAW", "OWN", {"static": shown}, "FB", isr=True) == (
            revision_messages("SYS", "RAW", "OWN", plain, "FB", isr=True)
        )
        assert (
            f"STATIC REPORT:\n{REPORTS['static']}"
            in revision_messages("SYS", "RAW", "OWN", plain, "FB", isr=True)[1][1]
        )

    def test_one_claim_is_headed_as_one(self) -> None:
        assert peer_report_heading("static", ShownReport("x", (2,))) == (
            "STATIC REPORT (claim 2 quoted; the whole report is not shown):"
        )
        assert peer_report_heading("static", "x") == "STATIC REPORT:"

    def test_the_excerpt_records_what_it_cut(self) -> None:
        shown = _shown(LINE)["static"]

        assert isinstance(shown, ShownReport)
        assert shown.claims == (1, 3)
        assert shown.whole_chars == len(REPORTS["static"])
        assert shown.note == ""
        assert "Opens a key." not in shown
        assert "NETWORK Claim 1 is wording only." not in shown

    def test_a_peer_named_by_its_label_has_its_disputes_kept(self) -> None:
        isrs = dict(IN_FORCE)
        isrs["static"] = _isr(
            "static", "Reads the flag.", disputes=("The Sandbox Watch is wrong.",)
        )
        line = "[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claim 1. [blocking: x]"

        shown = _shown(line, isrs=isrs, labels={"dynamic": "Sandbox Watch"})["static"]

        assert "The Sandbox Watch is wrong." in shown

    def test_the_excerpt_survives_a_copy(self) -> None:
        shown = _shown(LINE)["static"]

        for again in (copy.deepcopy(shown), copy.copy(shown)):
            assert again == shown
            assert isinstance(again, ShownReport)
            assert (again.claims, again.whole_chars, again.note) == (
                shown.claims,
                shown.whole_chars,
                shown.note,
            )

    def test_without_the_answers_in_force_every_peer_is_whole_as_before(self) -> None:
        _feedback, peers = contested_input("dynamic", _finding(LINE), [LINE], NAMES, REPORTS)

        assert peers == {"static": REPORTS["static"]}
        assert type(peers["static"]) is str


# ---------------------------------------------------------------------------
# Every fallback is per peer and says why
# ---------------------------------------------------------------------------


class TestEveryFallbackSaysWhy:
    def test_a_line_naming_the_peer_with_no_claim_number(self) -> None:
        line = "[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC. [blocking: x]"

        shown = _shown(line)["static"]

        assert shown == REPORTS["static"] and not shown.claims
        assert shown.note == (
            "The dynamic analyst's round-0 revision was shown the static analyst's whole "
            "report: contested line 1 names it without a claim number."
        )

    def test_a_claim_number_past_the_answer_in_force(self) -> None:
        line = (
            "[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claims 2 and 9. [blocking: x]"
        )

        shown = _shown(line, revision_round=2)["static"]

        assert shown == REPORTS["static"]
        assert shown.note == (
            "The dynamic analyst's round-2 revision was shown the static analyst's whole "
            "report: contested line 1 names its claim 9, and its answer in force holds 3 "
            "claim(s)."
        )

    def test_many_numbers_past_the_claims_are_counted_not_listed(self) -> None:
        numbers = ", ".join(str(n) for n in range(10, 400))
        line = f"[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claims {numbers}."

        note = _shown(line)["static"].note

        assert "names its claims 10, 11, 12, 13, 14 and 385 more, and its answer" in note
        assert len(note) < 300

    def test_a_claim_number_of_zero_is_past_every_claim(self) -> None:
        line = "[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claim 0. [blocking: x]"

        assert "names its claim 0" in _shown(line)["static"].note

    def test_a_claim_number_too_long_to_read(self) -> None:
        line = f"[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claim {'9' * 5000}."

        shown = _shown(line)["static"]

        assert shown == REPORTS["static"]
        assert shown.note == (
            "The dynamic analyst's round-0 revision was shown the static analyst's whole "
            "report: contested line 1 writes a claim number for it too long to be one."
        )
        assert len(shown.note) < 300

    def test_an_answer_in_force_not_held(self) -> None:
        isrs = {k: v for k, v in IN_FORCE.items() if k != "static"}

        shown = _shown(LINE, isrs=isrs)["static"]

        assert shown == REPORTS["static"]
        assert shown.note == (
            "The dynamic analyst's round-0 revision was shown the static analyst's whole "
            "report: its answer in force was not read."
        )

    def test_the_fallback_is_per_peer(self) -> None:
        line = (
            "[analysts: dynamic] DYNAMIC Claim 1 contradicts STATIC Claim 2 and the NETWORK "
            "host. [blocking: x]"
        )

        peers = _shown(line)

        assert peers["static"].claims == (2,)
        assert peers["network"] == REPORTS["network"] and peers["network"].note
        assert set(peers) == {"static", "network"}

    def test_one_line_without_a_number_shows_that_peer_whole(self) -> None:
        other = "[analysts: dynamic] STATIC is wrong about the mutex. [blocking: x]"

        _feedback, peers = contested_input(
            "dynamic", _finding(LINE, other), [LINE, other], NAMES, REPORTS, isrs=IN_FORCE
        )

        assert peers["static"] == REPORTS["static"]
        assert "contested line 2 names it without a claim number" in peers["static"].note


# ---------------------------------------------------------------------------
# The revision round
# ---------------------------------------------------------------------------


def _container() -> tuple[Any, dict[str, Any]]:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = NAMES
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    container.config.agents.definitions = {}
    from maljan.core.input_meter import InputMeter

    container.input_meter = InputMeter()
    agents: dict[str, Any] = {}
    for name in NAMES:
        agent = MagicMock()
        agent.safe_revise_isr.return_value = (f"{name} revised", IN_FORCE[name])
        agent.drain_evidence_entries.return_value = []
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    return container, agents


def _revise(lines: list[str], revise: list[str], **state_kw: Any) -> tuple[Any, Any, Any]:
    container, agents = _container()
    argument = AgentArgument(
        agent_name="Mediator",
        finding=_finding(*lines),
        confidence_score=0.6,
        contradictions=lines,
        revise=revise,
    )
    state = {
        "iteration_count": 2,
        "is_consensus": False,
        "consensus_applicable": True,
        "reports": dict(REPORTS),
        "revised_reports": {},
        "isr_reports": dict(IN_FORCE),
        "sycophancy_detected": False,
        "discussion_history": [argument],
        **state_kw,
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes._revision_input", lambda *a: RevisionInput(text="data"))
        update = asyncio.run(make_revision_node(container)(state))
    return update, agents, container


class TestTheRound:
    def test_the_revision_gets_the_excerpt_and_its_own_report_whole(self) -> None:
        _update, agents, _container_ = _revise([LINE], ["dynamic"])

        args, _kw = agents["dynamic"].safe_revise_isr.call_args
        own, peers = args[1], args[2]
        assert own == REPORTS["dynamic"]
        assert isinstance(peers["static"], ShownReport) and peers["static"].claims == (1, 3)
        human = revision_messages("S", "R", own, peers, "F", isr=True)[1][1]
        assert EXCERPT in human

    def test_the_round_records_the_excerpts_against_the_whole_reports(self) -> None:
        other = "[analysts: dynamic] DYNAMIC Claim 1 contradicts NETWORK. [blocking: x]"

        update, _agents, container = _revise([LINE, other], ["dynamic"])

        record = update["revision_rounds"][0]["peers"]
        excerpt = EXCERPT.split("\n", 1)[1]
        assert record == {
            "excerpted": 1,
            "whole": 1,
            "excerpt_chars": len(excerpt),
            "excerpted_whole_chars": len(REPORTS["static"]),
            "whole_chars": len(REPORTS["network"]),
            "quoted": {"dynamic": {"static": [1, 3]}},
            "notes": [
                "The dynamic analyst's round-2 revision was shown the network analyst's whole "
                "report: contested line 2 names it without a claim number."
            ],
        }
        (row,) = container.input_meter.peer_rows()
        assert row == {
            "stage": "debate",
            "round": 2,
            **{k: v for k, v in record.items() if k not in ("quoted", "notes")},
        }

    def test_the_numbers_come_from_the_answer_in_force_of_a_peer_revised_before(self) -> None:
        revised = _isr("static", "Reads the flag at 0x80.", "Writes a log.", round_=1)

        _update, agents, _c = _revise(
            [LINE.replace("Claims 1 and 3", "Claim 2")],
            ["dynamic"],
            isr_reports={**IN_FORCE, "static": revised},
            revised_reports={"static": "static revised text"},
        )

        peers = agents["dynamic"].safe_revise_isr.call_args[0][2]
        assert peers["static"].claims == (2,)
        assert "Writes a log." in peers["static"]
        assert peers["static"].whole_chars == len("static revised text")

    def test_a_run_state_marker_in_an_excerpt_is_written_out_and_the_claims_kept(self) -> None:
        from maljan.pipeline.run_state import RUN_STATE_BEGIN

        marked = _isr("static", f"Reads {RUN_STATE_BEGIN} here.")

        _update, agents, _c = _revise(
            [LINE.replace("Claims 1 and 3", "Claim 1")],
            ["dynamic"],
            isr_reports={**IN_FORCE, "static": marked},
        )

        shown = agents["dynamic"].safe_revise_isr.call_args[0][2]["static"]
        assert RUN_STATE_BEGIN not in shown
        assert isinstance(shown, ShownReport) and shown.claims == (1,)

    def test_a_round_asking_every_analyst_shows_every_peer_whole_as_before(self) -> None:
        container, agents = _container()
        argument = AgentArgument(
            agent_name="Mediator", finding=_finding(LINE), contradictions=[LINE]
        )
        state = {
            "iteration_count": 1,
            "reports": dict(REPORTS),
            "revised_reports": {},
            "isr_reports": dict(IN_FORCE),
            "discussion_history": [argument],
        }
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "maljan.pipeline.nodes._revision_input", lambda *a: RevisionInput(text="data")
            )
            update = asyncio.run(make_revision_node(container)(state))

        peers = agents["dynamic"].safe_revise_isr.call_args[0][2]
        assert all(type(text) is str for text in peers.values())
        assert "peers" not in update["revision_rounds"][0]


class TestTheRecord:
    def test_a_round_that_showed_no_peer_records_nothing(self) -> None:
        assert peers_shown_record({}) == {}
        assert peers_shown_record({"dynamic": {}}) == {}

    def test_the_efficiency_inputs_carry_the_rows_and_say_them(self) -> None:
        from maljan.analysis.efficiency import _input_lines, inputs_record
        from maljan.core.input_meter import InputMeter

        meter = InputMeter()
        record = {"excerpted": 2, "whole": 1, "excerpt_chars": 300, "excerpted_whole_chars": 9000}
        meter.peers_shown("debate", 1, {**record, "whole_chars": 4000})
        container = MagicMock()
        container.input_meter = meter

        inputs = inputs_record(container)

        assert inputs is not None
        assert inputs["peer_reports"] == [
            {"stage": "debate", "round": 1, **record, "whole_chars": 4000}
        ]
        assert (
            "Peer reports shown to the named revisions: 2 excerpts of 300 characters, for "
            "reports of 9,000 characters whole, and 1 whole report of 4,000 characters."
        ) in _input_lines(inputs)

    def test_a_meter_with_no_round_adds_no_part(self) -> None:
        from maljan.analysis.efficiency import inputs_record
        from maljan.core.input_meter import InputMeter

        container = MagicMock()
        container.input_meter = InputMeter()

        assert "peer_reports" not in (inputs_record(container) or {})


# ---------------------------------------------------------------------------
# The built-in analysts head an excerpt the same way
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["static", "dynamic", "network"])
def test_every_built_in_revision_heads_the_excerpt(role: str) -> None:
    from unittest.mock import patch

    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    agent = ServiceContainer(Settings(_env_file=None), mock=True).get_agent(role)
    seen: list[str] = []

    def _ask(messages: Any, **_kw: Any) -> str:
        seen.extend(str(getattr(m, "content", "")) for m in messages if m.type == "human")
        return "CLAIM: none\nEVIDENCE: none\nCONFIDENCE: 0.1\nTECHNIQUE: NONE\nDISPUTES: NONE"

    peers = {"peer": ShownReport("  Claim 2: x", (2,), 900), "other": "whole text"}
    with patch.object(agent, "ask_the_model", side_effect=_ask):
        agent.revise_isr("data", "own", peers, "feedback")

    assert seen
    assert "PEER REPORT (claim 2 quoted; the whole report is not shown):\n  Claim 2: x" in seen[0]
    assert "OTHER REPORT:\nwhole text" in seen[0]
