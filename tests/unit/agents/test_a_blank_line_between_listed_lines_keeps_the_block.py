"""A blank line between two lines of the mediator's final block does not end it.

A paid run's third mediation wrote its CONTRADICTIONS: block as unbulleted
lines, each opening with its [analysts: ...] field and ending with its mark,
with a blank line between every two. The reader ended the block at the first
blank line followed by a line that was not bulleted or numbered, so it read 1
of 19 lines (5 blocking) and the revision round acted on one point. The
mediator's words were in no artefact, so nobody could read the block again.

- A plain line that holds a field every listed line is asked for (opening
  with the [analysts: ...] field or ending with a [blocking ...] mark)
  continues the block after a blank line, as a bulleted or numbered line
  does. A sentence that only names a field or a mark does not.
- The block still ends at the agreement line, the end of the answer, and
  prose after a blank line: a closing sentence is never read as a
  contradiction. A remark after a blank line followed by a line with the
  fields is read past and is no item; after a NONE, a blank line ends the
  block.
- A heading with no blank line above it is no item: inside the block it is
  read past; before the block's first line it heads the lines under it when
  the next line is a list line or holds the fields, and otherwise ends the
  block, which is then unreadable and asked about, never read as consensus.
- Each mediation keeps its answer whole and masked in
  ``run_summary.negotiation.mediator_answers``, with its round.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from maljan.agents.judge_agent import JudgeAgent, read_contradictions_block
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline import events
from maljan.pipeline.debate_facts import carries_line_field, read_marks
from maljan.pipeline.events import remember_secret_values
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.credential_shapes import lowercase_body
from tests.linear_cost import TIME_RATIO_LIMIT, calls, cpu_seconds

BLOCKING = [
    "[analysts: DYNAMIC ANALYST, STATIC ANALYST] DYNAMIC claim 24 says the name does not reach "
    "CreateMutexW; ev_0020 gives the slot chain. [blocking: the mutex-name claims differ]",
    "[analysts: ALL_TOOLS_STATIC_R2 ANALYST] STATIC_R2 says the sample ran under rundll32; four "
    "analysts attribute the launch to a harness. [blocking: the wording must match the record]",
    "[analysts: TRIAGE ANALYST] TRIAGE claims 16 to 25 repeat one claim under ten technique ids. "
    "[blocking: each claim must carry one technique that matches its text]",
]
NOT_BLOCKING = [
    "[analysts: NETWORK ANALYST, DYNAMIC ANALYST] [not blocking: NETWORK reads the export name as "
    "a label and DYNAMIC as the module name; both agree it is no function name.]",
    "[analysts: STATIC ANALYST] [not blocking: the family-label counts are now stated alike.]",
]
LINES = BLOCKING + NOT_BLOCKING
AGREEMENT = "agreement_confidence: 0.68"


def _answer(*parts: str, sep: str = "\n\n", tail: str = AGREEMENT) -> str:
    return (
        "Most earlier conflicts have converged.\n\nCONTRADICTIONS:\n"
        + sep.join(parts)
        + (f"\n\n{tail}" if tail else "")
    )


class TestBlankLinesBetweenTheBlocksLines:
    def test_the_paid_run_s_shape_reads_every_line(self) -> None:
        reading = read_contradictions_block(_answer(*LINES))

        assert reading.items == LINES
        assert reading.mixed is False and reading.ambiguous == ""
        assert sum(m.blocking for m in read_marks(reading.items)) == len(BLOCKING)

    @pytest.mark.parametrize(
        "shape",
        [
            pytest.param([f"{n}. {line}" for n, line in enumerate(LINES, 1)], id="numbered"),
            pytest.param([f"- {line}" for line in LINES], id="bulleted"),
            pytest.param(
                [f"- {LINES[0]}", LINES[1], f"2) {LINES[2]}", LINES[3], f"* {LINES[4]}"],
                id="mixed",
            ),
        ],
    )
    def test_every_list_form_reads_every_line(self, shape: list[str]) -> None:
        assert read_contradictions_block(_answer(*shape)).items == LINES

    def test_without_blank_lines_the_block_reads_as_before(self) -> None:
        assert read_contradictions_block(_answer(*LINES, sep="\n")).items == LINES

    def test_blank_lines_right_after_the_label_do_not_end_the_block(self) -> None:
        text = "Reasoning.\n\nCONTRADICTIONS:\n\n\n" + "\n\n".join(LINES) + f"\n{AGREEMENT}"
        assert read_contradictions_block(text).items == LINES

    def test_a_line_with_only_a_mark_continues_the_block(self) -> None:
        marked = "STATIC claim 3 says X; ev_0004 says Y. [blocking: incompatible]"
        assert read_contradictions_block(_answer(LINES[0], marked)).items == [LINES[0], marked]

    def test_an_indented_line_after_a_blank_one_is_an_item_of_its_own(self) -> None:
        text = _answer(LINES[0], f"   {LINES[1]}")
        assert read_contradictions_block(text).items == [LINES[0], LINES[1]]

    def test_the_end_of_the_answer_ends_the_block(self) -> None:
        assert read_contradictions_block(_answer(*LINES, tail="")).items == LINES


class TestTheBlocksEndIsStillRead:
    @pytest.mark.parametrize(
        "after",
        [
            pytest.param("These remain open, so the analysts revise.", id="closing prose"),
            pytest.param("Summary: two lines stand.", id="section label"),
            pytest.param("## Resolved points", id="heading"),
            pytest.param("**Notes:**", id="emphasised label"),
        ],
    )
    def test_unbulleted_lines_then_what_follows_them(self, after: str) -> None:
        text = _answer(LINES[0], LINES[1], after, "- rerun the unpacker", "Later prose.")
        assert read_contradictions_block(text).items == [LINES[0], LINES[1]]

    def test_bulleted_lines_then_closing_prose(self) -> None:
        text = _answer(f"- {LINES[0]}", f"- {LINES[1]}", "These remain open.", "- not a line")
        assert read_contradictions_block(text).items == [LINES[0], LINES[1]]

    def test_a_heading_inside_the_block_is_read_past_whatever_follows_it(self) -> None:
        # As dev reads it: the plain line under the heading stays a line, and
        # with no field it blocks and every analyst is asked.
        text = "CONTRADICTIONS:\n- a [analysts: s]\n### 1. C2\nstatic says x, dynamic says y\n"
        reading = read_contradictions_block(text + AGREEMENT)
        assert reading.items == ["a [analysts: s]", "static says x, dynamic says y"]
        (_, second) = read_marks(reading.items)
        assert second.blocking and not carries_line_field(second.line)

    def test_a_quoted_field_line_after_a_blank_one_ends_the_block(self) -> None:
        text = _answer(LINES[0], "> [analysts: d] quoted text")
        assert read_contradictions_block(text).items == [LINES[0]]

    def test_a_heading_between_the_block_s_lines_is_read_past(self) -> None:
        text = _answer("### Blocking", *BLOCKING, "**Not blocking**", *NOT_BLOCKING)
        assert read_contradictions_block(text).items == LINES

    def test_plain_prose_paragraphs_without_the_fields_are_not_read_past_a_blank(self) -> None:
        # Two plain paragraphs read alike to a closing sentence after the
        # block: without the fields the line is asked to carry, the second is
        # not taken for a contradiction.
        text = _answer("STATIC says X; ev_0004 says Y.", "DYNAMIC says P; NETWORK says Q.")
        assert read_contradictions_block(text).items == ["STATIC says X; ev_0004 says Y."]

    def test_a_none_block_and_a_closing_sentence_read_as_before(self) -> None:
        text = "CONTRADICTIONS: NONE\n\nThe analysts agree.\n" + AGREEMENT
        reading = read_contradictions_block(text)
        assert reading.items == [] and reading.ambiguous == ""


class TestTheFields:
    @pytest.mark.parametrize(
        ("line", "held"),
        [
            ("[analysts: STATIC ANALYST] x", True),
            ("x [blocking: y]", True),
            ("x [Not  Blocking: y]", True),
            ("- **[analysts: STATIC ANALYST]** x", True),
            ("> [analysts: d] quoted text", False),
            ("2) [analysts: STATIC ANALYST] x", True),
            ("x [blocking: y]**.", True),
            ("These remain open.", False),
            ("Summary: [ev_0001] says so.", False),
            ("Of these, only the first is [blocking]; the rest are cosmetic.", False),
            ("Note: an earlier draft listed C2 [analysts: static] but it was resolved.", False),
            ("- static [analysts: static]: recheck the C2 string", False),
            ('> static wrote: "see line [analysts: dynamic] above"', False),
        ],
    )
    def test_a_line_holds_the_fields_or_not(self, line: str, held: bool) -> None:
        assert carries_line_field(line) is held


# The shapes a review of this change found, each read as before it (on dev)
# unless the case says otherwise.
AS_ON_DEV = {
    "prose after a blank label line": (
        "CONTRADICTIONS:\n\nNo material contradictions remain; the analysts agree.\n\n"
        "agreement_confidence: 0.92",
        [],
    ),
    "revision directives after the block": (
        "CONTRADICTIONS:\n- C2 domain differs [analysts: static, dynamic]\n\n"
        "Revision directives:\n- static [analysts: static]: recheck the C2 string\n"
        "- dynamic [analysts: dynamic]: recheck PCAP\nagreement_confidence: 0.5",
        ["C2 domain differs [analysts: static, dynamic]"],
    ),
    "a sentence naming a mark": (
        "CONTRADICTIONS:\n- C2 domain differs [analysts: static, dynamic] [blocking: core]\n\n"
        "Of these, only the first is [blocking]; the rest are cosmetic.\n"
        "agreement_confidence: 0.5",
        ["C2 domain differs [analysts: static, dynamic] [blocking: core]"],
    ),
    "a quoted analyst line": (
        "CONTRADICTIONS:\n- C2 differs [analysts: static, dynamic]\n\n"
        '> static wrote: "see line [analysts: dynamic] above"\nagreement_confidence: 0.5',
        ["C2 differs [analysts: static, dynamic]"],
    ),
    "a remark after NONE": (
        "CONTRADICTIONS: NONE\n\nNote: an earlier draft listed C2 [analysts: static] but it "
        "was resolved.\nagreement_confidence: 0.9",
        [],
    ),
    "a resolved line after NONE": (
        "CONTRADICTIONS:\nNONE\n\nPreviously: [analysts: static] C2 resolved "
        "[not blocking: resolved]\nagreement_confidence: 0.9",
        [],
    ),
    "a fenced code block": (
        "CONTRADICTIONS:\n- a [analysts: static]\n\n```\nexample [analysts: x]\n```\n"
        "agreement_confidence: 0.5",
        ["a [analysts: static]"],
    ),
}


class TestWhatTheReviewFound:
    @pytest.mark.parametrize(("text", "items"), list(AS_ON_DEV.values()), ids=list(AS_ON_DEV))
    def test_the_shape_reads_as_before(self, text: str, items: list[str]) -> None:
        reading = read_contradictions_block(text)
        assert reading.items == items
        assert reading.ambiguous == ""

    def test_a_heading_under_the_label_heads_the_numbered_lines(self) -> None:
        text = (
            "CONTRADICTIONS:\n## Still standing\n1. static vs dynamic on C2\n2. mutex name\n"
            "agreement_confidence: 0.85"
        )
        assert read_contradictions_block(text).items == ["static vs dynamic on C2", "mutex name"]

    def test_a_heading_under_the_label_with_plain_text_is_asked_about(self) -> None:
        # The block ends at the heading before any line: neither a line that
        # stands nor a NONE, so it is unreadable and asked once, never consensus.
        text = (
            "## CONTRADICTIONS:\n### 1. C2 domain\nstatic says x, dynamic says y\n"
            "agreement_confidence: 0.85"
        )
        assert read_contradictions_block(text).items is None

    def test_a_heading_inside_a_bulleted_block_keeps_the_lines_after_it(self) -> None:
        text = (
            "CONTRADICTIONS:\n- a vs b on C2\n### Minor\n- c vs d on mutex\n"
            "agreement_confidence: 0.4"
        )
        assert read_contradictions_block(text).items == ["a vs b on C2", "c vs d on mutex"]

    def test_a_heading_over_unfielded_bullets_heads_them(self) -> None:
        text = (
            "CONTRADICTIONS:\n### Blocking\n- static says X, dynamic says Y\n"
            "- C2 disagreement\nagreement_confidence: 0.4"
        )
        assert read_contradictions_block(text).items == [
            "static says X, dynamic says Y",
            "C2 disagreement",
        ]

    def test_a_line_of_emphasis_alone_is_no_item(self) -> None:
        text = f"CONTRADICTIONS:\n{LINES[0]}\n**\n{LINES[1]}\n{AGREEMENT}"
        assert read_contradictions_block(text).items == [LINES[0], LINES[1]]


class TestLinearTime:
    @pytest.mark.parametrize(
        "unit",
        [
            pytest.param(lambda n: f"[analysts: A{n}] x{n} [blocking: r]\n\n", id="field lines"),
            pytest.param(
                lambda n: f"## Heading {n}\n\n[analysts: A] x [blocking: r]\n", id="heads"
            ),
            pytest.param(lambda n: "[ " + " " * 50 + f"analysts{n}\n\n", id="open brackets"),
            pytest.param(lambda n: "*" * 60 + f" x{n}\n", id="emphasis runs"),
            pytest.param(lambda n: f"x{n} [blocking: r]" + " " * 60 + "y\n", id="spaces after"),
        ],
    )
    def test_four_times_the_answer_costs_under_eight_times(self, unit: Any) -> None:
        def read(lines: int) -> Any:
            text = "CONTRADICTIONS:\n" + "".join(unit(n) for n in range(lines)) + AGREEMENT
            return lambda: read_contradictions_block(text)

        # CPU time, not wall-clock: four times the lines must take under eight
        # times as long, and a quadratic read takes sixteen times. The calls
        # made are held to the same ratio, which a load cannot move.
        read(50)()
        small, large = read(3_000), read(12_000)
        assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
        assert calls(large) <= calls(small) * 4 * 1.2 + 100

    @pytest.mark.parametrize(
        "line",
        [
            pytest.param(lambda size: "[analysts: " + " [" * size, id="open brackets"),
            pytest.param(lambda size: "*" * size + " x", id="emphasis"),
            pytest.param(lambda size: "x [blocking: r]" + " " * size + "y", id="spaces"),
            pytest.param(lambda size: "x " + "[blocking " * size, id="mark openings"),
        ],
    )
    def test_one_long_line_costs_in_proportion(self, line: Any) -> None:
        def read(size: int) -> Any:
            text = f"CONTRADICTIONS:\n- a\n\n{line(size)}\n\n{AGREEMENT}"
            return lambda: read_contradictions_block(text)

        read(50)()
        small, large = read(100_000), read(400_000)
        assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT


class _Model:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)

    async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
        return AIMessage(content=self.answers.pop(0))

    def with_structured_output(self, _schema: Any) -> Any:
        return RunnableLambda(
            lambda _in: MediatorVerdict(contradictions=[], resolution_summary="s", confidence=0.68)
        )


def _mediate(answer: str, claimants: tuple[str, ...] = ("gamma", "beta")) -> AgentArgument:
    isrs = {
        name: AgentISR(
            agent_id=name,
            domain="static",
            claims=[ClaimEvidence(claim="c", evidence_ref="[ev_0001]", confidence=0.9)] * 3
            if name in claimants
            else [],
        )
        for name in ("gamma", "beta")
    }
    judge = JudgeAgent(llm=_Model(answer))  # type: ignore[arg-type]
    with patch.object(judge, "_supports_structured_output", return_value=False):
        argument, _ = asyncio.run(judge.mediate({"gamma": "r", "beta": "r"}, [], isr_reports=isrs))
    return argument


def _negotiation(history: list[AgentArgument]) -> dict[str, Any]:
    state = {
        "iteration_count": len(history),
        "is_consensus": False,
        "sycophancy_detected": False,
        "confidence_history": [0.68] * len(history),
        "discussion_history": history,
        "isr_reports": {},
        "revision_rounds": [],
    }
    return (
        RunSummaryBuilder(start_time=0.0)
        .set_negotiation(state, max_iterations=5)
        .build()
        .to_dict()["negotiation"]
    )


class TestTheMediatorsAnswerIsKept:
    def test_the_round_acts_on_every_blocking_line_and_keeps_the_answer(self) -> None:
        answer = _answer(*LINES)
        argument = _mediate(answer)

        assert argument.contradictions == BLOCKING
        assert argument.not_blocking == NOT_BLOCKING
        assert argument.answer == answer
        # Record data, never model input: the history a prompt carries is the repr.
        assert answer not in repr(argument)

    def test_a_round_where_consensus_did_not_apply_keeps_the_answer_too(self) -> None:
        answer = _answer(*LINES)
        argument = _mediate(answer, claimants=("gamma",))

        assert argument.confidence_score is None
        assert argument.answer == answer

    def test_the_run_summary_keeps_each_answer_with_its_round(self) -> None:
        first = AgentArgument(agent_name="Mediator", finding="f", answer="first answer")
        unanswered = AgentArgument(agent_name="Mediator", finding="", status="no_answer")
        third = AgentArgument(agent_name="Mediator", finding="f", answer=_answer(*LINES))

        kept = _negotiation([first, unanswered, third])["mediator_answers"]

        assert kept == [
            {"round": "1", "answer": "first answer"},
            {"round": "3", "answer": _answer(*LINES)},
        ]
        assert read_contradictions_block(kept[1]["answer"]).items == LINES

    def test_a_run_with_no_kept_answer_records_no_key(self) -> None:
        assert "mediator_answers" not in _negotiation(
            [AgentArgument(agent_name="Mediator", finding="f")]
        )

    def test_the_answer_is_masked_as_model_text_in_the_record_is(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key = lowercase_body(24)
        monkeypatch.setattr(events, "_SECRET_SCOPES", {})
        monkeypatch.setattr(events, "_SHORT_SECRETS", {})
        monkeypatch.setattr(events, "_FAILED_SCOPES", set())
        monkeypatch.setattr(events, "_CONFIGURED_PATTERN", None)
        remember_secret_values([key], scope="job")
        line = f"[analysts: STATIC ANALYST] STATIC quotes {key} from ev_0003. [blocking: r]"

        argument = _mediate(_answer(line, *LINES))

        assert key not in argument.answer
        assert argument.answer.endswith(AGREEMENT)
        assert len(argument.contradictions) == len(BLOCKING) + 1
