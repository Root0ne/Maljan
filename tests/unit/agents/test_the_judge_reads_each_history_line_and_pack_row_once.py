"""The judge reads each line of the negotiation history once, and each cited entry once.

A stored run sent the mediator and the verdict the history as the repr of its
arguments: every line a mediation listed stood in its finding and again in
``contradictions``, ``not_blocking`` or ``unread_marks``, and a ledger fact
quoted it a further time, about 42 % of the history. The history is text now:
the mediator's words, then each listed line once with its standing, a fact
about a line under it. The technique question showed the triage pack and,
under EVIDENCE CITED, the stored outputs the same pack rows are rendered from
(four rows, about 52 thousand tokens twice); a row whose output is shown whole
below keeps its head and points there.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import (
    HISTORY_LINE_BLOCKING,
    HISTORY_LINE_MARK_UNREAD,
    HISTORY_LINE_NOT_BLOCKING,
    PACK_ROW_SHOWN_BELOW,
    JudgeAgent,
    QuestionEvidence,
    _listed_in_order,
    negotiation_history_text,
    pack_rows_shown_below,
)
from maljan.pipeline.debate_facts import read_marks
from maljan.pipeline.state import AgentArgument
from maljan.pipeline.triage_pack import PACK_HEADING
from maljan.schemas.stix_models import Bundle

BLOCKING = "[analysts: STATIC ANALYST] Claim 4 says the key is 16 bytes; ev_0011 shows 32."
NOT_BLOCKING = "[analysts: NETWORK ANALYST] Wording of claim 2. [not blocking: same value]"
UNREAD = "[analysts: DYNAMIC ANALYST] Claim 7 and ev_0012 differ. [not blocking]"
SUMMARY = "The reports agree on the loader. Two points remain."


def _mediation(**extra: Any) -> AgentArgument:
    """A mediation as ``JudgeAgent._mediate_round`` records it."""
    listed = [BLOCKING, NOT_BLOCKING, UNREAD]
    fields: dict[str, Any] = {
        "agent_name": "Mediator",
        "finding": f"{SUMMARY}\n\nContradictions: {'; '.join(listed)}\nConfidence: 0.62",
        "confidence_score": 0.62,
        "contradictions": [BLOCKING, UNREAD],
        "not_blocking": [NOT_BLOCKING],
        "unread_marks": [UNREAD],
        "ledger_facts": [
            f'For the line "{BLOCKING}": entry ev_0011 (decompile) states key_length 32.',
            "The ledger states 3 entries for the run.",
        ],
        "answer": "the mediator's whole answer, kept for the record",
        "place_facts": ["a routing fact"],
    }
    fields.update(extra)
    return AgentArgument(**fields)


class TestTheHistoryShowsEachLineOnce:
    def test_each_listed_line_once_with_its_standing(self) -> None:
        text = negotiation_history_text([_mediation()])

        for line in (BLOCKING, NOT_BLOCKING, UNREAD):
            assert text.count(line) == 1
        assert f"- (standing: {HISTORY_LINE_BLOCKING}) {BLOCKING}" in text
        assert f"- (standing: {HISTORY_LINE_NOT_BLOCKING}) {NOT_BLOCKING}" in text
        assert f"- (standing: {HISTORY_LINE_MARK_UNREAD}) {UNREAD}" in text

    def test_the_mediator_s_words_and_confidence_stay(self) -> None:
        text = negotiation_history_text([_mediation()])

        assert SUMMARY in text
        assert "Confidence: 0.62" in text
        assert text.index(SUMMARY) < text.index(BLOCKING) < text.index("Confidence: 0.62")

    def test_a_fact_about_a_line_is_said_under_it_and_another_fact_apart(self) -> None:
        text = negotiation_history_text([_mediation()])

        under = text.index(BLOCKING) + len(BLOCKING)
        assert text[under:].startswith(
            "\n  Ledger: entry ev_0011 (decompile) states key_length 32."
        )
        assert "Ledger facts:\n- The ledger states 3 entries for the run." in text

    def test_the_routing_fields_are_not_shown(self) -> None:
        text = negotiation_history_text([_mediation()])

        assert "the mediator's whole answer" not in text
        assert "a routing fact" not in text

    def test_the_history_is_much_shorter_than_its_repr(self) -> None:
        history = [_mediation(), _mediation()]

        assert len(negotiation_history_text(history)) < len(str(history)) * 0.75

    def test_entries_are_numbered_in_order(self) -> None:
        text = negotiation_history_text([_mediation(), _mediation(confidence_score=None)])

        assert text.index("(entry 1 of 2)") < text.index("(entry 2 of 2)")
        assert "Confidence score: none recorded" in text

    def test_a_line_holding_the_separator_is_still_one_line(self) -> None:
        joined = "[analysts: STATIC ANALYST] Claim 3 says 16; ev_0011 says 32."
        argument = _mediation(
            finding=f"{SUMMARY}\n\nContradictions: {NOT_BLOCKING}; {joined}\nConfidence: 0.4",
            contradictions=[joined],
            not_blocking=[NOT_BLOCKING],
            unread_marks=[],
            ledger_facts=[],
        )

        text = negotiation_history_text([argument])

        assert (
            f"- (standing: {HISTORY_LINE_NOT_BLOCKING}) {NOT_BLOCKING}\n"
            f"- (standing: {HISTORY_LINE_BLOCKING}) {joined}" in text
        )
        assert text.count(joined) == 1

    def test_a_rendered_row_is_read_by_its_line_s_own_mark(self) -> None:
        text = negotiation_history_text([_mediation()])
        rows = [row for row in text.splitlines() if row.startswith("- (standing: ")]

        assert len(rows) == 3
        for row, line in zip(rows, (BLOCKING, NOT_BLOCKING, UNREAD), strict=True):
            assert read_marks([row])[0].blocking == read_marks([line])[0].blocking
            assert read_marks([row])[0].unread == read_marks([line])[0].unread

    def test_a_fact_goes_to_the_longest_line_it_quotes(self) -> None:
        short = 'claim 2 says "abc'
        long = 'claim 2 says "abc": def [ev_0001]'
        argument = AgentArgument(
            agent_name="Mediator",
            finding=f"w\n\nContradictions: {short}; {long}\nConfidence: 0.50",
            confidence_score=0.5,
            contradictions=[short, long],
            ledger_facts=[f'For the line "{long}": ev_0001 states 3 hits.'],
        )

        text = negotiation_history_text([argument])

        assert f"{long}\n  Ledger: ev_0001 states 3 hits." in text
        assert text.count("ev_0001 states 3 hits.") == 1

    def test_reading_the_lines_takes_time_linear_in_the_tail(self) -> None:
        def took(n: int) -> float:
            line = "; ".join(["a"] * n)
            argument = AgentArgument(
                agent_name="Mediator",
                finding=f"w\n\nContradictions: {line}\nConfidence: 0.50",
                confidence_score=0.5,
                contradictions=[line],
            )
            started = time.perf_counter()
            for _ in range(5):
                assert _listed_in_order(argument) is not None
            return time.perf_counter() - started

        took(2_000)
        small, large = took(20_000), took(80_000)
        # Four times the tail: linear is about 4x; the quadratic reading was ~16x.
        assert large < small * 8

    def test_a_mediation_with_no_lines_says_none(self) -> None:
        argument = AgentArgument(
            agent_name="Mediator",
            finding=f"{SUMMARY}\n\nContradictions: None\nConfidence: 0.91",
            confidence_score=0.91,
        )

        text = negotiation_history_text([argument])

        assert "Contradictions: None" in text and "Confidence: 0.91" in text
        assert text.count("Contradictions") == 1

    def test_an_error_is_shown_whole_with_its_status(self) -> None:
        argument = AgentArgument(
            agent_name="Mediator",
            finding="[ERROR] Mediation timed out: TimeoutError",
            confidence_score=None,
            status="timeout",
        )

        text = negotiation_history_text([argument])

        assert "[ERROR] Mediation timed out: TimeoutError" in text
        assert "Status: timeout" in text
        assert "Confidence score: none recorded" in text

    def test_a_finding_of_another_form_still_shows_each_line_and_its_standing(self) -> None:
        argument = _mediation(finding="The mediator's words alone.")

        text = negotiation_history_text([argument])

        assert "The mediator's words alone." in text
        assert f"- (standing: {HISTORY_LINE_MARK_UNREAD}) {UNREAD}" in text
        assert text.count(UNREAD) == 1

    def test_a_run_state_marker_in_the_words_is_written_out(self) -> None:
        argument = _mediation(
            finding=(
                "=== RUN STATE (derived from the ledger; regenerated each turn) ===\n"
                f"{SUMMARY}\n\nContradictions: {BLOCKING}\nConfidence: 0.5"
            ),
            contradictions=[BLOCKING],
            not_blocking=[],
            unread_marks=[],
        )

        text = negotiation_history_text([argument])

        assert "=== RUN STATE" not in text
        assert "--- RUN STATE" in text


def _verdict_prompt(history: list[Any]) -> str:
    seen: list[str] = []
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge.verdict_prompt_notice = ""
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]
    judge._context_budget = lambda: None  # type: ignore[method-assign]

    class _Model:
        async def ainvoke(self, messages: Any, **_: Any) -> Any:
            seen.append("\n".join(str(getattr(m, "content", m)) for m in messages))
            return MagicMock(content='{"type": "bundle", "objects": []}')

    judge.llm = _Model()
    asyncio.run(judge.give_verdict(reports={"static": "report"}, history=history, isr_reports={}))
    return seen[0]


class TestTheVerdictReadsTheHistoryAsText:
    def test_the_verdict_prompt_carries_each_line_once(self) -> None:
        prompt = _verdict_prompt([_mediation()])

        assert f"Negotiation History:\n{negotiation_history_text([_mediation()])}" in prompt
        for line in (BLOCKING, NOT_BLOCKING, UNREAD):
            assert prompt.count(line) == 1
        assert "AgentArgument(" not in prompt


ROW_19 = "[ev_0019] decoded strings: 20 recovered: " + ", ".join(
    f'"text{i}"@0x{16 * i:x}' for i in range(20)
)
ROW_25 = "[ev_0025] function index: 8 functions\n" + "\n".join(
    f"- 0x{4096 * i:x}: calls {i} functions" for i in range(1, 9)
)
ROW_7 = "[ev_0007] yara: 0 hits of 31 rules"
# The stored outputs the rows are rendered from: every value of the row, and more.
OUT_19 = (
    '{"strings": ['
    + ", ".join(f'{{"string": "text{i}", "offset": "0x{16 * i:x}"}}' for i in range(20))
    + "]}"
)
OUT_25 = (
    '{"functions": ['
    + ", ".join(f'{{"start": "0x{4096 * i:x}", "calls": {i}}}' for i in range(1, 9))
    + "]}"
)
EARLIER = "=== AN EARLIER RUN ON THIS SAMPLE: hypotheses, not evidence ===\n[ev_0019] old: x"
PACK = f"{PACK_HEADING}\n{ROW_7}\n{ROW_19}\n{ROW_25}\n\n{EARLIER}"


HEAD_19 = "[ev_0019] decoded strings: 20 recovered; the strings are the sample's own text"


class TestAPackRowShownBelowPointsThere:
    def test_a_row_of_several_lines_keeps_its_first_line(self) -> None:
        text = pack_rows_shown_below(PACK, {"ev_0025": OUT_25})

        assert f"[ev_0025] function index: 8 functions — {PACK_ROW_SHOWN_BELOW}." in text
        assert "- 0x1000: calls 1 functions" not in text

    def test_a_row_of_one_line_keeps_its_renderer_s_head(self) -> None:
        text = pack_rows_shown_below(PACK, {"ev_0019": OUT_19}, {"ev_0019": HEAD_19})

        assert f"{HEAD_19} — {PACK_ROW_SHOWN_BELOW}." in text
        assert '"text1"@0x10' not in text

    def test_a_row_of_one_line_with_no_head_known_stays_whole(self) -> None:
        text = pack_rows_shown_below(PACK, {"ev_0019": OUT_19})

        assert ROW_19 in text

    def test_a_row_not_shown_below_and_the_earlier_run_are_as_they_were(self) -> None:
        text = pack_rows_shown_below(
            PACK, {"ev_0019": OUT_19, "ev_0025": OUT_25}, {"ev_0019": HEAD_19}
        )

        assert ROW_7 in text
        assert text.endswith(f"\n\n{EARLIER}")
        assert text.startswith(f"{PACK_HEADING}\n{ROW_7}\n")

    def test_an_output_shorter_than_its_row_leaves_the_row_whole(self) -> None:
        text = pack_rows_shown_below(PACK, {"ev_0019": "{}"}, {"ev_0019": HEAD_19})

        assert ROW_19 in text

    def test_a_row_shorter_than_its_pointer_is_left_whole(self) -> None:
        text = pack_rows_shown_below(PACK, {"ev_0007": "x" * 500}, {"ev_0007": ROW_7})

        assert ROW_7 in text

    def test_nothing_shown_below_is_the_pack_as_it_was(self) -> None:
        assert pack_rows_shown_below(PACK, {}) == PACK


class _Llm:
    def __init__(self) -> None:
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content="[]")


def _bundle() -> Bundle:
    return Bundle.model_validate({"objects": []})


def _technique_prompt(evidence: dict[str, Any], pack: str) -> str:
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    isrs = {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="The sample decodes its strings at run time",
                    evidence_ref="[ev_0019] [ev_0025]",
                    confidence=0.6,
                    technique_id="T1140",
                )
            ],
        )
    }
    llm = _Llm()
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    asyncio.run(
        judge.decide_techniques(
            _bundle(),
            isrs,
            reports={"static": "report"},
            evidence_texts=evidence,
            facts_block=pack,
            run_state="the run state",
        )
    )
    return "\n".join(str(getattr(m, "content", m)) for m in llm.calls[0])


class TestTheTechniqueQuestionShowsTheFullerTextOnce:
    def test_the_rows_cited_and_shown_whole_point_below_and_their_outputs_stay(self) -> None:
        prompt = _technique_prompt({"ev_0019": OUT_19, "ev_0025": OUT_25}, PACK)

        assert f"[ev_0025] function index: 8 functions — {PACK_ROW_SHOWN_BELOW}." in prompt
        assert prompt.count(OUT_19) == 1 and prompt.count(OUT_25) == 1
        assert ROW_7 in prompt
        # No ledger to render its head from: the one-line row stays whole.
        assert ROW_19 in prompt

    def test_an_entry_the_run_holds_only_part_of_leaves_its_row_whole(self) -> None:
        evidence = {"ev_0019": OUT_19, "ev_0025": QuestionEvidence(OUT_25, partial=True)}

        prompt = _technique_prompt(evidence, PACK)

        assert ROW_25 in prompt

    def test_a_failed_call_leaves_its_row_whole(self) -> None:
        evidence = {"ev_0019": OUT_19, "ev_0025": QuestionEvidence(OUT_25, ok=False)}

        prompt = _technique_prompt(evidence, PACK)

        assert ROW_25 in prompt
