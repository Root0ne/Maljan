"""A whole retry that restates few of the first answer's claims does not replace it.

haiku6: the reverser's first answer left one claim block unread, so its
validation retry was asked for a whole answer. Written in a tools-free turn,
the retry wrote 46 claims and restated none of the first answer's 42 (by
``retry_drops``: every one held a value the retry states nowhere), and it was
kept as the analyst's answer because it had more claim blocks. What it left out
was then asked about as items of an answer the retry had replaced.

A retry that restates fewer of the first answer's claims than it leaves out is
more another answer than a fix of this one. It no longer replaces the first
answer: the run log says so once (``isr.retry_restated_few``), and the one
question about what it left out says the items stand beside the retry's claims
as first written. The analyst's answer stands: a withdrawn item stays out,
every other item stays. The count is ``retry_drops``' own identity, compared
with what the retry left out; there is no tuned share.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import (
    RETRY_DROP_KEPT,
    RETRY_DROP_NOT_ANSWERED,
    RETRY_DROP_WITHDRAWN,
    RETRY_DROPPED_CODE,
    RETRY_RESTATED_FEW_CODE,
    retry_drops,
    retry_restated_few_question,
)
from maljan.schemas.isr_models import AgentISR

RESTATED_HEAD = "so it does not replace your first answer"
REPLACED_HEAD = "Your retry stands as your answer"


def _block(sentence: str, technique: str = "NONE", evidence: str = "[ev_0080] decompile") -> str:
    return (
        f"CLAIM: {sentence}\nEVIDENCE: {evidence}\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}\n---\n"
    )


# Three claims read from decompiles, each with values of its own.
FIRST = (
    _block("Routine 0x3868 exits when GetLastError returns 0xb7.")
    + _block("The command switch 0x3cf4 runs 0x7170 for code 0xe.")
    + _block("The string at 0xf920 decodes to `Update_%x`.")
)
# A retry written without the decompiles: four claims, none restating them.
OTHER = (
    _block("The sample is an AMD64 DLL of 60,928 bytes.", evidence="[ev_0001] identity")
    + _block("Its imports name 0x9484 as a resolver.", evidence="[ev_0004] imports")
    + _block("The sandbox ran export ordinal 1 through rundll32.", evidence="[ev_0012] procs")
    + _block("The overlay holds 0x40 bytes of padding.", evidence="[ev_0003] sections")
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[Any]) -> None:
        super().__init__(llm=MagicMock(), name="all_tools_reverser_ghidra")
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.questions: list[str] = []
        self.events: list[tuple[str, dict[str, Any]]] = []
        self._container = SimpleNamespace(
            event_sink=lambda kind, payload: self.events.append((kind, payload)),
            get_context_budget=lambda: None,
        )

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.questions.append(str(messages[-1].content))
        reply = self._replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        self._record_usage(AIMessage(content=reply))
        return reply


def _settle(analyst: _Analyst, first_text: str, retry_text: str) -> tuple[AgentISR, AgentISR]:
    first = analyst._text_to_isr(first_text, 0)
    retried = analyst._text_to_isr(retry_text, 0)
    result = analyst._settle_retry_drops(
        first, retried, retry_text, [], [HumanMessage(content="evidence")], None
    )
    return first, result


def _settle_asked(
    analyst: _Analyst, first_text: str, retry_text: str, asked: list[str]
) -> AgentISR:
    first = analyst._text_to_isr(first_text, 0)
    retried = analyst._text_to_isr(retry_text, 0)
    return analyst._settle_retry_drops(
        first, retried, retry_text, asked, [HumanMessage(content="evidence")], None
    )


def _codes(analyst: _Analyst) -> list[str]:
    return [payload["code"] for _kind, payload in analyst.events]


def _rows(analyst: _Analyst) -> list[dict[str, str]]:
    return [row for row in analyst.drain_unparsed_answers() if row.get("record") == "retry_drop"]


class TestARetryThatRestatesNone:
    """The haiku6 shape: the retry restates none of the first answer's claims."""

    def test_the_question_says_the_retry_does_not_replace_the_first_answer(self) -> None:
        analyst = _Analyst(["KEEP C1: yes\nKEEP C2: yes\nKEEP C3: yes"])

        _settle(analyst, FIRST, OTHER)

        (question,) = analyst.questions
        assert question.startswith(
            "Your retry restated 0 of your first answer's claims that state a value and leaves "
            "out 3, so it does not replace your first answer: these items of your first answer "
            "stand in your answer as you wrote them, beside your retry's claims:\n"
        )
        assert REPLACED_HEAD not in question
        assert "C1. CLAIM: Routine 0x3868 exits when GetLastError returns 0xb7." in question
        assert "KEEP <label>: <reason>" in question

    def test_every_first_claim_stands_beside_the_retry_claims_when_kept(self) -> None:
        analyst = _Analyst(["KEEP C1: yes\nKEEP C2: yes\nKEEP C3: yes"])

        first, result = _settle(analyst, FIRST, OTHER)

        claims = [c.claim for c in result.claims]
        assert len(claims) == 4 + 3
        assert all(c.claim in claims for c in first.claims)
        assert [row["state"] for row in _rows(analyst)] == [RETRY_DROP_KEPT] * 3

    def test_unanswered_every_first_claim_stays(self) -> None:
        analyst = _Analyst([TimeoutError("no answer")])

        first, result = _settle(analyst, FIRST, OTHER)

        assert len(result.claims) == 4 + 3
        assert [row["state"] for row in _rows(analyst)] == [RETRY_DROP_NOT_ANSWERED] * 3

    def test_a_withdrawal_the_analyst_writes_stands(self) -> None:
        analyst = _Analyst(["KEEP C1: yes\nWITHDRAW C2: the code was 0xd\nKEEP C3: yes"])

        _first, result = _settle(analyst, FIRST, OTHER)

        claims = [c.claim for c in result.claims]
        assert "The command switch 0x3cf4 runs 0x7170 for code 0xe." not in claims
        assert len(claims) == 4 + 2
        states = [row["state"] for row in _rows(analyst)]
        assert states == [RETRY_DROP_KEPT, RETRY_DROP_WITHDRAWN, RETRY_DROP_KEPT]

    def test_the_run_log_says_why_with_the_drops_code_s_lifecycle(self) -> None:
        from maljan.pipeline.events import VALIDATION_RESOLVED, VALIDATION_RETRIED

        analyst = _Analyst(["KEEP C1: yes\nKEEP C2: yes\nKEEP C3: yes"])

        _settle(analyst, FIRST, OTHER)

        restated = [p for _k, p in analyst.events if p["code"] == RETRY_RESTATED_FEW_CODE]
        assert [p["state"] for p in restated] == [VALIDATION_RETRIED, VALIDATION_RESOLVED]
        assert restated[0]["message"].startswith(
            "The retry restated 0 of the first answer's claims that hold a value and left out "
            "3, so it does not replace the first answer: those 3 claim(s), 0 claim(s) holding "
            "no value that the retry does not write and 0 finding(s) stand beside"
        )
        assert restated[0]["agent"] == "all_tools_reverser_ghidra"
        assert analyst.validation_fed_back[RETRY_RESTATED_FEW_CODE] == 1
        assert analyst.validation_fed_back[RETRY_DROPPED_CODE] == 1

    def test_unanswered_the_code_survives(self) -> None:
        from maljan.pipeline.events import VALIDATION_SURVIVED

        analyst = _Analyst([TimeoutError("no answer")])

        _settle(analyst, FIRST, OTHER)

        states = [p["state"] for _k, p in analyst.events if p["code"] == RETRY_RESTATED_FEW_CODE]
        assert states[-1] == VALIDATION_SURVIVED

    def test_the_loop_record_counts_what_was_restated(self) -> None:
        analyst = _Analyst(["KEEP C1: yes\nKEEP C2: yes\nKEEP C3: yes"])
        analyst._budget_records = [{"loop": 1}]

        _settle(analyst, FIRST, OTHER)

        assert analyst._budget_records[-1]["validation_retry_restated"] == {
            "restated_claims": 0,
            "left_out_claims": 3,
            "plain_claims_asked": 0,
            "left_out_findings": 0,
        }

    def test_a_question_asked_in_parts_states_the_answer_s_totals_in_each(self) -> None:
        from maljan.llm.context_window import ContextBudget, WindowFact
        from maljan.schemas.evidence import LedgerEntry

        # Two claims with values, each citing an entry too large to share a part,
        # and one claim with no value: every part states 0 restated, 2 left out, 1 plain.
        first = (
            _block("Routine 0x1000 builds the first configuration.", evidence="[ev_0081] d")
            + _block("Routine 0x2000 builds the second configuration.", evidence="[ev_0082] d")
            + _block("The sample is a loader.", evidence="[ev_0081] d")
        )
        analyst = _Analyst(["KEEP all: yes", "KEEP all: yes", "KEEP all: yes"])
        analyst._evidence_entries = [
            LedgerEntry(id="ev_0081", tool="batch_decompile", output="A" * 30_000),
            LedgerEntry(id="ev_0082", tool="batch_decompile", output="B" * 30_000),
        ]
        window = WindowFact(16_384 + 45_000 // 3, "probed", "test")
        analyst._container = SimpleNamespace(
            event_sink=lambda kind, payload: analyst.events.append((kind, payload)),
            get_context_budget=lambda: ContextBudget(window),
        )

        _settle(analyst, first, OTHER)

        assert len(analyst.questions) >= 2
        head = (
            "Your retry restated 0 of your first answer's claims that state a value and leaves "
            "out 2, and leaves out 1 that state none, so it does not replace your first answer"
        )
        assert all(question.startswith(head) for question in analyst.questions)


class TestTheCountIsTheRetryDropsIdentity:
    """Restated means ``retry_drops`` does not name it; compared with what was left out."""

    def test_a_retry_that_restates_most_is_asked_about_as_before(self) -> None:
        # Two of three restated (every value stated), one left out.
        retry = (
            _block("Routine 0x3868 exits on error 0xb7, a single-instance check.")
            + _block("Switch 0x3cf4 sends code 0xe to 0x7170.")
            + OTHER
        )
        analyst = _Analyst(["KEEP C1: yes"])

        _settle(analyst, FIRST, retry)

        (question,) = analyst.questions
        assert question.startswith(REPLACED_HEAD)
        assert RESTATED_HEAD not in question
        assert RETRY_RESTATED_FEW_CODE not in _codes(analyst)

    def test_as_many_restated_as_left_out_is_asked_about_as_before(self) -> None:
        first = FIRST + _block("The blob at 0x10250 decodes to the first URL.")
        retry = (
            _block("Routine 0x3868 exits on error 0xb7.")
            + _block("Switch 0x3cf4 sends code 0xe to 0x7170.")
            + OTHER
        )
        analyst = _Analyst(["KEEP C1: yes\nKEEP C2: yes"])

        _settle(analyst, first, retry)

        assert analyst.questions[0].startswith(REPLACED_HEAD)
        assert RETRY_RESTATED_FEW_CODE not in _codes(analyst)

    def test_a_claim_with_no_value_is_counted_neither_way_and_asked_about(self) -> None:
        # Two claims with no value and three with values; the retry restates
        # none. The two are not counted, and are named with the three so the
        # analyst decides on them: none leaves the answer unasked.
        first = _block("The sample is a loader.") + _block("The sample runs as a DLL.") + FIRST
        analyst = _Analyst(["KEEP all: they hold"])

        first_isr, result = _settle(analyst, first, OTHER)

        question = analyst.questions[0]
        assert (
            "restated 0 of your first answer's claims that state a value and leaves out 3, and "
            "leaves out 2 that state none, so it does not replace" in question
        )
        # The event, the log and the loop's record give the same counts.
        restated = [p for _k, p in analyst.events if p["code"] == RETRY_RESTATED_FEW_CODE]
        assert "left out 3, so" in restated[0]["message"]
        assert "2 claim(s) holding no value" in restated[0]["message"]
        assert "C1. CLAIM: The sample is a loader.\n" in question
        assert "C2. CLAIM: The sample runs as a DLL.\n" in question
        assert "it stated , " not in question
        assert len(result.claims) == 4 + 5
        assert all(c in result.claims for c in first_isr.claims)
        rows = _rows(analyst)
        assert [row["state"] for row in rows] == [RETRY_DROP_KEPT] * 5
        assert rows[0]["missing"] == ""

    def test_a_claim_with_no_value_the_retry_writes_again_is_not_asked(self) -> None:
        first = _block("The sample is a loader.") + FIRST
        retry = _block("The sample  is a loader.") + OTHER
        analyst = _Analyst(["KEEP all: they hold"])

        _first, result = _settle(analyst, first, retry)

        assert "The sample is a loader." not in analyst.questions[0]
        assert len(result.claims) == 5 + 3

    def test_a_claim_with_no_value_beside_a_retry_that_restates_most_is_as_before(self) -> None:
        first = _block("The sample is a loader.") + FIRST
        retry = (
            _block("Routine 0x3868 exits on error 0xb7, a single-instance check.")
            + _block("Switch 0x3cf4 sends code 0xe to 0x7170.")
            + OTHER
        )
        analyst = _Analyst(["KEEP C1: yes"])

        _settle(analyst, first, retry)

        assert analyst.questions[0].startswith(REPLACED_HEAD)
        assert "The sample is a loader." not in analyst.questions[0]

    def test_a_claim_left_out_only_by_an_asked_id_is_counted_neither_way(self) -> None:
        # The first claim's only value the retry states nowhere is the id it
        # was asked about: that answered the question, and is not a restatement.
        first = _block("The sample hollows a process via T1055.012.", technique="T9999") + _block(
            "The routine 0x4444 decodes the key."
        )
        analyst = _Analyst(["KEEP C1: yes"])

        _settle_asked(analyst, first, OTHER, ["T9999", "T1055.012"])

        assert RESTATED_HEAD in analyst.questions[0]
        assert (
            "restated 0 of your first answer's claims that state a value and leaves out 1,"
            in (analyst.questions[0])
        )
        assert RETRY_RESTATED_FEW_CODE in _codes(analyst)

    def test_a_claim_restated_by_its_values_beside_one_left_out_is_as_before(self) -> None:
        first = _block("Hollowing at 0x5555 via T1055.012.") + _block(
            "The routine 0x4444 decodes the key."
        )
        retry = _block("Hollowing at 0x5555 via T1055.012.") + OTHER
        analyst = _Analyst(["KEEP C1: yes"])

        _settle_asked(analyst, first, retry, ["T9999"])

        assert analyst.questions[0].startswith(REPLACED_HEAD)
        assert RETRY_RESTATED_FEW_CODE not in _codes(analyst)

    def test_a_claim_set_aside_is_not_counted_as_restated(self) -> None:
        analyst = _Analyst(["KEEP C1: yes\nKEEP C2: yes"])
        first = analyst._text_to_isr(FIRST + _block("The blob at 0x10250 is a URL."), 0)
        # One restated, one set aside (withdrawn by the retry), two left out.
        retry_text = _block("Routine 0x3868 exits on error 0xb7.") + OTHER
        retried = analyst._text_to_isr(retry_text, 0)

        analyst._settle_retry_drops(
            first,
            retried,
            retry_text,
            [],
            [HumanMessage(content="evidence")],
            None,
            set_aside=[first.claims[3]],
        )

        assert RESTATED_HEAD in analyst.questions[0]
        assert (
            "restated 1 of your first answer's claims that state a value and leaves out 2,"
            in (analyst.questions[0])
        )

    def test_findings_left_out_are_named_with_the_claims(self) -> None:
        analyst = _Analyst(["KEEP C1: yes"])
        first = analyst._text_to_isr(FIRST, 0)
        first.findings = [
            SimpleNamespace(title="Mutex runnung", detail="", evidence_ids=["ev_0080"])
        ]
        retried = analyst._text_to_isr(OTHER, 0)

        drops = retry_drops(first, retried, OTHER)
        question = retry_restated_few_question(drops, restated=0)

        assert "F1. FINDING: Mutex runnung" in question
        assert "    EVIDENCE: ev_0080" in question


class TestTheWholeTurn:
    """Through the validation turn: an unread block asks for a whole answer, as on haiku6."""

    FIRST = FIRST + (
        "CLAIM: The beacon loop sleeps between requests.\nEVIDENCE: [ev_0080] decompile\n"
        "CONFIDENCE: NONE\nTECHNIQUE: NONE\n---\n"
    )

    def test_the_kept_whole_retry_does_not_replace_the_first_answer(self) -> None:
        reply = "KEEP C1: the decompile shows it\nKEEP C2: yes\nKEEP C3: yes"
        analyst = _Analyst([OTHER, reply])
        isr = analyst._text_to_isr(self.FIRST, 0)

        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            result = analyst._validate_isr(isr, "evidence")

        retry_question, drops_question = analyst.questions
        assert "write your whole answer again" in retry_question
        assert RESTATED_HEAD in drops_question
        claims = [c.claim for c in result.claims]
        assert "Routine 0x3868 exits when GetLastError returns 0xb7." in claims
        assert "The sample is an AMD64 DLL of 60,928 bytes." in claims
        assert len(claims) == 4 + 3
        assert RETRY_RESTATED_FEW_CODE in _codes(analyst)


class TestThePathsThatAreNotAskedAbout:
    """A whole answer asked for because the first was cut or repeated is not asked about again.

    The count never runs there, so a whole answer that restates none of the cut
    or repeating one stands as it did; a claim the library-only question asked
    to fold away is never put back by it.
    """

    @staticmethod
    def _validate(analyst: _Analyst, first: str) -> AgentISR:
        isr = analyst._text_to_isr(first, 0)
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            return analyst._validate_isr(isr, "evidence")

    def test_a_whole_answer_to_a_cut_one_stands_unasked(self) -> None:
        cap = 4096
        first = FIRST + "CLAIM: The beacon loop sle"
        analyst = _Analyst([OTHER])
        isr = analyst._text_to_isr(first, 0)
        with (
            patch("maljan.agents.base_agent.analyst_output_cap", return_value=cap),
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            analyst._record_usage(
                AIMessage(
                    content=first,
                    usage_metadata={
                        "input_tokens": 900,
                        "output_tokens": cap,
                        "total_tokens": 900 + cap,
                    },
                )
            )
            result = analyst._validate_isr(isr, "evidence")

        assert len(analyst.questions) == 1
        assert [c.claim for c in result.claims] == [
            c.claim for c in analyst._text_to_isr(OTHER, 0).claims
        ]
        assert RETRY_RESTATED_FEW_CODE not in analyst.validation_fed_back
        assert RETRY_RESTATED_FEW_CODE not in _codes(analyst)

    def test_a_whole_answer_to_a_repeating_one_stands_unasked(self) -> None:
        def _numbered(n: int, sentence: str) -> str:
            return _block(sentence).replace("CLAIM:", f"CLAIM {n}:")

        sentences = [
            "Routine 0x3868 exits when GetLastError returns 0xb7.",
            "The command switch 0x3cf4 runs 0x7170 for code 0xe.",
            "The string at 0xf920 decodes to `Update_%x`.",
        ]
        runaway = FIRST + "".join(
            _numbered(n + 3 * k, sentences[n - 1]) for k in range(1, 5) for n in (1, 2, 3)
        )
        analyst = _Analyst([OTHER])

        result = self._validate(analyst, runaway)

        assert len(analyst.questions) == 1
        assert len(result.claims) == 4
        assert RETRY_RESTATED_FEW_CODE not in _codes(analyst)

    def test_library_only_claims_folded_away_are_not_put_back(self) -> None:
        behaviour = _block(
            "The sample exits when event `Global\\Mtx` exists.", evidence="[ev_0005]"
        )
        libraries = "".join(
            _block(f"The sample uses `kernel32.dll` APIs for {purpose}.", evidence="[ev_0002]")
            for purpose in ("event handling", "console output", "timer control")
        )
        retry = _block("The sample checks a named event 0x10 at start.", evidence="[ev_0005]")
        analyst = _Analyst([retry, retry, "KEEP C1: it holds"])
        analyst.pack_ledger_ids = ["ev_0002", "ev_0005"]

        result = self._validate(analyst, behaviour + libraries)

        drops_question = analyst.questions[-1]
        assert RESTATED_HEAD in drops_question
        assert "Global\\Mtx" in drops_question
        assert "kernel32.dll" not in drops_question
        claims = [c.claim for c in result.claims]
        assert not any("kernel32.dll" in c for c in claims)
        assert "The sample exits when event `Global\\Mtx` exists." in claims
