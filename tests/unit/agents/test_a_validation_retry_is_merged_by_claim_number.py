"""An analyst's validation retry is merged into the answer it fixes, by claim number.

The retry is asked to write again only the claims it changes, under their
numbers, and to withdraw a claim with a ``WITHDRAW CLAIM`` line. What it does
not write again stays as the first answer wrote it and is not a drop: the
drops question is put only about a claim the retry was asked to fix and
neither wrote again nor withdrew. A retry whose numbers do not decide which
claim is which is read as the analyst's whole answer, as before, with the
reason on the loop's record.

Every sentence and value here is made up for the test.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import (
    ANALYST_FEEDBACK_CLOSING,
    ANALYST_FEEDBACK_CLOSING_BY_NUMBER,
    RETRY_DROP_KEPT,
    RETRY_DROP_WITHDRAWN,
    RETRY_DROPPED_CODE,
    validation_metrics,
)
from maljan.schemas.isr_models import AgentISR


def _block(n: int, technique: str, number: int | None = None, cites: str = "ev_0001") -> str:
    head = "CLAIM:" if number is None else f"CLAIM {number}:"
    return (
        f"{head} The file carries configuration string number {n}.\n"
        f"EVIDENCE: [{cites}] strings\n"
        "CONFIDENCE: 0.8\n"
        f"TECHNIQUE: {technique}\n"
        "---\n"
    )


# 32 claim blocks; the first is asked about, nine list two ids: 41 claims.
FIRST = _block(1, "T1055 or T1106") + "".join(
    _block(n, "T1027, T1140" if n <= 10 else "T1027") for n in range(2, 33)
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[Any]) -> None:
        super().__init__(llm=MagicMock(), name="all_tools_static_r2")
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.questions: list[str] = []
        self._budget_records = [{"agent": "all_tools_static_r2"}]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.questions.append(str(messages[-1].content))
        reply = self._replies.pop(0)
        self._record_usage(AIMessage(content=reply))
        return reply


def _check(analyst: _Analyst, first: str = FIRST) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


def _drop_rows(analyst: _Analyst) -> list[dict[str, str]]:
    return [row for row in analyst.drain_unparsed_answers() if row.get("record") == "retry_drop"]


class TestTheRetryChangesOnlyWhatItWrites:
    def test_the_question_asks_for_the_claims_changed_by_number(self) -> None:
        analyst = _Analyst([_block(1, "T1055", number=1)])

        _check(analyst)

        assert analyst.questions[0].rstrip().endswith(ANALYST_FEEDBACK_CLOSING_BY_NUMBER)

    def test_a_retry_fixing_the_one_claim_asked_about_keeps_every_other(self) -> None:
        analyst = _Analyst([_block(1, "T1055", number=1)])

        result = _check(analyst)

        assert len(analyst.questions) == 1
        assert len(result.claims) == 41
        assert result.claims[0].technique_id == "T1055"
        assert [c.technique_id for c in result.claims[1:3]] == ["T1027", "T1140"]
        assert _drop_rows(analyst) == []
        assert RETRY_DROPPED_CODE not in analyst.validation_fed_back

    def test_the_loop_s_record_says_what_the_merge_did(self) -> None:
        analyst = _Analyst([_block(1, "T1055", number=1)])

        _check(analyst)

        record = analyst._budget_records[-1]["validation_retry"]
        assert record["kept"] == "merged"
        assert record["merge"] == {
            "merged": True,
            "replaced": ["1"],
            "added": [],
            "unchanged_blocks": 31,
            "withdrawn_claims": 0,
            "findings_replaced": 0,
            "withdrawn_findings": 0,
            "findings_added": 0,
            "unplaced": 0,
        }

    def test_a_withdrawn_claim_is_out_with_no_question(self) -> None:
        analyst = _Analyst(["WITHDRAW CLAIM 1: the id is a guess.\n"])

        result = _check(analyst)

        assert len(analyst.questions) == 1
        assert len(result.claims) == 40
        assert "number 1." not in " ".join(c.claim for c in result.claims)
        assert _drop_rows(analyst) == []


# Claim 3 cites an entry this run does not have: its technique is asked about
# by the claim's path.
UNGROUNDED = _block(1, "T1027") + _block(2, "T1027") + _block(3, "T1027", cites="ev_0099")


class TestAClaimAskedAboutAndLeftIsAskedOnce:
    def test_kept_when_asked_it_stays_and_is_recorded(self) -> None:
        retry = _block(2, "T1027", number=2)
        analyst = _Analyst([retry, "KEEP C1: the entry holds it"])

        result = _check(analyst, UNGROUNDED)

        retry_question, left_question = analyst.questions
        assert "isr.ungrounded_technique" in retry_question
        assert "C1. CLAIM 3: The file carries configuration string number 3." in left_question
        assert "C2." not in left_question
        assert [c.claim[-2:] for c in result.claims] == ["1.", "2.", "3."]
        (row,) = _drop_rows(analyst)
        assert row["state"] == RETRY_DROP_KEPT and row["reason"] == "the entry holds it"
        assert analyst.validation_fed_back[RETRY_DROPPED_CODE] == 1
        assert "isr.ungrounded_technique" in {v.code for v in analyst.validation_findings}

    def test_withdrawn_when_asked_it_is_out_and_recorded(self) -> None:
        retry = _block(2, "T1027", number=2)
        analyst = _Analyst([retry, "WITHDRAW C1: no entry holds it"])

        result = _check(analyst, UNGROUNDED)

        assert [c.claim[-2:] for c in result.claims] == ["1.", "2."]
        (row,) = _drop_rows(analyst)
        assert row["state"] == RETRY_DROP_WITHDRAWN

    def test_a_claim_fixed_under_its_number_is_not_asked_about(self) -> None:
        analyst = _Analyst([_block(3, "T1027", number=3)])

        result = _check(analyst, UNGROUNDED)

        assert len(analyst.questions) == 1
        assert result.claims[2].evidence_ref == "[ev_0001] strings"
        assert _drop_rows(analyst) == []

    def test_the_rows_reach_the_run_summary_in_their_shape(self) -> None:
        analyst = _Analyst([_block(2, "T1027", number=2), "KEEP C1: the entry holds it"])
        _check(analyst, UNGROUNDED)

        metrics = validation_metrics(1, [], unparsed_answers=analyst.drain_unparsed_answers())

        (row,) = metrics["retry_drops"]
        assert set(row) == {
            "agent",
            "round",
            "kind",
            "item",
            "missing",
            "state",
            "reason",
            "merged",
            "sentence",
        }
        assert row["merged"] == "true"
        assert (
            "merged validation retry neither wrote again nor withdrew the claim"
            in (row["sentence"])
        )


class TestARetryTheNumbersDoNotPlace:
    def test_a_retry_written_whole_without_numbers_is_read_as_before(self) -> None:
        retry = _block(1, "T1055") + "".join(_block(n, "T1027") for n in range(2, 33))
        reply = "\n".join(f"KEEP C{n}: it holds" for n in range(1, 10))
        analyst = _Analyst([retry, reply])

        result = _check(analyst)

        assert len(analyst.questions) == 2
        assert len(result.claims) == 32 + 9
        assert len(_drop_rows(analyst)) == 9
        record = analyst._budget_records[-1]["validation_retry"]
        assert record["kept"] == "retry"
        assert record["merge"] == {
            "merged": False,
            "why": "the retry wrote a claim block without its number",
            "withdrawn_claims": 0,
            "withdrawn_findings": 0,
            "whole_answer_asked": False,
        }

    def test_an_answer_asked_for_whole_is_asked_as_before(self) -> None:
        analyst = _Analyst([FIRST])
        isr = analyst._text_to_isr(FIRST, 0)
        analyst._last_answer_cut = (4096, FIRST)
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            analyst._validate_isr(isr, "evidence")

        assert analyst.questions[0].rstrip().endswith(ANALYST_FEEDBACK_CLOSING)
        assert "merge" not in analyst._budget_records[-1].get("validation_retry", {})

    def test_a_first_answer_numbered_out_of_order_is_asked_for_a_whole_answer(self) -> None:
        first = _block(1, "T1055 or T1106", number=1) + _block(2, "T1027", number=5)
        analyst = _Analyst([first])

        _check(analyst, first)

        assert analyst.questions[0].rstrip().endswith(ANALYST_FEEDBACK_CLOSING)


def _fenced(*titles: str) -> str:
    """A findings block carrying one finding per title."""
    import json

    body = json.dumps({"findings": [{"title": t, "technique_ids": ["T1027"]} for t in titles]})
    return f"```maljan-findings\n{body}\n```"


def _check_written(analyst: _Analyst, text: str) -> AgentISR:
    """An answer read as the loop reads one: its findings block and its claims."""
    isr = analyst._text_to_isr(analyst._capture_findings(text), 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


def _withdrawn_rows(analyst: _Analyst) -> list[dict[str, str]]:
    rows = analyst.drain_unparsed_answers()
    return [row for row in rows if row.get("record") == "retry_withdrawn"]


# The first block lists two techniques; the third cites an entry this run does
# not have, and its flag's path names it as block 2.
TWO_FIRST = _block(1, "T1027, T1140") + _block(2, "T1027") + _block(3, "T1027", cites="ev_0099")


class TestTheFlaggedBlockIsTheOneAsked:
    def test_after_a_block_of_two_techniques_the_fix_of_the_flagged_block_stands(self) -> None:
        analyst = _Analyst([_block(3, "T1027", number=3)])

        result = _check(analyst, TWO_FIRST)

        assert len(analyst.questions) == 1
        assert "claims[2]" in analyst.questions[0]
        assert [c.evidence_ref for c in result.claims] == ["[ev_0001] strings"] * 4
        assert _drop_rows(analyst) == []

    def test_after_a_block_of_two_techniques_the_flagged_block_left_is_the_one_asked(
        self,
    ) -> None:
        added = _block(4, "T1027", number=4)
        analyst = _Analyst([added, "KEEP C1: the entry holds it"])

        result = _check(analyst, TWO_FIRST)

        assert len(analyst.questions) == 2
        assert (
            "C1. CLAIM 3: The file carries configuration string number 3." in (analyst.questions[1])
        )
        assert "C2." not in analyst.questions[1]
        assert len(result.claims) == 5


class TestARetryNotPlacedAsksForTheWholeAnswer:
    def test_a_one_claim_retry_numbered_from_one_is_asked_for_the_whole_answer(self) -> None:
        from maljan.pipeline.validation import WHOLE_ANSWER_AFTER_RETRY_LEAD

        partial = (
            "CLAIM 1: The packed section is read from disk only.\n"
            "EVIDENCE: [ev_0001] strings\nCONFIDENCE: 0.8\nTECHNIQUE: T1027\n"
        )
        whole = _block(1, "T1027") + _block(2, "T1027") + _block(3, "T1027")
        analyst = _Analyst([partial, whole])

        result = _check(analyst, UNGROUNDED)

        assert len(analyst.questions) == 2
        assert analyst.questions[1].startswith(WHOLE_ANSWER_AFTER_RETRY_LEAD)
        assert analyst.questions[1].rstrip().endswith(ANALYST_FEEDBACK_CLOSING)
        assert [c.evidence_ref for c in result.claims] == ["[ev_0001] strings"] * 3
        record = analyst._budget_records[-1]["validation_retry"]
        assert record["merge"]["whole_answer_asked"] is True
        assert "claim 1, which no question was about" in record["merge"]["why"]

    def test_withdrawals_stand_when_the_whole_answer_is_not_given(self) -> None:
        partial = (
            "CLAIM: The file carries configuration string number 3.\n"
            "EVIDENCE: [ev_0001] strings\nCONFIDENCE: 0.8\nTECHNIQUE: T1027\n"
            "---\n"
            "WITHDRAW CLAIM 2: it repeats claim 1.\n"
        )
        analyst = _Analyst([partial])

        result = _check(analyst, UNGROUNDED)

        assert [c.claim[-2:] for c in result.claims] == ["1.", "3."]
        (row,) = _withdrawn_rows(analyst)
        assert row["reason"] == "it repeats claim 1."
        assert "withdrew the claim" in row["sentence"]

    def test_a_retry_written_whole_without_numbers_keeps_its_withdrawal_unasked(self) -> None:
        whole = (
            _block(1, "T1027")
            + _block(3, "T1027")
            + _block(4, "T1027")
            + "WITHDRAW CLAIM 2: it repeats claim 1.\n"
        )
        analyst = _Analyst([whole])

        result = _check(analyst, UNGROUNDED)

        # Read whole as written, and the claim it withdrew is not put back to
        # it as one it left out.
        assert len(analyst.questions) == 1
        assert [c.claim[-2:] for c in result.claims] == ["1.", "3.", "4."]
        assert len(_withdrawn_rows(analyst)) == 1
        record = analyst._budget_records[-1]["validation_retry"]
        assert record["merge"]["whole_answer_asked"] is False


class TestWithdrawalsAreRecorded:
    def test_a_range_written_in_lower_case_withdraws_each_block_with_its_reason(self) -> None:
        analyst = _Analyst(["withdraw claims 2-3 - the decoder claim covers them\n"])

        result = _check(analyst, UNGROUNDED)

        assert [c.claim[-2:] for c in result.claims] == ["1."]
        rows = _withdrawn_rows(analyst)
        assert [row["reason"] for row in rows] == ["the decoder claim covers them"] * 2

    def test_the_rows_reach_the_run_summary_and_section_13(self) -> None:
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        analyst = _Analyst(["WITHDRAW CLAIM 3: no entry holds it.\n"])
        _check(analyst, UNGROUNDED)
        metrics = validation_metrics(1, [], unparsed_answers=analyst.drain_unparsed_answers())
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            run_summary={"validation": metrics},
        )

        markdown = MarkdownRenderer().render(report)

        (row,) = metrics["retry_withdrawals"]
        assert "record" not in row
        assert "**Items a validation retry withdrew:**" in markdown
        assert "(no entry holds it.)" in markdown


class TestWhatTheMergeLeavesAlone:
    def test_a_revision_round_answer_keeps_its_disputes(self) -> None:
        analyst = _Analyst([_block(3, "T1027", number=3)])
        isr = analyst._text_to_isr(UNGROUNDED, 1)
        isr.dissent_items = ["The dynamic analyst's string 4 is not in its capture."]
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            result = analyst._validate_isr(isr, "evidence")

        assert result.dissent_items == ["The dynamic analyst's string 4 is not in its capture."]
        assert result.revision_round == 1

    def test_a_renamed_finding_is_asked_about_once(self) -> None:
        first = f"{UNGROUNDED}\n{_fenced('Strings XOR-encrypted', 'Mutex guard')}"
        retry = f"{_block(3, 'T1027', number=3)}\n{_fenced('Strings encrypted at rest')}"
        analyst = _Analyst([retry, "WITHDRAW F1: renamed\nKEEP F2: it stands"])

        result = _check_written(analyst, first)

        assert len(analyst.questions) == 2
        assert "F1. FINDING: Strings XOR-encrypted" in analyst.questions[1]
        assert [f.title for f in result.findings] == ["Mutex guard", "Strings encrypted at rest"]
        rows = _drop_rows(analyst)
        assert [(row["kind"], row["state"]) for row in rows] == [
            ("finding", RETRY_DROP_WITHDRAWN),
            ("finding", RETRY_DROP_KEPT),
        ]


# A retry the numbers do not place (claim 2 written twice) that withdraws
# claim 3: the whole answer is asked for.
DOUBTED = (
    _block(2, "T1027", number=2)
    + _block(2, "T1027", number=2)
    + "WITHDRAW CLAIM 3: no entry holds it.\n"
)


class TestTheRecordNeverContradictsTheAnswer:
    def test_a_whole_answer_that_writes_the_withdrawn_claim_again_records_no_withdrawal(
        self,
    ) -> None:
        whole = _block(1, "T1027") + _block(2, "T1027") + _block(3, "T1027")
        analyst = _Analyst([DOUBTED, whole])

        result = _check(analyst, UNGROUNDED)

        assert len(analyst.questions) == 2
        assert [c.claim[-2:] for c in result.claims] == ["1.", "2.", "3."]
        assert _withdrawn_rows(analyst) == []

    def test_a_whole_answer_that_leaves_the_withdrawn_claim_out_records_it(self) -> None:
        whole = _block(1, "T1027") + _block(2, "T1027") + _block(4, "T1027")
        analyst = _Analyst([DOUBTED, whole])

        result = _check(analyst, UNGROUNDED)

        assert len(analyst.questions) == 2
        assert [c.claim[-2:] for c in result.claims] == ["1.", "2.", "4."]
        (row,) = _withdrawn_rows(analyst)
        assert row["reason"] == "no entry holds it."

    def test_a_retry_read_whole_that_writes_a_claim_and_withdraws_it_asks_for_the_whole_answer(
        self,
    ) -> None:
        from maljan.pipeline.validation import WHOLE_ANSWER_AFTER_RETRY_LEAD

        both = (
            _block(1, "T1027")
            + _block(2, "T1027")
            + _block(3, "T1027")
            + "WITHDRAW CLAIM 3: no entry holds it.\n"
        )
        whole = _block(1, "T1027") + _block(2, "T1027") + _block(4, "T1027")
        analyst = _Analyst([both, whole])

        result = _check(analyst, UNGROUNDED)

        assert len(analyst.questions) == 2
        assert analyst.questions[1].startswith(WHOLE_ANSWER_AFTER_RETRY_LEAD)
        assert [c.claim[-2:] for c in result.claims] == ["1.", "2.", "4."]
        (row,) = _withdrawn_rows(analyst)
        assert row["reason"] == "no entry holds it."
        record = analyst._budget_records[-1]["validation_retry"]
        assert record["merge"]["whole_answer_asked"] is True
        assert record["merge"]["why"].startswith("the retry both wrote again and withdrew")

    def test_a_withdrawn_claim_with_no_value_the_whole_answer_leaves_out_is_recorded(
        self,
    ) -> None:
        plain = (
            "CLAIM: The file carries plain configuration strings.\n"
            "EVIDENCE: [ev_0001] strings\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
        )
        first = plain + _block(2, "T1027") + _block(3, "T1027", cites="ev_0099")
        doubted = (
            _block(2, "T1027", number=2)
            + _block(2, "T1027", number=2)
            + "WITHDRAW CLAIM 1: it says nothing the others do not.\n"
        )
        whole = _block(2, "T1027") + _block(3, "T1027") + _block(4, "T1027")
        analyst = _Analyst([doubted, whole])

        result = _check(analyst, first)

        assert all("plain" not in c.claim for c in result.claims)
        (row,) = _withdrawn_rows(analyst)
        assert row["reason"] == "it says nothing the others do not."
