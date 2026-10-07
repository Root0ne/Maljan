"""What a kept validation retry left out of the first answer is put to the analyst once.

A local run kept a static analyst's retry that read 32 claims against the
first answer's 41, and a dynamic analyst's retry that carried none of the
first answer's 6 findings; neither loss was recorded anywhere. The platform
now states which claims (by the values the retry states nowhere, the
technique ids it was asked about aside) and which findings (by title) the
kept retry left out, per analyst, and asks the analyst once to keep or
withdraw each with a reason. Its answer stands: a kept item goes back into
the answer as the first answer wrote it, a withdrawn one stays out. With no
answer, the first answer's items stay, their state said. Every item is
recorded in ``run_summary.validation.retry_drops``.

The two cases are replayed here with synthetic answers of the same shape.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import (
    RETRY_DROP_KEPT,
    RETRY_DROP_NOT_ANSWERED,
    RETRY_DROP_WITHDRAWN,
    RETRY_DROPPED_CODE,
    read_retry_drop_answers,
    retry_drop_question,
    retry_drops,
    validation_metrics,
)
from maljan.schemas.isr_models import AgentISR, Finding


def _block(n: int, technique: str) -> str:
    return (
        f"CLAIM: The file carries configuration string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\n"
        "CONFIDENCE: 0.8\n"
        f"TECHNIQUE: {technique}\n"
        "---\n"
    )


# 32 claim blocks; the first is asked about, nine list two ids: 41 claims.
FIRST = _block(1, "T1055 or T1106") + "".join(
    _block(n, "T1027, T1140" if n <= 10 else "T1027") for n in range(2, 33)
)
# The retry answers the question and writes each block with one id: 32 claims.
RETRY = _block(1, "T1055") + "".join(_block(n, "T1027") for n in range(2, 33))


class _Analyst(BaseAnalyst):
    def __init__(self, name: str, replies: list[Any]) -> None:
        super().__init__(llm=MagicMock(), name=name)
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.questions: list[str] = []

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


def _check(analyst: _Analyst, first: str) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


def _drop_rows(analyst: _Analyst) -> list[dict[str, str]]:
    return [row for row in analyst.drain_unparsed_answers() if row.get("record") == "retry_drop"]


class TestTheStaticReplay:
    """41 claims, a kept retry of 32: nine claims no longer stated."""

    REPLY = "\n".join(
        [*(f"KEEP C{n}: the routine decodes it" for n in range(1, 6))]
        + [*(f"WITHDRAW C{n}: the id was a guess" for n in range(6, 10))]
    )

    def test_the_first_answer_has_41_claims_and_the_retry_32(self) -> None:
        analyst = _Analyst("all_tools_static_r2", [])

        assert len(analyst._text_to_isr(FIRST, 0).claims) == 41
        assert len(analyst._text_to_isr(RETRY, 0).claims) == 32

    def test_the_nine_left_out_are_named_once_and_the_answer_stands(self) -> None:
        analyst = _Analyst("all_tools_static_r2", [RETRY, self.REPLY])

        result = _check(analyst, FIRST)

        retry_question, drops_question = analyst.questions
        assert "C9. CLAIM: The file carries configuration string number 10." in drops_question
        assert "C10." not in drops_question
        assert "it stated T1140, which your retry states nowhere" in drops_question
        assert len(result.claims) == 32 + 5
        rows = _drop_rows(analyst)
        assert [row["state"] for row in rows] == [RETRY_DROP_KEPT] * 5 + [RETRY_DROP_WITHDRAWN] * 4
        assert rows[0]["reason"] == "the routine decodes it"
        assert rows[0]["missing"] == "T1140"
        assert "left out the claim" in rows[0]["sentence"]
        assert analyst.validation_fed_back[RETRY_DROPPED_CODE] == 1

    def test_the_rows_reach_the_run_summary(self) -> None:
        analyst = _Analyst("all_tools_static_r2", [RETRY, self.REPLY])
        _check(analyst, FIRST)

        metrics = validation_metrics(1, [], unparsed_answers=analyst.drain_unparsed_answers())

        assert len(metrics["retry_drops"]) == 9
        assert all("record" not in row for row in metrics["retry_drops"])


class TestTheDynamicReplay:
    """23 claims kept, the first answer's 6 findings carried by no retry finding."""

    FIRST = _block(1, "T1055 or T1106") + "".join(_block(n, "T1027") for n in range(2, 24))
    RETRY = _block(1, "T1055") + "".join(_block(n, "T1027") for n in range(2, 24))

    def _findings(self) -> list[Finding]:
        return [
            Finding(title=f"The sample writes cache file {n}", evidence_ids=["ev_0001"])
            for n in range(1, 7)
        ]

    def test_an_unanswered_question_keeps_the_six_findings_with_their_state(self) -> None:
        analyst = _Analyst("dynamic", [self.RETRY, TimeoutError("no answer")])
        analyst._findings_buffer = self._findings()

        result = _check(analyst, self.FIRST)

        assert len(result.claims) == 23
        assert [f.title for f in result.findings] == [f.title for f in self._findings()]
        rows = _drop_rows(analyst)
        assert [row["kind"] for row in rows] == ["finding"] * 6
        assert {row["state"] for row in rows} == {RETRY_DROP_NOT_ANSWERED}

    def test_withdrawn_findings_stay_out(self) -> None:
        reply = "\n".join(f"- **WITHDRAW F{n}** - a guest file" for n in range(1, 7))
        analyst = _Analyst("dynamic", [self.RETRY, reply])
        analyst._findings_buffer = self._findings()

        result = _check(analyst, self.FIRST)

        assert result.findings == []
        assert {row["reason"] for row in _drop_rows(analyst)} == {"a guest file"}


class TestTheParts:
    def test_an_id_the_retry_was_asked_about_is_no_loss(self) -> None:
        analyst = _Analyst("static", [])
        first, retried = analyst._text_to_isr(FIRST, 0), analyst._text_to_isr(RETRY, 0)

        assert len(retry_drops(first, retried, RETRY).claims) == 9
        assert not retry_drops(first, retried, RETRY, asked_about=["T1140"])

    def test_a_retry_that_states_everything_leaves_nothing_to_ask(self) -> None:
        analyst = _Analyst("static", [_block(1, "T1055") + FIRST.split("---\n", 1)[1]])

        _check(analyst, FIRST)

        assert len(analyst.questions) == 1
        assert _drop_rows(analyst) == []

    def test_only_named_labels_are_read_and_each_once(self) -> None:
        text = "KEEP C1: yes\nKEEP C1: again\nWITHDRAW C7: no\nkeep f1\nsome prose"

        assert read_retry_drop_answers(text, ["C1", "F1"]) == {
            "C1": ("KEEP", "yes"),
            "F1": ("KEEP", ""),
        }

    def test_the_question_says_what_to_write(self) -> None:
        analyst = _Analyst("static", [])
        drops = retry_drops(analyst._text_to_isr(FIRST, 0), analyst._text_to_isr(RETRY, 0))

        question = retry_drop_question(drops)
        assert question.startswith("Your retry stands as your answer")
        assert "KEEP <label>: <reason>" in question
        assert "WITHDRAW <label>: <reason>" in question


def test_section_13_lists_each_item_with_its_state() -> None:
    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    analyst = _Analyst("all_tools_static_r2", [RETRY, TestTheStaticReplay.REPLY])
    _check(analyst, FIRST)
    metrics = validation_metrics(1, [], unparsed_answers=analyst.drain_unparsed_answers())
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"validation": metrics},
    )

    markdown = MarkdownRenderer().render(report)

    assert "**Items a kept validation retry left out:**" in markdown
    assert markdown.count(f": {RETRY_DROP_WITHDRAWN} (the id was a guess).") == 4


class TestTheExactClaimComesBack:
    """A list split on commas gives claims one sentence; the one left out is the one put back."""

    def test_keeping_a_dropped_t1140_brings_back_t1140(self) -> None:
        reply = "\n".join(f"KEEP C{n}: the routine decodes it" for n in range(1, 10))
        analyst = _Analyst("all_tools_static_r2", [RETRY, reply])
        first = analyst._text_to_isr(FIRST, 0)

        result = _check(analyst, FIRST)

        ids = [c.technique_id for c in result.claims]
        assert ids.count("T1140") == [c.technique_id for c in first.claims].count("T1140") == 9
        assert ids.count("T1027") == 31
        assert len(result.claims) == 41

    def test_the_question_names_each_claim_s_own_technique(self) -> None:
        analyst = _Analyst("static", [RETRY, "WITHDRAW C1, C2, C3, C4, C5, C6, C7, C8, C9: no"])

        result = _check(analyst, FIRST)

        _retry, question = analyst.questions
        assert question.count("TECHNIQUE T1140 (it stated T1140") == 9
        assert [c.technique_id for c in result.claims].count("T1140") == 0


class TestTheAnswerForms:
    def test_a_comma_list_and_a_because_and_a_dash_are_read(self) -> None:
        text = "KEEP C1, C2 and F1: both decode it\nWITHDRAW C3 because it was a guess\nKEEP C4 - x"

        assert read_retry_drop_answers(text, ["C1", "C2", "C3", "C4", "F1"]) == {
            "C1": ("KEEP", "both decode it"),
            "C2": ("KEEP", "both decode it"),
            "F1": ("KEEP", "both decode it"),
            "C3": ("WITHDRAW", "it was a guess"),
            "C4": ("KEEP", "x"),
        }


def test_the_question_and_its_outcome_are_events() -> None:
    sent: list[tuple[str, dict[str, Any]]] = []
    analyst = _Analyst("all_tools_static_r2", [RETRY, TestTheStaticReplay.REPLY])
    analyst._container = MagicMock(event_sink=lambda kind, data: sent.append((kind, data)))

    _check(analyst, FIRST)

    asked = [d for k, d in sent if k == "validation_feedback" and d["code"] == RETRY_DROPPED_CODE]
    assert [d["state"] for d in asked] == ["retried", "resolved"]
    assert "9 claim(s) and 0 finding(s)" in asked[0]["message"]


class TestNothingUnmaskedInTheRecord:
    def _secrets(self, monkeypatch: Any) -> tuple[str, str]:
        from maljan.pipeline import events
        from maljan.pipeline.events import remember_secret_values
        from tests.credential_shapes import lowercase_body, password

        monkeypatch.setattr(events, "_SECRET_SCOPES", {})
        monkeypatch.setattr(events, "_SHORT_SECRETS", {})
        monkeypatch.setattr(events, "_FAILED_SCOPES", set())
        monkeypatch.setattr(events, "_CONFIGURED_PATTERN", None)
        key = lowercase_body(8).upper() + lowercase_body(12)
        remember_secret_values([key], scope="job")
        return key, password(12)

    def test_a_configured_value_and_url_userinfo_are_masked_everywhere(
        self, monkeypatch: Any, caplog: Any
    ) -> None:
        import logging

        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        key, secret = self._secrets(monkeypatch)
        url = f"http://admin:{secret}@evil.example.org/gate"
        dropped = f'CLAIM: The sample sends the key "{key}" to "{url}".\n'
        first = FIRST + dropped + "EVIDENCE: [ev_0001] strings\nCONFIDENCE: 0.7\nTECHNIQUE: NONE\n"
        retry = RETRY + (
            "CLAIM: The sample sends a key to its server.\nEVIDENCE: [ev_0001] strings\n"
            "CONFIDENCE: 0.7\nTECHNIQUE: NONE\n"
        )
        analyst = _Analyst("network", [retry, "KEEP C10: it is in the capture"])
        caplog.set_level(logging.DEBUG)

        _check(analyst, first)
        rows = analyst.drain_unparsed_answers()
        metrics = validation_metrics(1, [], unparsed_answers=rows)
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            run_summary={"validation": metrics},
        )
        from maljan.analysis.run_summary import RunSummaryBuilder

        summary = RunSummaryBuilder(start_time=0.0).set_validation(metrics).build()
        surfaces = {
            "record": repr(metrics["retry_drops"]),
            "run summary": repr(summary.to_dict()["validation"]) + summary.to_markdown(),
            "section 13": MarkdownRenderer().render(report),
            "log": caplog.text,
            "question": analyst.questions[-1],
        }
        for name, text in surfaces.items():
            for value in (key, key.lower(), secret, secret.lower()):
                assert value not in text, (name, value)
        row = next(r for r in metrics["retry_drops"] if "evil" in r["sentence"])
        assert "evil[.]example[.]org" in row["sentence"]


def test_a_url_is_masked_then_defanged_whole() -> None:
    from maljan.pipeline.validation import retry_drop_row

    text = 'The sample beacons to "https://relay.example.net/live/" every 60 s.'
    row = retry_drop_row(
        "network", 0, "claim", text, ("https://relay.example.net/live/",), RETRY_DROP_KEPT, ""
    )

    # The host whole and defanged; the path as the record's mask writes a URL.
    assert '"The sample beacons to "hxxps://relay[.]example[.]net/' in row["sentence"]
    assert "https://relay" not in row["sentence"]
    assert "relay[…" not in row["sentence"]


class TestSeveralDecisionsOnALine:
    LABELS = ["C1", "C2", "C3", "F1"]

    def test_two_decisions_with_reasons(self) -> None:
        assert read_retry_drop_answers("KEEP C1: yes; WITHDRAW C2: no", self.LABELS) == {
            "C1": ("KEEP", "yes"),
            "C2": ("WITHDRAW", "no"),
        }

    def test_two_decisions_without_reasons(self) -> None:
        assert read_retry_drop_answers("KEEP C1, WITHDRAW C2", self.LABELS) == {
            "C1": ("KEEP", ""),
            "C2": ("WITHDRAW", ""),
        }

    def test_labels_separated_by_spaces(self) -> None:
        assert read_retry_drop_answers("KEEP C1 C2: x", self.LABELS) == {
            "C1": ("KEEP", "x"),
            "C2": ("KEEP", "x"),
        }

    def test_all_decides_every_item_asked_and_a_label_of_its_own_wins(self) -> None:
        assert read_retry_drop_answers(
            "KEEP all: they hold\nWITHDRAW C2: a guess", self.LABELS
        ) == {
            "C1": ("KEEP", "they hold"),
            "C2": ("WITHDRAW", "a guess"),
            "C3": ("KEEP", "they hold"),
            "F1": ("KEEP", "they hold"),
        }

    def test_withdraw_all(self) -> None:
        decided = read_retry_drop_answers("WITHDRAW all", self.LABELS)

        assert set(decided) == set(self.LABELS)
        assert {d for d, _r in decided.values()} == {"WITHDRAW"}

    def test_a_decision_word_inside_a_reason_is_a_word(self) -> None:
        assert read_retry_drop_answers("KEEP C1: I keep it because it holds", self.LABELS) == {
            "C1": ("KEEP", "I keep it because it holds"),
        }

    def test_a_decision_written_inside_a_reason_is_not_read(self) -> None:
        line = "KEEP C1: I keep it because withdraw C2 would lose data"

        assert read_retry_drop_answers(line, self.LABELS) == {
            "C1": ("KEEP", "I keep it because withdraw C2 would lose data"),
        }

    def test_all_except_leaves_the_listed_labels_undecided(self) -> None:
        assert read_retry_drop_answers("WITHDRAW all except C1", self.LABELS) == {
            "C2": ("WITHDRAW", ""),
            "C3": ("WITHDRAW", ""),
            "F1": ("WITHDRAW", ""),
        }
        assert read_retry_drop_answers(
            "KEEP all except C1, C2: they hold\nWITHDRAW C1: a guess", self.LABELS
        ) == {
            "C1": ("WITHDRAW", "a guess"),
            "C3": ("KEEP", "they hold"),
            "F1": ("KEEP", "they hold"),
        }

    def test_a_decision_only_opens_a_clause(self) -> None:
        assert read_retry_drop_answers("It holds, so KEEP C1", self.LABELS) == {}

    def test_a_long_hostile_line_is_read_in_linear_time(self) -> None:
        import time

        lines = [
            "KEEP " + " ".join(f"C{n}" for n in range(40_000)) + " " + "keep " * 40_000,
            ("KEEP C1" + " " * 100_000) * 3 + "x",
            "KEEP C1" + " and" * 100_000 + " x",
        ]
        started = time.perf_counter()
        for line in lines:
            read_retry_drop_answers(line, self.LABELS)
        assert time.perf_counter() - started < 2.0


class TestMoreClauseStarts:
    LABELS = ["C1", "C2", "C3", "F1"]

    def test_a_decision_after_a_sentence_end(self) -> None:
        assert read_retry_drop_answers("KEEP C1. WITHDRAW C2.", self.LABELS) == {
            "C1": ("KEEP", ""),
            "C2": ("WITHDRAW", ""),
        }

    def test_a_decision_after_a_comma_and(self) -> None:
        assert read_retry_drop_answers("KEEP C1, and WITHDRAW C2: no", self.LABELS) == {
            "C1": ("KEEP", ""),
            "C2": ("WITHDRAW", "no"),
        }

    def test_a_decision_after_a_list_number(self) -> None:
        assert read_retry_drop_answers("1. WITHDRAW C2: guess\n2) KEEP C1: x", self.LABELS) == {
            "C2": ("WITHDRAW", "guess"),
            "C1": ("KEEP", "x"),
        }

    def test_labels_written_first(self) -> None:
        assert read_retry_drop_answers("C2: WITHDRAW - guess\nC1, F1: KEEP", self.LABELS) == {
            "C2": ("WITHDRAW", "guess"),
            "C1": ("KEEP", ""),
            "F1": ("KEEP", ""),
        }

    def test_keep_all_others_after_a_reason(self) -> None:
        assert read_retry_drop_answers("WITHDRAW C2: no. KEEP all others.", self.LABELS) == {
            "C2": ("WITHDRAW", "no"),
            "C1": ("KEEP", ""),
            "C3": ("KEEP", ""),
            "F1": ("KEEP", ""),
        }

    def test_keep_the_rest_leaves_a_decided_label_as_decided(self) -> None:
        assert read_retry_drop_answers("KEEP the rest: they hold\nWITHDRAW C3", self.LABELS) == {
            "C1": ("KEEP", "they hold"),
            "C2": ("KEEP", "they hold"),
            "C3": ("WITHDRAW", ""),
            "F1": ("KEEP", "they hold"),
        }

    def test_a_sentence_of_a_reason_opening_with_a_decision_word_stays_a_reason(self) -> None:
        line = "KEEP C1: it holds. Withdraw C2 would lose data"

        assert read_retry_drop_answers(line, self.LABELS) == {
            "C1": ("KEEP", "it holds. Withdraw C2 would lose data"),
        }

    def test_a_decision_after_a_comma_inside_a_reason_is_not_read(self) -> None:
        line = "KEEP C1: I keep it because, withdraw C2 would lose data"

        assert read_retry_drop_answers(line, self.LABELS) == {
            "C1": ("KEEP", "I keep it because, withdraw C2 would lose data"),
        }

    def test_all_except_after_a_sentence_end_leaves_its_labels_undecided(self) -> None:
        assert read_retry_drop_answers("KEEP C3: x. WITHDRAW all except C1.", self.LABELS) == {
            "C3": ("KEEP", "x"),
            "C2": ("WITHDRAW", ""),
            "F1": ("WITHDRAW", ""),
        }

    def test_every_new_form_is_read_in_linear_time(self) -> None:
        import time

        repeats = 100_000
        lines = [
            "KEEP C1. " * repeats,
            "KEEP C1: x. " * repeats,
            "KEEP C1: a. " + "Withdraw C2 would. " * repeats,
            "KEEP C1, and " * repeats + "x",
            "C1 " * repeats + "x",
            "1. " * repeats,
            "KEEP C1: a" + ". KEEP C1 C2 C3 x" * repeats,
        ]
        started = time.perf_counter()
        for line in lines:
            read_retry_drop_answers(line, self.LABELS)
        # Linear: about a second here; quadratic would take hours.
        assert time.perf_counter() - started < 20.0
