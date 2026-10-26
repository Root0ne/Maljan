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

    def test_labels_first_with_an_arrow(self) -> None:
        assert read_retry_drop_answers("C2 -> WITHDRAW\nC1 => KEEP", self.LABELS) == {
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


class TestTheQuestionShowsWhatTheItemsCite:
    """haiku6: the reverser's retry, written without its decompiles, no longer stated 42 claims.

    Asked about them without the entries they cite, the analyst withdrew 18 true
    claims as resting "on bodies I could not re-read". The question now shows
    each item whole with every entry it cites that the conversation does not
    hold verbatim; the analyst's answer stands as it gives it.
    """

    BODY = "void FUN_3868(void) { CreateMutexW(0, 0); if (GetLastError() == 0xb7) ExitProcess(0); }"
    PACK_BODY = "PE32+ DLL, 60,928 bytes, five sections, four exports"
    CLAIM = (
        "Routine 0x3868 creates a mutex and exits when GetLastError returns 0xb7, so a second "
        "copy of the sample ends at once; the same routine then checks PEB.BeingDebugged, the "
        "process count and the adapter list before it starts the beacon thread 0x5750."
    )
    RETRY = (
        "CLAIM: The sample is a DLL.\nEVIDENCE: [ev_0001] identity\nCONFIDENCE: 0.9\n"
        "TECHNIQUE: NONE\n---\n"
    )

    def _first(self) -> str:
        return (
            f"CLAIM: {self.CLAIM}\nEVIDENCE: [ev_0080] decompile of 0x3868; [ev_0001] identity\n"
            "CONFIDENCE: 0.9\nTECHNIQUE: NONE\n---\n"
            "CLAIM: The string at 0xf1f5 is Update_%x.\nEVIDENCE: [ev_0080] decompile\n"
            "CONFIDENCE: 0.6\nTECHNIQUE: NONE\n---\n"
        )

    def _settle(
        self,
        reply: str,
        conversation_text: str,
        read: dict[str, Any] | None = None,
        rows: tuple[Any, ...] = (),
    ) -> Any:
        from langchain_core.messages import HumanMessage

        from maljan.schemas.evidence import LedgerEntry

        name = "all_tools_reverser_ghidra"
        analyst = _Analyst(name, [reply])
        analyst.pack_ledger_ids = ["ev_0001"]
        analyst._evidence_entries = [
            LedgerEntry(id="ev_0001", tool="identify_file", output=self.PACK_BODY),
            LedgerEntry(id="ev_0080", agent=name, tool="batch_decompile", output=self.BODY),
        ]
        analyst._evidence_entries.extend(rows)
        if read is not None:
            # The agent's own read of the pack entry, filed as a repeat of it.
            analyst._evidence_entries.append(
                LedgerEntry(
                    id="ev_0102",
                    agent=name,
                    tool="read_evidence",
                    args=read,
                    output="read again: ev_0001",
                    repeated_of="ev_0001",
                )
            )
        first = analyst._text_to_isr(self._first(), 0)
        retried = analyst._text_to_isr(self.RETRY, 0)
        conversation = [HumanMessage(content=conversation_text)]
        result = analyst._settle_retry_drops(first, retried, self.RETRY, [], conversation, None)
        return analyst, result

    def test_each_item_is_asked_whole_with_the_entries_it_cites(self) -> None:
        from maljan.pipeline.validation import RETRY_DROP_ENTRIES_HEAD

        analyst, _result = self._settle(
            "KEEP C1: the decompile shows it\nKEEP C2: yes",
            f"[ev_0001] identity:\n{self.PACK_BODY}",
        )

        (question,) = analyst.questions
        assert f"C1. CLAIM: {self.CLAIM}" in question
        assert "    EVIDENCE: [ev_0080] decompile of 0x3868; [ev_0001] identity" in question
        assert RETRY_DROP_ENTRIES_HEAD in question
        assert f"[ev_0080] batch_decompile:\n{self.BODY}" in question
        # Once, under the items, though both cite it; the conversation holds ev_0001 verbatim.
        assert question.count(self.BODY) == 1
        assert self.PACK_BODY not in question
        assert "KEEP <label>: <reason>" in question
        assert "part 1" not in question

    def test_a_pack_entry_seen_as_its_summary_line_is_named_as_that_line(self) -> None:
        from maljan.agents.base_agent import PACK_SUMMARY_NOTE

        analyst, _result = self._settle(
            "KEEP C1: yes\nKEEP C2: yes", "[ev_0001] identity: pe windows, dll\nmore pack"
        )

        (question,) = analyst.questions
        assert f"[ev_0001] {PACK_SUMMARY_NOTE}." in question
        assert question.count("pe windows, dll") == 0
        assert self.PACK_BODY not in question
        # The agent's own call is shown whole beside it.
        assert f"[ev_0080] batch_decompile:\n{self.BODY}" in question

    def test_a_pack_entry_the_agent_read_whole_is_shown_whole(self) -> None:
        analyst, _result = self._settle(
            "KEEP C1: yes\nKEEP C2: yes",
            "[ev_0001] identity: pe windows, dll",
            read={"evidence_id": "ev_0001"},
        )

        assert f"[ev_0001] identify_file:\n{self.PACK_BODY}" in analyst.questions[0]

    def test_a_pack_entry_read_in_pages_is_shown_whole(self) -> None:
        analyst, _result = self._settle(
            "KEEP C1: yes\nKEEP C2: yes",
            "[ev_0001] identity: pe windows, dll",
            read={"evidence_id": "ev_0001", "offset": 0, "limit": 10},
        )

        assert f"[ev_0001] identify_file:\n{self.PACK_BODY}" in analyst.questions[0]

    def test_a_pack_entry_read_again_cut_is_shown_whole_and_marked_partial(self) -> None:
        from maljan.agents.judge_agent import PARTIAL_ENTRY_MARK
        from maljan.schemas.evidence import LedgerEntry

        name = "all_tools_reverser_ghidra"
        cut_read = LedgerEntry(
            id="ev_0103",
            agent=name,
            tool="read_evidence",
            args={"evidence_id": "ev_0002"},
            output="read again: ev_0002",
            repeated_of="ev_0002",
            truncated=True,
        )
        held_part = LedgerEntry(
            id="ev_0002", tool="floss", output="decoded text, first part", truncated=True
        )
        self._first = lambda: (  # type: ignore[method-assign]
            "CLAIM: The string at 0xf1f5 is Update_%x.\nEVIDENCE: [ev_0002] floss\n"
            "CONFIDENCE: 0.6\nTECHNIQUE: NONE\n---\n"
        )
        analyst, _result = self._settle(
            "KEEP C1: yes", "[ev_0002] floss: 81 decodes", rows=(held_part, cut_read)
        )

        question = analyst.questions[0]
        assert f"[ev_0002] floss ({PARTIAL_ENTRY_MARK}):\ndecoded text, first part" in question

    def test_a_chain_of_repeats_is_followed_to_the_entry_that_holds_the_answer(self) -> None:
        from maljan.schemas.evidence import LedgerEntry

        peer = LedgerEntry(
            id="ev_0102", agent="static", tool="read_evidence", repeated_of="ev_0001"
        )
        own = LedgerEntry(
            id="ev_0103",
            agent="all_tools_reverser_ghidra",
            tool="read_evidence",
            repeated_of="ev_0102",
        )
        analyst, _result = self._settle(
            "KEEP C1: yes\nKEEP C2: yes",
            "[ev_0001] identity: pe windows, dll",
            rows=(peer, own),
        )

        assert f"[ev_0001] identify_file:\n{self.PACK_BODY}" in analyst.questions[0]

    def test_an_entry_read_whole_that_the_pack_holds_cut_short_is_shown_whole(self) -> None:
        analyst, _result = self._settle(
            "KEEP C1: yes\nKEEP C2: yes",
            f"[ev_0001] identity:\n{self.PACK_BODY[:20]}…",
            read={"evidence_id": "ev_0001"},
        )

        assert self.PACK_BODY in analyst.questions[0]

    def test_every_withdrawal_stands_as_the_analyst_gives_it(self) -> None:
        reply = (
            "WITHDRAW C1: the mutex exit is not in my retry and rests on a body I could not "
            "re-read\nWITHDRAW C2: the first answer's offset 0xf1f5 was wrong"
        )
        analyst, result = self._settle(reply, "evidence")

        assert [c.claim for c in result.claims] == ["The sample is a DLL."]
        rows = _drop_rows(analyst)
        assert [row["state"] for row in rows] == [RETRY_DROP_WITHDRAWN] * 2
        assert rows[1]["reason"] == "the first answer's offset 0xf1f5 was wrong"


def _budget(tokens: int) -> Any:
    from maljan.llm.context_window import ContextBudget, WindowFact

    return ContextBudget(WindowFact(tokens, "probed", "test"))


class TestTheQuestionIsAskedInPartsThatFit:
    """Measured framed against the real window budget; nothing cut, nothing hidden."""

    BODY_A = "A" * 30_000
    BODY_B = "B" * 30_000
    HUGE = "H" * 200_000

    def _first(self, *, huge: bool = False) -> str:
        third = (
            "CLAIM: The blob at 0x3000 decodes to a third configuration.\n"
            "EVIDENCE: [ev_0090] dump; [ev_0081] decompile\nCONFIDENCE: 0.7\nTECHNIQUE: NONE\n---\n"
            if huge
            else ""
        )
        return (
            "CLAIM: Routine 0x1000 builds the first configuration.\nEVIDENCE: [ev_0081] decompile"
            "\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
            "CLAIM: Routine 0x2000 builds the second configuration.\nEVIDENCE: [ev_0082] "
            "decompile\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n" + third
        )

    def _analyst(self, replies: list[Any], window: Any) -> _Analyst:
        from maljan.llm.context_window import ContextBudget
        from maljan.schemas.evidence import LedgerEntry

        analyst = _Analyst("all_tools_reverser_ghidra", replies)
        analyst._evidence_entries = [
            LedgerEntry(id="ev_0081", tool="batch_decompile", output=self.BODY_A),
            LedgerEntry(id="ev_0082", tool="batch_decompile", output=self.BODY_B),
            LedgerEntry(id="ev_0090", tool="read_memory", output=self.HUGE),
        ]
        if window is not None:
            analyst._container = MagicMock(get_context_budget=lambda: ContextBudget(window))
        return analyst

    def _settle(self, analyst: _Analyst, *, huge: bool = False) -> AgentISR:
        from langchain_core.messages import HumanMessage

        retry = TestTheQuestionShowsWhatTheItemsCite.RETRY
        first = analyst._text_to_isr(self._first(huge=huge), 0)
        retried = analyst._text_to_isr(retry, 0)
        return analyst._settle_retry_drops(
            first, retried, retry, [], [HumanMessage(content="evidence")], None
        )

    @staticmethod
    def _window(prompt_chars: int, source: str = "probed") -> Any:
        from maljan.llm.context_window import WindowFact

        # Room for ``prompt_chars`` beside the analyst's 16,384-token cap, at 3 chars a token.
        return WindowFact(16_384 + prompt_chars // 3, source, "test")

    def test_items_whose_entries_do_not_fit_together_are_asked_in_parts(self) -> None:
        analyst = self._analyst(["KEEP C1: yes", "WITHDRAW C1: a guess"], self._window(45_000))

        result = self._settle(analyst)

        first_part, second_part = analyst.questions
        assert "this is part 1." in first_part and "this is part 2." in second_part
        assert self.BODY_A in first_part and self.BODY_B not in first_part
        assert self.BODY_B in second_part and self.BODY_A not in second_part
        assert "C1. CLAIM: Routine 0x2000" in second_part
        claims = [c.claim for c in result.claims]
        assert "Routine 0x1000 builds the first configuration." in claims
        assert "Routine 0x2000 builds the second configuration." not in claims
        assert [row["state"] for row in _drop_rows(analyst)] == [
            RETRY_DROP_KEPT,
            RETRY_DROP_WITHDRAWN,
        ]

    def test_an_entry_named_for_a_later_item_stays_shown_in_the_earlier_part(self) -> None:
        """Room 42,000 beside the turn; ev_0081 30,000 chars, ev_0082 20,000 (the 4,200 case x10).

        C1 cites ev_0081 and fits with it. C2 cites both, which do not fit
        together beside it; each fits alone, so the larger is named in C2's
        part only, and C1's part, measured with it shown, still shows it.
        """
        from langchain_core.messages import AIMessage, HumanMessage

        from maljan.agents.base_agent import current_run_state, frame_messages
        from maljan.pipeline.validation import RETRY_DROP_ENTRIES_UNFIT
        from maljan.schemas.evidence import LedgerEntry

        retry = TestTheQuestionShowsWhatTheItemsCite.RETRY
        analyst = _Analyst("all_tools_reverser_ghidra", ["KEEP C1: yes", "KEEP C1: yes"])
        analyst._evidence_entries = [
            LedgerEntry(id="ev_0081", tool="batch_decompile", output="A" * 30_000),
            LedgerEntry(id="ev_0082", tool="batch_decompile", output="B" * 20_000),
        ]
        first = analyst._text_to_isr(
            "CLAIM: Routine 0x1000 builds the first configuration.\nEVIDENCE: [ev_0081]\n"
            "CONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
            "CLAIM: Routine 0x2000 builds the second configuration.\nEVIDENCE: [ev_0081]; "
            "[ev_0082]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n",
            0,
        )
        conversation = [HumanMessage(content="evidence")]
        framed = frame_messages(
            [*conversation, AIMessage(content=retry), HumanMessage(content="")],
            run_state=current_run_state(analyst),
        )
        base = sum(len(str(m.content)) for m in framed)
        # 42,000 characters past the conversation and a 2,000-character question frame.
        analyst._container = MagicMock(
            get_context_budget=lambda: _budget(16_384 + (base + 44_000) // 3)
        )

        analyst._settle_retry_drops(
            first, analyst._text_to_isr(retry, 0), retry, [], conversation, None
        )

        first_part, second_part = analyst.questions
        assert "A" * 30_000 in first_part
        assert "B" * 20_000 in second_part and "A" * 30_000 not in second_part
        assert f"{RETRY_DROP_ENTRIES_UNFIT} ev_0081." in second_part

    def test_a_window_that_holds_everything_asks_once(self) -> None:
        analyst = self._analyst(["KEEP C1, C2: yes"], self._window(200_000))

        self._settle(analyst)

        (question,) = analyst.questions
        assert self.BODY_A in question and self.BODY_B in question

    def test_an_entry_too_large_even_alone_is_named_by_id(self) -> None:
        from maljan.pipeline.validation import RETRY_DROP_ENTRIES_UNFIT

        analyst = self._analyst(
            ["KEEP C1: yes", "KEEP C1: yes", "KEEP C1: yes"], self._window(45_000)
        )

        self._settle(analyst, huge=True)

        third = analyst.questions[-1]
        assert f"{RETRY_DROP_ENTRIES_UNFIT} ev_0090." in third
        assert self.HUGE not in third
        assert self.BODY_A in third

    def test_with_no_learned_window_the_model_s_declared_window_is_used(self) -> None:
        from maljan.llm.context_window import record_built_window

        analyst = self._analyst(["KEEP C1: yes", "KEEP C1: yes"], None)
        record_built_window(analyst.llm, self._window(45_000, source="declared"))

        self._settle(analyst)

        assert len(analyst.questions) == 2

    def test_with_no_window_known_the_question_is_asked_once(self) -> None:
        analyst = self._analyst(["KEEP C1, C2: yes"], None)

        self._settle(analyst)

        assert len(analyst.questions) == 1
