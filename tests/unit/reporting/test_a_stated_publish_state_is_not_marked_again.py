"""A value written with a publish state the IOC table agrees with is not marked again.

A benchmark report's command-and-control subsection wrote an unpublished
address as "<address> (publish state: the sandbox report does not say which
process made the flows to it)", the table's own reason. The check read only
``no: <reason>`` as a state, so the sentence was flagged and the report printed
"[not published by this run: <address> (no: …); not asked]" right after the
state the sentence already gave, twice. A state is now read as stated when it
says what the table says: ``no: <reason>``, a state under its own name that
does not call the value published, the platform's own "not published by this
run", or the table's reason restated word for word. A stated state that calls
the value published contradicts the table and is asked about as before. The
renderer reads a stored mark's sentence again and prints no mark beside a
sentence whose every value carries such a state.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from maljan.pipeline.validation import UNPUBLISHED_VALUE_CODE, unpublished_value_violations
from maljan.reporting.composer import ReportComposer, _ProseOut
from maljan.reporting.models import (
    FileHashes,
    FlaggedStatement,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

ADDRESS = "198.18.44.12"
OTHER = "198.18.71.203"
# The reason the stub table gives, and one longer than a few words.
REASON = "the capture names no process behind its flows"
ANSWER = f"no: {REASON}"


def _answers(kind: str, value: str) -> str:
    return ANSWER if value == ADDRESS else ""


def _body(text: str) -> dict[str, Any]:
    return {"body": text, "evidence_refs": []}


def _found(text: str) -> list[Any]:
    return unpublished_value_violations(_body(text), _answers)


class TestAStatedState:
    @pytest.mark.parametrize(
        "written",
        [
            f"(publish state: {REASON})",
            "(publish state: not attributed to the sample in the capture)",
            "(publication state is unpublished, the capture names no process)",
            "(published state — kept out of the indicator table)",
            "(not published by this run: no process is named)",
        ],
    )
    def test_a_state_that_agrees_with_the_table_raises_nothing(self, written: str) -> None:
        assert _found(f"The capture holds {ADDRESS} {written} with two flows [ev_0031].") == []

    def test_the_table_s_reason_restated_is_a_stated_state(self) -> None:
        body = f"It holds {ADDRESS}:53 (the capture names no process behind these flows)."

        assert _found(body) == []

    def test_a_reason_restated_in_part_is_no_state(self) -> None:
        (found,) = _found(f"It holds {ADDRESS} (the capture names its flows).")

        assert found.code == UNPUBLISHED_VALUE_CODE
        assert ADDRESS in found.message

    @pytest.mark.parametrize(
        "written", ["(publish state: published)", "(publish state: yes, as C2)"]
    )
    def test_a_state_that_calls_the_value_published_is_asked_about(self, written: str) -> None:
        (found,) = _found(f"It beacons to {ADDRESS} {written} [ev_0031].")

        assert REASON in found.message

    def test_a_contradicting_state_is_not_saved_by_a_reason_beside_it(self) -> None:
        body = f"It beacons to {ADDRESS} (publish state: published; no: {REASON})."

        assert len(_found(body)) == 1

    def test_a_state_covers_only_the_value_it_follows(self) -> None:
        (found,) = _found(f"It holds {ADDRESS} (publish state: {REASON}) and C2 {OTHER}.")

        assert OTHER in found.message
        assert found.labels and ADDRESS not in found.labels[0]

    def test_an_empty_named_state_is_no_state(self) -> None:
        assert len(_found(f"It holds {ADDRESS} (publish state: ) today.")) == 1

    def test_a_named_state_restating_most_of_the_reason_is_a_stated_state(self) -> None:
        # The table's reason with its last word put another way.
        body = f"It holds {ADDRESS}:53 (publish state: the capture names no process behind them)."

        assert _found(body) == []


# A second value with a reason of its own, for the claims that turn a reason around.
ANALYST_REASON = "named only by an analyst"


def _two_answers(kind: str, value: str) -> str:
    return {ADDRESS: ANSWER, OTHER: f"no: {ANALYST_REASON}"}.get(value, "")


def _flagged(text: str) -> set[str]:
    return {
        value
        for found in unpublished_value_violations(_body(text), _two_answers)
        for label in found.labels
        for value in (ADDRESS, OTHER)
        if f"{value} (" in label
    }


class TestAStateTheTableDoesNotAgreeWith:
    @pytest.mark.parametrize(
        "said",
        [
            "unknown",
            "pending the judge",
            "likely published",
            "it is published",
            "not unpublished",
            "kept as an indicator",
            "**yes**",
            "Yes",
            "not withheld",
            "no longer withheld",
            "no doubt published",
            "not only flagged but published",
        ],
    )
    def test_a_named_state_that_does_not_read_as_withheld_is_asked(self, said: str) -> None:
        assert _flagged(f"It connects to {ADDRESS} (publish state: {said}).") == {ADDRESS}

    def test_a_restatement_dropping_the_reason_s_negation_is_asked(self) -> None:
        dropped = (
            f"It holds {ADDRESS} (publish state: the capture names a process behind its flows)."
        )
        kept = f"It holds {ADDRESS} (publish state: the capture names no process behind them)."

        assert _flagged(dropped) == {ADDRESS}
        assert _flagged(kept) == set()

    @pytest.mark.parametrize(
        "body",
        [
            f"{ADDRESS} (no: {REASON}) is contacted; the dropped file is kept in Temp.",
            f"{ADDRESS} (no: {REASON}) was seen; the beacon was kept alive.",
            f"{ADDRESS} (no: {REASON}) was contacted and the dropped file is kept in Temp.",
            f"{ADDRESS} (no: {REASON}), and the payload is kept in memory.",
            f"{ADDRESS} (publish state: never published; withheld) here.",
        ],
    )
    def test_kept_said_of_something_else_after_the_clause_raises_nothing(self, body: str) -> None:
        assert _flagged(body) == set()

    def test_a_negation_a_few_words_before_a_withholding_word_turns_it(self) -> None:
        body = f"It holds {ADDRESS} (publish state: not, as one says, withheld)."

        assert _flagged(body) == {ADDRESS}

    @pytest.mark.parametrize("kept", ["kept as indicator", "kept as an indicator", "so it is kept"])
    def test_a_later_clause_keeping_the_value_outweighs_the_state(self, kept: str) -> None:
        assert _flagged(f"It holds {ADDRESS} (publish state: not published, {kept}).") == {ADDRESS}

    @pytest.mark.parametrize(
        "body",
        [
            f"{ADDRESS} is published by this run as an indicator; {REASON}.",
            f"{ADDRESS} is published: contrary to the table, {REASON}.",
            f"{ADDRESS} is never published in this report, but this run publishes it.",
            f"{OTHER} was not {ANALYST_REASON}; this run publishes it.",
            f"{OTHER} is published, though {ANALYST_REASON}.",
        ],
    )
    def test_a_claim_that_the_value_is_published_outweighs_any_state(self, body: str) -> None:
        assert _flagged(body)

    def test_a_negation_the_reason_does_not_carry_turns_it_around(self) -> None:
        assert _flagged(f"Then {OTHER} (not {ANALYST_REASON}) answers.") == {OTHER}

    def test_a_reason_s_words_out_of_order_or_far_apart_are_no_restatement(self) -> None:
        scrambled = f"It holds {ADDRESS} (flows behind its process: no names, the capture)."
        apart = (
            f"It holds {ADDRESS} (the capture of the long night names, as one may see, no "
            "process at all and nothing behind any of its flows)."
        )

        assert _flagged(scrambled) == {ADDRESS}
        assert _flagged(apart) == {ADDRESS}

    @pytest.mark.parametrize(
        "body",
        [
            f"{ADDRESS}, which this run is not published by this run's table but is in STIX.",
            f"{ADDRESS} is the C2, while publish state: no applies to another host only.",
            f"{ADDRESS} is the C2, and {REASON}.",
        ],
    )
    def test_a_state_counts_only_in_the_clause_right_after_the_value(self, body: str) -> None:
        assert _flagged(body) == {ADDRESS}

    def test_each_value_is_read_with_its_own_state(self) -> None:
        assert _flagged(f"{ADDRESS} and {OTHER} (publish state: no).") == {ADDRESS}
        assert _flagged(
            f"{OTHER} (publish state: yes) talks to {ADDRESS} (publish state: no)."
        ) == {OTHER}


def _report(sentence: str, label: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)),
        verdict="Malware",
        network=NetworkIOCs(ips=[NetworkIP(address=ADDRESS, source="sandbox")]),
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(title="Command and control", body=sentence)
        ),
        flagged_statements=[
            FlaggedStatement(
                sentence=sentence, code=UNPUBLISHED_VALUE_CODE, label=label, asked=False
            )
        ],
    )


class TestTheRenderer:
    def test_a_stored_mark_beside_a_stated_state_is_not_printed(self) -> None:
        sentence = (
            f"The summary holds {ADDRESS} (publish state: not published, {REASON}) [ev_0031]."
        )
        text = MarkdownRenderer().render(_report(sentence, f"{ADDRESS} ({ANSWER})"))

        line = next(line for line in text.splitlines() if "[ev_0031]" in line)
        assert "not published by this run" not in line

    def test_a_stored_mark_on_a_sentence_without_a_state_is_printed(self) -> None:
        sentence = f"The sample beacons to {ADDRESS} every minute [ev_0031]."
        text = MarkdownRenderer().render(_report(sentence, f"{ADDRESS} (no: a stored reason)"))

        line = next(line for line in text.splitlines() if "every minute" in line)
        assert "not published by this run" in line and "not asked" in line


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


class TestTheComposer:
    def test_a_sentence_with_a_named_state_costs_no_question_and_no_mark(self) -> None:
        from langchain_core.messages import HumanMessage

        sentence = f"The summary holds {ADDRESS} (publish state: {REASON})."
        llm = _RawLLM(json.dumps(_body(sentence)))
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)), verdict="Malware"
        )
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        comp._report = report
        comp._answers = _answers
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            result = asyncio.run(
                comp._invoke(
                    [HumanMessage(content="write it")], _ProseOut, section="command_and_control"
                )
            )

        assert len(llm.sent) == 1
        assert result is not None and result.body == sentence
        assert report.flagged_statements == []
