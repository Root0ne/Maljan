"""Technical prose names a network value this run does not publish only with its state.

A local run's command-and-control subsection called an address C2
infrastructure that the IOC table refused ("no: …"). The publish check read
only the recommendations, in the narrative round, so the composer was never
told; the one finding on the subsection was about a citation and said nothing
of the address. Each composer section's prose — a subsection's body, the
introduction, the execution flow's steps — is now checked against the IOC
table's own answers: a value it does not publish, named without its
``no: <reason>`` beside it, is listed in one question per section, grouped by
state with the sentences that name it. The model's answer stands, and each
sentence kept after it is marked where it stands with its own values' states.
A table cell is never asked about: the report prints the IOC table's state
beside an unpublished value in a configuration, identifier or endpoint cell.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    NO_TABLE_ANSWER,
    NO_TABLE_ROW,
    UNPUBLISHED_VALUE_CODE,
    record_flagged_statements,
    unpublished_value_violations,
)
from maljan.reporting.composer import ReportComposer, _C2Out, _ProseOut
from maljan.reporting.models import (
    ConsolidatedIOC,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.narrative_agent import published_answers
from maljan.reporting.renderers.markdown import MarkdownRenderer

PUBLISHED = "gate.example.com"
REFUSED = "198.51.100.7"
REFUSAL = "no: the sandbox report does not say which process made the flows to it"


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        consolidated_iocs=[
            ConsolidatedIOC(
                type="Domain",
                kind="domain",
                value=PUBLISHED,
                source="decoded",
                published="yes: recovered by emulation",
                is_network=True,
            ),
            ConsolidatedIOC(
                type="IPv4",
                kind="ip",
                value=REFUSED,
                source="sandbox",
                published=REFUSAL,
                is_network=True,
            ),
        ],
        **over,
    )


def _answers() -> Any:
    return published_answers(_report())


def _body(text: str) -> dict[str, Any]:
    return {"body": text, "evidence_refs": []}


class TestTheCheck:
    def test_an_unpublished_address_stated_as_infrastructure_is_asked_about(self) -> None:
        sentence = f"The sample connects to {REFUSED} on port 443, its C2 server [ev_0017]."

        (found,) = unpublished_value_violations(_body(sentence), _answers())

        assert found.code == UNPUBLISHED_VALUE_CODE
        assert f'{REFUSED} ({REFUSAL}) in "The sample connects to {REFUSED} on…"' in (found.message)
        assert found.quoted == (sentence,)

    def test_a_defanged_address_is_read_as_the_address(self) -> None:
        defanged = REFUSED.replace(".", "[.]")

        (found,) = unpublished_value_violations(_body(f"It reaches {defanged}."), _answers())

        assert REFUSED in found.message

    def test_a_published_value_raises_nothing(self) -> None:
        assert unpublished_value_violations(_body(f"It posts to {PUBLISHED}."), _answers()) == []

    def test_a_value_written_with_its_state_raises_nothing(self) -> None:
        body = f"The sandbox recorded {REFUSED} ({REFUSAL})."

        assert unpublished_value_violations(_body(body), _answers()) == []

    def test_a_state_exempts_only_the_value_it_stands_beside(self) -> None:
        other = "203.0.113.9"
        body = f"It recorded {REFUSED} ({REFUSAL}) and C2 {other}."

        (found,) = unpublished_value_violations(_body(body), _answers())

        assert other in found.message and f"{REFUSED} ({REFUSAL})" not in found.message
        assert found.labels == (f"{other} (no: {NO_TABLE_ROW})",)

    def test_a_value_no_table_row_holds_is_asked_with_that_state(self) -> None:
        (found,) = unpublished_value_violations(_body("It also reaches 203.0.113.9."), _answers())

        assert f"no: {NO_TABLE_ROW}" in found.message

    def test_a_reference_host_no_row_holds_is_not_an_indicator(self) -> None:
        body = "The API is described at learn.microsoft.com."

        assert unpublished_value_violations(_body(body), _answers()) == []

    def test_a_table_cell_is_never_asked_about(self) -> None:
        for payload in (
            {"channels": [{"name": "fallback", "endpoints": [REFUSED, PUBLISHED]}]},
            {"items": [{"key": "C2", "value": REFUSED, "evidence_refs": ["ev_0019"]}]},
            {"identifiers": [{"kind": "Address", "value": REFUSED, "evidence_refs": []}]},
        ):
            assert unpublished_value_violations(payload, _answers()) == []

    def test_a_flow_step_is_prose(self) -> None:
        payload = {"steps": [{"order": 1, "action": f"It beacons to {REFUSED}.", "voice": "x"}]}

        (found,) = unpublished_value_violations(payload, _answers())

        assert found.quoted == (f"It beacons to {REFUSED}.",)

    def test_one_question_per_section_groups_values_by_state_and_names_sentences(self) -> None:
        other = "203.0.113.9"
        body = (
            f"It reaches {REFUSED} and {other} on 443. It writes a file. "
            f"Later it reaches {REFUSED} again. Then {other} once more."
        )

        (found,) = unpublished_value_violations(_body(body), _answers())

        assert (
            f'{REFUSED} ({REFUSAL}) in "It reaches {REFUSED} and {other} on…", '
            f'"Later it reaches {REFUSED} again.";'
        ) in found.message
        assert (
            f'{other} (no: {NO_TABLE_ROW}) in "It reaches {REFUSED} and {other} on…", '
            f'"Then {other} once more."'
        ) in found.message
        assert found.quoted == (
            f"It reaches {REFUSED} and {other} on 443.",
            f"Later it reaches {REFUSED} again.",
            f"Then {other} once more.",
        )
        refused, other_said = REFUSED, other
        assert found.labels == (
            f"{refused} ({REFUSAL}); {other_said} (no: {NO_TABLE_ROW})",
            f"{refused} ({REFUSAL})",
            f"{other_said} (no: {NO_TABLE_ROW})",
        )

    def test_a_state_is_said_once_for_every_value_it_refuses(self) -> None:
        others = ["203.0.113.9", "203.0.113.10", "203.0.113.11"]
        body = " ".join(f"It connects to {value}." for value in others)

        (found,) = unpublished_value_violations(_body(body), _answers())

        assert found.message.count(NO_TABLE_ROW) == 1
        assert f"{', '.join(others)} (no: {NO_TABLE_ROW}) in " in found.message
        assert all(f'"It connects to {value}."' in found.message for value in others)

    def test_each_sentence_is_named_by_its_quoted_start(self) -> None:
        body = " ".join(f"It connects to {REFUSED} on port {n}." for n in range(1, 20))

        (found,) = unpublished_value_violations(_body(body), _answers())

        assert found.message.count('"It connects to') == 19
        assert len(found.message) < 1200

    def test_the_state_is_the_answer_s_first_clause(self) -> None:
        def _long(kind: str, value: str) -> str:
            return f"{REFUSAL}; an analyst artifact lists it"

        (found,) = unpublished_value_violations(_body(f"It reaches {REFUSED}."), _long)

        assert REFUSAL in found.message and "artifact" not in found.message
        assert found.labels == (f"{REFUSED} ({REFUSAL})",)

    def test_the_finding_is_kept_and_marked_in_place(self) -> None:
        assert UNPUBLISHED_VALUE_CODE in KEPT_WITH_A_FINDING
        assert UNPUBLISHED_VALUE_CODE in MARKED_IN_PLACE


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


def _invoke(schema: type, *answers: str) -> tuple[Any, _RawLLM, ReportComposer, MalwareReport]:
    from langchain_core.messages import HumanMessage

    llm = _RawLLM(*answers)
    report = _report()
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._report = report
    comp._answers = published_answers(report)
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        result = asyncio.run(
            comp._invoke([HumanMessage(content="write it")], schema, section="command_and_control")
        )
    return result, llm, comp, report


class TestTheComposerAsksOnce:
    def test_a_sentence_the_model_rewrites_is_taken_and_not_marked(self) -> None:
        wrong = json.dumps(_body(f"It uses {REFUSED} as C2."))
        right = json.dumps(_body(f"It uses {PUBLISHED} as C2."))

        result, llm, comp, report = _invoke(_ProseOut, wrong, right)

        assert len(llm.sent) == 2
        assert REFUSAL in str(llm.sent[1][-1].content)
        assert result is not None and PUBLISHED in result.body
        assert report.flagged_statements == []

    def test_a_sentence_the_model_keeps_stands_and_is_marked_with_the_state(self) -> None:
        sentence = f"It uses {REFUSED} as C2."
        wrong = json.dumps(_body(sentence))

        result, _llm, comp, report = _invoke(_ProseOut, wrong, wrong)

        assert result is not None and result.body == sentence
        (row,) = report.flagged_statements
        assert row.sentence == sentence and row.code == UNPUBLISHED_VALUE_CODE
        # Stored as written; the renderer defangs and escapes it.
        assert REFUSAL in row.label and REFUSED in row.label

    def test_a_record_section_costs_no_question(self) -> None:
        answer = json.dumps({"channels": [{"name": "fallback", "endpoints": [REFUSED]}]})

        _result, llm, _comp, report = _invoke(_C2Out, answer)

        assert len(llm.sent) == 1
        assert report.flagged_statements == []

    def test_each_kept_sentence_is_marked_with_its_own_values(self) -> None:
        other = "203.0.113.9"
        body = f"It uses {REFUSED} as C2. It falls back to {other}."
        wrong = json.dumps(_body(body))

        _result, llm, _comp, report = _invoke(_ProseOut, wrong, wrong)

        assert len(llm.sent) == 2
        marks = {row.sentence: row.label for row in report.flagged_statements}
        assert REFUSAL in marks[f"It uses {REFUSED} as C2."]
        assert other not in marks[f"It uses {REFUSED} as C2."]
        assert NO_TABLE_ROW in marks[f"It falls back to {other}."]

    def test_compose_reads_the_ioc_table(self) -> None:
        captured: dict[str, Any] = {}

        async def _author(self: Any, section: str, *args: Any, validators: Any = None) -> None:
            captured["answers"] = getattr(self, "_answers", None)

        comp = ReportComposer(llm=_RawLLM(), per_section_timeout=5)  # type: ignore[arg-type]
        with patch.object(ReportComposer, "_author", _author):
            asyncio.run(comp.compose(_report()))

        assert captured["answers"]("ip", REFUSED) == REFUSAL


class TestAnUnreadableTable:
    def test_the_composer_asks_once_saying_the_table_could_not_be_read(self) -> None:
        from maljan.reporting import composer as composer_module

        with patch(
            "maljan.reporting.narrative_agent.published_answers",
            side_effect=RuntimeError("unreadable"),
        ):
            answers = composer_module._published_answers(_report())

        (found,) = unpublished_value_violations(_body(f"It uses {REFUSED} as C2."), answers)
        assert "the IOC table could not be read" in found.message


class TestTheReportStatesTheState:
    def test_the_kept_sentence_is_printed_with_the_value_s_state_beside_it(self) -> None:
        sentence = f"It uses {REFUSED} as C2 [ev_0017]."
        report = _report(
            technical_analysis=TechnicalAnalysis(
                command_and_control=TechnicalSubsection(title="Command and control", body=sentence)
            )
        )
        record_flagged_statements(
            report, unpublished_value_violations(_body(sentence), published_answers(report))
        )

        text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if "as C2 [ev_0017]." in line)
        assert "not published by this run" in line
        assert REFUSAL in line
        assert f"not published by this run: {REFUSED.replace('.', '[.]')} ({REFUSAL})" in line

    def test_a_table_cell_carries_the_state_beside_the_value(self) -> None:
        from maljan.reporting.models import C2Channel, ConfigItem, HostIdentifier

        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[
                    ConfigItem(key="Fallback", value=REFUSED, how_obtained="decrypted"),
                    ConfigItem(key="Gate", value=PUBLISHED, how_obtained="decrypted"),
                ],
                host_identifiers=[HostIdentifier(kind="Address", value=REFUSED)],
            ),
            c2_channels=[C2Channel(name="fallback", endpoints=[REFUSED, PUBLISHED])],
        )

        text = MarkdownRenderer().render(report)

        fallback = next(line for line in text.splitlines() if line.startswith("| Fallback"))
        assert f"({REFUSAL})" in fallback
        gate = next(line for line in text.splitlines() if line.startswith("| Gate"))
        assert "no:" not in gate
        address = next(line for line in text.splitlines() if line.startswith("| Address"))
        assert f"({REFUSAL})" in address
        channel = next(line for line in text.splitlines() if line.startswith("| fallback"))
        # An endpoint already marked as no address the run may publish keeps
        # that mark alone; a documentation address is one.
        assert "(not an address this run may publish)" in channel
        assert "no:" not in channel

    def test_an_endpoint_with_no_mark_of_its_own_carries_the_table_s_state(self) -> None:
        from maljan.reporting.models import C2Channel

        refused_host = "relay.example.net"
        report = _report(c2_channels=[C2Channel(name="relay", endpoints=[refused_host])])
        report.consolidated_iocs.append(
            report.consolidated_iocs[1].model_copy(
                update={"type": "Domain", "kind": "domain", "value": refused_host}
            )
        )

        text = MarkdownRenderer().render(report)

        channel = next(line for line in text.splitlines() if line.startswith("| relay"))
        assert f"({REFUSAL})" in channel


class TestOddAndLargeInput:
    def test_odd_input_raises_nothing(self) -> None:
        def _broken(kind: str, value: str) -> str:
            raise ValueError("no table")

        payload: dict[str, Any] = {"body": None, "steps": [None, 7, {"action": "\u202e" * 100}]}

        assert unpublished_value_violations(payload, _answers()) == []
        # Fails closed: a value the table cannot answer for is refused for that reason.
        (found,) = unpublished_value_violations(_body(f"It reaches {REFUSED}."), _broken)
        assert NO_TABLE_ANSWER in found.message

    def test_a_lookup_raising_on_a_package_shaped_name_refuses_that_name_only(self) -> None:
        package = "com.evil-c2.update.cdn.ru"

        def _raises_on_the_package(kind: str, value: str) -> str:
            if value == package:
                raise ValueError("no table")
            return ""

        (found,) = unpublished_value_violations(
            _body(f"It reaches {REFUSED} and resolves {package}."), _raises_on_the_package
        )
        assert package in found.message
        assert NO_TABLE_ANSWER in found.message
        assert REFUSED in found.message

    def test_a_long_section_finishes_quickly(self) -> None:
        import time

        body = " ".join(
            f"Step {n} reaches 203.0.{n % 250}.{n % 200} and {PUBLISHED} [ev_0017]."
            for n in range(3000)
        )

        started = time.monotonic()
        found = unpublished_value_violations(_body(body), _answers())
        elapsed = time.monotonic() - started

        (asked,) = found
        assert asked.code == UNPUBLISHED_VALUE_CODE
        assert elapsed < 10, elapsed
