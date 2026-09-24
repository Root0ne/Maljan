"""A technique published on a rule match alone is not written as something the sample does.

A benchmark run published five techniques on single-string YARA matches that
no analyst claimed, marked "rule match only" in the ATT&CK table, and the
report then wrote them as execution steps: "The sample dumps credentials from
the target system. (assessed)". The report writer is now told, per technique,
that it is a rule match with no analyst claim; a sentence stating one as an
action is asked about once; and a sentence that survives is marked where it
stands, its words unchanged. The publish rule is unchanged.

The same mark answers the capability check, whose flagged sentences stayed in
the text with nothing on them (fifteen on one run, seven in the summary).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from maljan.pipeline.evidence_summary import yara_rule_strings
from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    RULE_MATCH_AS_ACTION_CODE,
    UNGROUNDED_CAPABILITY_CODE,
    CapabilityGrounding,
    record_flagged_statements,
    rule_match_statement_violations,
    section_capability_violations,
)
from maljan.reporting.composer import (
    RULE_ONLY_NOTE,
    ReportComposer,
    _FlowOut,
    _published_techniques,
)
from maljan.reporting.models import (
    FileHashes,
    FlaggedStatement,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from maljan.reporting.narrative_agent import build_prompt_text
from maljan.reporting.renderers.markdown import MarkdownRenderer

RULE = "example_hollowing_rule"


def _report(claimed_by: list[str] | None = None) -> MalwareReport:
    entry = SimpleNamespace(
        id="ev_0007",
        tool="yara_scan",
        structured={
            "matches": [
                {
                    "rule": RULE,
                    "meta": {"technique_id": "T1055.012"},
                    "strings": [{"identifier": "$0", "offset": 10}],
                }
            ]
        },
    )
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
        verdict="Malware",
        ttp_mappings=[
            TTPMapping(
                technique_id="T1055.012",
                technique_name="Process Hollowing",
                confidence=0.8,
                contributing_layers=["judge"],
            ),
            TTPMapping(technique_id="T1027", technique_name="Obfuscated Files or Information"),
        ],
        run_summary={
            "corroboration": {
                "T1055.012": {"asserted_by": ["yara"], "claimed_by": claimed_by or []},
                "T1027": {"asserted_by": [], "claimed_by": ["static"]},
            }
        },
        rule_match_strings=yara_rule_strings([entry]),
    )


class TestTheWriterIsTold:
    def test_each_rule_only_technique_carries_its_note_in_every_section_s_prompt(self) -> None:
        block = _published_techniques(_report())

        assert (
            "- T1055.012 Process Hollowing — rule match only "
            f"(yara `{RULE}`, 1 string), no analyst claim"
        ) in block
        assert "- T1027 Obfuscated Files or Information\n" in block
        assert block.endswith(RULE_ONLY_NOTE)

    def test_a_claimed_technique_carries_no_note(self) -> None:
        assert RULE_ONLY_NOTE not in _published_techniques(_report(claimed_by=["static"]))

    def test_the_summary_prompt_carries_it_too(self) -> None:
        text = build_prompt_text(_report())

        assert "rule match only" in text and RULE_ONLY_NOTE in text


class TestTheQuestion:
    def _grounding(self, claimed_by: list[str] | None = None) -> CapabilityGrounding:
        return CapabilityGrounding.from_report(_report(claimed_by))

    def test_a_sentence_naming_it_as_an_action_is_asked(self) -> None:
        text = "The sample performs process hollowing into a suspended child. It is packed."

        (found,) = rule_match_statement_violations(text, self._grounding())

        assert found.code == RULE_MATCH_AS_ACTION_CODE
        assert "T1055.012" in found.message and "rule match only" in found.message
        assert found.quoted == ("The sample performs process hollowing into a suspended child.",)

    def test_the_id_is_read_as_well_as_the_name(self) -> None:
        text = "Execution continues through T1055.012 in a new process."

        assert rule_match_statement_violations(text, self._grounding())

    def test_a_sentence_about_the_rule_is_not_asked(self) -> None:
        text = "A YARA rule for process hollowing matched one string."

        assert rule_match_statement_violations(text, self._grounding()) == []

    def test_an_estimate_or_a_negation_is_not_asked(self) -> None:
        text = (
            "The sample may use process hollowing. "
            "No evidence of process hollowing was recorded by any analyst."
        )

        assert rule_match_statement_violations(text, self._grounding()) == []

    def test_a_technique_an_analyst_claimed_is_not_asked(self) -> None:
        text = "The sample performs process hollowing."

        assert rule_match_statement_violations(text, self._grounding(["static"])) == []

    def test_a_capability_word_behind_it_is_told_it_is_a_rule_match(self) -> None:
        payload = {"steps": [{"order": 1, "action": "Injects code into a child process"}]}

        found = section_capability_violations(payload, self._grounding())

        (capability,) = [v for v in found if v.code == UNGROUNDED_CAPABILITY_CODE]
        assert "T1055.012" in capability.message
        assert "say that a rule matched" in capability.message
        assert capability.quoted == ("Injects code into a child process",)

    def test_the_answer_is_kept_with_a_finding(self) -> None:
        assert RULE_MATCH_AS_ACTION_CODE in KEPT_WITH_A_FINDING


class _Answers:
    model_name = "m"

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.seen: list[list[Any]] = []

    async def ainvoke(self, messages: Any) -> AIMessage:
        self.seen.append(list(messages))
        return AIMessage(content=self.answers.pop(0))


_ACTION = (
    '{"steps": [{"order": 1, "action": "Performs process hollowing into a child", '
    '"voice": "assessed", "evidence_refs": []}]}'
)
_RULE = (
    '{"steps": [{"order": 1, "action": "A rule for process hollowing matched one string", '
    '"voice": "assessed", "evidence_refs": []}]}'
)


def _compose(llm: _Answers, report: MalwareReport) -> Any:
    composer = ReportComposer(llm=llm, section_max_tokens=900)  # type: ignore[arg-type]
    composer._report = report
    composer._grounding = CapabilityGrounding.from_report(report)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "maljan.reporting.composer.structured_output_supported_for_llm", lambda _l: False
        )
        return asyncio.run(
            composer._invoke([HumanMessage(content="x")], _FlowOut, section="execution_flow")
        )


class TestTheLoop:
    def test_asked_once_and_the_fix_is_taken(self) -> None:
        report = _report()
        llm = _Answers(_ACTION, _RULE)

        result = _compose(llm, report)

        assert result.steps[0].action.startswith("A rule for process hollowing")
        assert RULE_MATCH_AS_ACTION_CODE in str(llm.seen[1][-1].content)
        assert report.flagged_statements == []

    def test_a_sentence_that_survives_is_recorded_as_written(self) -> None:
        report = _report()
        llm = _Answers(_ACTION, _ACTION)

        result = _compose(llm, report)

        assert result.steps[0].action == "Performs process hollowing into a child"
        assert (
            FlaggedStatement(
                sentence="Performs process hollowing into a child",
                code=RULE_MATCH_AS_ACTION_CODE,
                label="T1055.012",
            )
            in report.flagged_statements
        )


class TestTheMark:
    def test_a_surviving_sentence_is_marked_where_it_stands(self) -> None:
        sentence = "The sample exfiltrates documents to its operator."
        report = _report()
        report.executive_summary = f"It is packed. {sentence} It runs once."
        report.flagged_statements = [
            FlaggedStatement(
                sentence=sentence, code=UNGROUNDED_CAPABILITY_CODE, label="exfiltration"
            )
        ]

        md = MarkdownRenderer().render(report)

        assert (
            f"It is packed. {sentence} **[not established by this run: exfiltration]** "
            "It runs once."
        ) in md

    def test_the_rule_match_mark(self) -> None:
        report = _report()
        report.executive_summary = "Performs process hollowing into a child."
        record_flagged_statements(
            report,
            rule_match_statement_violations(
                report.executive_summary, CapabilityGrounding.from_report(report)
            ),
        )

        md = MarkdownRenderer().render(report)

        assert (
            "Performs process hollowing into a child. "
            "**[a rule match only, stated as an action: T1055.012]**"
        ) in md

    def test_two_sentences_under_one_label_are_both_marked(self) -> None:
        first = "The sample exfiltrates documents over FTP."
        second = "Stolen data is later exfiltrated to a second server."
        report = _report()
        report.executive_summary = f"{first} {second}"
        report.flagged_statements = [
            FlaggedStatement(sentence=first, code=UNGROUNDED_CAPABILITY_CODE, label="exfiltration"),
            FlaggedStatement(
                sentence=second, code=UNGROUNDED_CAPABILITY_CODE, label="exfiltration"
            ),
        ]

        md = MarkdownRenderer().render(report)

        mark = "**[not established by this run: exfiltration]**"
        assert f"{first} {mark} {second} {mark}" in md

    def test_a_sentence_in_a_table_cell_is_marked(self) -> None:
        from maljan.reporting.renderers.markdown import _Context

        report = _report()
        report.flagged_statements = [
            FlaggedStatement(
                sentence="Sends the host profile out", code=UNGROUNDED_CAPABILITY_CODE, label="x"
            )
        ]

        cell = _Context(report).cell("Sends the host profile out")

        assert cell == "Sends the host profile out **[not established by this run: x]**"

    def test_a_report_stored_before_the_field_renders_unmarked(self) -> None:
        report = _report()
        report.executive_summary = "The sample exfiltrates documents."

        md = MarkdownRenderer().render(report)

        assert "The sample exfiltrates documents.\n" in md
        assert "not established by this run" not in md
