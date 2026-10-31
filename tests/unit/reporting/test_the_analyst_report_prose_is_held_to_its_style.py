"""The analyst report's prose: written by the composer, held to its style, never rewritten.

REPORT-PRO's composer step (T-472). The composer writes four sections of the
analyst report beside the technical spine — the executive summary's capability
bullets, the conclusion, the limitations paragraph and one procedure per
published technique — and every section's prose is held to the report's style:
no confidence written as a number, no word of how the report was made. A
finding is shown to the model once; a sentence that stays is marked where it
stands, never rewritten. The channel table binds each value to the code that
holds it (T-407), and the encryption table is asked for by its fields (T-408).

The models are stubs: each answer below is written by hand, good and bad.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

from langchain_core.messages import AIMessage, BaseMessage

from maljan.pipeline.validation import (
    CHANNEL_BINDING_CODE,
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    NUMERIC_CONFIDENCE_CODE,
    PROCESS_WORDS_CODE,
    PROSE_SHAPE_CODE,
    VALUE_NOT_CARRIED_CODE,
    EntryTexts,
)
from maljan.reporting import composer as composer_module
from maljan.reporting.composer import _EXAMPLES, _INSTRUCTIONS, ReportComposer
from maljan.reporting.composer_pro import (
    MAX_SUMMARY_BULLETS,
    channel_binding_violations,
    conclusion_shape_violations,
    limitations_shape_violations,
    procedure_value_violations,
    procedure_violations,
    statements_to_fold,
    style_violations,
    summary_shape_violations,
    summary_value_violations,
)
from maljan.reporting.models import (
    C2Channel,
    CapabilityBullet,
    CapabilityCell,
    Conclusion,
    ConfigItem,
    EncryptionScheme,
    EvidenceIndexRow,
    FileHashes,
    FlaggedStatement,
    FlowStep,
    KeyFinding,
    MalwareReport,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
    SeverityAssessment,
    StaticAnalysis,
    TechnicalAnalysis,
    TechnicalSubsection,
    TechniqueProcedure,
    TTPMapping,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.layout import ANALYST
from maljan.reporting.renderers.markdown import MarkdownRenderer, confidence_word
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _report(**over: Any) -> MalwareReport:
    fields: dict[str, Any] = {
        "identity": SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.exe"),
        "verdict": "Malware",
        "overall_confidence": 0.85,
        "generated_at": datetime(2026, 1, 1, tzinfo=UTC),
        "executive_summary": "The sample encrypts files [ev_0002].",
        "key_findings": [KeyFinding(text="It encrypts files.", evidence_ids=["ev_0002"])],
        "capability_matrix": [
            CapabilityCell(
                tactic="TA0040",
                tactic_name="Impact",
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                evidence=["Encrypts each file with ChaCha20 [ev_0002]. Then renames it."],
            )
        ],
        "ttp_mappings": [
            TTPMapping(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactic="TA0040",
                tactic_name="Impact",
            )
        ],
        "evidence_index": [
            EvidenceIndexRow(id=f"ev_000{n}", agent="static", tool="tool") for n in range(1, 5)
        ],
    }
    fields.update(over)
    return MalwareReport(**fields)


# ---------------------------------------------------------------------------
# Goal 1: no confidence as a number, no word of how the report was made
# ---------------------------------------------------------------------------


class TestTheStyleCheck:
    def test_prose_in_the_sample_s_terms_passes(self) -> None:
        good = {
            "body": "Routine 0x3a24 renames the file and deletes it on close; we assess with "
            "high confidence that this removes the image. Its user agent is a fixed string, "
            "and a producer/consumer queue feeds the worker. It reads the CPU's model name.",
            "evidence_refs": ["ev_0002"],
        }
        assert style_violations(good) == []

    def test_a_confidence_written_as_a_number_is_found_in_each_shape(self) -> None:
        for sentence in (
            "The overall confidence is 0.85.",
            "The family is assessed (confidence 0.60).",
            "The 0.35 confidence reflects that doubt.",
            "It is a stealer with 85% confidence.",
        ):
            found = style_violations({"body": sentence})
            assert [v.code for v in found] == [NUMERIC_CONFIDENCE_CODE], sentence
            assert found[0].quoted == (sentence,)

    def test_a_number_not_attached_to_a_confidence_word_is_no_confidence(self) -> None:
        for sentence in (
            "It sleeps (0.50) seconds between tries.",
            "The loader reports version (1.25).",
            "With high confidence, version 1.0 is the one shipped.",
            "We are confident it encrypts 100% of each file.",
            "The family is assessed (0.60).",
        ):
            assert style_violations({"body": sentence}) == [], sentence

    def test_a_process_word_is_found_and_its_sentence_quoted(self) -> None:
        payload = {"body": "The key is 12345. The ledger holds no listing of 0x5030."}
        (found,) = style_violations(payload)
        assert found.code == PROCESS_WORDS_CODE
        assert found.quoted == ("The ledger holds no listing of 0x5030.",)
        assert found.labels == ("The ledger",)
        assert found.path == "body"

    def test_each_process_word_of_the_list(self) -> None:
        for sentence in (
            "The judge kept the claim.",
            "A tool call returned the table.",
            "The report model wrote that it decodes strings.",
            "Analyst claim 5 says so.",
            "Per the judge, it is malicious.",
            "Ledger entry 12 holds the listing.",
        ):
            assert [v.code for v in style_violations({"text": sentence})] == [PROCESS_WORDS_CODE], (
                sentence
            )

    def test_a_sample_s_own_term_is_no_process_word(self) -> None:
        for sentence in (
            "It keeps a ledger of victims in its configuration.",
            "The producer thread fills the queue the sender drains.",
            "It steals LLM API keys from the browser profile.",
            "Its tool outputs are uploaded to the server.",
            "It reads the model of the device from the registry.",
            "The judge parameter selects the payload.",
        ):
            assert style_violations({"body": sentence}) == [], sentence

    def test_a_phrasing_the_section_was_shown_is_the_evidence_s_term(self) -> None:
        payload = {"body": "The ledger holds the operator's wallet list."}
        assert style_violations(payload)
        shown = "strings: 'the ledger holds' at 0x4010"
        assert style_violations(payload, evidence=shown) == []

    def test_an_agent_s_identifier_name_is_a_process_word(self) -> None:
        (found,) = style_violations({"body": "static_r2 read the export."}, ["static_r2"])
        assert found.labels == ("static_r2",)

    def test_the_sample_s_values_are_not_read_as_prose(self) -> None:
        payload = {"items": [{"key": "judge", "value": "ledger 0.85 confidence"}]}
        assert style_violations(payload) == []

    def test_a_nested_field_names_its_path(self) -> None:
        payload = {
            "steps": [{"order": 1, "action": "Ok."}, {"order": 2, "action": "Per the judge, ok."}]
        }
        (found,) = style_violations(payload)
        assert found.path == "steps[1].action"

    def test_both_findings_are_kept_and_marked_where_they_stand(self) -> None:
        for code in (NUMERIC_CONFIDENCE_CODE, PROCESS_WORDS_CODE):
            assert code in KEPT_WITH_A_FINDING
            assert code in MARKED_IN_PLACE
        for code in (PROSE_SHAPE_CODE, CHANNEL_BINDING_CODE):
            assert code in KEPT_WITH_A_FINDING
            assert code not in MARKED_IN_PLACE

    def test_a_kept_sentence_is_marked_in_the_analyst_report_and_its_words_stand(self) -> None:
        sentence = "The ledger holds no listing of 0x5030."
        report = _report(
            technical_analysis=TechnicalAnalysis(
                packing_obfuscation=TechnicalSubsection(
                    title="Packing", body=f"It packs. {sentence}"
                )
            ),
            flagged_statements=[
                FlaggedStatement(sentence=sentence, code=PROCESS_WORDS_CODE, label="ledger")
            ],
        )
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        assert f"{sentence} **[names how the report was made: ledger]**" in markdown


# ---------------------------------------------------------------------------
# The four sections' shapes
# ---------------------------------------------------------------------------


def _bullets(n: int) -> dict[str, Any]:
    return {"bullets": [{"text": f"Routine 0x{n:x}{i} does one thing."} for i in range(n)]}


class TestTheShapes:
    def test_eight_bullets_pass_and_nine_are_asked_about(self) -> None:
        assert summary_shape_violations(_bullets(MAX_SUMMARY_BULLETS)) == []
        (found,) = summary_shape_violations(_bullets(MAX_SUMMARY_BULLETS + 1))
        assert found.code == PROSE_SHAPE_CODE and found.path == "bullets"

    def test_a_bullet_of_three_sentences_is_more_than_one_line(self) -> None:
        payload = {"bullets": [{"text": "The sample packs. It decodes. It runs."}]}
        (found,) = summary_shape_violations(payload)
        assert found.path == "bullets[0].text"

    def test_a_conclusion_is_two_or_three_paragraphs(self) -> None:
        assert conclusion_shape_violations({"body": "One.\n\nTwo."}) == []
        assert conclusion_shape_violations({"body": "One.\n\nTwo.\n\nThree."}) == []
        assert [v.code for v in conclusion_shape_violations({"body": "One only."})] == [
            PROSE_SHAPE_CODE
        ]
        assert conclusion_shape_violations({"body": "1.\n\n2.\n\n3.\n\n4."})
        assert conclusion_shape_violations({"body": ""}) == []

    def test_limitations_are_one_paragraph(self) -> None:
        assert limitations_shape_violations({"body": "In the analysed sample, x."}) == []
        assert limitations_shape_violations({"body": "One.\n\nTwo."})

    def test_a_procedure_is_one_sentence_for_a_published_technique(self) -> None:
        good = {"procedures": [{"technique_id": "T1486", "procedure": "Encrypts files."}]}
        assert procedure_violations(good, ["T1486"]) == []
        unknown = {"procedures": [{"technique_id": "T9999", "procedure": "Does it."}]}
        assert [v.path for v in procedure_violations(unknown, ["T1486"])] == [
            "procedures[0].technique_id"
        ]
        long = {"procedures": [{"technique_id": "T1486", "procedure": "Encrypts. Renames."}]}
        assert [v.path for v in procedure_violations(long, ["T1486"])] == [
            "procedures[0].procedure"
        ]


# ---------------------------------------------------------------------------
# The composer writes the sections, and asks a bad answer once
# ---------------------------------------------------------------------------

_LEAD = "The evidence for the "


def _section_of(messages: list[BaseMessage]) -> str:
    text = str(messages[1].content)
    start = text.index(_LEAD) + len(_LEAD)
    return text[start : text.index(" section follows.", start)]


class _Stub:
    """Answers each section from ``answers``; a list answers its calls in turn."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: dict[str, list[str]] = {}

    def with_structured_output(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("unused")

    async def ainvoke(self, messages: list[BaseMessage], **_: Any) -> AIMessage:
        section = _section_of(messages)
        self.asked.setdefault(section, []).append(str(messages[-1].content))
        answer = self.answers.get(section, {})
        if isinstance(answer, list):
            answer = answer[min(len(self.asked[section]), len(answer)) - 1]
        return AIMessage(content=json.dumps(answer))


_GOOD = {
    "summary": {
        "bullets": [
            {"text": "The sample encrypts every file with ChaCha20.", "evidence_refs": ["ev_0002"]}
        ]
    },
    "conclusion": {
        "body": "The sample is a file encryptor [ev_0002].\n\nWe assess with high confidence "
        "that encrypted files cannot be restored without its key.",
        "evidence_refs": ["ev_0002"],
    },
    "limitations": {
        "body": "In the analysed sample the key exchange was not recovered.",
        "evidence_refs": [],
    },
    "attack_procedures": {
        "procedures": [
            {
                "technique_id": "T1486",
                "procedure": "Encrypts each file with ChaCha20 and renames it.",
                "evidence_refs": ["ev_0002"],
            }
        ]
    },
}


def _isr() -> dict[str, Any]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[ClaimEvidence(claim="Encrypts files", evidence_ref="ev_0002", confidence=0.7)],
        )
    }


def _compose(report: MalwareReport, answers: dict[str, Any]) -> tuple[_Stub, ReportComposer]:
    llm = _Stub(answers)
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    with patch.object(composer_module, "structured_output_supported_for_llm", return_value=False):
        asyncio.run(comp.compose(report, _isr(), citable_ids=[f"ev_000{n}" for n in range(1, 5)]))
    return llm, comp


class TestTheComposerWritesTheAnalystSections:
    def test_good_answers_land_on_the_report_unasked(self) -> None:
        report = _report()
        llm, comp = _compose(report, _GOOD)
        ta = report.technical_analysis
        assert ta is not None
        assert [b.text for b in ta.capability_summary] == [
            "The sample encrypts every file with ChaCha20."
        ]
        assert ta.analyst_conclusion is not None and "\n\n" in ta.analyst_conclusion.body
        assert ta.analyst_limitations is not None
        assert [p.technique_id for p in ta.technique_procedures] == ["T1486"]
        for section in _GOOD:
            assert len(llm.asked[section]) == 1, section
        codes = set(comp.validation_tally.to_dict().get("by_code") or {})
        assert not codes & {NUMERIC_CONFIDENCE_CODE, PROCESS_WORDS_CODE, PROSE_SHAPE_CODE}

    def test_nine_bullets_are_asked_about_once_and_the_fixed_answer_kept(self) -> None:
        report = _report()
        answers = dict(_GOOD, summary=[_bullets(9), _bullets(8)])
        llm, _comp = _compose(report, answers)
        assert len(llm.asked["summary"]) == 2
        assert PROSE_SHAPE_CODE in llm.asked["summary"][1]
        assert report.technical_analysis is not None
        assert len(report.technical_analysis.capability_summary) == 8

    def test_a_process_word_kept_after_the_question_is_marked_not_rewritten(self) -> None:
        report = _report()
        bad = {"body": "The judge kept 0x5030 as the sender. It sends.", "evidence_refs": []}
        answers = dict(_GOOD, conclusion=[bad, bad])
        llm, _comp = _compose(report, answers)
        assert len(llm.asked["conclusion"]) == 2
        assert PROCESS_WORDS_CODE in llm.asked["conclusion"][1]
        ta = report.technical_analysis
        assert ta is not None and ta.analyst_conclusion is not None
        assert ta.analyst_conclusion.body == bad["body"]
        assert any(
            row.code == PROCESS_WORDS_CODE and row.sentence.startswith("The judge kept")
            for row in report.flagged_statements
        )

    def test_a_confidence_number_in_a_spine_section_is_asked_about(self) -> None:
        report = _report()
        bad = {"text": "A Windows file that encrypts files (confidence 0.60)."}
        good = {"text": "A Windows file that encrypts files, assessed with moderate confidence."}
        answers = dict(_GOOD, introduction=[bad, good])
        llm, _comp = _compose(report, answers)
        assert len(llm.asked["introduction"]) == 2
        assert NUMERIC_CONFIDENCE_CODE in llm.asked["introduction"][1]
        assert report.intro_background == good["text"]

    def test_the_summary_is_shown_the_key_findings_and_no_claim_in_force(self) -> None:
        report = _report()
        llm, _comp = _compose(report, _GOOD)
        prompt = llm.asked["summary"][0]
        assert "[summary finding 1]" in prompt and "It encrypts files." in prompt
        assert "Encrypts files —" not in prompt
        # The confidence is shown in words, never as the number.
        assert "0.85" not in prompt


# ---------------------------------------------------------------------------
# Goals 2-6: the analyst report prints what the composer wrote
# ---------------------------------------------------------------------------


def _composed(**ta: Any) -> MalwareReport:
    return _report(technical_analysis=TechnicalAnalysis(**ta))


class TestTheAnalystReportPrintsTheComposedProse:
    def test_the_summary_is_the_bullets_then_the_assessment_in_words(self) -> None:
        report = _composed(
            capability_summary=[
                CapabilityBullet(text="The sample encrypts files.", evidence_refs=["ev_0002"])
            ]
        )
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        summary = markdown.split("## 1. Executive summary", 1)[1].split("\n## ", 1)[0]
        assert "- The sample encrypts files." in summary
        assert "It encrypts files." not in summary
        assert "The sample encrypts files [" not in summary
        assert f"**Assessment:** the verdict is Malware ({confidence_word(0.85)})" in summary
        assert "0.85" not in summary

    def test_a_value_only_the_summary_paragraph_names_stays_beside_the_bullets(self) -> None:
        report = _composed(capability_summary=[CapabilityBullet(text="The sample encrypts.")])
        report.executive_summary = "It packs. It holds the mutex QZ_MUTEX_771 while it runs."
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        summary = markdown.split("## 1. Executive summary", 1)[1].split("\n## ", 1)[0]
        assert "It holds the mutex QZ_MUTEX_771 while it runs." in summary
        assert "It packs." not in summary

    def test_a_value_only_a_key_finding_names_keeps_the_finding(self) -> None:
        report = _composed(capability_summary=[CapabilityBullet(text="The sample encrypts.")])
        report.key_findings = [
            KeyFinding(text="It encrypts files."),
            KeyFinding(text="It is started as `rundll32 s.dll,#1`."),
        ]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        summary = markdown.split("## 1. Executive summary", 1)[1].split("\n## ", 1)[0]
        assert "rundll32 s.dll,#1" in summary
        assert "It encrypts files." not in summary

    def test_a_value_a_later_section_prints_does_not_keep_the_finding(self) -> None:
        report = _composed(
            capability_summary=[CapabilityBullet(text="The sample encrypts.")],
            configuration=[ConfigItem(key="mutex", value="QZ_MUTEX_771")],
        )
        report.key_findings = [KeyFinding(text="It holds QZ_MUTEX_771.")]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        summary = markdown.split("## 1. Executive summary", 1)[1].split("\n## ", 1)[0]
        assert "QZ_MUTEX_771" not in summary

    def test_a_key_finding_a_check_marked_stays_beside_the_bullets(self) -> None:
        marked = "It talks to 192.0.2.7."
        report = _composed(capability_summary=[CapabilityBullet(text="The sample encrypts files.")])
        report.key_findings = [
            KeyFinding(text="It encrypts files."),
            KeyFinding(text=marked),
        ]
        report.executive_summary = f"It packs. {marked}"
        report.flagged_statements = [
            FlaggedStatement(sentence=marked, code=PROCESS_WORDS_CODE, label="x")
        ]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        summary = markdown.split("## 1. Executive summary", 1)[1].split("\n## ", 1)[0]
        assert "It encrypts files." not in summary
        assert summary.count("**[names how the report was made: x]**") == 2
        assert "It packs." not in summary

    def test_a_marked_first_sentence_keeps_its_row_over_a_written_procedure(self) -> None:
        report = _composed(
            technique_procedures=[TechniqueProcedure(technique_id="T1486", procedure="Encrypts.")]
        )
        report.flagged_statements = [
            FlaggedStatement(
                sentence="Encrypts each file with ChaCha20 [ev_0002].",
                code=PROCESS_WORDS_CODE,
                label="x",
            )
        ]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        row = next(line for line in markdown.splitlines() if "| T1486 |" in line)
        assert "Encrypts each file with ChaCha20" in row

    def test_without_bullets_the_key_findings_stand(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_report())
        assert "- It encrypts files." in markdown

    def test_the_conclusion_is_the_composer_s_paragraphs(self) -> None:
        report = _composed(
            analyst_conclusion=TechnicalSubsection(
                title="Conclusion", body="First paragraph.\n\nSecond paragraph."
            )
        )
        report.severity = SeverityAssessment(
            rating="High",
            business_impact="Files are lost.",
            likely_targets=["finance"],
        )
        report.conclusion = Conclusion(sophistication_rating="medium", text="It is malware.")
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        conclusion = markdown.split("## 7. Conclusion", 1)[1].split("\n## ", 1)[0]
        assert "First paragraph.\n\nSecond paragraph." in conclusion
        # The platform's verdict sentence stands above them, its fields after them;
        # the judge's words, naming no value, are the bundle's.
        assert conclusion.index("The sample is assessed as") < conclusion.index("First paragraph.")
        assert conclusion.index("Second paragraph.") < conclusion.index("Likely targets: finance.")
        assert "Sophistication: medium." in conclusion
        assert "Files are lost." not in conclusion and "It is malware." not in conclusion

    def test_a_replaced_conclusion_sentence_naming_a_value_found_nowhere_else_stays(self) -> None:
        report = _composed(
            analyst_conclusion=TechnicalSubsection(title="Conclusion", body="One.\n\nTwo.")
        )
        report.conclusion = Conclusion(text="It is malware. Its key sits at 0xFD30 only.")
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        conclusion = markdown.split("## 7. Conclusion", 1)[1].split("\n## ", 1)[0]
        assert "Its key sits at 0xFD30 only." in conclusion
        assert "It is malware." not in conclusion

    def test_without_one_the_deterministic_conclusion_stands(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_report())
        assert "The sample is assessed as" in markdown

    def test_the_limitations_are_one_paragraph_with_the_platform_s_caveats(self) -> None:
        report = _composed(
            analyst_limitations=TechnicalSubsection(
                title="Limitations", body="In the analysed sample the key was not recovered."
            )
        )
        report.claims_not_discussed = ["static 1"]  # type: ignore[assignment]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        section = markdown.split("## 11. Limitations", 1)[1].split("\n## ", 1)[0]
        body = [line for line in section.strip().splitlines() if line.strip()]
        assert body[0].startswith("In the analysed sample the key was not recovered.")
        assert "not discussed in this report" in body[0]
        # The platform's own sentences stay after the composed paragraph.
        assert "Without a sandbox observation" in body[0]

    def test_a_written_procedure_replaces_the_first_sentence_pick(self) -> None:
        report = _composed(
            technique_procedures=[
                TechniqueProcedure(
                    technique_id="T1486", procedure="Encrypts and renames files with ChaCha20."
                )
            ]
        )
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        row = next(line for line in markdown.splitlines() if "| T1486 |" in line)
        assert "Encrypts and renames files with ChaCha20." in row
        assert "Encrypts each file with ChaCha20" not in row

    def test_a_procedure_that_drops_a_value_found_nowhere_else_keeps_the_first_sentence(
        self,
    ) -> None:
        report = _composed(
            technique_procedures=[TechniqueProcedure(technique_id="T1486", procedure="Encrypts.")]
        )
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        row = next(line for line in markdown.splitlines() if "| T1486 |" in line)
        assert "Encrypts each file with ChaCha20" in row

    def test_without_one_the_first_sentence_is_the_procedure(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_report())
        row = next(line for line in markdown.splitlines() if "| T1486 |" in line)
        assert "Encrypts each file with ChaCha20" in row
        assert "Then renames it" not in row


# ---------------------------------------------------------------------------
# Goal 7: the deterministic parts
# ---------------------------------------------------------------------------


class TestTheDeterministicParts:
    def _flow(self, n: int) -> MalwareReport:
        steps = [
            FlowStep(order=i, action=f"Step {i} runs routine 0x{i}000. More.", voice="assessed")
            for i in range(1, n + 1)
        ]
        return _composed(execution_flow=steps)

    def test_the_flow_is_a_diagram_in_markdown_and_a_figure_in_html(self) -> None:
        report = self._flow(3)
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        assert "```mermaid\nflowchart TD" in markdown
        assert 's1["1. Step 1 runs routine 0x1000. (assessed)"]' in markdown
        assert "s2 --> s3" in markdown
        html = HtmlRenderer(layout=ANALYST).render(report)
        assert "language-mermaid" not in html
        assert 'id="fig-execution-flow"' in html
        assert "<svg" in html.split('id="fig-execution-flow"', 1)[1].split("</figure>", 1)[0]

    def test_one_step_draws_no_diagram(self) -> None:
        report = self._flow(1)
        assert "```mermaid" not in MarkdownRenderer(layout=ANALYST).render(report)
        assert "fig-execution-flow" not in HtmlRenderer(layout=ANALYST).render(report)

    def test_the_single_file_report_and_the_bundle_draw_none(self) -> None:
        report = self._flow(3)
        assert "```mermaid" not in MarkdownRenderer().render(report)

    def test_a_recorded_message_format_is_annotated_field_by_field(self) -> None:
        report = _composed(configuration=[ConfigItem(key="group", value="Alpha")])
        report.c2_channels = [
            C2Channel(name="Check-in", beacon_format="id=%08x&group=%s&v=%d.%d [ev_0003]")
        ]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        block = markdown.split("Message example, Check-in", 1)[1].split("```", 2)[1]
        assert "id=%08x" in block and "a hexadecimal number" in block
        assert "group=%s" in block
        assert "a text; a configuration item of the same name holds Alpha" in block
        assert 'a decimal number, then ".", then a decimal number' in block

    def test_a_format_of_another_shape_gets_no_example(self) -> None:
        report = _report(
            c2_channels=[C2Channel(name="Check-in", beacon_format="A JSON body with an id field")]
        )
        assert "Message example" not in MarkdownRenderer(layout=ANALYST).render(report)

    def test_an_observed_request_is_its_table_row_printed_once(self) -> None:
        report = _report(
            network=NetworkIOCs(
                urls=[
                    NetworkURL(
                        url="https://c2.example.invalid/gate?x=1",
                        method="POST",
                        source="sandbox",
                        user_agent="Agent/1.0",
                    )
                ]
            )
        )
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        assert "Request example" not in markdown
        assert markdown.count("hxxps://c2[.]example[.]invalid/gate?x=1") == 1

    def test_a_step_cannot_break_out_of_its_diagram_node(self) -> None:
        steps = [
            FlowStep(order=1, action='Runs "]; click s1 call evil(); s9["x. Then more.'),
            FlowStep(order=2, action="Writes <script>alert(1)</script> to a file."),
        ]
        report = _composed(execution_flow=steps)
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        node = next(line for line in markdown.splitlines() if line.strip().startswith("s1["))
        assert node.count('"') == 2 and "#quot;" in node
        html = HtmlRenderer(layout=ANALYST).render(report)
        figure = html.split('id="fig-execution-flow"', 1)[1].split("</figure>", 1)[0]
        assert "<script>" not in figure and "&lt;script&gt;" in figure

    def test_with_neither_there_is_no_example(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_report())
        assert "Message example" not in markdown


# ---------------------------------------------------------------------------
# Goal 5: the statements only the ATT&CK section held are folded in
# ---------------------------------------------------------------------------


class TestTheStatementsAreFoldedIntoTheirSections:
    def test_a_rule_only_technique_s_statements_go_to_its_tactic_s_section(self) -> None:
        report = _report(
            static=StaticAnalysis(
                api_technique_hits=[
                    {
                        "technique_id": "T1070.004",
                        "matched_apis": ["DeleteFileW"],
                        "resolved_apis": ["DeleteFileW"],
                    }
                ]
            ),
            capability_matrix=[
                CapabilityCell(
                    tactic="TA0005",
                    tactic_name="Defense Evasion",
                    technique_id="T1070.004",
                    technique_name="File Deletion",
                    statements=["static: Routine 0x3a24 renames the image to :stream."],
                )
            ],
        )
        folded = statements_to_fold(report)
        assert list(folded) == ["evasion_antiforensics"]
        (claim,) = folded["evasion_antiforensics"]
        assert claim["claim"] == "Routine 0x3a24 renames the image to :stream."
        assert claim["label"] == "T1070.004 statement"

    def test_a_technique_a_rule_matched_on_imports_folds_nothing(self) -> None:
        report = _report(
            static=StaticAnalysis(
                api_technique_hits=[
                    {
                        "technique_id": "T1070.004",
                        "matched_apis": ["DeleteFileW"],
                        "resolved_apis": [],
                    }
                ]
            ),
            capability_matrix=[
                CapabilityCell(
                    tactic="TA0005",
                    tactic_name="Defense Evasion",
                    technique_id="T1070.004",
                    technique_name="File Deletion",
                    statements=["static: It deletes files."],
                )
            ],
        )
        assert statements_to_fold(report) == {}


# ---------------------------------------------------------------------------
# T-407: a channel row is bound to the code that holds its values
# ---------------------------------------------------------------------------


def _entry(entry_id: str, output: Any) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="pipeline", tool="tool", output=json.dumps(output))


# The haiku7 shape: the decoder's answer places each decoded text with the
# function that references it, and the function index lists each function's
# decoded texts. The two URLs are referenced from 0x6988 (which stores them in
# a table); "POST" and "GET" from 0x5030 (the request routine, which takes the
# POST branch); 0x8d90 fetches URLs a command supplies and references neither.
_DECODED = {
    "results": [
        {
            "rva": "0x10256",
            "text": "https://one.example.invalid/live/",
            "references": [{"at": "0x69af", "function": "0x6988"}],
        },
        {
            "rva": "0x1027e",
            "text": "https://two.example.invalid/live/",
            "references": [{"at": "0x6a1b", "function": "0x6988"}],
        },
        {"rva": "0xfba0", "text": "POST", "references": [{"at": "0x5170", "function": "0x5030"}]},
        {"rva": "0xfbb0", "text": "GET", "references": [{"at": "0x5180", "function": "0x5030"}]},
    ]
}
_INDEX = {
    "rows": [
        {
            "function": "0x5030",
            "decoded_strings": [{"text": "GET"}, {"text": "POST"}],
            "callers": ["0x4d20"],
        },
        {"function": "0x8d90", "decoded_strings": [], "callers": ["0x4110"]},
    ]
}
_URLS = ["https://one.example.invalid/live/", "https://two.example.invalid/live/"]


def _entries() -> EntryTexts:
    return EntryTexts.from_ledger([_entry("ev_0021", _DECODED), _entry("ev_0025", _INDEX)])


class TestAChannelRowIsBoundToItsCode:
    def test_the_haiku7_shape_is_asked_about_on_the_payload_fetch_row(self) -> None:
        bad = {
            "channels": [
                {
                    "name": "Check-in",
                    "protocol": 'HTTP POST via routine 0x5030; the "POST" string at 0xfba0',
                    "endpoints": _URLS,
                },
                {
                    "name": "Payload retrieval",
                    "protocol": 'HTTP GET via routine 0x8d90; "GET" string at 0xfbb0',
                    "endpoints": _URLS,
                },
            ]
        }
        found = channel_binding_violations(bad, _entries())
        assert {v.code for v in found} == {CHANNEL_BINDING_CODE}
        verb = next(v for v in found if v.values == ("GET",))
        assert verb.path == "channels[1]"
        assert "0x5030" in verb.message and "channel 1 (Check-in)" in verb.message
        shared = next(v for v in found if v.path == "channels")
        assert set(shared.values) == set(_URLS)
        assert "0x6988" in shared.message

    def test_a_row_given_only_its_own_code_s_values_passes(self) -> None:
        good = {
            "channels": [
                {
                    "name": "Check-in",
                    "protocol": "HTTP POST via routine 0x5030, which reads the table 0x6988 fills; "
                    '"POST" at 0xfba0',
                    "endpoints": _URLS,
                },
                {
                    "name": "Payload retrieval",
                    "protocol": "HTTP via routine 0x8d90, to a URL the command supplies",
                    "endpoints": [],
                },
            ]
        }
        assert channel_binding_violations(good, _entries()) == []

    def test_one_channel_or_no_entries_asks_nothing(self) -> None:
        one = {"channels": [{"name": "x", "protocol": "routine 0x8d90 GET", "endpoints": _URLS}]}
        assert channel_binding_violations(one, _entries()) == []
        two = {"channels": [{"name": "a", "endpoints": _URLS}, {"name": "b", "endpoints": _URLS}]}
        assert channel_binding_violations(two, None) == []

    def test_the_c2_section_is_told_to_bind_each_value_to_its_code(self) -> None:
        said = _INSTRUCTIONS["communications"]
        assert "name that code" in said
        assert "never copy the sample's whole list of endpoints into every channel" in said


# ---------------------------------------------------------------------------
# T-408: the encryption table is asked for by its fields, and a field without
# evidence is left out
# ---------------------------------------------------------------------------


class TestTheEncryptionTable:
    def test_each_field_is_described_and_the_example_is_a_valid_answer(self) -> None:
        said = _INSTRUCTIONS["encryption_scheme"]
        for field in EncryptionScheme.model_fields:
            assert f"{field}," in said or f"{field} " in said, field
        assert "leave every other field null" in said
        EncryptionScheme.model_validate(json.loads(_EXAMPLES["encryption_scheme"]))

    def test_a_field_left_null_prints_no_row(self) -> None:
        report = _composed(
            encryption_scheme=EncryptionScheme(
                cipher="RC4", key_source="A literal decoded at 0xfd30", evidence_ref="ev_0002"
            )
        )
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        assert "| Cipher | RC4" in markdown
        assert "Extension" not in markdown

    def test_an_answer_filling_the_extension_for_a_non_encryptor_prints_it_as_written(
        self,
    ) -> None:
        # Not rewritten: what the model wrote is printed; the prompt is the fix.
        report = _composed(encryption_scheme=EncryptionScheme(cipher="RC4", extension=".dat"))
        assert "| Extension | .dat" in MarkdownRenderer(layout=ANALYST).render(report)


# ---------------------------------------------------------------------------
# The composer is asked once about a value its section dropped
# ---------------------------------------------------------------------------


class TestADroppedValueIsAskedAbout:
    def test_a_finding_value_no_bullet_and_nothing_else_carries(self) -> None:
        findings = "It holds the mutex QZ_MUTEX_771. It is started as rundll32 s.dll,#1."
        bullets = {"bullets": [{"text": "The sample holds a mutex."}]}
        (found,) = summary_value_violations(bullets, findings, held="{}")
        assert found.code == VALUE_NOT_CARRIED_CODE
        assert "QZ_MUTEX_771" in found.values and "s.dll,#1" in found.values
        carried = {"bullets": [{"text": "The sample holds QZ_MUTEX_771; rundll32 s.dll,#1."}]}
        assert summary_value_violations(carried, findings, held="{}") == []
        # A value the report holds elsewhere is a later section's to state.
        assert (
            summary_value_violations(bullets, findings, held="QZ_MUTEX_771 rundll32 s.dll,#1") == []
        )

    def test_a_procedure_that_drops_its_first_claim_s_value(self) -> None:
        firsts = {"T1218.011": "The sample is started as rundll32.exe x.dll,#1."}
        dropped = {"procedures": [{"technique_id": "T1218.011", "procedure": "Runs via rundll32."}]}
        (found,) = procedure_value_violations(dropped, firsts)
        assert found.code == VALUE_NOT_CARRIED_CODE and "x.dll,#1" in found.values
        kept = {
            "procedures": [
                {"technique_id": "T1218.011", "procedure": "Started by rundll32.exe as x.dll,#1."}
            ]
        }
        assert procedure_value_violations(kept, firsts) == []

    def test_the_finding_is_kept_not_marked_and_asked_on_a_parsed_answer(self) -> None:
        from maljan.reporting.composer import ASKED_ON_A_PARSED_ANSWER

        assert VALUE_NOT_CARRIED_CODE in KEPT_WITH_A_FINDING
        assert VALUE_NOT_CARRIED_CODE not in MARKED_IN_PLACE
        assert VALUE_NOT_CARRIED_CODE in ASKED_ON_A_PARSED_ANSWER

    def test_the_summary_is_shown_the_summary_paragraph(self) -> None:
        report = _report(executive_summary="It holds QZ_MUTEX_771.")
        llm, _comp = _compose(report, _GOOD)
        assert "[summary paragraph]" in llm.asked["summary"][0]
        assert "QZ_MUTEX_771" in llm.asked["summary"][0]


# ---------------------------------------------------------------------------
# The exemption reads the sample's evidence only, never the platform's own text
# ---------------------------------------------------------------------------


class TestThePlatformsOwnTextExemptsNothing:
    def test_run_state_and_claims_in_the_prompt_leave_the_phrasings_flagged(self) -> None:
        bad = {"text": "Per the analyst claims and claim number 3, the ledger shows it."}
        good = {"text": "A Windows file that encrypts files."}
        llm = _Stub(dict(_GOOD, introduction=[bad, good]))
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        with patch.object(
            composer_module, "structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(
                comp.compose(
                    _report(),
                    _isr(),
                    facts_block="DETERMINISTIC FACTS: the ledger holds 4 entries.",
                    run_state="Stages run: static. the ledger holds analyst claims.",
                    citable_ids=[f"ev_000{n}" for n in range(1, 5)],
                )
            )
        # The prompt carried the run state, the facts and the claims heading ...
        assert "analyst claim" in llm.asked["introduction"][0].lower()
        assert "the ledger" in llm.asked["introduction"][0].lower()
        # ... and the phrasings were asked about all the same.
        assert len(llm.asked["introduction"]) == 2
        assert PROCESS_WORDS_CODE in llm.asked["introduction"][1]
        assert comp._shown["introduction"] == ""

    def test_the_exemption_is_the_tool_outputs_and_the_code(self) -> None:
        from maljan.reporting.composer_pro import evidence_text

        bundle = {
            "claims": [{"claim": "the ledger"}],
            "facts": {"x": "tool calls"},
            "tool_outputs": [{"tool": "strings", "output": "the ledger of victims"}],
            "function_code": [{"symbol": "0x10", "output": "claim_number = 3"}],
        }
        shown = evidence_text(bundle)
        assert "the ledger of victims" in shown and "claim_number" in shown
        assert "tool calls" not in shown


# ---------------------------------------------------------------------------
# What counts as a value a replaced text carries
# ---------------------------------------------------------------------------


class TestWhatCountsAsAValue:
    def test_the_shapes_that_are_always_values(self) -> None:
        from maljan.reporting.composer_pro import ValueReader, carried_values

        text = (
            "It injects into explorer.exe, writes HKCU\\Software\\Qz\\run, mails "
            "ops@drop.example.invalid, reads 0x4f and runs 'cfg-blob 7'."
        )
        found = carried_values(text, ValueReader(sample="", family=""))
        for value in (
            "explorer.exe",
            "HKCU\\Software\\Qz\\run",
            "ops@drop.example.invalid",
            "drop.example.invalid",
            "0x4f",
            "cfg-blob 7",
        ):
            assert value in found, value

    def test_the_attributed_family_is_a_value(self) -> None:
        from maljan.reporting.composer_pro import ValueReader, carried_values

        reader = ValueReader(family="IcedID")
        assert "IcedID" in carried_values("Some engines label the file IcedID.", reader)
        assert carried_values("Some engines label the file.", reader) == []

    def test_no_attack_id_generic_token_or_ordinary_quoted_word(self) -> None:
        from maljan.reporting.composer_pro import ValueReader, carried_values

        reader = ValueReader()
        assert carried_values("It maps to T1055 and TA0005.", reader) == []
        assert carried_values("It uses SHA256 hashing.", reader) == []
        assert carried_values("It is a Win32 program.", reader) == []
        assert carried_values("It calls it 'sample'.", reader) == []

    def test_an_identifier_counts_only_where_the_run_s_entries_hold_it(self) -> None:
        from maljan.reporting.composer_pro import ValueReader, carried_values

        reader = ValueReader(sample="createmutexw qz_mutex_771")
        found = carried_values("It calls CreateMutexW for QZ_MUTEX_771 via GetProcAddress.", reader)
        assert "CreateMutexW" in found and "QZ_MUTEX_771" in found
        assert "GetProcAddress" not in found

    def test_generic_and_attack_tokens_keep_no_finding(self) -> None:
        report = _composed(capability_summary=[CapabilityBullet(text="The sample encrypts.")])
        report.key_findings = [
            KeyFinding(text="It uses SHA256 hashing."),
            KeyFinding(text="It is a Win32 program."),
            KeyFinding(text="It maps to T1486."),
            KeyFinding(text="It injects into explorer.exe via VirtualAllocEx."),
        ]
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        summary = markdown.split("## 1. Executive summary", 1)[1].split("\n## ", 1)[0]
        assert "SHA256" not in summary and "Win32" not in summary
        assert "It maps to T1486." not in summary
        assert "explorer.exe" in summary

    def test_a_defanged_value_is_carried(self) -> None:
        from maljan.reporting.composer_pro import values_not_carried

        assert values_not_carried(["ops@drop.example"], "mail ops[@]drop[.]example") == []

    def test_a_sentence_s_stop_is_no_part_of_a_key_path_or_file_name(self) -> None:
        from maljan.reporting.composer_pro import ValueReader, carried_values, values_not_carried

        text = (
            "It writes HKCU\\Software\\Qz\\Run. It drops C:\\Temp\\a.bin; then b.dll, then c.exe:"
        )
        found = carried_values(text, ValueReader())
        assert "HKCU\\Software\\Qz\\Run" in found
        assert "C:\\Temp\\a.bin" in found
        assert "b.dll" in found and "c.exe" in found
        printed = "Run key HKCU\\Software\\Qz\\Run holds the path C:\\Temp\\a.bin, b.dll and c.exe"
        assert values_not_carried(found, printed) == []

    def test_a_quoted_word_the_sample_holds_is_a_value(self) -> None:
        from maljan.reporting.composer_pro import ValueReader, carried_values

        text = "It decrypts its strings with the key 'secretkey'."
        assert carried_values(text, ValueReader(sample="key: secretkey")) == ["secretkey"]
        assert carried_values(text, ValueReader(sample="key: other")) == []
        assert carried_values(text, ValueReader()) == []
