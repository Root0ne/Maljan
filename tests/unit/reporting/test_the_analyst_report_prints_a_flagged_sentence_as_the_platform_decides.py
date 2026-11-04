"""The analyst report prints a sentence a check left standing as the platform decides (T-555).

A sentence flagged only for a value the run does not publish stands where it
writes a state right after each such value; one flagged only for a confidence
written as a number stands with the confidence in words; any other is left
out, and the section says how many it left out. A value only a left-out
sentence names brings no replaced text back; a closing section every sentence
of which was left out says so and never falls back to the words it replaced;
the judge's answer when asked is the bundle's. The bundle prints each sentence
with its mark. Every value is a neutral one.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from maljan.reporting.models import (
    CapabilityBullet,
    CapabilityCell,
    Conclusion,
    FileHashes,
    FlaggedStatement,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.layout import ANALYST, BUNDLE
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import judge_kept_note

UNPUBLISHED = "The beacon also reaches 192.0.2.7 on port 80."
PROCESS = "The ledger holds no listing of 0x5030."
NUMERIC = "It is malware with confidence 0.95."


def _report(**ta: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ef" * 32), file_name="sample.exe"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(**ta),
    )


def _analyst(report: MalwareReport) -> str:
    return MarkdownRenderer(layout=ANALYST).render(report)


def _section(markdown: str, heading: str) -> str:
    return markdown.split(heading, 1)[1].split("\n## ", 1)[0]


def test_an_unpublished_value_s_sentence_stands_where_it_states_the_value_s_state() -> None:
    stated = "The beacon also reaches 192.0.2.7 (not a published indicator) on port 80."
    report = _report(
        command_and_control=TechnicalSubsection(
            title="C2", body=f"It beacons. {stated} {UNPUBLISHED}"
        )
    )
    report.flagged_statements = [
        FlaggedStatement(sentence=stated, code="report.unpublished_value", label="x"),
        FlaggedStatement(sentence=UNPUBLISHED, code="report.unpublished_value", label="y"),
    ]
    c2 = _section(_analyst(report), "## 6. Command and control")
    # Stated beside its value: the sentence stands, the mark is the bundle's.
    assert "192[.]0[.]2[.]7 (not a published indicator) on port 80." in c2
    # Named bare: the sentence is left out and counted.
    assert "on port 80. The beacon" not in c2 and c2.count("192[.]0[.]2[.]7") == 1
    assert "_1 sentence of this section was left out" in c2
    assert "**[" not in c2
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert "**[not published by this run: x" in bundle
    assert "**[not published by this run: y" in bundle


def test_a_bracket_restating_the_table_s_reason_states_the_publish_state() -> None:
    # As haiku10's c.pki.goog sentence did: the table's "no: no row of this run's IOC
    # table holds it", restated under a negation.
    sentence = "Its Host header is cdn.example.org (not a row of this run's IOC table) today."
    report = _report(
        command_and_control=TechnicalSubsection(title="C2", body=f"It beacons. {sentence}")
    )
    report.flagged_statements = [
        FlaggedStatement(sentence=sentence, code="report.unpublished_value", label="x")
    ]
    c2 = _section(_analyst(report), "## 6. Command and control")
    assert "cdn[.]example[.]org (not a row of this run's IOC table) today." in c2
    assert "left out" not in c2 and "**[" not in c2


@pytest.mark.parametrize(
    "bracket",
    [
        "(a published indicator)",
        "(UDP 53)",
    ],
)
def test_a_bracket_not_saying_unpublished_states_no_publish_state(bracket: str) -> None:
    sentence = f"The beacon also reaches 192.0.2.7 {bracket} on port 80."
    report = _report(
        command_and_control=TechnicalSubsection(title="C2", body=f"It beacons. {sentence}")
    )
    report.flagged_statements = [
        FlaggedStatement(sentence=sentence, code="report.unpublished_value", label="x")
    ]
    c2 = _section(_analyst(report), "## 6. Command and control")
    assert "192[.]0[.]2[.]7" not in c2 and "**[" not in c2
    assert "_1 sentence of this section was left out" in c2


def test_a_numeric_confidence_is_worded_and_another_flag_leaves_its_sentence_out() -> None:
    report = _report(
        packing_obfuscation=TechnicalSubsection(
            title="Packing", body=f"It packs. {NUMERIC} {PROCESS}"
        )
    )
    report.flagged_statements = [
        FlaggedStatement(sentence=NUMERIC, code="report.numeric_confidence", label="0.95"),
        FlaggedStatement(sentence=PROCESS, code="report.process_words", label="ledger"),
    ]
    functionality = _section(_analyst(report), "## 5. Functionality")
    assert "It packs. It is malware with high confidence." in functionality
    assert "0.95" not in functionality and "0x5030" not in functionality
    assert "_1 sentence of this section was left out; the bundle lists each with the reason._" in (
        functionality
    )


def test_a_value_only_a_left_out_sentence_names_brings_no_finding_back() -> None:
    sentence = "The ledger shows it reaches 192.0.2.9."
    report = _report(
        capability_summary=[CapabilityBullet(text="The sample beacons.")],
        command_and_control=TechnicalSubsection(title="C2", body=f"It beacons. {sentence}"),
    )
    report.key_findings = [KeyFinding(text="It contacts 192.0.2.9.")]
    report.flagged_statements = [
        FlaggedStatement(sentence=sentence, code="report.process_words", label="ledger")
    ]
    summary = _section(_analyst(report), "## 1. Executive summary")
    assert "192[.]0[.]2[.]9" not in summary and "192.0.2.9" not in summary


def test_a_closing_section_left_out_whole_says_so_and_never_falls_back() -> None:
    report = _report(
        analyst_conclusion=TechnicalSubsection(title="Conclusion", body=PROCESS),
        analyst_limitations=TechnicalSubsection(title="Limitations", body=""),
    )
    report.conclusion = Conclusion(text="The judge's own unchecked words.")
    report.flagged_statements = [
        FlaggedStatement(sentence=PROCESS, code="report.process_words", label="ledger")
    ]
    report.run_summary = {
        "validation": {
            "unresolved": [
                {"code": "agreement.dropped", "message": "left out", "subject": "limitations"}
            ]
        }
    }
    markdown = _analyst(report)
    conclusion = _section(markdown, "## 7. Conclusion")
    assert "The conclusion the report model wrote was left out" in conclusion
    assert "unchecked words" not in conclusion
    assert "_1 sentence of this section was left out" in conclusion
    limitations = _section(markdown, "## 11. Limitations")
    assert "The limitations the report model wrote were left out" in limitations
    assert "The run recorded no limitation." not in limitations
    assert "_1 sentence of this section was left out" in limitations


def test_the_judge_s_answer_when_asked_is_the_bundle_s() -> None:
    report = _report()
    report.capability_matrix = [
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1140",
            technique_name="Deobfuscate/Decode Files or Information",
            evidence=["Routine 0xae78 decodes the strings."],
            note=judge_kept_note("the listing shows the decoder"),
        )
    ]
    attack = _section(_analyst(report), "## 10. MITRE ATT&CK mapping")
    assert "| T1140 |" in attack and "kept by the judge" not in attack
    assert "kept by the judge when asked" in MarkdownRenderer(layout=BUNDLE).render(report)


def test_a_flagged_first_sentence_with_its_citations_is_found_and_left_out() -> None:
    claim = "Encrypts each file with ChaCha20 [ev_0002]."
    report = _report()
    report.capability_matrix = [
        CapabilityCell(
            tactic="TA0040",
            tactic_name="Impact",
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            evidence=[claim],
        )
    ]
    report.flagged_statements = [
        FlaggedStatement(sentence=claim, code="report.process_words", label="x")
    ]
    row = next(line for line in _analyst(report).splitlines() if "| T1486 |" in line)
    assert "ChaCha20" not in row and row.endswith("| - |")
