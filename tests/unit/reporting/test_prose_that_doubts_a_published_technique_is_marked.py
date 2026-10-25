"""A sentence that calls a published technique a candidate carries the publication beside it.

A stored run published T1053.005 as corroborated while its persistence prose
said "The report's ATT&CK entry T1053.005 should therefore be read as a
candidate", and published T1497.001 with the judge's kept note citing the 75
and 50 thresholds while a key finding said "(T1497.001 candidate) ... the
thresholds are not confirmed in this ledger". The report model's words stood
beside the decision with nothing saying they disagree.

The publication is the decision. A sentence of the report model's prose (a
key finding, the summary, a flow step, a technical subsection) whose clause
names a technique this run publishes and calls it a candidate or not
confirmed is marked where it stands with what the run published: the id,
whether it is corroborated, and the judge's kept note where there is one. The
words are never changed, the stored report is not edited, and the console is
served the same marks the exports print.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.report_service import with_current_iocs
from maljan.reporting.models import (
    CapabilityCell,
    FileHashes,
    FlaggedStatement,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
    TTPMapping,
)
from maljan.reporting.prose_decisions import (
    PUBLISHED_TECHNIQUE_DOUBTED_CODE,
    statements_against_publication,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

KEPT = "kept by the judge when asked (The disassembly shows a gate with the 75 and 50 thresholds.)"
GATES = (
    "Init routine 0x3868 holds environment gates that could end execution early "
    "(T1497.001 candidate); the thresholds are not confirmed in this ledger [ev_0012]."
)
TASK = (
    "The report's ATT&CK entry T1053.005 should therefore be read as a candidate, "
    "not an observed behaviour."
)
SELF_DELETE = (
    "Routine 0x3a24 renames the module into a stream and sets delete-on-close (T1070.004); "
    "this is a code-path candidate and was not observed [ev_0020]."
)


def _cell(tid: str, **over: Any) -> CapabilityCell:
    fields: dict[str, Any] = {
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": tid,
        "technique_name": tid,
    }
    fields.update(over)
    return CapabilityCell(**fields)


def _report(*findings: str, persistence: str = "", **over: Any) -> MalwareReport:
    published = {"T1497.001": False, "T1053.005": True, "T1070.004": True}
    fields: dict[str, Any] = {
        "identity": SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        "verdict": "Malware",
        "key_findings": [KeyFinding(text=text, evidence_ids=["ev_0012"]) for text in findings],
        "ttp_mappings": [
            TTPMapping(technique_id=tid, technique_name=tid, is_corroborated=corroborated)
            for tid, corroborated in published.items()
        ],
        "capability_matrix": [
            _cell("T1497.001", note=KEPT),
            _cell("T1053.005"),
            _cell("T1070.004"),
            _cell("T1564.004", not_published="the judge dropped it (self-deletion only)"),
        ],
        "technical_analysis": TechnicalAnalysis(
            persistence_detail=TechnicalSubsection(
                title="Persistence",
                body=persistence or f"A logon task is coded through COM [ev_0020]. {TASK}",
            )
        ),
    }
    fields.update(over)
    return MalwareReport(**fields)


def _marked(report: MalwareReport) -> dict[str, FlaggedStatement]:
    return {row.sentence: row for row in statements_against_publication(report)}


class TestTheCheck:
    def test_a_key_finding_that_calls_a_published_technique_a_candidate_is_marked(self) -> None:
        row = _marked(_report(GATES))[GATES]

        assert row.code == PUBLISHED_TECHNIQUE_DOUBTED_CODE
        assert row.asked is False
        assert row.label.startswith("T1497.001")
        # The judge's kept note, which states the thresholds, is the label's.
        assert "75 and 50 thresholds" in row.label

    def test_a_sentence_of_a_subsection_is_marked_alone(self) -> None:
        row = _marked(_report("A finding [ev_0001]."))[TASK]

        assert row.label == "T1053.005, corroborated"

    def test_a_doubt_in_another_clause_is_not_about_the_technique(self) -> None:
        assert SELF_DELETE not in _marked(_report(SELF_DELETE))

    def test_a_technique_the_run_does_not_publish_is_not_marked(self) -> None:
        sentence = "The stream reading (T1564.004) is a candidate [ev_0020]."

        assert sentence not in _marked(_report(sentence))

    def test_a_sentence_with_no_doubt_is_not_marked(self) -> None:
        sentence = "A logon task is created through COM (T1053.005) [ev_0020]."

        assert _marked(_report(sentence, persistence=sentence)) == {}


# Ordinary prose that names a published technique beside a doubt about
# something else, or a doubt it denies: a false mark reaches every surface.
NOT_DOUBTS = [
    "T1053.005 is confirmed by the judge and is no longer a candidate.",
    "T1053.005 is not a candidate: the task creation was observed.",
    "The task (T1053.005) was observed, while T1564.004 remains unconfirmed.",
    "T1053.005 traffic went to an unconfirmed host.",
    "The candidate task was created over COM (T1053.005).",
    'The analyst wrote "T1053.005 candidate" before the sandbox confirmed it.',
    "Code `T1053.005` was confirmed, and `candidate` is a field name.",
    "T1053.005 is published; T1564.004 is a candidate.",
    "T1053.005 is published - T1564.004 is a candidate.",
    "T1053.005 is published, and T1564.004 is a candidate.",
    "T1053.005 is published, but the stream is a candidate.",
    "T1053.005 names a candidate persistence path.",
]


@pytest.mark.parametrize("sentence", NOT_DOUBTS)
def test_a_sentence_that_does_not_doubt_the_technique_is_not_marked(sentence: str) -> None:
    assert _marked(_report(sentence, persistence=sentence)) == {}


@pytest.mark.parametrize(
    "sentence",
    [
        "The task is coded (T1053.005 candidate) [ev_0020].",
        "T1053.005 remains unconfirmed in this run.",
        "T1053.005 is not yet confirmed.",
        "The entry T1053.005 should therefore be read as a candidate.",
    ],
)
def test_a_doubt_bound_to_the_technique_is_marked(sentence: str) -> None:
    assert sentence in _marked(_report(sentence, persistence=sentence))


class TestTheSurfaces:
    def test_the_markdown_prints_the_publication_after_the_words(self) -> None:
        md = MarkdownRenderer().render(_report(GATES))

        assert f"{TASK} **[published by this run: T1053.005, corroborated; not asked]**" in md
        (line,) = [line for line in md.splitlines() if "environment gates" in line]
        assert line.startswith(f"- {GATES} **[published by this run: T1497.001")
        assert "75 and 50 thresholds" in line

    def test_the_stored_report_is_not_edited(self) -> None:
        report = _report(GATES)
        MarkdownRenderer().render(report)

        assert report.flagged_statements == []

    def test_the_console_is_served_the_same_marks_once(self) -> None:
        stored = _report(GATES).model_dump(mode="json")
        served, _note = with_current_iocs(stored, "owner")
        again, _note = with_current_iocs(served, "owner")

        sentences = [row["sentence"] for row in again["flagged_statements"]]
        assert sorted(sentences) == sorted([GATES, TASK])
        assert stored.get("flagged_statements") == []
