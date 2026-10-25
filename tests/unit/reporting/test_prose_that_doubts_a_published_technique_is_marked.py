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

A doubt may also point back or stand before the id: a stored run wrote
"(T1070.004); this is a code-path candidate and was not observed", and
another "(possible T1620, not remote injection)". A clause opening "this is
a ... candidate" is bound to the id that ends the clause before it, and a
closed set of doubt words is bound to the id it stands right before.
"""

from __future__ import annotations

from collections.abc import Callable
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
from tests.linear_cost import TIME_RATIO_LIMIT, calls, cpu_seconds

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
POSSIBLE = (
    "The only code-loading path calls the retrieved buffer in-process "
    "(possible T1070.004, not remote injection) [ev_0014]."
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
    published = {
        "T1497.001": False,
        "T1053.005": True,
        "T1070.004": True,
        "T1027": False,
        "T1071": False,
    }
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

    def test_a_clause_that_points_back_doubts_the_id_ending_the_clause_before(self) -> None:
        row = _marked(_report(SELF_DELETE))[SELF_DELETE]

        assert row.label == "T1070.004, corroborated"

    def test_a_doubt_word_right_before_the_id_is_marked(self) -> None:
        row = _marked(_report(POSSIBLE))[POSSIBLE]

        assert row.label == "T1070.004, corroborated"

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
    # A clause pointing back binds only to an id that ends the clause before.
    "A logon task is coded (T1053.005) and a host is contacted; this is a candidate.",
    "A logon task is coded (T1053.005, T1564.004); this is a candidate.",
    "A logon task is coded (T1053.005, T1070.004); this is a candidate.",
    "A logon task is coded (T1053.005); this is our best candidate.",
    "A logon task is coded (T1053.005); this is a separate candidate for persistence.",
    "A logon task is coded (T1053.005); this is another candidate for persistence.",
    "A logon task is coded (T1053.005); this is a second candidate for persistence.",
    "A logon task is coded (T1053.005); this is hardly a candidate.",
    "A logon task is coded (T1053.005); this is hardly unconfirmed.",
    # What it was before a confirmation is not a doubt now.
    "A logon task is coded (T1053.005); this was a candidate until the sandbox confirmed it.",
    "A logon task is coded (T1053.005); it was a candidate until confirmed by the judge.",
    "T1053.005 remains a candidate until the sandbox confirmed it.",
    "A logon task is coded (T1053.005); this is a candidate until PCAP confirmed it.",
    "A logon task is coded (T1053.005); this is not a candidate.",
    "A logon task is coded (T1053.005); this is no longer a candidate.",
    "A logon task is coded (T1053.005); this is a candidate host.",
    "A logon task is coded (T1053.005); this is the only candidate for persistence.",
    "A logon task is coded (T1053.005). This is a candidate.",
    # A doubt word binds only right before the id, never through a negation.
    "There is no possible T1053.005 path left unobserved.",
    "The task is not a possible T1053.005 entry but the observed one.",
    "A possible host was contacted after the task (T1053.005) was created.",
    "Impossible T1053.005 is not a word the rule reads as possible.",
    "The likely-benign loader created the task T1053.005 over COM.",
    # A clause that says something is confirmed: the doubt was weighed before.
    "The possible T1027 variants are all confirmed.",
    "All possible T1027 variants are confirmed by the sandbox.",
    "The likely T1071 traffic was confirmed by PCAP.",
    "Candidate T1071 is confirmed.",
    "PCAP confirms the likely T1071 beacon [ev_3].",
    "The report confirms the suspected T1071 channel.",
    # A doubt word ruled out, denied or followed by its noun.
    "The sandbox ruled out a possible T1071 path.",
    "Hardly a possible T1071 case.",
    "Confirmed rather than a possible T1071 channel.",
    "Beyond any possible T1071 doubt, it beacons.",
    "It beacons, rather than a possible (T1071), over HTTP.",
    # A run of whitespace does not push the negation out of reach.
    "The traffic is not" + " " * 200 + "a" + " " * 200 + "possible" + " " * 200 + "T1071.",
    # A confirmation anywhere in the sentence, in any clause.
    "The possible T1071; PCAP confirms it.",
    "Possible T1071 — PCAP confirms the beacon.",
    "(T1053.005); this is a candidate; the sandbox confirmed it.",
    "(T1053.005); this is a candidate, and the sandbox confirmed it.",
    "(T1053.005); this is a candidate — the sandbox later confirmed it.",
    "Possible T1071, verified by PCAP.",
    "Possible T1071, since proven by PCAP.",
    "The beacon is a possible T1071; PCAP confirms it.",
    "The beacon goes to a possible T1071, as PCAP later verified.",
    # A denial anywhere in the clause before the id, or in a clause ending in a colon.
    "There is no evidence of a possible T1071, [ev_1].",
    "We never saw it as a possible T1071, per the PCAP.",
    "The run disproves the possible T1071.",
    "The sandbox eliminated the possible T1071.",
    "Ruled out: possible T1071.",
    "Ruled out by the sandbox: the run shows a possible T1071.",
    "The sandbox ruled it out, possible T1071, [ev].",
    # The walk back stops at the id before: a list hides what came before it.
    "No beacon was seen for T1105 or a possible T1071.",
    # A clause pointing back does not bind to an id a denial or a contrast
    # stands before, published or not.
    "The sandbox ruled out T1564.004; it is unconfirmed.",
    "Unlike earlier builds, it skips T1564.004; this is a candidate for the next version.",
    "The sandbox ruled out T1053.005; it is unconfirmed.",
    "Unlike earlier builds, it skips T1053.005; this is a candidate for the next version.",
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
        "A logon task is coded (T1053.005) [ev_0020]; this is only a candidate.",
        "A logon task is coded (T1053.005), but it remains unconfirmed.",
        "A logon task is coded (T1053.005): this is a static candidate, not observed.",
        "The run shows a task over COM (likely T1053.005).",
        "A task is coded, suspected T1053.005, at logon [ev_0020].",
        "The scheduled task is a possible T1053.005.",
        # A doubt that lasts until something that has not come.
        "T1053.005 remains a candidate until the sandbox runs it.",
        "T1053.005 is a candidate until dynamic evidence exists.",
        "The task is probably (T1053.005) created at logon.",
    ],
)
def test_a_doubt_bound_to_the_technique_is_marked(sentence: str) -> None:
    assert sentence in _marked(_report(sentence, persistence=sentence))


class TestLinearTime:
    def test_four_times_the_prose_costs_under_eight_times(self) -> None:
        def read(units: int) -> Callable[[], Any]:
            # Long clauses of many ids, quotations and clause ends, each kind of
            # doubt among them, all in one subsection read sentence by sentence
            # and one key finding read whole.
            clause = (
                'T1564.004 and "T1053.005 candidate" (T1070.004) - possible T1053.005, '
                "T1497.001 remains unconfirmed; this is a code-path candidate"
            )
            body = " ".join(f"{clause} [ev_{n:04d}]." for n in range(units))
            report = _report(f"{clause}, {clause}; " * units, persistence=body)
            return lambda: statements_against_publication(report)

        # CPU time, not wall-clock: four times the prose must take under eight
        # times as long, and a quadratic read takes sixteen times. The calls
        # made are held to the same ratio too, which a load cannot move.
        read(10)()  # one-time costs (caches, lazy imports) are not the read's
        small, large = read(500), read(2_000)
        assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
        assert calls(large) <= calls(small) * 4 * 1.2 + 100

    def test_a_run_of_whitespace_four_times_as_long_costs_under_eight_times(self) -> None:
        def read(units: int) -> Callable[[], Any]:
            # A whitespace run that grows with the input, after an id that ends
            # its clause and before the words that keep it from ending there.
            sentence = "(T1053.005)" + " " * (40 * units) + "x; this is a candidate"
            report = _report(sentence, persistence=sentence)
            return lambda: statements_against_publication(report)

        read(10)()
        small, large = read(100), read(400)
        assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
        assert calls(large) <= calls(small) * 4 * 1.2 + 100

    def test_ids_written_without_spaces_four_times_as_many_cost_under_eight_times(self) -> None:
        def read(units: int) -> Callable[[], Any]:
            # One token of many ids: the walk back from each id stops at the one
            # before it, not at the clause's start.
            sentence = "(T1053.005," * (50 * units)
            report = _report(sentence, persistence=sentence)
            return lambda: statements_against_publication(report)

        read(1)()
        small, large = read(10), read(40)
        assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
        assert calls(large) <= calls(small) * 4 * 1.2 + 100


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
