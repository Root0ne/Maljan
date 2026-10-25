"""A key finding or a flow step cites each entry once.

A stored run's key findings each ended in its citations twice: the report
model wrote them into the sentence ("... no packer signature [ev_0001,
ev_0003].") and the renderer printed the finding's ``evidence_ids`` after it
again. The renderer now prints after the text only the entries the text does
not already cite; a text that cites every one of them gets nothing more, and a
text that cites none prints them all as before. The words are never changed.
"""

from __future__ import annotations

from maljan.reporting.models import (
    FileHashes,
    FlowStep,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _report(*findings: KeyFinding, steps: list[FlowStep] | None = None) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        key_findings=list(findings),
        technical_analysis=TechnicalAnalysis(execution_flow=steps or []),
    )


def _line(markdown: str, opening: str) -> str:
    (line,) = [line for line in markdown.splitlines() if opening in line]
    return line


def test_a_finding_that_cites_its_entries_is_not_cited_again() -> None:
    text = "The sample is an unsigned DLL [ev_0001, ev_0003]."
    md = MarkdownRenderer().render(
        _report(KeyFinding(text=text, evidence_ids=["ev_0001", "ev_0003"]))
    )

    line = _line(md, "unsigned DLL")
    assert line.endswith("[ev_0001, ev_0003].")
    assert line.count("ev_0001") == 1


def test_a_finding_gets_only_the_entries_its_text_does_not_cite() -> None:
    text = "Its strings are decoded at run time [ev_0005]."
    md = MarkdownRenderer().render(
        _report(KeyFinding(text=text, evidence_ids=["ev_0005", "ev_0018"]))
    )

    line = _line(md, "decoded at run time")
    assert line.endswith("[ev_0005]. [ev_0018]")
    assert line.count("ev_0005") == 1


def test_a_finding_that_cites_nothing_prints_its_entries_as_before() -> None:
    text = "Two HTTPS hosts are configured."
    md = MarkdownRenderer().render(_report(KeyFinding(text=text, evidence_ids=["ev_0013"])))

    assert _line(md, "HTTPS hosts").endswith("Two HTTPS hosts are configured. [ev_0013]")


def test_a_flow_step_cites_each_entry_once() -> None:
    step = FlowStep(
        order=1,
        action="Init runs its gates [ev_0024].",
        evidence_refs=["ev_0024", "ev_0020"],
    )
    md = MarkdownRenderer().render(_report(KeyFinding(text="x [ev_0001]."), steps=[step]))

    line = _line(md, "Init runs its gates")
    assert line.count("ev_0024") == 1
    assert "[ev_0020]" in line


def test_an_entry_stored_with_spaces_around_it_is_the_one_the_text_cites() -> None:
    text = "Seen in the sandbox [ev_0001]."
    md = MarkdownRenderer().render(_report(KeyFinding(text=text, evidence_ids=[" ev_0001 "])))

    assert _line(md, "Seen in the sandbox").endswith("[ev_0001].")
