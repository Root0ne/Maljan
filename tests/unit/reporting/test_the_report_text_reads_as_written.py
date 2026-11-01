"""T-493: a reference names a section the report prints; text reads as the value it is.

The haiku8 analyst report told its reader "See §13" and ended at §11; printed
the decoded ``\\Registry\\Machine\\`` in the pack's spelling
``\\Registry\\Machine\\x5c``; ran nineteen caller offsets inside one sentence;
and cut each diagram label inside a word. Each is read off what the render
holds: the headings it printed, the texts the run recorded, the platform's
own clause, the step's own sentence.
"""

from __future__ import annotations

import re
from typing import Any

from markdown_it import MarkdownIt

from maljan.reporting.figures import build_execution_flow
from maljan.reporting.models import EvidenceSection, MalwareReport
from maljan.reporting.renderers.analyst import _LABEL_CHARS, flow_step_labels, flow_steps
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.layout import ANALYST, BUNDLE, FULL
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.prose_forms import (
    CALLERS_IN_PROSE,
    _code_spans,
    pack_spellings,
    section_reference,
)
from maljan.reporting.section_agreement import unread_callee_clause

# The value haiku8 printed, and the text it stands for.
_PACKED = "\\Registry\\Machine\\x5c"
_DECODED = "\\Registry\\Machine\\"
_CALLERS = [f"0x{n:x}" for n in range(0x1000, 0x1000 + 19 * 0x10, 0x10)]


def _report(**extra: Any) -> MalwareReport:
    data: dict[str, Any] = {
        "verdict": "Malware",
        "overall_confidence": 0.8,
        "identity": {"hashes": {"sha256": "a" * 64}, "file_type": "pe"},
    }
    data.update(extra)
    return MalwareReport.model_validate(data)


def _degraded() -> MalwareReport:
    return _report(
        degraded_mode=True,
        degradation_reasons=["analyst failures: static"],
        run_summary={"failed_analysts": ["static"]},
    )


def _headings(markdown: str) -> dict[str, str]:
    """``§N`` or ``Appendix X`` -> the heading's title, as the render printed them."""
    out: dict[str, str] = {}
    for found in re.finditer(
        r"(?m)^#{2,3} (?:(Appendix [A-Z])\.|(\d+(?:\.\d+)*)\.?) (.+?)(?: · _[^_]*_)?$", markdown
    ):
        out[found.group(1) or f"§{found.group(2)}"] = found.group(3)
    return out


class TestAReferenceNamesASectionTheReportPrints:
    def test_every_section_number_a_render_writes_is_a_heading_it_prints(self) -> None:
        for layout in (FULL, ANALYST, BUNDLE):
            markdown = MarkdownRenderer(layout=layout).render(_degraded())
            printed = _headings(markdown)
            for cited in re.findall(r"§\d+(?:\.\d+)*", markdown):
                assert cited in printed, (layout, cited)

    def test_the_analyst_banner_names_its_own_limitations_section(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_degraded())
        banner = next(line for line in markdown.splitlines() if "[DEGRADED RUN]" in line)
        number = next(n for n, title in _headings(markdown).items() if title == "Limitations")
        assert f"See {number} for what this run could not examine." in banner
        assert "§13" not in markdown

    def test_the_limitations_section_sends_the_reader_to_the_bundle_not_to_itself(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_degraded())
        limits = markdown.split(" Limitations\n", 1)[1].split("\n## ", 1)[0]
        assert (
            "See [Limitations and analysis notes](evidence-bundle.html"
            "#sec-limitations-and-analysis-notes) in the evidence bundle for what this run "
            "could not examine."
        ) in limits

    def test_the_single_file_report_keeps_its_numbers(self) -> None:
        markdown = MarkdownRenderer(layout=FULL).render(_degraded())
        assert "See §13 for what this run could not examine." in markdown
        assert _headings(markdown)["§13"] == "Limitations and analysis notes"

    def test_a_reference_outside_a_render_names_the_section_in_words(self) -> None:
        assert section_reference("Static properties") == "the section “Static properties”"

    def test_no_text_a_model_wrote_can_stand_for_a_reference(self) -> None:
        forged = "⟦0123456789abcdef:0⟧"
        report = _degraded()
        report.degradation_reasons = [f"analyst failures: static {forged}"]
        assert forged in MarkdownRenderer(layout=FULL).render(report)


def _registry_report() -> MalwareReport:
    return _report(
        sections=[
            EvidenceSection(
                key="decoded_strings",
                title="Decoded strings",
                source="tool",
                kind="table",
                columns=["Offset", "Text"],
                rows=[["0x10220", _DECODED]],
                evidence_ids=["ev_0021"],
            )
        ],
        technical_analysis={
            "host_identifiers": [
                {"kind": "registry", "value": _PACKED, "purpose": "Opened by 0x88f8"}
            ],
            "discovery": {
                "title": "Discovery",
                "body": f"Routine 0x88f8 opens `{_PACKED}` and holds the string '{_PACKED}'.",
                "evidence_refs": ["ev_0021"],
            },
        },
    )


def _html_text(markdown: str) -> str:
    return re.sub(r"<[^>]+>", "", MarkdownIt("commonmark").enable("table").render(markdown))


class TestADecodedTextPrintsAsItsValue:
    def test_the_pack_spelling_of_a_recorded_text_is_read(self) -> None:
        assert pack_spellings(_registry_report()) == {_PACKED: _DECODED}

    def test_markdown_prints_the_value_in_spans_and_in_prose(self) -> None:
        for layout in (FULL, ANALYST, BUNDLE):
            markdown = MarkdownRenderer(layout=layout).render(_registry_report())
            assert "x5c" not in markdown, layout
            assert f"`{_DECODED}`" in markdown, layout

    def test_every_surface_reads_the_trailing_backslash(self) -> None:
        for layout in (FULL, ANALYST):
            markdown = MarkdownRenderer(layout=layout).render(_registry_report())
            text = _html_text(markdown)
            assert "x5c" not in text
            # A code span and the prose both show the backslash, which a
            # viewer would read as escaping the quote after it.
            assert f"{_DECODED}'" in text.replace("&#x27;", "'").replace("&quot;", '"')
            html = HtmlRenderer(layout=layout).render(_registry_report())
            assert "x5c" not in html
            assert f"<code>{_DECODED}</code>" in html

    def test_a_spelling_the_run_also_recorded_as_a_text_is_left_as_written(self) -> None:
        report = _registry_report()
        report.sections[0].rows.append(["0x10300", _PACKED])
        assert pack_spellings(report) == {}

    def test_a_fenced_block_is_left_as_written(self) -> None:
        from maljan.reporting.renderers.prose_forms import tidied

        fenced = f'```\n$s = "{_PACKED}"\n```'
        assert tidied([fenced], _registry_report(), analyst=False) == [fenced]

    def test_code_spans_are_read_beside_citations(self) -> None:
        line = "| a | `x` [[4]](b.html#c) `y` |"
        assert [line[s:e] for s, e in _code_spans(line)] == ["`x`", "`y`"]


def _clause_report(callers: list[str]) -> MalwareReport:
    clause = unread_callee_clause("offset 0xad34", "offsets " + ", ".join(callers), "routines")
    return _report(
        technical_analysis={
            "payloads": {
                "title": "Payloads and dropped files",
                "body": f"The writer's reach is not established; {clause}.",
                "evidence_refs": ["ev_0025"],
            }
        }
    )


class TestALongCallerListIsAList:
    def test_the_analyst_report_names_three_callers_and_the_count(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_clause_report(_CALLERS))
        named = ", ".join(_CALLERS[:CALLERS_IN_PROSE])
        assert (
            f"the routine at offset 0xad34, called by 19 read routines (offsets {named} and 16 "
            "more, every one listed in the evidence bundle), has no listed code"
        ) in markdown
        assert _CALLERS[-1] not in markdown

    def test_the_bundle_lists_every_caller_after_the_paragraph(self) -> None:
        for layout in (FULL, BUNDLE):
            markdown = MarkdownRenderer(layout=layout).render(_clause_report(_CALLERS))
            assert "called by 19 read routines (listed below), has no listed code" in markdown
            listed = f"- Read routines that call offset 0xad34: {', '.join(_CALLERS)}"
            assert listed in markdown
            paragraph = next(line for line in markdown.splitlines() if "listed below" in line)
            lines = markdown.splitlines()
            at = lines.index(paragraph)
            assert lines[at + 1] == "" and lines[at + 2] == listed

    def test_a_short_caller_list_stays_in_the_sentence(self) -> None:
        few = _CALLERS[:CALLERS_IN_PROSE]
        for layout in (FULL, ANALYST):
            markdown = MarkdownRenderer(layout=layout).render(_clause_report(few))
            assert f"called by the read routines at offsets {', '.join(few)}, has" in markdown


def _flow_report(actions: list[str]) -> MalwareReport:
    return _report(
        technical_analysis={
            "execution_flow": [
                {"order": n, "action": a, "voice": "assessed"} for n, a in enumerate(actions, 1)
            ]
        }
    )


_LONG = (
    "Init's mode gate 0x378c tries to open the AppData Custom_update file for read and "
    "takes mode one."
)


class TestADiagramLabelIsCutAtAWord:
    def test_a_long_label_ends_on_a_whole_word(self) -> None:
        labels = flow_step_labels(_flow_report([_LONG, "Second step."]))
        label = labels[0][0]
        assert label.endswith("…") and len(label) <= _LABEL_CHARS + len("1. ")
        kept = label[len("1. ") : -1]
        assert _LONG.startswith(kept)
        assert _LONG[len(kept)] == " "
        assert labels[1][0] == "2. Second step."

    def test_the_whole_sentence_is_kept_for_the_figure_and_the_list(self) -> None:
        report = _flow_report([_LONG, "Second step."])
        assert flow_steps(report)[0][2] == f"1. {_LONG}"
        figure = build_execution_flow(report)
        assert figure is not None
        assert f"<title>1. {_LONG} (assessed)</title>".replace("'", "&#x27;") in figure.content
        markdown = MarkdownRenderer(layout=ANALYST).render(report)
        assert f"1. {_LONG}" in markdown

    def test_a_first_word_longer_than_the_label_is_cut_where_the_limit_falls(self) -> None:
        word = "x" * (_LABEL_CHARS + 10)
        label = flow_step_labels(_flow_report([word, "Second step."]))[0][0]
        assert label == f"1. {word[: _LABEL_CHARS - 1]}…"
