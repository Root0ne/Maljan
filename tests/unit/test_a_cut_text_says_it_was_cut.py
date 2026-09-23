"""A text shortened where it is shown carries the mark of the cut.

A claim's evidence is stored at a fixed width. It ended mid-sentence — "… This
suggests", "… like PowerShell di" — and a report section, shown the claim,
printed the fragment as its own finished sentence. Every place that shortens a
model's words or a tool's answer before showing it now ends the cut with a
mark, so a cut is never read as an ending.
"""

from __future__ import annotations

from types import SimpleNamespace

from maljan.agents.base_agent import _EVIDENCE_REF_CHARS, evidence_ref_text
from maljan.pipeline.events import claims_to_payload
from maljan.reporting.composer import _bundle_text
from maljan.utils.marked_cut import CUT_MARK, marked_cut

# The shape of the stored evidence that was printed as prose: a line longer
# than the field, the model's own next sentence starting just before the cut.
LONG_EVIDENCE = (
    "The sample carries strings for file operations (`%d.dat`, `example.bin`) and "
    "for dynamically named modules (`%s%d.dll`) [ev_0011]. This suggests the sample "
    "fetches further stages and writes them beside itself before loading them."
)


class TestTheMark:
    def test_a_text_that_fits_is_whole(self) -> None:
        assert marked_cut("whole", 10) == "whole"

    def test_a_cut_text_ends_in_the_mark_inside_the_width(self) -> None:
        cut = marked_cut("a sentence that goes on", 10)

        assert cut.endswith(CUT_MARK)
        assert len(cut) <= 10

    def test_no_width_is_no_cut(self) -> None:
        assert marked_cut("whole", 0) == "whole"


class TestTheStoredEvidence:
    def test_a_cut_line_says_so(self) -> None:
        assert len(LONG_EVIDENCE) > _EVIDENCE_REF_CHARS

        stored = evidence_ref_text(LONG_EVIDENCE)

        assert CUT_MARK in stored
        assert not stored.rstrip().endswith("This suggests")
        assert "ev_0011" in stored

    def test_a_line_that_fits_carries_no_mark(self) -> None:
        assert evidence_ref_text("import table [ev_0002]") == "import table [ev_0002]"


class TestWhereItIsShown:
    def test_the_live_transcript_marks_a_cut_claim(self) -> None:
        claim = SimpleNamespace(
            claim="x" * 500, evidence_ref="y" * 400, confidence=0.5, technique_id=None
        )

        (row,) = claims_to_payload([claim])

        assert row["claim"].endswith(CUT_MARK)
        assert row["evidence_ref"].endswith(CUT_MARK)

    def test_a_section_is_shown_a_cut_tool_answer_as_cut(self) -> None:
        text = _bundle_text(
            "payloads", {"tool_outputs": [{"tool": "decompile_function", "output": "z" * 5000}]}
        )

        assert f"{'z' * 10}{CUT_MARK}" in text

    def test_the_attack_table_marks_a_cut_procedure(self) -> None:
        from maljan.extractors.capability_matrix import build_capability_matrix

        claim = SimpleNamespace(
            claim="w" * 400,
            evidence_ref="import table [ev_0002]",
            confidence=0.8,
            technique_id="T1204.002",
            technique_id_valid=True,
        )
        isr = SimpleNamespace(domain="static", claims=[claim], findings=[])

        cells, _mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert all(quote.endswith(CUT_MARK) for quote in cells[0].evidence)
