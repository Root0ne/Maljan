"""The evidence bundle: the record behind the analyst report, in one file and in JSON.

The analyst report (``renderers/analyst.py``) prints the findings and moves
the rest here, so nothing the single-file report prints is lost: the bundle
prints every section of the single-file report as that report prints it — the
observed behaviour, the static properties, the full ATT&CK, indicator and
detection sections with their published states, the limitations, every claim
whose code the body does not name, the evidence index with every tool's output
and the run summary — and adds the notes the analyst report cites, each
listing its evidence ids, each id linked to its row in the evidence index.

In HTML every evidence id the index lists has an anchor (``#ev_0064``), every
note has one (``#cite-3``) and every section and subsection has one
(``#sec-command-and-control``), so each link the analyst report makes lands.

The JSON form carries the same content for a program: the notes, the
evidence index and each section's Markdown under its anchor.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.analyst import CitationNote, bundle_anchor, unique_anchor
from maljan.reporting.renderers.layout import ANALYST, BUNDLE
from maljan.reporting.renderers.markdown import (
    _PIPE,
    MEASURED,
    _appendix_heading,
    _item,
    report_title,
)

if TYPE_CHECKING:
    from maljan.reporting.renderers.markdown import MarkdownRenderer, _Context

FORMAT = "maljan-evidence-bundle/1"
NOTES_TITLE = "Notes cited by the analyst report"

# The analyst report's sections, by the key a note records, as its headings
# name them.
SECTION_TITLES: dict[str, str] = {
    "title": "Title block",
    "summary": "Executive summary",
    "scope": "Introduction and scope",
    "metadata": "Sample metadata",
    "flow": "Execution flow",
    "functionality": "Functionality",
    "c2": "Command and control",
    "conclusion": "Conclusion",
    "detection": "Detection",
    "recommendations": "Recommendations",
    "attack": "MITRE ATT&CK mapping",
    "limitations": "Limitations",
    "appendix": "Appendix",
}

_H2 = re.compile(r"^## ", re.MULTILINE)
_HEADING_TITLE = re.compile(r"^(?:\d+(?:\.\d+)*\.?\s+" + _PIPE + r"Appendix [A-Z]\.\s+)")


def bundle_sections(
    renderer: MarkdownRenderer,
    report: MalwareReport,
    ctx: _Context,
    sections: list[str],
    notes: list[CitationNote],
) -> list[str]:
    """The single-file report's sections under the bundle's title, then the notes."""
    title, _, rest = sections[0].partition("\n") if sections else ("", "", "")
    heading = "# Evidence bundle: " + title.removeprefix("# ").strip()
    intro = (
        "_The record behind the analyst report of the same name: every section the "
        "single-file report prints, as it prints it, and the notes the analyst report cites, "
        "each linked to the evidence entries it rests on._"
    )
    out = ["\n".join([heading, "", intro, rest]), *sections[1:]]
    out.append(renderer._safe_section("bundle_notes", lambda: _notes_section(report, notes)))
    return out


def _notes_section(report: MalwareReport, notes: list[CitationNote]) -> str:
    """Each note with its ids linked to the index; an id the index does not hold, said so."""
    lines = [_appendix_heading("E", NOTES_TITLE, MEASURED), ""]
    if not notes:
        lines.append("The analyst report cites no evidence entry.")
        return "\n".join(lines)
    indexed = {row.id for row in report.evidence_index}
    lines.append(
        "_Each numbered note of the analyst report, the section it stands in, and the "
        "evidence entries it rests on, each linked to its row in Appendix A._"
    )
    lines.append("")
    missing: list[str] = []
    for note in notes:
        ids = ", ".join(f"[{i}](#{i})" if i in indexed else i for i in note.evidence_ids)
        missing.extend(i for i in note.evidence_ids if i not in indexed and i not in missing)
        section = SECTION_TITLES.get(note.section, note.section)
        lines.append(_item(f"**Note {note.number}** ({section}): {ids}"))
    if missing:
        lines.extend(
            ["", "Cited by the analyst report and not in this report's evidence index:", ""]
        )
        lines.extend(
            _item(f"**{i}**: no entry of the evidence index carries this id.") for i in missing
        )
    return "\n".join(lines)


def section_index(markdown: str) -> list[dict[str, str]]:
    """The bundle's Markdown split at its H2 headings: each part with its title and anchor."""
    parts = _H2.split(markdown)
    out = [{"anchor": "title", "title": "Title", "markdown": parts[0].rstrip()}]
    seen: set[str] = set()
    for part in parts[1:]:
        heading = part.split("\n", 1)[0]
        title = _HEADING_TITLE.sub("", heading.split(" · ", 1)[0]).strip()
        anchor = unique_anchor(bundle_anchor(title), seen)
        out.append({"anchor": anchor, "title": title, "markdown": ("## " + part).rstrip()})
    return out


def bundle_json(report: MalwareReport) -> str:
    """The evidence bundle as JSON: the notes, the evidence index and every section."""
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    markdown, notes = MarkdownRenderer(layout=BUNDLE).render_with_notes(report)
    summary = report.run_summary or {}
    document: dict[str, Any] = {
        "format": FORMAT,
        "report": {
            "title": report_title(report),
            "sha256": report.identity.hashes.sha256,
            "report_id": summary.get("report_id"),
            "generated_at": report.generated_at.isoformat(),
        },
        "notes": [
            {
                "number": note.number,
                "anchor": f"cite-{note.number}",
                "section": SECTION_TITLES.get(note.section, note.section),
                "evidence_ids": list(note.evidence_ids),
            }
            for note in notes
        ],
        "evidence_index": [row.model_dump(mode="json") for row in report.evidence_index],
        "sections": section_index(markdown),
    }
    return json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


@dataclass(frozen=True)
class Products:
    """The analyst report and its evidence bundle, rendered from one report."""

    report_markdown: str
    report_html: str
    bundle_markdown: str
    bundle_html: str
    bundle_json: str


def render_products(report: MalwareReport) -> Products:
    """Both products of one report, in every form they are served in."""
    from maljan.reporting.renderers.html import HtmlRenderer
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    return Products(
        report_markdown=MarkdownRenderer(layout=ANALYST).render(report),
        report_html=HtmlRenderer(layout=ANALYST).render(report),
        bundle_markdown=MarkdownRenderer(layout=BUNDLE).render(report),
        bundle_html=HtmlRenderer(layout=BUNDLE).render(report),
        bundle_json=bundle_json(report),
    )


def note_numbers(text: str) -> list[int]:
    """The note numbers a rendered analyst report links to, in order."""
    return [int(n) for n in re.findall(r"#cite-(\d+)", text)]
