"""Render a ``MalwareReport`` as a standalone, print-ready HTML document.

Content is **not** re-implemented here. ``MarkdownRenderer`` already owns the
section order, the tables and the degraded-run banner, and its headings are
pinned by tests; this renderer converts that markdown to HTML and adds the
things markdown cannot express — a table of contents, the deterministic
figures, and a print stylesheet. Keeping one content source means the markdown
and HTML exports can never drift apart, which is the whole point: two renderers
walking ``MalwareReport`` independently would disagree the first time a field is
added to one and not the other.

Two properties matter for safety and are covered by tests:

* **No raw HTML survives from report content.** Report text is LLM- and
  malware-derived, so ``markdown-it`` runs with ``html=False``: a ``<script>``
  in a file name or a decompiled string is escaped, not executed. The only raw
  HTML injected is ``Figure.content``, which ``reporting/figures.py`` generates
  itself and already escapes.
* **The document is self-contained.** No external CSS, fonts, or images — the
  stylesheet is inlined and figures are inline SVG. It renders identically
  offline, in an air-gapped analysis VM, and inside WeasyPrint.
"""

from __future__ import annotations

import re
import secrets
from html import escape, unescape
from typing import Any

from markdown_it import MarkdownIt

from maljan.reporting.defang import ProseDefanger
from maljan.reporting.models import Figure, MalwareReport
from maljan.reporting.renderers.layout import (
    ANALYST,
    BUNDLE,
    BUNDLE_FILES,
    BUNDLE_HTML,
    FULL,
    checked,
)
from maljan.reporting.renderers.markdown import (
    ABSENCE_PREFIXES,
    MarkdownRenderer,
    _defanged_text,
    report_title,
    run_network_values,
)

# Each figure kind is anchored to the section it illustrates so the graphic sits
# with the table or the prose it summarises rather than in a lump at the end.
# The first heading in the list that the report has wins; a heading is named by
# its title, without its number and its voice tag. Kinds not listed here
# (``code_listing``) fall through to the figure appendix, which is also where
# anything lands if every heading it could go under is absent — placement
# degrades, the figure is never dropped.
_FIGURE_ANCHORS: dict[str, tuple[str, ...]] = {
    "execution_flow": ("Execution flow",),
    "infection_chain": ("Execution flow",),
    "entropy_chart": ("Packing, obfuscation and anti-analysis", "Static properties"),
    "process_tree": ("Process tree", "Observed behaviour"),
    "network_graph": ("Command and control", "Network indicators", "Indicators of compromise"),
    "attack_matrix": ("MITRE ATT&CK mapping",),
}

# MarkdownRenderer._safe_section emits an HTML comment when a section blows up.
# With html=False that would render as visible escaped angle brackets, so it is
# promoted to a real callout instead — a reader of the PDF should be told a
# section is missing rather than shown "&lt;!-- ... --&gt;". The comment
# carries a marker drawn for the one render (``_body_html``), and only a
# comment with that marker is promoted: the same words written by a sample or
# a model stay text.
_SECTION_FAILED = r"<!--\s*section '([^']+)' rendering failed {marker} [^>]*-->"
# How many random bytes the marker is drawn from.
_MARKER_BYTES = 16

# A Mermaid diagram's source as the Markdown renderer writes it into the HTML.
_MERMAID_BLOCK = re.compile(r'<pre><code class="language-mermaid">.*?</code></pre>\n?', re.DOTALL)
_H2_SPLIT_RE = re.compile(r"(?=<h2>)")
_H2_HEAD_RE = re.compile(r"^<h2>(.*?)</h2>", re.DOTALL)
_H3_RE = re.compile(r"<h3>(.*?)</h3>", re.DOTALL)
_NUMBER_RE = re.compile(r"^(?:\d+(?:\.\d+)*\.?\s+|Appendix [A-Z]\.\s+)")
_TAG_RE = re.compile(r"<[^>]+>")

_STYLESHEET = """
@page {
  size: A4;
  margin: 18mm 16mm 20mm 16mm;
  @bottom-center {
    content: "Page " counter(page) " of " counter(pages);
    font-size: 8pt; color: #57606a;
  }
  @bottom-right { content: string(doc-sha); font-size: 7pt; color: #8c959f; }
}
:root {
  --ink: #1b1f24; --muted: #57606a; --line: #d0d7de; --accent: #0969da;
  --danger: #cf222e; --warn: #bc4c00; --surface: #f6f8fa;
}
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, "DejaVu Sans", sans-serif;
  font-size: 10.5pt; line-height: 1.55; color: var(--ink);
  margin: 0 auto; padding: 24px; max-width: 60rem; background: #fff;
}
h1 {
  font-size: 20pt; margin: 0 0 4px; letter-spacing: -0.01em;
  border-bottom: 2px solid var(--ink); padding-bottom: 8px;
}
h2 {
  font-size: 13pt; margin: 26px 0 8px; padding-bottom: 4px;
  border-bottom: 1px solid var(--line); break-after: avoid; page-break-after: avoid;
}
h3 { font-size: 11pt; margin: 16px 0 6px; color: var(--muted);
     break-after: avoid; page-break-after: avoid; }
p { margin: 6px 0; }
a { color: var(--accent); text-decoration: none; }

/* Hashes, rule bodies and decompiled listings are long and unbreakable; without
   an explicit wrap they run off the right edge of an A4 page. */
code, kbd, samp {
  font-family: "Cascadia Mono", "DejaVu Sans Mono", Consolas, monospace;
  font-size: 0.88em; background: var(--surface);
  border: 1px solid var(--line); border-radius: 3px; padding: 0 3px;
  word-break: break-all; overflow-wrap: anywhere;
}
pre {
  background: var(--surface); border: 1px solid var(--line); border-radius: 5px;
  padding: 10px 12px; white-space: pre-wrap;
  word-break: break-all; overflow-wrap: anywhere; font-size: 8.5pt; line-height: 1.4;
}
pre code { background: none; border: 0; padding: 0; font-size: inherit; }

table {
  border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 9.5pt;
  break-inside: auto;
}
th, td {
  border: 1px solid var(--line); padding: 5px 8px; text-align: left;
  vertical-align: top; overflow-wrap: anywhere;
}
th { background: var(--surface); font-weight: 600; }
thead { display: table-header-group; }
tr { break-inside: avoid; page-break-inside: avoid; }

/* The degraded-run banner is the one blockquote the markdown emits, and the
   audit showed readers miss it — it gets a real callout treatment. */
blockquote {
  margin: 12px 0; padding: 10px 14px; border-left: 4px solid var(--warn);
  background: #fff8f0; color: #6a4400; break-inside: avoid;
}
blockquote p { margin: 4px 0; }

nav.toc { break-after: page; page-break-after: always; margin: 18px 0 0; }
nav.toc h2 { border-bottom: 1px solid var(--line); margin-top: 18px; }
nav.toc ol { list-style: none; padding-left: 0; margin: 8px 0; }
nav.toc li { margin: 3px 0; border-bottom: 1px dotted var(--line); }
nav.toc a { display: flex; justify-content: space-between; gap: 8px; color: var(--ink); }

figure {
  margin: 14px 0; padding: 10px; border: 1px solid var(--line); border-radius: 6px;
  background: #fff; break-inside: avoid; page-break-inside: avoid;
}
figure svg { display: block; width: 100%; height: auto; max-width: 100%; }
figcaption {
  margin-top: 8px; font-size: 8.5pt; color: var(--muted); text-align: left;
}
figcaption b { color: var(--ink); }
.fig-legend { display: block; margin-top: 3px; font-style: italic; }

/* Screen-only. WeasyPrint has no scrollable overflow and logs a warning for
   every unknown property, which would mean a noisy line on every PDF render. */
@media screen {
  pre { overflow-x: auto; }
}

@media print {
  body { max-width: none; padding: 0; font-size: 9.5pt; }
  /* Every body cell is printed whole, and a sample's command line can run to
     kilobytes; an automatic layout measures every word of every cell to size
     its columns, which takes minutes on such a cell. A fixed layout sizes the
     columns once, from the first row, and keeps every word. */
  table { table-layout: fixed; width: 100%; }
  nav.toc a::after {
    content: target-counter(attr(href url), page);
    color: var(--muted); font-variant-numeric: tabular-nums;
  }
}
"""


# The analyst report's citation notes: a number linking into the evidence bundle.
_CITE_STYLE = (
    "sup.cite { font-size: 0.72em; line-height: 0; margin-left: 1px; }\n"
    "ol.notes { list-style: none; padding-left: 0; font-size: 8.5pt; }\n"
)


# The link targets the HTML report makes anchors of: the web's and mail's own
# schemes, and a place in the page or beside it.
_LINKED_SCHEMES = ("http:", "https:", "mailto:")


def _report_link(url: str) -> bool:
    """Whether a Markdown link's target becomes an anchor in the HTML report.

    An http, https or mailto target, a place in the page (``#…``), or a place
    in one of the evidence bundle's two files, which are written and served
    beside the report under those names; nothing else. Any other path
    relative to the page names a file no reader of an exported report has,
    and a protocol-relative target (``//host/…``) a host no reader can vouch
    for.
    """
    target = str(url or "").strip()
    # The Markdown escapes the "&" of every character reference it holds, so
    # an "&" here is one the source held: a target spelled with a reference
    # ("https&#58;//…") is no link the report makes.
    if "&" in target:
        return False
    if target.split("#", 1)[0] in BUNDLE_FILES:
        return True
    return target.lower().startswith(_LINKED_SCHEMES) or target.startswith("#")


def _no_image(renderer: Any, tokens: Any, idx: int, options: Any, env: Any) -> str:
    """An image written in the report's Markdown, rendered as its alt text and never fetched.

    The report generates its figures as inline SVG; an image in the Markdown is
    model- or sample-written, and loading one would tell its host the report
    was opened.
    """
    alt = "".join(str(child.content or "") for child in (tokens[idx].children or []))
    return escape(alt)


# The document's own policy, a second guard behind the renderer: nothing is
# fetched (no script, frame, font, connection or remote image), the inline
# stylesheet and the figures' style attributes apply, and an image may only be
# one the page carries itself as data.
CONTENT_SECURITY_POLICY = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"


class HtmlRenderer:
    """Render a complete ``MalwareReport`` as one self-contained HTML document.

    ``layout`` is the Markdown renderer's (``renderers/layout.py``). The
    analyst report draws only the figures whose section it prints and prints
    each citation note as a superscript link into the evidence bundle; the
    bundle gives every subsection, evidence id and note an anchor those links
    land on.
    """

    def __init__(
        self,
        *,
        layout: str = FULL,
        self_contained: bool = False,
        bundle_location: str | None = None,
    ) -> None:
        """``self_contained`` (the analyst report's PDF): each note marker links to a
        "Notes" list the document ends with, which names each note's evidence ids;
        every other link into the bundle is printed as text, and the Notes say where
        the bundle is, ``bundle_location`` (the API path) among it, in words. A file
        printed alone has no bundle beside it for a relative link to reach."""
        self._layout = checked(layout)
        self._self_contained = self_contained and self._layout == ANALYST
        self._bundle_location = bundle_location
        self._notes: list[Any] = []

    def render(
        self, report: MalwareReport, *, embed_figures: bool = True, nonce: str | None = None
    ) -> str:
        """Return a full ``<!DOCTYPE html>`` document for ``report``.

        ``nonce`` is a caller-supplied CSP nonce for the one ``<style>`` tag
        this document emits. It is ``None`` for every existing caller (the PDF
        pipeline, and any HTML export served without a per-response CSP); the
        report route mints one so it can serve the export under a policy with
        no ``'unsafe-inline'``.
        """
        body_html = self._body_html(report)
        figures = list(report.figures or []) if embed_figures else []
        if self._layout == ANALYST:
            # The bundle draws the others, beside the sections they illustrate.
            from maljan.reporting.figures import build_execution_flow
            from maljan.reporting.renderers.analyst import FIGURE_KINDS

            figures = [fig for fig in figures if fig.kind in FIGURE_KINDS]
            # The execution flow is drawn from the steps the report holds now:
            # the composer writes them after the stored figures were drawn.
            flow = build_execution_flow(report) if embed_figures else None
            if flow is not None:
                figures.insert(0, flow)
        if figures:
            # A stored report's figures were drawn when it was built, perhaps
            # before their text was defanged: each is read again here, with
            # the run's own values, as the Markdown is. The read is
            # idempotent, so a figure drawn defanged prints as it was drawn.
            run_values = ProseDefanger(run_network_values(report))
            figures = [_figure_read(fig, run_values) for fig in figures]
        preamble, sections, leftover = self._place_figures(body_html, figures)
        if self._layout == BUNDLE:
            sections = _bundle_anchors(sections)
        toc = self._toc(sections)
        appendix = self._figure_appendix(
            leftover, start_index=_numbered(figures) - _numbered(leftover) + 1
        )
        title = self._title(report)
        sha = report.identity.hashes.sha256 or "unknown"
        # The analyst report's notes are superscripts; the other layouts print none.
        style = _CITE_STYLE if self._layout == ANALYST else ""
        style_open = f'<style nonce="{escape(nonce)}">' if nonce else "<style>"
        # Order matters: title block, then the contents page, then the body. The
        # TOC carries ``break-after: page`` so the report opens on its own cover.
        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n<head>\n'
            '<meta charset="utf-8">\n'
            f'<meta http-equiv="Content-Security-Policy" content="{CONTENT_SECURITY_POLICY}">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)}</title>\n"
            '<meta name="generator" content="Maljan">\n'
            f"{style_open}{_STYLESHEET}{style}</style>\n"
            "</head>\n<body>\n"
            f"<span style=\"string-set: doc-sha 'sha256 {escape(sha[:16])}…'\"></span>\n"
            f"{preamble}{toc}{''.join(sections)}{appendix}"
            "</body>\n</html>\n"
        )

    # ------------------------------------------------------------------
    # Markdown -> HTML
    # ------------------------------------------------------------------

    @staticmethod
    def _title(report: MalwareReport) -> str:
        return report_title(report)

    def _body_html(self, report: MalwareReport) -> str:
        marker = secrets.token_hex(_MARKER_BYTES)
        markdown, self._notes = MarkdownRenderer(
            failed_marker=marker, layout=self._layout
        ).render_with_notes(report)
        failed = re.compile(_SECTION_FAILED.format(marker=re.escape(marker)))
        markdown = failed.sub(
            lambda m: (
                f"> **Section '{m.group(1)}' could not be rendered.** "
                "The underlying data is present in the JSON report; see the server "
                "logs for the rendering error."
            ),
            markdown,
        )
        html = self._markdown_to_html(markdown)
        if self._layout == ANALYST:
            # The Markdown's diagram source; the HTML draws the flow as a figure.
            html = _MERMAID_BLOCK.sub("", html)
            html = _cited_superscripts(html)
        if self._self_contained:
            html = _notes_in_the_document(html, self._notes, self._bundle_location)
        return html

    @staticmethod
    def _markdown_to_html(markdown: str) -> str:
        """The report's Markdown as HTML, linking only what the report itself links.

        ``html=False`` is the XSS guard: report content is LLM- and
        malware-derived. The CommonMark preset links no bare text (no
        linkify), so a value the defanger left as written is never an anchor;
        and a link is made only for an http, https or mailto target, or one
        inside the page, so a defanged URL ("hxxps://…", written in angle
        brackets or as a link's target) is never one either.
        """
        md = MarkdownIt("commonmark", {"html": False}).enable("table").enable("strikethrough")
        md.validateLink = _report_link  # type: ignore[method-assign]
        md.add_render_rule("image", _no_image)
        return str(md.render(markdown))

    # ------------------------------------------------------------------
    # Figure placement
    # ------------------------------------------------------------------

    def _place_figures(
        self, body_html: str, figures: list[Figure]
    ) -> tuple[str, list[str], list[Figure]]:
        """Split the body at H2 boundaries, give each an id, and inject figures.

        A figure goes after the section, or the subsection, it is anchored to:
        at the end of an H2 chunk, or before the next H3 after an H3 heading.
        Returns the leading title block (everything before the first H2), the
        section chunks, and the figures that found no home — those go to the
        appendix rather than being dropped.
        """
        chunks = [c for c in _H2_SPLIT_RE.split(body_html) if c]
        # A heading whose body is only the line saying the run had nothing for
        # it is no home for a figure; the next anchor in the list is.
        present = {
            _heading_key(m.group(1))
            for c in chunks
            for m in [*_H2_HEAD_RE.finditer(c), *_H3_RE.finditer(c)]
            if not _only_an_absence(c, m.end())
        }
        by_heading: dict[str, list[Figure]] = {}
        leftover: list[Figure] = []
        for fig in figures:
            anchor = next((a for a in _FIGURE_ANCHORS.get(fig.kind, ()) if a in present), None)
            if anchor is None:
                leftover.append(fig)
            else:
                by_heading.setdefault(anchor, []).append(fig)

        number = 1
        out: list[str] = []
        preamble_parts: list[str] = []
        for chunk in chunks:
            match = _H2_HEAD_RE.match(chunk)
            if not match:
                # Everything before the first H2: <h1> + the verdict/degraded block.
                (preamble_parts if not out else out).append(chunk)
                continue
            # The anchor is the title alone: a voice tag can change with what a
            # run recorded, and a link to a section must not.
            chunk = chunk.replace("<h2>", f'<h2 id="sec-{_slug(_heading_key(match.group(1)))}">', 1)
            # Insertion points inside the chunk, in document order: after each
            # anchored H3's block, then the chunk's own figures at its end.
            points: list[tuple[int, list[Figure]]] = []
            for h3 in _H3_RE.finditer(chunk):
                attached = by_heading.get(_heading_key(h3.group(1)))
                if attached:
                    following = chunk.find("<h3>", h3.end())
                    points.append((following if following != -1 else len(chunk), attached))
            own = by_heading.get(_heading_key(match.group(1)))
            if own:
                points.append((len(chunk), own))
            # Numbered in document order, inserted back to front so each
            # position is still where it was measured.
            inserts: list[tuple[int, str]] = []
            for position, attached in sorted(points, key=lambda p: p[0]):
                rendered = "".join(_figure_html(fig, number) for fig in attached)
                number += _numbered(attached)
                inserts.append((position, rendered))
            for position, rendered in reversed(inserts):
                chunk = chunk[:position].rstrip() + "\n" + rendered + chunk[position:]
            out.append(chunk)
        return "".join(preamble_parts), out, leftover

    def _figure_appendix(self, figures: list[Figure], *, start_index: int) -> str:
        if not figures:
            return ""
        parts = [
            '<h2 id="sec-figures">Appendix — Figures</h2>\n',
            "<p>Deterministic figures generated from the report's own data.</p>\n",
        ]
        number = start_index
        for fig in figures:
            parts.append(_figure_html(fig, number))
            number += _numbered([fig])
        return "".join(parts)

    # ------------------------------------------------------------------
    # Table of contents
    # ------------------------------------------------------------------

    @staticmethod
    def _toc(sections: list[str]) -> str:
        entries: list[str] = []
        for chunk in sections:
            match = re.match(r'^<h2 id="(sec-[^"]+)">(.*?)</h2>', chunk, re.DOTALL)
            if not match:
                continue
            heading = unescape(_TAG_RE.sub("", match.group(2))).strip().split(" · ", 1)[0]
            entries.append(f'<li><a href="#{match.group(1)}">{escape(heading)}</a></li>')
        if not entries:
            return ""
        return '<nav class="toc"><h2>Contents</h2><ol>' + "".join(entries) + "</ol></nav>\n"


# A note marker of the analyst report as the Markdown converter draws it, and
# what the bundle's anchors are given to.
_CITE_LINK = re.compile(r'<a href="' + re.escape(BUNDLE_HTML) + r'#cite-(\d+)">\[\1\]</a>')
_EVIDENCE_ROW = re.compile(r"<tr>(\s*<td>)(ev_\d+)(</td>)")
_INDEX_ANCHOR = "sec-evidence-index"
_NOTES_ANCHOR = "sec-notes-cited-by-the-analyst-report"
_NOTE_ITEM = re.compile(r"<li><strong>(Note (\d+)|(ev_\d+))</strong>")


def _cited_superscripts(html: str) -> str:
    """Each note marker of the analyst report as a superscript note number."""
    return _CITE_LINK.sub(
        lambda m: (
            f'<sup class="cite"><a href="{BUNDLE_HTML}#cite-{m.group(1)}">{m.group(1)}</a></sup>'
        ),
        html,
    )


# A link of the analyst report into the bundle, as the Markdown converter draws it.
_BUNDLE_LINK = re.compile(r'<a href="' + re.escape(BUNDLE_HTML) + r'#([^"]*)">(.*?)</a>', re.S)
_BUNDLE_FILE_LINK = re.compile(
    r'<a href="(' + "|".join(map(re.escape, BUNDLE_FILES)) + r')">(.*?)</a>', re.S
)


def _notes_in_the_document(html: str, notes: list[Any], bundle_location: str | None) -> str:
    """The analyst report's body, readable alone: its notes listed in it, no link out of it.

    Each note marker links to its entry in a "Notes" section the body ends
    with, naming the evidence ids; every other link into the bundle (a
    section, an id) is printed as its text. Where the bundle is is said in
    words: beside a downloaded report as ``evidence-bundle.html``, and at
    ``bundle_location`` (the API path, which serves it to a signed-in user)
    where the caller names one. No link is built to it: no setting names
    the address a reader reaches the API at.
    """

    def link(found: re.Match[str]) -> str:
        target, text = found.group(1), found.group(2)
        if target.startswith("cite-"):
            return f'<a href="#note-{target[5:]}">{text}</a>'
        return text

    html = _BUNDLE_FILE_LINK.sub(lambda m: m.group(2), _BUNDLE_LINK.sub(link, html))
    items = "".join(
        f'<li id="note-{note.number}">{note.number}. '
        + ", ".join(escape(i) for i in note.evidence_ids)
        + "</li>"
        for note in notes
    )
    where = f"the evidence bundle, downloaded beside this report as <code>{BUNDLE_HTML}</code>"
    if bundle_location:
        where += f" or served at <code>{escape(bundle_location)}</code> (the API requires sign-in),"
    return (
        html
        + "<h2>Notes</h2>\n"
        + f"<p>Each numbered note and the evidence entries it rests on, which {where} "
        + "lists with every tool's output.</p>\n"
        + (f'<ol class="notes">{items}</ol>\n' if items else "")
    )


def _bundle_anchors(sections: list[str]) -> list[str]:
    """The bundle's sections with an anchor on each subsection, evidence id and note.

    A subsection's id is its title's, as a section's is (:func:`_slug`); a
    title used twice keeps the first place, the body's, and the later one is
    numbered. An evidence id's anchor is its row in the evidence index.
    Given after the figures are placed, which find a subsection by its bare
    heading.
    """
    from maljan.reporting.renderers.analyst import bundle_anchor, unique_anchor

    taken: set[str] = set()

    def section(found: re.Match[str]) -> str:
        # Numbered by the counter the bundle's JSON numbers its sections by.
        return f'<h2 id="{unique_anchor(found.group(1), taken)}">'

    sections = [re.sub(r'^<h2 id="([^"]+)">', section, chunk) for chunk in sections]

    def heading(found: re.Match[str]) -> str:
        anchor = unique_anchor(bundle_anchor(_heading_key(found.group(1))), taken)
        return f'<h3 id="{anchor}">{found.group(1)}</h3>'

    def row(found: re.Match[str]) -> str:
        if found.group(2) in taken:
            return found.group(0)
        taken.add(found.group(2))
        return f'<tr id="{found.group(2)}">{found.group(1)}{found.group(2)}{found.group(3)}'

    def note(found: re.Match[str]) -> str:
        anchor = f"cite-{found.group(2)}" if found.group(2) else str(found.group(3))
        if anchor in taken:
            return found.group(0)
        taken.add(anchor)
        return f'<li id="{anchor}"><strong>{found.group(1)}</strong>'

    out: list[str] = []
    for chunk in sections:
        chunk = _H3_RE.sub(heading, chunk)
        if chunk.startswith(f'<h2 id="{_INDEX_ANCHOR}"'):
            chunk = _EVIDENCE_ROW.sub(row, chunk)
        elif chunk.startswith(f'<h2 id="{_NOTES_ANCHOR}"'):
            chunk = _NOTE_ITEM.sub(note, chunk)
        out.append(chunk)
    return out


def _only_an_absence(chunk: str, after_heading: int) -> bool:
    """Whether the paragraph right after a heading is the line saying it is empty."""
    following = chunk[after_heading:].lstrip()
    if not following.startswith("<p>"):
        return False
    return unescape(_TAG_RE.sub("", following[3:200])).startswith(ABSENCE_PREFIXES)


def _heading_key(inner_html: str) -> str:
    """A heading's title without its tags, its number and its voice tag."""
    text = unescape(_TAG_RE.sub("", inner_html)).strip()
    return _NUMBER_RE.sub("", text.split(" · ", 1)[0]).strip()


def _slug(heading: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")
    return slug or "section"


def _numbered(figures: list[Figure]) -> int:
    """How many of ``figures`` take a figure number: a line saying one was not drawn takes none."""
    return sum(1 for fig in figures if fig.kind != "not_drawn")


# A listing figure's code, and an SVG text element's words: the escaped text
# between the tags a figure builder wrote around it.
_LISTING_BODY = re.compile(r'(<pre class="listing">)(.*?)(</pre>)', re.DOTALL)
_SVG_TEXT = re.compile(r"(<text\b[^>]*>)(.*?)(</text>)", re.DOTALL)


def _figure_read(fig: Figure, run_values: ProseDefanger) -> Figure:
    """``fig`` with every network value in its words defanged, the run's own values first.

    The caption and the legend are read as text. A listing's code and every
    SVG figure's text elements (a process tree's names, an entropy chart's
    section names) are the escaped text a figure builder wrote: each is
    unescaped, defanged and escaped again, and the markup around it is left
    as drawn. A line saying a figure was not drawn names no value and
    is left alone.
    """
    if fig.kind == "not_drawn":
        return fig

    def read(text: str) -> str:
        return _defanged_text(text, run_values)

    def inner(found: re.Match[str]) -> str:
        return found.group(1) + escape(read(unescape(found.group(2)))) + found.group(3)

    content = fig.content
    if fig.kind == "code_listing":
        content = _LISTING_BODY.sub(inner, content)
    elif content.lstrip().startswith("<svg"):
        content = _SVG_TEXT.sub(inner, content)
    return fig.model_copy(
        update={
            "caption": read(fig.caption),
            "legend": read(fig.legend) if fig.legend else fig.legend,
            "content": content,
        }
    )


def _figure_html(fig: Figure, number: int) -> str:
    """Wrap a figure. ``fig.content`` is trusted — see ``reporting/figures.py``.

    A figure that failed to draw is its one line, said once, with no caption and no number.
    """
    if fig.kind == "not_drawn":
        return fig.content + "\n"
    legend = f'<span class="fig-legend">{escape(fig.legend)}</span>' if fig.legend else ""
    return (
        f'<figure id="{escape(fig.id)}">{fig.content}'
        f"<figcaption><b>Figure {number}.</b> {escape(fig.caption)}{legend}</figcaption>"
        "</figure>\n"
    )
