"""Render a ``MalwareReport`` as a standalone, print-ready HTML document (Phase 6).

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
from html import escape, unescape

from markdown_it import MarkdownIt

from maljan.reporting.models import Figure, MalwareReport
from maljan.reporting.renderers.markdown import MarkdownRenderer

# Each figure kind is anchored to the H2 section it illustrates so the graphic
# sits with the table it summarises rather than in a lump at the end. Kinds not
# listed here (``code_listing``) fall through to the figure appendix, which is
# also where anything lands if a heading is ever renamed — placement degrades,
# the figure is never dropped.
_FIGURE_ANCHORS: dict[str, str] = {
    "infection_chain": "Executive Summary",
    "entropy_chart": "Static Analysis",
    "process_tree": "Dynamic Behavior",
    "network_graph": "Network IOCs",
    "attack_matrix": "MITRE ATT&CK Matrix",
}

# MarkdownRenderer._safe_section emits an HTML comment when a section blows up.
# With html=False that would render as visible escaped angle brackets, so it is
# promoted to a real callout instead — a reader of the PDF should be told a
# section is missing rather than shown "&lt;!-- ... --&gt;".
_SECTION_FAILED_RE = re.compile(r"<!--\s*section '([^']+)' rendering failed[^>]*-->")

_H2_SPLIT_RE = re.compile(r"(?=<h2>)")
_H2_HEAD_RE = re.compile(r"^<h2>(.*?)</h2>", re.DOTALL)
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
  nav.toc a::after {
    content: target-counter(attr(href url), page);
    color: var(--muted); font-variant-numeric: tabular-nums;
  }
}
"""


class HtmlRenderer:
    """Render a complete ``MalwareReport`` as one self-contained HTML document."""

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
        preamble, sections, leftover = self._place_figures(body_html, figures)
        toc = self._toc(sections)
        appendix = self._figure_appendix(leftover, start_index=len(figures) - len(leftover) + 1)
        title = self._title(report)
        sha = report.identity.hashes.sha256 or "unknown"
        style_open = f'<style nonce="{escape(nonce)}">' if nonce else "<style>"
        # Order matters: title block, then the contents page, then the body. The
        # TOC carries ``break-after: page`` so the report opens on its own cover.
        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)}</title>\n"
            '<meta name="generator" content="Maljan">\n'
            f"{style_open}{_STYLESHEET}</style>\n"
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
        name = (report.identity.file_name or "").strip()
        if not name:
            name = (report.identity.hashes.sha256 or "unknown sample")[:16]
        return f"Malware Analysis Report — {name}"

    def _body_html(self, report: MalwareReport) -> str:
        markdown = MarkdownRenderer().render(report)
        markdown = _SECTION_FAILED_RE.sub(
            lambda m: (
                f"> **Section '{m.group(1)}' could not be rendered.** "
                "The underlying data is present in the JSON report; see the server "
                "logs for the rendering error."
            ),
            markdown,
        )
        # html=False is the XSS guard: report content is LLM- and malware-derived.
        md = MarkdownIt("commonmark", {"html": False}).enable("table").enable("strikethrough")
        return str(md.render(markdown))

    # ------------------------------------------------------------------
    # Figure placement
    # ------------------------------------------------------------------

    def _place_figures(
        self, body_html: str, figures: list[Figure]
    ) -> tuple[str, list[str], list[Figure]]:
        """Split the body at H2 boundaries, give each an id, and inject figures.

        Returns the leading title block (everything before the first H2), the
        section chunks, and the figures that found no home — those go to the
        appendix rather than being dropped.
        """
        chunks = [c for c in _H2_SPLIT_RE.split(body_html) if c]
        by_heading: dict[str, list[Figure]] = {}
        for fig in figures:
            anchor = _FIGURE_ANCHORS.get(fig.kind)
            if anchor:
                by_heading.setdefault(anchor, []).append(fig)

        number = 1
        out: list[str] = []
        preamble_parts: list[str] = []
        used: set[str] = set()
        for chunk in chunks:
            match = _H2_HEAD_RE.match(chunk)
            if not match:
                # Everything before the first H2: <h1> + the verdict/degraded block.
                (preamble_parts if not out else out).append(chunk)
                continue
            heading = unescape(_TAG_RE.sub("", match.group(1))).strip()
            slug = _slug(heading)
            chunk = chunk.replace("<h2>", f'<h2 id="sec-{slug}">', 1)
            attached = by_heading.get(heading, [])
            if attached:
                used.add(heading)
                rendered = []
                for fig in attached:
                    rendered.append(_figure_html(fig, number))
                    number += 1
                chunk = chunk.rstrip() + "\n" + "".join(rendered)
            out.append(chunk)

        # Anything with no anchor kind, or whose anchor section is absent from
        # this particular report, still gets published — in the appendix.
        leftover = [fig for fig in figures if _FIGURE_ANCHORS.get(fig.kind) not in used]
        return "".join(preamble_parts), out, leftover

    def _figure_appendix(self, figures: list[Figure], *, start_index: int) -> str:
        if not figures:
            return ""
        parts = [
            '<h2 id="sec-figures">Appendix — Figures</h2>\n',
            "<p>Deterministic figures generated from the report's own data.</p>\n",
        ]
        for offset, fig in enumerate(figures):
            parts.append(_figure_html(fig, start_index + offset))
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
            heading = unescape(_TAG_RE.sub("", match.group(2))).strip()
            entries.append(f'<li><a href="#{match.group(1)}">{escape(heading)}</a></li>')
        if not entries:
            return ""
        return '<nav class="toc"><h2>Contents</h2><ol>' + "".join(entries) + "</ol></nav>\n"


def _slug(heading: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")
    return slug or "section"


def _figure_html(fig: Figure, number: int) -> str:
    """Wrap a figure. ``fig.content`` is trusted — see ``reporting/figures.py``."""
    legend = f'<span class="fig-legend">{escape(fig.legend)}</span>' if fig.legend else ""
    return (
        f'<figure id="{escape(fig.id)}">{fig.content}'
        f"<figcaption><b>Figure {number}.</b> {escape(fig.caption)}{legend}</figcaption>"
        "</figure>\n"
    )
