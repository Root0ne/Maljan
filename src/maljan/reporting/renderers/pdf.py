"""Render a ``MalwareReport`` to PDF by printing the HTML export (Phase 6).

There is no second layout here on purpose: the PDF is exactly what
``HtmlRenderer`` produces, run through WeasyPrint, so the two exports can never
disagree. Everything that makes the output page-ready — the A4 ``@page`` box,
page numbers, ``break-inside`` rules on tables and figures, and the print-only
table-of-contents page numbers — already lives in the HTML stylesheet.

WeasyPrint is imported lazily. The Python wheel installs anywhere, but it binds
to Pango/HarfBuzz through ``ctypes`` at *call* time, so a machine without those
system libraries would otherwise fail at import and take down every renderer
import (including markdown) with it. Deferring it means only the PDF path is
affected, and it fails with an actionable message instead of an ImportError
traceback from a dependency the caller never mentioned.
"""

from __future__ import annotations

from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.html import HtmlRenderer


class PdfUnavailableError(RuntimeError):
    """WeasyPrint or its system libraries are missing on this host."""


class PdfRenderer:
    """Render a complete ``MalwareReport`` as PDF bytes."""

    def render(self, report: MalwareReport) -> bytes:
        """Return the report as a PDF document.

        Raises:
            PdfUnavailableError: WeasyPrint cannot be loaded on this host.
        """
        html_doc = HtmlRenderer().render(report)
        return self.render_html(html_doc)

    @staticmethod
    def render_html(html_doc: str) -> bytes:
        """Convert an already-rendered HTML document to PDF bytes."""
        try:
            from weasyprint import HTML  # noqa: PLC0415 — see module docstring
        except (ImportError, OSError) as exc:
            # OSError is what WeasyPrint raises when the wheel is installed but
            # libpango/libharfbuzz are absent — a different failure to ImportError,
            # and the far more likely one in a slim container.
            raise PdfUnavailableError(
                "PDF export is unavailable: WeasyPrint could not be loaded "
                f"({type(exc).__name__}: {exc}). The backend image installs "
                "libpango-1.0-0, libpangoft2-1.0-0 and libharfbuzz0b for this; "
                "on a bare host install those system packages, or use the "
                "Markdown/HTML export instead."
            ) from exc

        # base_url=None: the document is self-contained by construction (inline
        # CSS, inline SVG), so WeasyPrint must never be given a filesystem root
        # it could be talked into reading through a crafted url().
        pdf = HTML(string=html_doc, base_url=None).write_pdf()
        if pdf is None:  # pragma: no cover — write_pdf() returns bytes when no target
            raise PdfUnavailableError("WeasyPrint returned no PDF payload.")
        return bytes(pdf)
