"""Renderer entry points for ``MalwareReport``.

Each renderer is a stateless class with a single ``render()`` method, so they
compose freely from CLI, API and pipeline contexts.

``PdfRenderer`` is re-exported here, but it defers its WeasyPrint import to
``render()`` — importing this package never requires the PDF system libraries.
"""

from __future__ import annotations

from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.pdf import PdfRenderer, PdfUnavailableError
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

__all__ = [
    "ExtendedSTIXRenderer",
    "HtmlRenderer",
    "MarkdownRenderer",
    "PdfRenderer",
    "PdfUnavailableError",
]
