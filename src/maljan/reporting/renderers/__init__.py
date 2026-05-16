"""Renderer entry points for ``MalwareReport``.

Each renderer is a stateless class with a single ``render()`` method, so they
compose freely from CLI, API and pipeline contexts.
"""

from __future__ import annotations

from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

__all__ = ["ExtendedSTIXRenderer", "MarkdownRenderer"]
