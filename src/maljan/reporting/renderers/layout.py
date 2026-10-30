"""Which report a render produces, and the names of the files the analyst report links to.

Three layouts render the same ``MalwareReport``:

* :data:`ANALYST` — the analyst report: the findings a reader acts on, in a
  fixed order, with each citation a numbered note that links into the
  evidence bundle (``renderers/analyst.py``);
* :data:`BUNDLE` — the evidence bundle: every section the single-file report
  prints, the citation notes the analyst report links to, and an anchor for
  every evidence id (``renderers/bundle.py``);
* :data:`FULL` — the single-file report as it was printed before the split.

The served exports print the analyst report unless an operator sets
``reporting.full_report_in_one_file``; the bundle is served beside it. The
renderers themselves default to the single-file layout, which every caller
that names no layout has always read.
"""

from __future__ import annotations

from typing import Any, Literal

Layout = Literal["full", "analyst", "bundle"]
FULL: Layout = "full"
ANALYST: Layout = "analyst"
BUNDLE: Layout = "bundle"
LAYOUTS: frozenset[str] = frozenset({FULL, ANALYST, BUNDLE})

# The evidence bundle's two files, named as the analyst report links to them:
# beside the report wherever it is written (the job package's ``report/``),
# and served at the same names under the report's own route, so a relative
# link resolves in both.
BUNDLE_HTML = "evidence-bundle.html"
BUNDLE_JSON = "evidence-bundle.json"
BUNDLE_FILES: tuple[str, ...] = (BUNDLE_HTML, BUNDLE_JSON)


def report_layout(settings: Any = None) -> Layout:
    """The layout the served report prints: the single file where the operator asked for it.

    ``settings`` is the caller's ``Settings`` (the API's, read from the store);
    without one the process's own are read.
    """
    if settings is None:
        from maljan.core.config import get_settings

        settings = get_settings()
    return FULL if settings.reporting.full_report_in_one_file else ANALYST


def checked(layout: str) -> Layout:
    """``layout`` when it is one of :data:`LAYOUTS`; a ``ValueError`` naming them otherwise."""
    if layout not in LAYOUTS:
        raise ValueError(f"unknown report layout {layout!r}; one of {sorted(LAYOUTS)}")
    return layout  # type: ignore[return-value]
