"""The two settings that hold records are served with the editor the console draws a form with.

``api.enrichment_sources`` (a map of sources) and ``sandbox.report_formats`` (a
list of formats, each with its ``display_name``) used to be edited as one JSON
value. Their catalog entries now name an editor; the value itself is unchanged.
"""

from __future__ import annotations

import pytest

from app.services.settings_catalog_api import catalog_index


@pytest.mark.parametrize(
    ("key", "editor", "kind"),
    [
        ("api.enrichment_sources", "enrichment_sources", "dict"),
        ("sandbox.report_formats", "report_formats", "list"),
    ],
)
def test_a_record_setting_names_its_editor(key: str, editor: str, kind: str) -> None:
    entry = catalog_index().get(key) or catalog_index().get(f"core.{key}")
    assert entry is not None
    assert entry.editor == editor
    assert entry.type in (kind, "json")
