"""A document an earlier release wrote under the previous name reads as the same version.

The rename (T-576) changed every format and schema label a writer emits;
``malspark.core.previous_name.under_current_name`` is how a reader takes one
written before it. The frozen tool-facts snapshot is the one data file a
reader holds to its schema label, so it is read here as it was cut.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from malspark.core import legacy_tool_facts, paths
from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME, under_current_name
from malspark.reporting.renderers import bundle


@pytest.mark.parametrize(
    "label",
    ["settings/3", "job-package/2", "job-package/1", "evidence-bundle/1", "legacy-tool-facts/v1"],
)
def test_a_previous_name_label_reads_as_the_same_version(label: str) -> None:
    assert under_current_name(f"{PREVIOUS_NAME}-{label}") == f"{CURRENT_NAME}-{label}"


@pytest.mark.parametrize("value", [f"{CURRENT_NAME}-settings/3", "other-settings/3", "", None, 3])
def test_anything_else_is_returned_as_it_is(value: Any) -> None:
    assert under_current_name(value) == value


def test_the_evidence_bundle_writer_emits_the_current_name() -> None:
    assert bundle.FORMAT == f"{CURRENT_NAME}-evidence-bundle/1"
    assert under_current_name(f"{PREVIOUS_NAME}-evidence-bundle/1") == bundle.FORMAT


def test_the_frozen_snapshot_as_it_was_cut_still_reads(tmp_path: Path, monkeypatch: Any) -> None:
    """The snapshot byte for byte as cut, its label under the previous name, reads the same."""
    current = paths.resolve_data(legacy_tool_facts.SNAPSHOT_PATH).read_text(encoding="utf-8")
    label = f'"schema": "{legacy_tool_facts.SNAPSHOT_SCHEMA}"'
    assert current.count(label) == 1
    as_cut = current.replace(
        label, f'"schema": "{PREVIOUS_NAME}-{legacy_tool_facts.SNAPSHOT_SCHEMA.split("-", 1)[1]}"'
    )
    stored = tmp_path / "legacy_tool_facts_v1.json"
    stored.write_text(as_cut, encoding="utf-8")
    expected = json.loads(current)["tools"]

    legacy_tool_facts._document.cache_clear()
    monkeypatch.setattr(paths, "resolve_data", lambda _relative: stored)
    try:
        assert legacy_tool_facts._document()["tools"] == expected
    finally:
        legacy_tool_facts._document.cache_clear()


def test_a_changed_snapshot_is_still_refused(tmp_path: Path, monkeypatch: Any) -> None:
    current = paths.resolve_data(legacy_tool_facts.SNAPSHOT_PATH).read_text(encoding="utf-8")
    stored = tmp_path / "legacy_tool_facts_v1.json"
    stored.write_text(current + "\n", encoding="utf-8")
    legacy_tool_facts._document.cache_clear()
    monkeypatch.setattr(paths, "resolve_data", lambda _relative: stored)
    try:
        with pytest.raises(ValueError, match="not the frozen snapshot"):
            legacy_tool_facts._document()
    finally:
        legacy_tool_facts._document.cache_clear()
