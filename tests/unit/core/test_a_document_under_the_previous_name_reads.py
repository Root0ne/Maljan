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


def test_an_answer_stored_with_the_previous_findings_tag_is_parsed() -> None:
    from malspark.agents.findings_block import has_findings_block, parse_findings_block

    body = '{"findings": [{"title": "a"}]}'
    stored = f"prose\n\n```{PREVIOUS_NAME}-findings\n{body}\n```"
    current = f"prose\n\n```{CURRENT_NAME}-findings\n{body}\n```"
    assert has_findings_block(stored)
    old, new = parse_findings_block(stored), parse_findings_block(current)
    assert old.prose == new.prose == "prose"
    assert [f.title for f in old.findings] == [f.title for f in new.findings] == ["a"]


def test_a_bundle_stored_with_previous_name_properties_reads_them() -> None:
    from malspark.schemas.stix_models import Bundle

    stored = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [],
        f"x_{PREVIOUS_NAME}_fallback_verdict": {"decision": "Malware", "source": "pipeline"},
    }
    current = dict(stored)
    current[f"x_{CURRENT_NAME}_fallback_verdict"] = current.pop(
        f"x_{PREVIOUS_NAME}_fallback_verdict"
    )
    old, new = Bundle.model_validate(stored), Bundle.model_validate(current)
    assert old.x_malspark_fallback_verdict is not None
    assert old.model_dump(mode="json") == new.model_dump(mode="json")


def test_identifiers_external_stores_hold_keep_their_values() -> None:
    """A MISP attribute's uuid, the STIX producer's id and the repair markers stay as written."""
    import uuid

    from app.services.settings_service import MARKER_PREFIX
    from malspark.reporting import misp
    from malspark.reporting.renderers import stix_renderer
    from malspark.schemas.stix_models import ATTACK_PATTERN_NAMESPACE

    assert misp._NAMESPACE == uuid.uuid5(uuid.NAMESPACE_URL, f"{PREVIOUS_NAME}:misp-attribute")
    assert stix_renderer.PRODUCER_IDENTITY_ID == (
        f"identity--{uuid.uuid5(ATTACK_PATTERN_NAMESPACE, PREVIOUS_NAME)}"
    )
    assert MARKER_PREFIX == f"{PREVIOUS_NAME}.repair."


def test_a_judge_answer_stored_with_previous_name_properties_is_renamed_in_place() -> None:
    from malspark.schemas.stix_models import current_property_names_in_place

    obj = {"type": "malware", "id": "malware--1", f"x_{PREVIOUS_NAME}_confidence": 0.8}
    both = {
        "type": "indicator",
        f"x_{PREVIOUS_NAME}_confidence": 0.1,
        f"x_{CURRENT_NAME}_confidence": 0.9,
    }
    bundle = {"type": "bundle", "objects": [obj, both], f"x_{PREVIOUS_NAME}_assessment": {}}
    current_property_names_in_place(bundle)
    assert bundle["objects"][0] is obj
    assert obj == {"type": "malware", "id": "malware--1", f"x_{CURRENT_NAME}_confidence": 0.8}
    assert both == {"type": "indicator", f"x_{CURRENT_NAME}_confidence": 0.9}
    assert f"x_{CURRENT_NAME}_assessment" in bundle


# ---- stored fixtures under the previous name (T-576) ----------------------

ROOT = Path(__file__).resolve().parents[3]


def _back(text: str) -> str:
    """``text`` as a release before the rename wrote it: every case of the name."""
    for current, previous in (
        (CURRENT_NAME.upper(), PREVIOUS_NAME.upper()),
        (CURRENT_NAME.capitalize(), PREVIOUS_NAME.capitalize()),
        (CURRENT_NAME, PREVIOUS_NAME),
    ):
        text = text.replace(current, previous)
    return text


def _forward(text: str) -> str:
    for previous, current in (
        (PREVIOUS_NAME.upper(), CURRENT_NAME.upper()),
        (PREVIOUS_NAME.capitalize(), CURRENT_NAME.capitalize()),
        (PREVIOUS_NAME, CURRENT_NAME),
    ):
        text = text.replace(previous, current)
    return text


def test_a_stored_report_written_before_the_rename_renders_as_it_does_now() -> None:
    """Every difference is the report's own stored text; nothing it reads by key is lost.

    The fixture holds no ledger seal, so there is no seal to verify here; the
    seal tags are held unchanged by ``test_identifiers_external_stores_hold_keep_their_values``
    and the ledger-chain tests.
    """
    from malspark.reporting.models import MalwareReport, key_ordered
    from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer

    fixture = ROOT / "tests/fixtures/reporting/stored_report_redacted.json"
    current_text = fixture.read_text(encoding="utf-8")
    previous_text = _back(current_text)
    assert previous_text != current_text
    current = MalwareReport.model_validate(key_ordered(json.loads(current_text)))
    previous = MalwareReport.model_validate(key_ordered(json.loads(previous_text)))
    assert _forward(MarkdownRenderer().render(previous)) == MarkdownRenderer().render(current)
    assert _forward(HtmlRenderer().render(previous, nonce="n")) == HtmlRenderer().render(
        current, nonce="n"
    )


def test_a_stored_run_written_before_the_rename_replays_to_the_same_codes(
    tmp_path: Path,
) -> None:
    """The tiny run with every file as a release before the rename wrote it decides the same."""
    import shutil

    from scripts.replay.record import BOOKKEEPING_KEYS
    from scripts.replay.rules import replay_run
    from scripts.replay.stored import read_run

    fixture = ROOT / "tests/fixtures/replay/tiny"
    previous = tmp_path / "tiny"
    shutil.copytree(fixture, previous)
    changed = 0
    for path in previous.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        if _back(text) != text:
            changed += 1
            path.write_text(_back(text), encoding="utf-8")
    assert changed

    def _decided(record: dict[str, Any]) -> Any:
        return json.loads(
            _forward(
                json.dumps(
                    {k: v for k, v in record.items() if k not in BOOKKEEPING_KEYS and k != "run"},
                    sort_keys=True,
                )
            )
        )

    assert _decided(replay_run(read_run(previous))) == _decided(replay_run(read_run(fixture)))
