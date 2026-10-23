"""A judge attack-pattern naming a tactic id is not published, catalogue or none."""

from __future__ import annotations

from typing import Any

import pytest

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.pipeline.validation import unknown_technique_ids
from maljan.tools import knowledge


def _bundle(external_id: str) -> dict[str, Any]:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
                "name": "Defense Evasion",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": external_id}
                ],
            }
        ],
    }


class _NoCatalogue:
    """A knowledge module whose every question fails: the catalogue is unavailable."""

    @staticmethod
    def attck_validate(_ids: Any) -> Any:
        raise RuntimeError("no catalogue")


def test_the_shape_check_needs_no_catalogue() -> None:
    assert unknown_technique_ids(["TA0005", "T1055.1", "T1055"], None) == {"TA0005", "T1055.1"}
    assert unknown_technique_ids(["TA0005", "T1055"], _NoCatalogue) == {"TA0005"}


def test_a_tactic_id_never_becomes_a_published_mapping_without_a_catalogue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(knowledge, "attck_validate", _NoCatalogue.attck_validate)
    monkeypatch.delattr(knowledge, "attck_lookup", raising=False)

    cells, mappings = build_capability_matrix(stix_output=_bundle("TA0005"), isr_reports={})

    assert [m.technique_id for m in mappings] == []
