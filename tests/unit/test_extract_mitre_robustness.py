"""A malformed STIX object must cost a field, never the run.

`_extract_mitre` runs at the very end of `run_analysis`, after every analyst,
the negotiation and the judge have finished — so anything that raises here
throws away the entire analysis. Two consecutive live runs did exactly that on
2026-07-27, failing with `IndexError: list index out of range` roughly six
minutes of LLM work after the last thing that could still have been retried.

The line read:

    obj.get("external_references", [{}])[0].get("external_id", "")

which looks defensive and is not. The `[{}]` default only applies when the key
is **absent**; an attack-pattern carrying `"external_references": []` — which
the model emits routinely — sails past it and dies on the `[0]`.

The tests below feed it every shape a model has produced or plausibly could.
None of them should be able to fail a run.
"""

from __future__ import annotations

from typing import Any

from app.worker.analysis_worker import _extract_mitre


def _bundle(*objects: dict[str, Any]) -> dict[str, Any]:
    return {"stix_output": {"objects": list(objects)}}


class TestMalformedStixCannotFailTheRun:
    def test_an_empty_external_references_list(self) -> None:
        """The exact shape that killed two live runs."""
        result = _extract_mitre(
            _bundle(
                {"type": "attack-pattern", "name": "Process Injection", "external_references": []}
            )
        )
        assert result is not None
        assert result[0]["technique_id"] == ""
        assert result[0]["name"] == "Process Injection", "the rest of the object survives"

    def test_a_missing_external_references_key(self) -> None:
        result = _extract_mitre(_bundle({"type": "attack-pattern", "name": "Masquerading"}))
        assert result is not None
        assert result[0]["technique_id"] == ""

    def test_external_references_that_is_not_a_list(self) -> None:
        result = _extract_mitre(
            _bundle({"type": "attack-pattern", "name": "X", "external_references": "T1055"})
        )
        assert result is not None
        assert result[0]["technique_id"] == ""

    def test_a_reference_that_is_not_a_dict(self) -> None:
        result = _extract_mitre(
            _bundle({"type": "attack-pattern", "name": "X", "external_references": ["T1055"]})
        )
        assert result is not None
        assert result[0]["technique_id"] == ""

    def test_an_object_that_is_not_a_dict_at_all(self) -> None:
        assert _extract_mitre({"stix_output": {"objects": ["nonsense", None, 42]}}) is None

    def test_one_bad_object_does_not_discard_the_good_ones(self) -> None:
        """The point of the fix: degrade the field, keep the analysis."""
        result = _extract_mitre(
            _bundle(
                {"type": "attack-pattern", "name": "Broken", "external_references": []},
                {
                    "type": "attack-pattern",
                    "name": "Process Injection",
                    "external_references": [{"external_id": "T1055"}],
                },
            )
        )
        assert result is not None
        assert [t["technique_id"] for t in result] == ["", "T1055"]


class TestTheHappyPathIsUnchanged:
    def test_a_well_formed_attack_pattern(self) -> None:
        result = _extract_mitre(
            _bundle(
                {
                    "type": "attack-pattern",
                    "name": "Process Injection",
                    "description": "d",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1055"}
                    ],
                }
            )
        )
        assert result == [
            {"technique_id": "T1055", "name": "Process Injection", "description": "d"}
        ]

    def test_ttp_mappings_still_win_over_the_stix_bundle(self) -> None:
        result = _extract_mitre(
            {
                "malware_report": {
                    "ttp_mappings": [
                        {"technique_id": "T1547", "technique_name": "Registry Run Keys"}
                    ]
                },
                "stix_output": {"objects": [{"type": "attack-pattern", "name": "Ignored"}]},
            }
        )
        assert result is not None
        assert result[0]["technique_id"] == "T1547"

    def test_no_stix_and_no_mappings_returns_none(self) -> None:
        assert _extract_mitre({}) is None
        assert _extract_mitre({"stix_output": None}) is None
