"""The standard SDO properties are declared, so they are carried, and checked.

``valid_until``, ``kill_chain_phases`` and the others were dropped at
validation and recorded as ``stix.property_not_carried``. They are declared on
the models now, optional as STIX makes them, with the orderings the standard
requires; an object that breaks one is set aside by the judge post-processing
with a record, not published invalid.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.agents.judge_postprocess import _not_carried, _object_problem
from maljan.schemas.stix_models import AttackPattern, Indicator, Malware, Relationship

PHASE = {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "delivery"}


def test_an_indicator_carries_valid_until_and_phases() -> None:
    obj = {
        "type": "indicator",
        "pattern": "[file:name = 'a']",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-06-01T00:00:00Z",
        "kill_chain_phases": [PHASE],
    }
    assert _not_carried(obj) == []
    dumped = Indicator.model_validate(obj).model_dump(mode="json")
    assert dumped["valid_until"].startswith("2026-06-01")
    assert dumped["kill_chain_phases"] == [PHASE]


def test_an_indicator_without_them_dumps_without_them() -> None:
    dumped = Indicator(pattern="[file:name = 'a']").model_dump(mode="json")
    assert "valid_until" not in dumped
    assert "kill_chain_phases" not in dumped


@pytest.mark.parametrize("until", ["2026-01-01T00:00:00Z", "2025-12-31T00:00:00Z"])
def test_valid_until_must_follow_valid_from(until: str) -> None:
    obj = {
        "type": "indicator",
        "pattern": "[file:name = 'a']",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": until,
    }
    with pytest.raises(ValidationError):
        Indicator.model_validate(obj)
    assert "valid_until" in _object_problem(obj)


def test_a_zone_less_timestamp_is_read_as_utc() -> None:
    Indicator.model_validate(
        {
            "pattern": "[file:name = 'a']",
            "valid_from": "2026-01-01T00:00:00",
            "valid_until": "2026-01-02T00:00:00Z",
        }
    )


def test_malware_last_seen_may_equal_but_not_precede_first_seen() -> None:
    same = "2026-01-01T00:00:00Z"
    Malware(name="x", first_seen=same, last_seen=same)
    with pytest.raises(ValidationError):
        Malware(name="x", first_seen=same, last_seen="2025-01-01T00:00:00Z")


def test_a_relationship_stop_time_must_follow_start_time() -> None:
    base = {"relationship_type": "uses", "source_ref": "a--1", "target_ref": "b--2"}
    Relationship(**base, start_time="2026-01-01T00:00:00Z", stop_time="2026-01-02T00:00:00Z")
    with pytest.raises(ValidationError):
        Relationship(**base, start_time="2026-01-02T00:00:00Z", stop_time="2026-01-01T00:00:00Z")


def test_an_attack_pattern_carries_phases_and_aliases() -> None:
    obj = {"type": "attack-pattern", "name": "x", "aliases": ["y"], "kill_chain_phases": [PHASE]}
    assert _not_carried(obj) == []
    assert AttackPattern.model_validate(obj).model_dump(mode="json")["aliases"] == ["y"]


def test_valid_until_is_not_checked_against_a_valid_from_nobody_wrote() -> None:
    # ``valid_from`` defaults to the clock; the order must not depend on it.
    Indicator.model_validate(
        {"pattern": "[file:name = 'a']", "valid_until": "2000-01-01T00:00:00Z"}
    )


def test_times_are_held_in_utc_and_written_with_z() -> None:
    obj = Indicator.model_validate(
        {
            "pattern": "[file:name = 'a']",
            "valid_from": "2026-01-01T02:00:00+02:00",
            "valid_until": "2026-01-02T00:00:00",
        }
    )
    dumped = obj.model_dump(mode="json")
    assert dumped["valid_from"] == "2026-01-01T00:00:00Z"
    assert dumped["valid_until"] == "2026-01-02T00:00:00Z"
    seen = Malware(name="x", first_seen="2026-01-01T00:00:00").model_dump(mode="json")
    assert seen["first_seen"].endswith("Z")


def test_a_phase_with_a_key_the_standard_does_not_define_is_refused() -> None:
    with pytest.raises(ValidationError):
        AttackPattern(name="x", kill_chain_phases=[{**PHASE, "extra": 1}])
