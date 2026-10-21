"""A standard property the standard does not allow as written is dropped, not the object.

Real judge answers wrote a ``valid_until`` equal to ``valid_from`` and
``kill_chain_phases`` with no ``kill_chain_name``. With the standard properties
declared, either would have failed the object's validation and set it aside. The
property is taken out of the object instead, recorded, and the object is kept;
the judge's own bundle keeps it as written. The export does not carry the times
a judge writes about the run, nor a phase of a chain the platform does not know.
"""

from __future__ import annotations

from typing import Any

from maljan.agents.judge_postprocess import PROPERTY_NOT_CARRIED_CODE, lift_misplaced_extensions
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.stix_models import Bundle

CONTACT = "185.199.111.20"
PHASE = {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "delivery"}
LATE = "2026-02-01T00:00:00Z"
EARLY = "2026-01-01T00:00:00Z"


def _lift(*objects: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    bundle = {"type": "bundle", "objects": list(objects)}
    rows = lift_misplaced_extensions(bundle)
    return bundle, rows


def _carried_rows(rows: list[Any]) -> list[Any]:
    return [r for r in rows if r.code == PROPERTY_NOT_CARRIED_CODE]


def _malware(**extra: Any) -> dict[str, Any]:
    return {"type": "malware", "id": "malware--1", "name": "x", "is_family": False, **extra}


def _indicator(**extra: Any) -> dict[str, Any]:
    return {"type": "indicator", "id": "indicator--1", "pattern": "[file:name = 'a']", **extra}


def test_an_indicator_with_valid_until_equal_to_valid_from_keeps_the_object() -> None:
    bundle, rows = _lift(_indicator(valid_from=EARLY, valid_until=EARLY))
    (kept,) = bundle["objects"]
    assert "valid_until" not in kept
    assert kept["valid_from"] == EARLY
    (row,) = _carried_rows(rows)
    assert "valid_until" in row.message and "does not allow" in row.message


def test_a_phase_with_no_chain_name_drops_the_property_not_the_object() -> None:
    bundle, rows = _lift(
        _malware(kill_chain_phases=[{"phase_name": "delivery"}]),
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "y",
            "kill_chain_phases": [{**PHASE, "extra": 1}],
        },
    )
    assert len(bundle["objects"]) == 2
    assert all("kill_chain_phases" not in obj for obj in bundle["objects"])
    assert len(_carried_rows(rows)) == 2


def test_the_later_of_an_ordered_pair_is_the_one_dropped() -> None:
    bundle, rows = _lift(
        _malware(first_seen=LATE, last_seen=EARLY),
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "uses",
            "source_ref": "malware--1",
            "target_ref": "attack-pattern--1",
            "start_time": LATE,
            "stop_time": EARLY,
        },
    )
    malware, relationship = bundle["objects"]
    assert "last_seen" not in malware and "first_seen" in malware
    assert "stop_time" not in relationship and "start_time" in relationship
    assert len(_carried_rows(rows)) == 2


def test_an_indicator_without_valid_from_keeps_its_valid_until() -> None:
    bundle, rows = _lift(_indicator(valid_until="2000-01-01T00:00:00Z"))
    assert bundle["objects"][0]["valid_until"] == "2000-01-01T00:00:00Z"
    assert _carried_rows(rows) == []


def test_a_value_the_standard_properties_do_not_cover_still_sets_the_object_aside() -> None:
    bundle, rows = _lift(_indicator(valid_from="not a time"))
    assert bundle["objects"] == []
    assert any(r.code == "stix.unknown_object" for r in rows)


def test_the_export_carries_what_the_run_grounds_and_declines_the_rest() -> None:
    bundle_dict, _ = _lift(
        _malware(
            aliases=["LDR"],
            first_seen=EARLY,
            kill_chain_phases=[PHASE, {"kill_chain_name": "invented", "phase_name": "p"}],
        ),
        _indicator(
            pattern=f"[ipv4-addr:value = '{CONTACT}']",
            valid_from=EARLY,
            valid_until="2026-06-01T00:00:00Z",
        ),
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "indicates",
            "source_ref": "indicator--1",
            "target_ref": "malware--1",
            "description": "the address",
            "start_time": EARLY,
        },
    )
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        malware_category="loader",
        overall_confidence=0.9,
        network=NetworkIOCs(
            ips=[NetworkIP(address=CONTACT, source="sandbox", sample_process_tree=True)]
        ),
    )
    renderer = ExtendedSTIXRenderer()
    exported = renderer.render(report, Bundle.model_validate(bundle_dict)).model_dump(mode="json")
    objects = {o["id"]: o for o in exported["objects"]}
    malware = objects["malware--1"]
    assert malware["aliases"] == ["LDR"]
    assert malware["kill_chain_phases"] == [PHASE]
    assert "first_seen" not in malware
    (indicator,) = [o for o in exported["objects"] if CONTACT in o.get("pattern", "")]
    relationships = [o for o in exported["objects"] if o["type"] == "relationship"]
    assert relationships
    assert "valid_until" not in indicator
    assert all("start_time" not in r for r in relationships)
    assert any(r.get("description") == "the address" for r in relationships)
    reasons = " | ".join(
        why for code, why in renderer.declined if code == PROPERTY_NOT_CARRIED_CODE
    )
    for named in ("first_seen", "invented", "valid_until", "start_time"):
        assert named in reasons, named


def test_only_the_failing_phase_goes_and_the_row_names_where() -> None:
    bundle, rows = _lift(
        _malware(kill_chain_phases=[PHASE, {"phase_name": "c2"}, {**PHASE, "phase_name": "x"}])
    )
    (kept,) = bundle["objects"]
    assert kept["kill_chain_phases"] == [PHASE, {**PHASE, "phase_name": "x"}]
    (row,) = _carried_rows(rows)
    assert "kill_chain_phases[1]" in row.message
    assert "kill_chain_phases.1.kill_chain_name" in row.message
