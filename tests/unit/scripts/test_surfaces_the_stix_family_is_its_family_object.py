"""The STIX surface's family is the name of its ``is_family: true`` malware object.

The judge's malware object may stand for the one sample, named for its hash
with ``is_family: false``; the export then adds the family's own object and
makes the judge's a ``variant-of`` it. The family the bundle states is that
object's name, wherever it stands in the bundle. A family object naming
another family is still a defect, and so is an export with no object named
for the family at all.
"""

from __future__ import annotations

from typing import Any

from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import SHA256, clean_run, clean_spec, defects


def _sample_object_first(run: dict[str, Any], family: str) -> None:
    objects = run["stix"]["objects"]
    objects[1] = {"type": "malware", "id": "malware--1", "name": SHA256, "is_family": False}
    objects.append({"type": "malware", "id": "malware--2", "name": family, "is_family": True})
    objects.append(
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "variant-of",
            "source_ref": "malware--1",
            "target_ref": "malware--2",
        }
    )
    run["report_row"]["run_summary"]["stix_object_count"] += 2
    run["run_summary"]["stix_object_count"] += 2


def test_a_sample_object_named_for_its_hash_beside_the_family_object_is_clean() -> None:
    run = clean_run()
    _sample_object_first(run, "Examplefam")

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == []
    assert result["checked"]["family"] > 0


def test_a_family_object_naming_another_family_is_a_defect() -> None:
    run = clean_run()
    _sample_object_first(run, "Otherfam")

    result = surfaces.audit(run, clean_spec())

    assert set(defects(result)) == {("differs", "family", "stix")}


def test_no_object_named_for_the_family_is_a_defect() -> None:
    run = clean_run()
    run["stix"]["objects"][1] = {
        "type": "malware",
        "id": "malware--1",
        "name": SHA256,
        "is_family": False,
    }

    result = surfaces.audit(run, clean_spec())

    assert set(defects(result)) == {("differs", "family", "stix")}
