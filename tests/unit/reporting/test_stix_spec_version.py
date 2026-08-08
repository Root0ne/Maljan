"""Every SDO we emit must carry ``spec_version``, because STIX 2.1 requires it.

In STIX 2.0 the bundle carried ``spec_version``; in 2.1 it moved onto each object and
became mandatory. We emitted it nowhere. Strictly, every bundle this project produced
was therefore not identifiable as 2.1 — a consumer applying the spec falls back to 2.0
semantics, and the OASIS ``cti-stix-validator`` rejects the object with "Cannot locate a
schema for the object's type".

Found on 2026-08-08 by pointing that validator at four bundles from real runs while
measuring the integrity pass (``tests/evaluation/eval_stix_integrity.py``). The point
worth keeping is *how* it was found: our own integrity pass checks empty patterns,
duplicate attack-patterns and dangling references, and has no opinion about this at all.
It took someone else's instrument to see it, which is the same argument §3.4 makes about
measurement instruments, arriving this time at our own expense.

These tests are cheap and deterministic so the property cannot regress silently again.
"""

from __future__ import annotations

import json

import pytest

from maljan.schemas.stix_models import (
    AttackPattern,
    Bundle,
    Indicator,
    Malware,
    Relationship,
)

# A syntactically valid SHA-256 pattern: the validator parses patterns, so a
# placeholder like 'ab' fails on hash length rather than on anything we control.
_PROBE_PATTERN = "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"


def _sdo_instances() -> list[object]:
    """One of each SDO the pipeline actually emits."""
    malware = Malware(name="example")
    ap = AttackPattern(name="Process Injection")
    return [
        malware,
        ap,
        Indicator(
            pattern=_PROBE_PATTERN,
            pattern_type="stix",
        ),
        Relationship(relationship_type="uses", source_ref=malware.id, target_ref=ap.id),
    ]


class TestEverySdoCarriesSpecVersion:
    @pytest.mark.parametrize("sdo", _sdo_instances(), ids=lambda s: type(s).__name__)
    def test_the_attribute_is_present_and_is_2_1(self, sdo: object) -> None:
        assert getattr(sdo, "spec_version", None) == "2.1"

    @pytest.mark.parametrize("sdo", _sdo_instances(), ids=lambda s: type(s).__name__)
    def test_it_survives_serialisation(self, sdo: object) -> None:
        """The validator reads serialised JSON, not the Python object."""
        dumped = json.loads(sdo.model_dump_json())  # type: ignore[attr-defined]
        assert dumped.get("spec_version") == "2.1", (
            f"{type(sdo).__name__} serialises without spec_version; a STIX 2.1 consumer "
            "would fall back to 2.0 semantics"
        )

    def test_a_whole_bundle_serialises_with_it_on_every_object(self) -> None:
        bundle = Bundle(objects=_sdo_instances())
        dumped = json.loads(bundle.model_dump_json())
        assert dumped["objects"], "fixture built an empty bundle"
        missing = [o.get("type") for o in dumped["objects"] if o.get("spec_version") != "2.1"]
        assert not missing, f"objects missing spec_version: {missing}"


class TestTheBundleItselfDoesNotCarryIt:
    def test_spec_version_is_not_a_bundle_property_in_2_1(self) -> None:
        """It moved onto the objects; leaving it on the bundle is the 2.0 shape and
        would make the bundle ambiguous about which version it claims."""
        dumped = json.loads(Bundle(objects=_sdo_instances()).model_dump_json())
        assert "spec_version" not in dumped
