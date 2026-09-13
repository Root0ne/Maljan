"""What the post-processor still does: shape repairs, and only shape repairs.

The indicator admission rules moved to ``pipeline.validation``, where they are
feedback the judge is shown rather than a silent drop; they are exercised in
``tests/unit/pipeline/test_validation.py``. What is left here is the STIX id
rewrite, the MITRE reference back-fill and the integrity pass.
"""

from __future__ import annotations

import pytest

from maljan.agents.judge_postprocess import (
    _technique_display_name,
    enforce_bundle_integrity,
    postprocess_judge_bundle,
)
from maljan.memory.attck_validator import ATTCKValidator


def _bundle_with(indicators: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000001",
        "objects": indicators,
    }


def _indicator(name: str, pattern: str) -> dict:
    return {
        "type": "indicator",
        "id": "indicator--00000000-0000-0000-0000-000000000002",
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-05-28T00:00:00Z",
    }


# ---------------------------------------------------------------------------
# enforce_bundle_integrity (referential integrity + dedup + empty-pattern)
# ---------------------------------------------------------------------------


def _ind(oid: str, pattern: str, ptype: str = "stix") -> dict:
    return {"type": "indicator", "id": oid, "pattern": pattern, "pattern_type": ptype}


def _ap(oid: str, tid: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": oid,
        "name": tid,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _rel(oid: str, rtype: str, src: str, tgt: str) -> dict:
    return {
        "type": "relationship",
        "id": oid,
        "relationship_type": rtype,
        "source_ref": src,
        "target_ref": tgt,
    }


class TestBundleIntegrity:
    def test_drops_empty_pattern_indicator(self) -> None:
        objs = [
            _ind("indicator--1", ""),
            _ind("indicator--2", "   "),
            _ind("indicator--3", "[x=1]"),
        ]
        out = enforce_bundle_integrity(objs)
        ids = {o["id"] for o in out}
        assert ids == {"indicator--3"}

    def test_drops_relationship_to_removed_indicator(self) -> None:
        # Relationship targets an indicator that gets dropped (empty pattern).
        objs = [
            {"type": "malware", "id": "malware--1", "name": "m"},
            _ind("indicator--1", ""),
            _rel("relationship--1", "indicates", "indicator--1", "malware--1"),
        ]
        out = enforce_bundle_integrity(objs)
        types = sorted(o["type"] for o in out)
        assert types == ["malware"]  # indicator + dangling relationship both gone

    def test_dedup_attack_patterns_by_tid_and_rewrite_refs(self) -> None:
        objs = [
            {"type": "malware", "id": "malware--1", "name": "m"},
            _ap("attack-pattern--a", "T1055"),
            _ap("attack-pattern--b", "T1055"),  # duplicate technique
            _rel("relationship--1", "uses", "malware--1", "attack-pattern--b"),
        ]
        out = enforce_bundle_integrity(objs)
        aps = [o for o in out if o["type"] == "attack-pattern"]
        rels = [o for o in out if o["type"] == "relationship"]
        assert len(aps) == 1 and aps[0]["id"] == "attack-pattern--a"
        # The relationship that pointed at the dropped duplicate is rewritten.
        assert len(rels) == 1 and rels[0]["target_ref"] == "attack-pattern--a"

    def test_dedup_indicators_by_pattern(self) -> None:
        objs = [
            _ind("indicator--1", "[ipv4-addr:value = '1.2.3.4']"),
            _ind("indicator--2", "[ipv4-addr:value = '1.2.3.4']"),
        ]
        out = enforce_bundle_integrity(objs)
        assert [o["id"] for o in out] == ["indicator--1"]

    def test_trims_dangling_object_refs(self) -> None:
        objs = [
            {"type": "malware", "id": "malware--1", "name": "m"},
            {
                "type": "report",
                "id": "report--1",
                "name": "r",
                "object_refs": ["malware--1", "indicator--gone"],
            },
        ]
        out = enforce_bundle_integrity(objs)
        report = next(o for o in out if o["type"] == "report")
        assert report["object_refs"] == ["malware--1"]

    def test_drops_malformed_pattern_indicator(self) -> None:
        objs = [
            _ind("indicator--1", "[file:name = 'unclosed"),  # missing closing bracket
            _ind("indicator--2", "not a pattern at all"),
            _ind("indicator--3", "[file:hashes.'SHA-256' = 'abc']"),  # valid
            _ind("indicator--4", "[ipv4-addr:value = '1.2.3.4']"),  # valid
        ]
        out = enforce_bundle_integrity(objs)
        assert {o["id"] for o in out} == {"indicator--3", "indicator--4"}

    def test_postprocess_runs_integrity_pass(self) -> None:
        # End-to-end: postprocess_judge_bundle now drops a dangling relationship.
        bundle = {
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "m"},
                _ind("indicator--1", ""),  # dropped -> its relationship dangles
                _rel("relationship--1", "indicates", "indicator--1", "malware--1"),
            ],
        }
        result = postprocess_judge_bundle(bundle)
        types = sorted(o["type"] for o in result["objects"])
        assert types == ["malware"]


class TestTechniqueDisplayName:
    def test_returns_none_without_singleton(self) -> None:
        ATTCKValidator.reset()
        assert _technique_display_name("T1055") is None

    def test_rep01_backfill_falls_back_without_index(self) -> None:
        # An uncurated technique ID with no built index must still get a valid
        # external_reference back-filled (no crash, deterministic URL).
        ATTCKValidator.reset()
        ap = {
            "type": "attack-pattern",
            "id": "attack-pattern--00000000-0000-4000-8000-0000000000bb",
            "name": "T1620",  # not in the curated _MITRE_LOOKUP table
            "external_references": [],
        }
        bundle = {"type": "bundle", "id": "bundle--1", "objects": [ap]}
        result = postprocess_judge_bundle(bundle)
        aps = [o for o in result["objects"] if o["type"] == "attack-pattern"]
        assert len(aps) == 1
        refs = aps[0].get("external_references") or []
        assert any(r.get("external_id") == "T1620" for r in refs)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
