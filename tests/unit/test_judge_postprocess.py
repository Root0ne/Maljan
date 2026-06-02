"""Unit tests for the tightened J-02 indicator filter (Wave 4)."""

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
# file:name acceptance
# ---------------------------------------------------------------------------


class TestFileNameAcceptance:
    def test_accepts_path_with_real_extension(self) -> None:
        bundle = _bundle_with([_indicator("payload", "[file:name = '/data/local/tmp/payload.so']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={"payload.so"})
        kept = [o for o in result["objects"] if o.get("type") == "indicator"]
        assert len(kept) == 1

    def test_accepts_path_with_os_prefix(self) -> None:
        bundle = _bundle_with([_indicator("staging", "[file:name = '/sdcard/Download/dropper']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={"dropper"})
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1

    def test_rejects_compile_artefact_path(self) -> None:
        # NDK build path — the noise audit's #1 source.
        ndk_path = (
            "/buildbot/src/android/ndk-r25-release/toolchain/llvm-project/libcxx/include/string"
        )
        bundle = _bundle_with([_indicator("ndk-leak", f"[file:name = '{ndk_path}']")])
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={ndk_path.lower()},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_rejects_foreign_class_ref(self) -> None:
        # `/lang/ClassCastException` etc. surfaced from bundled bytecode strings.
        bundle = _bundle_with(
            [_indicator("class-cast", "[file:name = '/lang/ClassCastException']")]
        )
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"/lang/classcastexception"},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_rejects_random_short_string_path(self) -> None:
        # /I FyD, /urLU4b — random extracted strings that aren't paths.
        bundle = _bundle_with(
            [
                _indicator("noise1", "[file:name = '/I FyD']"),
                _indicator("noise2", "[file:name = '/urLU4b']"),
            ]
        )
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"/i fyd", "/urlu4b"},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_file_name_cap_enforced(self) -> None:
        # Build 15 valid .exe indicators; only 10 should survive.
        inds = [_indicator(f"x{i}", f"[file:name = '/var/tmp/payload{i}.exe']") for i in range(15)]
        bundle = _bundle_with(inds)
        corpus = {f"payload{i}.exe" for i in range(15)}
        result = postprocess_judge_bundle(bundle, evidence_corpus=corpus)
        kept = [o for o in result["objects"] if o.get("type") == "indicator"]
        assert len(kept) == 10


# ---------------------------------------------------------------------------
# URL denylist
# ---------------------------------------------------------------------------


class TestUrlDenylist:
    def test_drops_developer_host(self) -> None:
        bundle = _bundle_with(
            [
                _indicator(
                    "ndk-url",
                    "[url:value = 'https://android.googlesource.com/toolchain/llvm-project']",
                )
            ]
        )
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"https://android.googlesource.com/toolchain/llvm-project"},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_keeps_arbitrary_c2_url(self) -> None:
        bundle = _bundle_with([_indicator("c2", "[url:value = 'http://evil.example.com/beacon']")])
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"http://evil.example.com/beacon"},
        )
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1


# ---------------------------------------------------------------------------
# Backwards compatibility — non file:name / non url indicators
# ---------------------------------------------------------------------------


class TestLegacyKindsUnchanged:
    def test_hash_indicator_kept_when_in_corpus(self) -> None:
        h = "95236ef71738807ce60ef7d042699decb7156931931682cf46e6ad" + "0" * 10
        bundle = _bundle_with([_indicator("hash", f"[file:hashes.'SHA-256' = '{h}']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={h})
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1

    def test_domain_indicator_kept_when_in_corpus(self) -> None:
        bundle = _bundle_with([_indicator("c2", "[domain-name:value = 'evil.example.com']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={"evil.example.com"})
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1


# ---------------------------------------------------------------------------
# REP-02 (Wave 9) — orphan attack-pattern dropping
# ---------------------------------------------------------------------------


def _attack_pattern(uid: str, tid: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{uid}",
        "name": tid,
        "external_references": [],
    }


def _relationship(uid: str, src: str, tgt: str) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{uid}",
        "relationship_type": "uses",
        "source_ref": src,
        "target_ref": tgt,
    }


class TestRep02OrphanDrop:
    def test_drops_orphan_attack_pattern(self) -> None:
        bundle = _bundle_with(
            [
                _attack_pattern("00000000-0000-4000-8000-000000000003", "T1497"),
                _attack_pattern("00000000-0000-4000-8000-000000000004", "T1562"),
            ]
        )
        result = postprocess_judge_bundle(
            bundle,
            valid_technique_ids=frozenset({"T1497"}),
        )
        aps = [o for o in result["objects"] if o.get("type") == "attack-pattern"]
        assert len(aps) == 1
        # REP-01 may promote the bare ID to the canonical MITRE name; check
        # via the external_references TID instead.
        refs = aps[0].get("external_references") or []
        assert any(r.get("external_id") == "T1497" for r in refs)

    def test_drops_relationships_to_orphan(self) -> None:
        ap_id_keep = "attack-pattern--00000000-0000-4000-8000-000000000005"
        ap_id_drop = "attack-pattern--00000000-0000-4000-8000-000000000006"
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000099",
            "objects": [
                # Malware sources for the relationships — required so the
                # referential-integrity pass does not treat the relationships
                # as dangling (their source_ref must resolve to a real object).
                {
                    "type": "malware",
                    "id": "malware--00000000-0000-4000-8000-000000000008",
                    "name": "m1",
                },
                {
                    "type": "malware",
                    "id": "malware--00000000-0000-4000-8000-00000000000a",
                    "name": "m2",
                },
                {
                    "type": "attack-pattern",
                    "id": ap_id_keep,
                    "name": "T1497",
                    "external_references": [],
                },
                {
                    "type": "attack-pattern",
                    "id": ap_id_drop,
                    "name": "T1562",
                    "external_references": [],
                },
                _relationship(
                    "00000000-0000-4000-8000-000000000007",
                    "malware--00000000-0000-4000-8000-000000000008",
                    ap_id_keep,
                ),
                _relationship(
                    "00000000-0000-4000-8000-000000000009",
                    "malware--00000000-0000-4000-8000-00000000000a",
                    ap_id_drop,
                ),
            ],
        }
        result = postprocess_judge_bundle(
            bundle,
            valid_technique_ids=frozenset({"T1497"}),
        )
        rels = [o for o in result["objects"] if o.get("type") == "relationship"]
        assert len(rels) == 1
        assert rels[0]["target_ref"] == ap_id_keep

    def test_no_filter_when_set_is_none(self) -> None:
        # Legacy callers (no cascade summary) must not see SDOs dropped.
        bundle = _bundle_with(
            [
                _attack_pattern("00000000-0000-4000-8000-00000000000b", "T1562"),
            ]
        )
        result = postprocess_judge_bundle(bundle, valid_technique_ids=None)
        aps = [o for o in result["objects"] if o.get("type") == "attack-pattern"]
        assert len(aps) == 1


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
