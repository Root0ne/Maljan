"""A static-only run knew its verdict but not what it was looking at.

``FamilyAttribution`` drew the family name from exactly one place — CAPE's
``cti.family[]``. With the sandbox unreachable, which is the normal case here,
every report came back with a verdict, a technique list, and no name.

A Cobalt Strike beacon, a Mimikatz build and an AsyncRAT client all carry
distinctive strings. Matching them is neither clever nor expensive; it was
simply never wired up.

Two properties carry the risk, and both are tested below.

**Two markers, never one.** Every string in the catalog can appear in something
benign — a detection signature, an EDR agent, a blue-team tool, this repo's own
data files. A one-hit rule flags the defenders' tooling, and a report calling
Sysinternals "Cobalt Strike" is worse than one that says nothing. The floor is
enforced in the loader as well as the data, because the JSON is hand-editable.

**It shares ``domain="yara"`` rather than claiming its own.** The cascade's
corroboration multiplier counts *distinct domains*, so a new domain here would
have manufactured cross-layer agreement out of a single piece of evidence — the
exact inflation the empty-domains fix was written to stop.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.analysis.tool_artifact_layer import (
    build_tool_artifact_isr,
    load_tool_artifacts,
    match_artifacts,
    reset_cache,
)
from maljan.analysis.ttp_cascade import TTPCascadeEngine
from maljan.core.paths import resolve_data

_CATALOG = str(resolve_data("data/tool_artifacts_v1.json"))


class TestTwoMarkersNeverOne:
    def setup_method(self) -> None:
        reset_cache()

    def test_a_single_marker_does_not_fire(self) -> None:
        """An EDR agent shipping the string 'mimikatz' in its signature table
        must not be reported as Mimikatz."""
        isr, matches = build_tool_artifact_isr(b"\x00mimikatz\x00" * 4, _CATALOG)
        assert isr is None
        assert matches == []

    def test_two_markers_do(self) -> None:
        blob = b"\x00mimikatz\x00gentilkiwi\x00sekurlsa::logonpasswords\x00"
        isr, matches = build_tool_artifact_isr(blob, _CATALOG)
        assert isr is not None
        assert matches and matches[0]["family"] == "Mimikatz"

    def test_the_floor_is_enforced_on_hand_edited_data(self, tmp_path: Path) -> None:
        """The data file is editable in place; a `"min_hits": 1` there would
        turn this layer into a false-attribution engine."""
        rogue = tmp_path / "rogue.json"
        rogue.write_text(
            json.dumps(
                {
                    "artifacts": [
                        {
                            "name": "X",
                            "family": "X",
                            "patterns": ["alpha", "beta"],
                            "min_hits": 1,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        artifacts = load_tool_artifacts(str(rogue))
        assert artifacts is not None
        assert artifacts[0].min_hits >= 2

    def test_a_clean_binary_produces_nothing(self) -> None:
        isr, matches = build_tool_artifact_isr(b"Hello, ordinary world." * 100, _CATALOG)
        assert isr is None and matches == []


class TestTheIsrShape:
    def setup_method(self) -> None:
        reset_cache()

    def test_it_shares_the_yara_domain(self) -> None:
        """A private domain would fake cross-layer corroboration from one
        source. It also gets the 0.90 weight for free this way."""
        blob = b"\x00AsyncRAT\x00Quasar.Client\x00AsyncClient\x00"
        isr, _ = build_tool_artifact_isr(blob, _CATALOG)
        assert isr is not None
        assert isr.domain == "yara"
        assert isr.agent_id == "tool_artifact"
        assert isr.revision_round == 0
        assert isr.dissent_items == []

    def test_confidence_stays_under_the_real_yara_band(self) -> None:
        """An unanchored string match is weaker than a structural rule."""
        blob = b"\x00" + b"\x00".join(
            [b"beacon.x64.dll", b"ReflectiveLoader", b"beacon.dll", b"malleable"]
        )
        isr, _ = build_tool_artifact_isr(blob, _CATALOG)
        assert isr is not None
        assert all(c.confidence <= 0.75 for c in isr.claims)

    def test_the_claim_names_the_family_in_its_text(self) -> None:
        """Load-bearing: attribution's grounding guardrail scans claim *text*
        for the family name, so this is what lets it reach the report."""
        blob = b"\x00beacon.x64.dll\x00ReflectiveLoader\x00"
        isr, _ = build_tool_artifact_isr(blob, _CATALOG)
        assert isr is not None
        assert any("Cobalt Strike" in c.claim for c in isr.claims)

    def test_claims_declare_their_platform(self) -> None:
        blob = b"\x00beacon.x64.dll\x00ReflectiveLoader\x00"
        isr, _ = build_tool_artifact_isr(blob, _CATALOG)
        assert isr is not None
        assert all(c.rule_platforms == ["windows"] for c in isr.claims)


class TestWideStrings:
    def setup_method(self) -> None:
        reset_cache()

    def test_utf16le_markers_match(self) -> None:
        """.NET tooling stores type names as wide strings; an AsyncRAT client
        scanned only as ASCII matches nothing at all."""
        blob = b"\x00\x00" + "AsyncRAT".encode("utf-16-le") + b"\x00" * 4
        blob += "Quasar.Client".encode("utf-16-le")
        artifacts = load_tool_artifacts(_CATALOG)
        assert artifacts is not None
        assert match_artifacts(blob, artifacts)


class TestCascadeIntegration:
    def setup_method(self) -> None:
        reset_cache()

    def test_the_claims_survive_the_cascade_on_windows(self) -> None:
        blob = b"\x00beacon.x64.dll\x00ReflectiveLoader\x00malleable\x00"
        isr, _ = build_tool_artifact_isr(blob, _CATALOG)
        assert isr is not None
        result = TTPCascadeEngine().compute({"tool_artifact": isr}, sample_platform="windows")
        assert any(r.technique_id == "T1071.001" for r in result.results)


class TestTheCatalogDegradesInsteadOfFailing:
    def setup_method(self) -> None:
        reset_cache()

    def test_a_missing_catalog_disables_the_layer(self, tmp_path: Path) -> None:
        isr, matches = build_tool_artifact_isr(b"beacon.x64.dll", str(tmp_path / "nope.json"))
        assert isr is None and matches == []

    def test_malformed_json_disables_the_layer(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        assert load_tool_artifacts(str(bad)) is None

    def test_an_empty_blob_is_safe(self) -> None:
        assert build_tool_artifact_isr(b"", _CATALOG) == (None, [])
        assert build_tool_artifact_isr(None, _CATALOG) == (None, [])
