"""Fields that existed in the schema and appeared in no report.

The audit that produced this file asked a simple question — "does any of the new
static-analysis work actually reach a reader?" — and the answer for most of it
was no. `api_capabilities`, `packer_matches`, `api_technique_hits` and
`tool_artifact_matches` were all populated (one of them was not even that) and
none of them were rendered anywhere.

That is a specific kind of failure worth a test: the pipeline gets measurably
better, every unit test passes, and the person reading the report sees exactly
what they saw before. `api_technique_hits` was the extreme case — declared on
the model, never written by anything, never read by anything. A field that
exists only in the schema is indistinguishable from a field that does not exist.

Carved payloads had a milder version of the same problem: they rendered, as
`- carved:PE (51200 bytes)`, which loses the offset and the hash — the two
things a reader needs in order to go and look at the payload.
"""

from __future__ import annotations

from maljan.reporting.models import (
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _report(static: StaticAnalysis | None = None, **attr: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        static=static,
        attribution=FamilyAttribution(**attr),  # type: ignore[arg-type]
    )


def _render(static: StaticAnalysis | None = None, **attr: object) -> str:
    return MarkdownRenderer().render(_report(static, **attr))


class TestTheImportDerivedTechniquesAreVisible:
    def test_the_audit_trail_is_rendered(self) -> None:
        md = _render(
            StaticAnalysis(
                api_technique_hits=[
                    {
                        "technique_id": "T1056.001",
                        "name": "Input Capture: Keylogging",
                        "confidence": 0.55,
                        "matched_apis": ["GetAsyncKeyState", "SetWindowsHookExW"],
                    }
                ]
            )
        )
        assert "T1056.001" in md
        assert "GetAsyncKeyState" in md, "the reasoning must be checkable"
        assert "SetWindowsHookExW" in md

    def test_it_says_the_evidence_needed_no_sandbox(self) -> None:
        """The whole point of the deterministic layer is that it works when
        CAPE does not. A reader cannot tell unless the report says so."""
        md = _render(
            StaticAnalysis(
                api_technique_hits=[
                    {"technique_id": "T1057", "name": "x", "confidence": 0.5, "matched_apis": ["a"]}
                ]
            )
        )
        assert "no sandbox" in md.lower()

    def test_the_capability_profile_is_rendered(self) -> None:
        md = _render(StaticAnalysis(api_capabilities={"process_injection": 7, "network": 3}))
        assert "process_injection" in md
        assert "×7" in md or "x7" in md


class TestPackerEvidenceReplacesABareString:
    def test_the_ranked_matches_are_rendered_with_confidence(self) -> None:
        md = _render(
            StaticAnalysis(
                packer_hint="UPX (packer)",
                packer_matches=[
                    {
                        "name": "UPX",
                        "kind": "packer",
                        "confidence": 0.85,
                        "method": "section+entry_point",
                        "evidence": ["UPX0", "UPX1"],
                    }
                ],
            )
        )
        assert "UPX" in md
        assert "0.85" in md, "a reader needs to know how sure the detector was"
        assert "section+entry_point" in md, "and on what basis"

    def test_the_bare_hint_still_renders_without_a_catalog(self) -> None:
        md = _render(StaticAnalysis(packer_hint="high-entropy sections (possibly packed)"))
        assert "high-entropy sections" in md


class TestCarvedPayloadsAreLocatable:
    def test_offset_and_hash_survive_into_the_report(self) -> None:
        md = _render(
            StaticAnalysis(
                embedded_resources=[
                    {
                        "type": "carved:PE",
                        "id": "overlay+0x1a400",
                        "size": 51200,
                        "offset": 107520,
                        "source": "overlay",
                        "sha256": "b" * 64,
                        "entropy": 7.21,
                        "carved": True,
                    }
                ]
            )
        )
        assert "carved:PE" in md
        assert "overlay+0x1a400" in md, "without the offset nobody can go and look"
        assert "bbbb" in md, "nor without the hash"
        assert "7.21" in md

    def test_ordinary_resources_still_render_as_before(self) -> None:
        md = _render(
            StaticAnalysis(embedded_resources=[{"type": "RT_ICON", "id": 1, "size": 1024}])
        )
        assert "RT_ICON" in md

    def test_the_two_kinds_are_not_conflated(self) -> None:
        """A nested executable and an icon are different findings."""
        md = _render(
            StaticAnalysis(
                embedded_resources=[
                    {"type": "RT_ICON", "id": 1, "size": 1024},
                    {"type": "carved:PE", "id": "overlay+0x100", "size": 9999, "carved": True},
                ]
            )
        )
        assert "Carved payloads" in md


class TestTheFamilyEvidenceIsShown:
    def test_tool_artifact_markers_are_rendered(self) -> None:
        """Without them the reader sees a family name and nothing to check."""
        md = _render(
            None,
            family="CobaltStrike",
            family_confidence=0.75,
            tool_artifact_matches=[
                {
                    "tool": "Cobalt Strike",
                    "family": "CobaltStrike",
                    "kind": "c2_framework",
                    "confidence": 0.75,
                    "markers": ["beacon.x64.dll", "ReflectiveLoader"],
                }
            ],
        )
        assert "Cobalt Strike" in md
        assert "beacon.x64.dll" in md
        assert "ReflectiveLoader" in md

    def test_no_artifacts_means_no_empty_table(self) -> None:
        md = _render(None, family="Emotet", family_confidence=0.8)
        assert "Offensive-tool artifacts" not in md
