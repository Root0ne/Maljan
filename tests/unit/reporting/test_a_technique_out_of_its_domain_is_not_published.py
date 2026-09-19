"""A technique the sample cannot perform is not published as one of its techniques.

An Android package's report carried ``T1027`` and ``T1005`` in ``ttp_mappings``,
in ``/mitre`` and in the STIX bundle. Both are enterprise-only ids; the sample
is mobile-domain. The check had said so, twice, in the words the analyst and
the judge were shown — *"TECHNIQUE T1027 belongs to the ATT&CK enterprise
domain (platforms ESXi, Linux, Network Devices, Windows, macOS); this sample is
mobile-domain, Android"* — and both violations were still unresolved when the
report published them as the verdict's supporting techniques.

The rule an unresolvable id already follows now covers them: kept in the
capability matrix, where the claim belongs to whoever made it, with the reason
written beside it; absent from the one validated list every technique surface
is built from; and named in the report under the claims that were not
published.

An ungrounded technique is not touched by any of this. It is advisory —
published and flagged — and widening the rule to cover it would drop a claim
for citing nothing rather than for being impossible.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle

# Enterprise-only, on a sample that is not.
ENTERPRISE = "T1027"
# Mobile, and the id the APK's own analyst never offered.
MOBILE = "T1406"
# Enterprise by the matrix it is filed in, and ``PRE`` by the only platform it
# declares: it happens before any host is touched, so no sample contradicts it.
PRE_ONLY = "T1583"

ANDROID = {"platform": "android", "file_type": "apk"}
WINDOWS = {"platform": "windows", "file_type": "pe"}


@pytest.fixture(autouse=True)
def _the_shared_attck_index(real_attck_index: None) -> None:
    """Building a capability matrix resolves technique names and tactics.

    It does that through ``ATTCKValidator.get_instance()``, which builds the
    shared ATT&CK index from the corpus — so a report assembled here reaches
    the catalogue whatever the test is about. The unit tree holds that build
    shut; these ask for it by name so the list of tests that pay for it is a
    list somebody can read.
    """


def _isr(*technique_ids: str) -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim=f"the sample does what {tid} describes",
                    evidence_ref="[ev_0001] archive_list",
                    confidence=0.7,
                    technique_id=tid,
                )
                for tid in technique_ids
            ],
        )
    }


def _attack_pattern(tid: str, index: int) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--0f1e2d3c-4b5a-4968-8776-6554433340{index:02d}",
        "name": tid,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _report(sample: dict[str, str], *technique_ids: str) -> Any:
    stix = {"objects": [_attack_pattern(tid, n) for n, tid in enumerate(technique_ids)]}
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="package.apk",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_isr(*technique_ids),
        stix_output=stix,
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.6,
        judge_assessment=None,
        malware_category="infostealer",
        sample_platform=sample["platform"],
        sample_file_type=sample["file_type"],
        evidence_ledger=[],
    ).build_deterministic()


class TestTheMatrixKeepsTheClaim:
    def test_the_row_stays_with_the_reason_beside_it(self) -> None:
        cells, _mappings = build_capability_matrix(
            stix_output=None, isr_reports=_isr(ENTERPRISE), sample=ANDROID
        )

        row = next(cell for cell in cells if cell.technique_id == ENTERPRISE)
        assert "enterprise" in row.not_published
        assert "mobile" in row.not_published

    def test_the_id_itself_is_untouched(self) -> None:
        cells, _mappings = build_capability_matrix(
            stix_output=None, isr_reports=_isr(ENTERPRISE), sample=ANDROID
        )

        assert [cell.technique_id for cell in cells] == [ENTERPRISE]
        assert cells[0].technique_id_valid is True, "it is a real id, in the wrong domain"


class TestTheThreeSurfacesDoNotCarryIt:
    def test_it_is_not_in_the_published_list(self) -> None:
        _cells, mappings = build_capability_matrix(
            stix_output=None, isr_reports=_isr(ENTERPRISE, MOBILE), sample=ANDROID
        )

        assert [m.technique_id for m in mappings] == [MOBILE]

    def test_it_is_in_neither_the_references_nor_the_bundle(self) -> None:
        report = _report(ANDROID, ENTERPRISE, MOBILE)
        base = Bundle.model_validate(
            {"objects": [_attack_pattern(ENTERPRISE, 0), _attack_pattern(MOBILE, 1)]}
        )

        bundle = ExtendedSTIXRenderer().render(report, base_bundle=base)

        published = {
            str(ref.get("external_id"))
            for obj in bundle.objects
            if getattr(obj, "type", "") == "attack-pattern"
            for ref in getattr(obj, "external_references", None) or []
        }
        assert published == {MOBILE}
        assert ENTERPRISE not in " ".join(ref.note or "" for ref in report.references)

    def test_the_report_names_it_under_the_claims_it_did_not_publish(self) -> None:
        report = _report(ANDROID, ENTERPRISE, MOBILE)

        markdown = MarkdownRenderer().render(report)

        assert "Claims that were not published as techniques" in markdown
        assert f"- {ENTERPRISE}" in markdown
        assert "enterprise" in markdown


class TestWhatIsLeftAlone:
    def test_a_windows_sample_keeps_its_enterprise_technique(self) -> None:
        _cells, mappings = build_capability_matrix(
            stix_output=None, isr_reports=_isr(ENTERPRISE), sample=WINDOWS
        )

        assert [m.technique_id for m in mappings] == [ENTERPRISE]

    def test_a_technique_fixed_on_the_retry_is_published(self) -> None:
        """The retry's answer is what the matrix is built from, so a replaced
        id is simply a different technique and passes the check."""
        _cells, mappings = build_capability_matrix(
            stix_output=None, isr_reports=_isr(MOBILE), sample=ANDROID
        )

        assert [m.technique_id for m in mappings] == [MOBILE]
        assert all(not cell.not_published for cell in _cells)

    def test_a_sample_with_no_platform_asks_nothing(self) -> None:
        for sample in (None, {"platform": "unknown", "file_type": "unknown"}, {}):
            _cells, mappings = build_capability_matrix(
                stix_output=None, isr_reports=_isr(ENTERPRISE), sample=sample
            )
            assert [m.technique_id for m in mappings] == [ENTERPRISE], sample

    def test_a_technique_that_happens_before_any_host_is_published(self) -> None:
        """``PRE`` is not a platform a sample can contradict, so nor is its domain.

        ATT&CK keeps every PRE technique in the enterprise matrix and mobile
        has none, so asking the domain first made each of them cross-domain on
        an Android sample — and once the report read that answer to decide what
        to publish, an infostealer's C2 registration lost its technique from
        every surface.
        """
        for tid in (PRE_ONLY, f"{PRE_ONLY}.001"):
            _cells, mappings = build_capability_matrix(
                stix_output=None, isr_reports=_isr(tid), sample=ANDROID
            )
            assert [m.technique_id for m in mappings] == [tid], tid

    def test_it_is_not_marked_in_the_matrix_either(self) -> None:
        cells, _mappings = build_capability_matrix(
            stix_output=None, isr_reports=_isr(PRE_ONLY), sample=ANDROID
        )

        assert [cell.not_published for cell in cells] == [""]

    def test_the_check_itself_says_nothing_about_it(self) -> None:
        from maljan.pipeline.validation import expected_technique_scope, platform_mismatch_message
        from maljan.tools import knowledge

        scope = expected_technique_scope(ANDROID)

        assert platform_mismatch_message(PRE_ONLY, knowledge, scope) == ""
        assert platform_mismatch_message(ENTERPRISE, knowledge, scope) != ""

    def test_the_linter_still_says_which_matrix_it_comes_from(self) -> None:
        """Published, and flagged: the two are different answers about it.

        The false-positive linter compares the matrix a technique is filed in
        against the sample's, which for a PRE technique on an APK is still a
        difference worth printing. What it is not is a reason to withhold the
        technique.
        """
        from maljan.qa.fp_linter import lint_report

        report = _report(ANDROID, PRE_ONLY)

        assert [m.technique_id for m in report.ttp_mappings] == [PRE_ONLY]
        assert any(
            warning.rule == "C1" and PRE_ONLY in warning.message
            for warning in lint_report(report, "android")
        )

    def test_an_ungrounded_technique_is_still_published(self) -> None:
        """A claim that cites no evidence is advisory, and stays advisory."""
        isrs = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="it hides its strings",
                        evidence_ref="",
                        confidence=0.7,
                        technique_id=ENTERPRISE,
                    )
                ],
            )
        }

        _cells, mappings = build_capability_matrix(
            stix_output=None, isr_reports=isrs, sample=WINDOWS
        )

        assert [m.technique_id for m in mappings] == [ENTERPRISE]
