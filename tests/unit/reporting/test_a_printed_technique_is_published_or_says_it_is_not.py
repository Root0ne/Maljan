"""Every technique id the report prints is published, or says it is not.

An ISR carries technique ids in two places. ``claims[].technique_id`` is what
``validate_isr`` questions and what the capability matrix collected;
``findings[].technique_ids`` is what the report's Findings table and the
corroboration metric are built from, and nothing ever questioned it. A recorded
Android run's final ISR had one claim with no id at all, so no domain check
fired anywhere — and the report printed ``T1027``, ``T1055`` and ``T1071``,
enterprise-only, in two tables and a count, with nothing saying they were not
published.
"""

from __future__ import annotations

from typing import Any

from maljan.analysis.corroboration import (
    UNPUBLISHED_WITHOUT_A_REASON,
    mark_unpublished,
    published_count,
    technique_label,
)
from maljan.reporting.ledger_report import NOT_PUBLISHED_MARKER, build_sections
from maljan.schemas.isr_models import AgentISR

# What the recorded Android run's static analyst wrote: one claim carrying no
# technique id, and three findings carrying enterprise-only ones.
ANDROID_SAMPLE = {"platform": "android", "file_type": "apk"}
ENTERPRISE_ONLY = ("T1027", "T1055", "T1071")


def _isr(**kwargs: Any) -> AgentISR:
    return AgentISR.model_validate(
        {
            "agent_id": "static",
            "domain": "static",
            "claims": [],
            "findings": [],
            "artifacts": [],
            **kwargs,
        }
    )


def _findings_isr() -> AgentISR:
    return _isr(
        claims=[
            {
                "claim": "the sample is flagged by 10 of 75 engines",
                "confidence": 0.95,
                "evidence_ref": "ev_0016",
                "technique_id": None,
            }
        ],
        findings=[
            {
                "title": "Obfuscation Indicators",
                "confidence": 0.70,
                "technique_ids": ["T1027"],
                "evidence_ids": ["ev_0005", "ev_0007"],
            },
            {
                "title": "Network IOCs",
                "confidence": 0.85,
                "technique_ids": ["T1071"],
                "evidence_ids": ["ev_0006"],
            },
            {
                "title": "Native Code Presence",
                "confidence": 0.90,
                "technique_ids": ["T1055"],
                "evidence_ids": ["ev_0004", "ev_0006"],
            },
        ],
    )


class TestTheFindingsTableSaysSo:
    def test_an_unpublished_id_is_marked_in_words(self) -> None:
        sections = build_sections(
            [], {"static": _findings_isr()}, "apk", "android", published_techniques=frozenset()
        )
        findings = next(s for s in sections if s.key == "findings")

        printed = " ".join(cell for row in findings.rows for cell in row)
        for tid in ENTERPRISE_ONLY:
            assert f"{tid} ({NOT_PUBLISHED_MARKER})" in printed, tid

    def test_a_published_id_is_printed_plainly(self) -> None:
        sections = build_sections(
            [],
            {"static": _findings_isr()},
            "pe",
            "windows",
            published_techniques=frozenset(ENTERPRISE_ONLY),
        )
        findings = next(s for s in sections if s.key == "findings")

        printed = " ".join(cell for row in findings.rows for cell in row)
        assert NOT_PUBLISHED_MARKER not in printed
        assert "T1027" in printed

    def test_nothing_is_marked_when_there_is_no_list_to_compare_against(self) -> None:
        sections = build_sections([], {"static": _findings_isr()}, "apk", "android")
        findings = next(s for s in sections if s.key == "findings")

        printed = " ".join(cell for row in findings.rows for cell in row)
        assert NOT_PUBLISHED_MARKER not in printed


class TestTheCorroborationRowsSaySo:
    ROWS = {tid: {"asserted_by": [], "claimed_by": ["static"]} for tid in ENTERPRISE_ONLY}

    def test_an_unpublished_id_carries_the_check_s_own_sentence(self) -> None:
        marked = mark_unpublished(self.ROWS, set(), {"T1027": "outside the sample's ATT&CK domain"})

        assert marked["T1027"]["not_published"] == "outside the sample's ATT&CK domain"

    def test_an_id_no_check_was_asked_about_says_what_is_known(self) -> None:
        marked = mark_unpublished(self.ROWS, set(), {})

        assert marked["T1055"]["not_published"] == UNPUBLISHED_WITHOUT_A_REASON

    def test_a_published_id_carries_nothing(self) -> None:
        marked = mark_unpublished(self.ROWS, {"T1027"}, {})

        assert "not_published" not in marked["T1027"]

    def test_the_label_prints_it(self) -> None:
        marked = mark_unpublished(self.ROWS, set(), {"T1027": "outside the domain"})

        assert technique_label("T1027", marked["T1027"]) == (
            "T1027 (claimed, not published: outside the domain)"
        )

    def test_the_count_says_what_it_counts(self) -> None:
        marked = mark_unpublished(self.ROWS, {"T1027"}, {})

        assert len(marked) == 3
        assert published_count(marked) == 1


class TestTheRunSummaryPrintsBothNumbers:
    def test_the_report_s_own_line(self) -> None:
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        marked = mark_unpublished(
            {tid: {"asserted_by": [], "claimed_by": ["static"]} for tid in ENTERPRISE_ONLY},
            set(),
            {},
        )
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

        rendered = MarkdownRenderer()._appendix_run(
            MalwareReport(
                identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
                run_summary={"corroboration": marked},
            )
        )

        assert "TTPs: 3 claimed, 0 published" in rendered
        assert "claimed, not published" in rendered


class TestTheReportNodeWritesItDown:
    """The first node holding both lists is the one that compares them."""

    @staticmethod
    def _report(published: list[str], reasons: dict[str, str]) -> Any:
        from maljan.reporting.models import (
            CapabilityCell,
            FileHashes,
            MalwareReport,
            SampleIdentity,
            TTPMapping,
        )

        return MalwareReport(
            verdict="Malware",
            identity=SampleIdentity(hashes=FileHashes(sha256="f" * 64), file_name="package.apk"),
            executive_summary="",
            ttp_mappings=[
                TTPMapping(technique_id=tid, technique_name=tid, tactic="TA0005")
                for tid in published
            ],
            capability_matrix=[
                CapabilityCell(
                    tactic="TA0005",
                    tactic_name="Defense Evasion",
                    technique_id=tid,
                    technique_name=tid,
                    not_published=reason,
                )
                for tid, reason in reasons.items()
            ],
            run_summary={
                "corroboration": {
                    tid: {"asserted_by": [], "claimed_by": ["static"]} for tid in ENTERPRISE_ONLY
                }
            },
        )

    def test_the_reason_the_matrix_wrote_reaches_the_summary(self) -> None:
        from maljan.pipeline.nodes import _corroboration_with_publication

        marked = _corroboration_with_publication(
            self._report([], {"T1027": "outside the sample's ATT&CK domain"}), {}
        )

        assert marked is not None
        assert marked["T1027"]["not_published"] == "outside the sample's ATT&CK domain"
        assert marked["T1055"]["not_published"] == UNPUBLISHED_WITHOUT_A_REASON

    def test_a_published_technique_is_left_plain(self) -> None:
        from maljan.pipeline.nodes import _corroboration_with_publication

        marked = _corroboration_with_publication(self._report(["T1027"], {}), {})

        assert marked is not None
        assert "not_published" not in marked["T1027"]

    def test_a_run_that_named_nothing_amends_nothing(self) -> None:
        from maljan.pipeline.nodes import _corroboration_with_publication

        report = self._report([], {})
        report.run_summary = {}

        assert _corroboration_with_publication(report, {}) is None
