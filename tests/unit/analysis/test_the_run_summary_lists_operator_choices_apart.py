"""The run summary and the report list the operator's choices apart from the losses (T-338).

Whichever caller hands a reason in, one that is the operator's configuration
(``pipeline.operator_choice``) lands in ``operator_choices``; a summary or a
report with none reads as it did before the list existed.
"""

from __future__ import annotations

from typing import Any

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.providers.sample_open import LISTED_SHARED_WITHHELD, withheld_unpinned
from maljan.reporting.builder import MalwareReportBuilder

WITHHELD = withheld_unpinned(
    "remote http://localhost:8089 (backend 1)", "run_ghidra_script", LISTED_SHARED_WITHHELD
)
LOST = "server.analysis.capa_unavailable(capa is not installed (No module named 'capa'))"


def _summary(reasons: list[str], degraded: bool = True) -> Any:
    return RunSummaryBuilder(start_time=0.0).set_degraded_mode(degraded, reasons).build()


class TestTheRunSummary:
    def test_a_choice_handed_in_as_a_reason_is_listed_apart(self) -> None:
        summary = _summary([LOST, WITHHELD])
        assert summary.degradation_reasons == [LOST]
        assert summary.operator_choices == [WITHHELD]
        record = summary.to_dict()
        assert record["degradation_reasons"] == [LOST]
        assert record["operator_choices"] == [WITHHELD]

    def test_its_markdown_lists_them_outside_the_banner(self) -> None:
        text = _summary([LOST, WITHHELD]).to_markdown()
        banner = text.split("**Degradation reasons:**", 1)[1].split("**Not configured", 1)[0]
        assert WITHHELD not in banner
        assert f"**Not configured or withheld by choice:**\n\n- {WITHHELD}" in text

    def test_they_are_listed_on_a_run_that_is_not_degraded(self) -> None:
        text = _summary([WITHHELD], degraded=False).to_markdown()
        assert "DEGRADED RUN" not in text
        assert f"- {WITHHELD}" in text

    def test_a_summary_with_none_has_no_key(self) -> None:
        assert "operator_choices" not in _summary([LOST]).to_dict()


def test_the_report_builder_lists_them_apart_too() -> None:
    builder = MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="s.exe",
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports={},
        stix_output=None,
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        degradation_reasons=[LOST, WITHHELD],
        operator_choices=["agent tool 'threatintel.*' unavailable: server disabled"],
    )
    assert builder.degradation_reasons == [LOST]
    assert builder.operator_choices == [
        "agent tool 'threatintel.*' unavailable: server disabled",
        WITHHELD,
    ]
