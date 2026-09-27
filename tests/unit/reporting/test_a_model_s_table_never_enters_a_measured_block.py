"""A model's table is the model's, and never a row of a block the report prints as measured.

An analyst's artifact of IOCs, processes or persistence used to be merged into
the string table, the process tree and the persistence mechanisms, which the
report prints under "Measured" and "Observed" and which the IOC table, the
corroboration corpus and the detection rules read. The rows stay visible in
Appendix A, labelled as the analyst's list, and nothing the model listed
changes what the platform counts or matches.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import AgentISR, Artifact

MUTEX = "Global\\relay-mutex-7f3c"
PROCESS = "relay-helper.exe"
RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\relay"


def _analyst(kind: str, columns: list[str], rows: list[list[str]]) -> dict[str, Any]:
    return {
        "dynamic": AgentISR(
            agent_id="dynamic",
            domain="dynamic",
            artifacts=[
                Artifact(
                    kind=kind,
                    label=kind.capitalize(),
                    columns=columns,
                    rows=rows,
                    evidence_ids=["ev_0001"],
                    source="dynamic",
                )
            ],
        )
    }


def _build(isrs: dict[str, Any]) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=isrs,
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=[],
    ).build_deterministic()


def _appendix_table(markdown: str, title: str) -> str:
    appendix = markdown[markdown.index("## Appendix A") :]
    return appendix[appendix.index(f"### {title}") :]


class TestAnIocList:
    ISRS = staticmethod(lambda: _analyst("iocs", ["Type", "Value"], [["mutex", MUTEX]]))

    def test_it_is_not_the_string_table(self) -> None:
        assert _build(self.ISRS()).static is None

    def test_it_is_no_row_of_the_ioc_table_and_stays_the_analyst_s(self) -> None:
        report = _build(self.ISRS())

        assert all(row.value != MUTEX for row in report.consolidated_iocs)
        table = _appendix_table(MarkdownRenderer().render(report), "Iocs")
        assert table.split("\n\n", 2)[1].startswith("_Listed by the dynamic analyst")


class TestAProcessList:
    ISRS = staticmethod(lambda: _analyst("processes", ["PID", "Name"], [["4242", PROCESS]]))

    def test_it_is_not_the_process_tree(self) -> None:
        assert _build(self.ISRS()).dynamic is None

    def test_it_stays_the_analyst_s(self) -> None:
        report = _build(self.ISRS())

        table = _appendix_table(MarkdownRenderer().render(report), "Processes")
        assert table.split("\n\n", 2)[1].startswith("_Listed by the dynamic analyst")
        assert PROCESS in table


class TestAPersistenceList:
    ISRS = staticmethod(
        lambda: _analyst(
            "persistence", ["Kind", "Target", "Payload"], [["registry_run", RUN_KEY, "x.exe"]]
        )
    )

    def test_it_matches_nothing_and_stays_the_analyst_s(self) -> None:
        report = _build(self.ISRS())

        assert report.persistence == []
        assert all(row.value != RUN_KEY for row in report.consolidated_iocs)
        markdown = MarkdownRenderer().render(report)
        technical = markdown[markdown.index("### 5.4") : markdown.index("### 5.5")]
        assert RUN_KEY not in technical
        table = _appendix_table(markdown, "Persistence")
        assert table.split("\n\n", 2)[1].startswith("_Listed by the dynamic analyst")
