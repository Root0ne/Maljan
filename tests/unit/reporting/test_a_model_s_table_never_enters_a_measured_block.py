"""A model's table is the model's, and never a row of a block the report prints as measured.

An analyst's artifact of IOCs, processes or persistence used to be merged into
the string table, the process tree and the persistence mechanisms, which the
report prints under "Measured" and "Observed" and which the IOC table, the
corroboration corpus and the detection rules read. The rows stay visible in
Appendix A, labelled as the analyst's list, and nothing the model listed
changes what the platform counts or matches.

The report body still shows them as the analyst's: §5.4 prints the persistence
an analyst listed under an Assessed block of its own, the narrative is handed
it as its own fact, and §9 carries an analyst's mutex, path, registry key, task
and service with source ``analyst`` and the rule's refusal. A kind several
analysts listed rows under is one table that says which analyst listed each
row.
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

    def test_its_mutex_is_the_analyst_s_row_of_the_ioc_table(self) -> None:
        report = _build(self.ISRS())

        (row,) = [row for row in report.consolidated_iocs if row.value == MUTEX]
        assert (row.kind, row.source) == ("mutex", "analyst")
        assert row.context == "listed by the dynamic analyst"
        assert str(row.published).startswith(
            "no: named only by an analyst (an artifact of the dynamic analyst); "
            "no tool in this run saw it"
        )

    def test_it_stays_the_analyst_s_in_appendix_a(self) -> None:
        table = _appendix_table(MarkdownRenderer().render(_build(self.ISRS())), "Iocs")

        note = table.split("\n\n", 2)[1]
        assert note.startswith("_Listed by the dynamic analyst")
        assert "§9" in note


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

    def test_it_matches_nothing(self) -> None:
        report = _build(self.ISRS())

        assert report.persistence == []
        assert not [rule for rule in report.detection_signatures if RUN_KEY in rule.body]

    def test_section_5_4_prints_it_as_assessed(self) -> None:
        markdown = MarkdownRenderer().render(_build(self.ISRS()))

        technical = markdown[markdown.index("### 5.4") : markdown.index("### 5.5")]
        block = technical[technical.index("_Assessed:_ persistence the analysts listed") :]
        assert "| Kind | Target | Payload | Listed by | Evidence |" in block
        assert "the dynamic analyst" in block
        assert "ev_0001" in block
        assert "relay" in block

    def test_the_narrative_is_handed_it_as_its_own_fact(self) -> None:
        from maljan.reporting.evidence_bundles import bundle_for

        facts = bundle_for("persistence_detail", _build(self.ISRS()))["facts"]

        assert facts["persistence_mechanisms"] == []
        (listed,) = facts["persistence_assessed"]
        assert RUN_KEY in listed and "dynamic" in listed

    def test_its_run_key_is_the_analyst_s_row_of_the_ioc_table(self) -> None:
        (row,) = [r for r in _build(self.ISRS()).consolidated_iocs if r.value == RUN_KEY]

        assert (row.kind, row.source) == ("registry", "analyst")
        assert str(row.published).startswith("no: named only by an analyst")

    def test_it_stays_the_analyst_s_in_appendix_a(self) -> None:
        table = _appendix_table(MarkdownRenderer().render(_build(self.ISRS())), "Persistence")

        assert table.split("\n\n", 2)[1].startswith("_Listed by the dynamic analyst")


class TestAKindTwoAnalystsListed:
    @staticmethod
    def _isrs() -> dict[str, Any]:
        return {
            name: AgentISR(
                agent_id=name,
                domain="static",
                artifacts=[
                    Artifact(
                        kind="iocs",
                        columns=["Type", "Value"],
                        rows=[["mutex", f"{MUTEX}-{name}"]],
                        evidence_ids=[],
                        source=name,
                    )
                ],
            )
            for name in ("static", "reverser")
        }

    def test_the_table_says_which_analyst_listed_each_row(self) -> None:
        report = _build(self._isrs())

        (section,) = [s for s in report.sections if s.key == "artifact_iocs"]
        assert section.columns == ["Listed by", "Type", "Value"]
        assert section.rows == [
            ["static", "mutex", f"{MUTEX}-static"],
            ["reverser", "mutex", f"{MUTEX}-reverser"],
        ]

    def test_each_row_of_the_ioc_table_names_its_own_analyst(self) -> None:
        rows = {r.value: r.context for r in _build(self._isrs()).consolidated_iocs}

        assert rows[f"{MUTEX}-static"] == "listed by the static analyst"
        assert rows[f"{MUTEX}-reverser"] == "listed by the reverser analyst"
