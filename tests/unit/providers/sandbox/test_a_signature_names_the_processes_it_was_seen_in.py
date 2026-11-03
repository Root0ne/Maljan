"""A sandbox signature carries the pids of the processes its hit was seen in (T-475).

Read where the report names them, by what the field is rather than by the
sandbox that wrote it: a mark's own process id, or the form's ``pids`` field a
reader fills where its source names them otherwise. The pids reach the tool's
answer, the report model, the evidence table and the markdown report, and a
signature that names none reads everywhere as it did before.
"""

from __future__ import annotations

from typing import Any

from maljan.core.report_mapping import RestMappingConfig
from maljan.pipeline.triage_pack import _SANDBOX_VIEWS
from maljan.providers.sandbox.rest_mapping import apply_mapping, compile_mapping
from maljan.providers.sandbox_tools import SIGNATURE_PIDS_SHOWN, sandbox_signatures
from maljan.reporting.dedupe import distinct_signatures
from maljan.reporting.ledger_projection import dynamic_from_ledger
from maljan.reporting.ledger_report import SIGNATURE_PROCESSES_COLUMN, build_sections
from maljan.reporting.models import SandboxSignature
from maljan.reporting.narrative_agent import build_prompt_text
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.sandbox_document import pid_of, sandbox_document, signature_pids
from maljan.schemas.sandbox_report import SandboxSignatureRow, triage_overview_to_sandbox_report
from tests.unit._ledger_helpers import entry
from tests.unit.reporting._report_shapes import rich_report


def _report(*signatures: dict[str, Any]) -> dict[str, Any]:
    return {"info": {"id": 1}, "signatures": list(signatures)}


class TestThePidsOfOneSignature:
    def test_each_mark_s_process_id_once_in_order(self) -> None:
        sig = {
            "data": [
                {"type": "call", "pid": 2100, "cid": 1},
                {"type": "call", "pid": 2100, "cid": 2},
                {"file": "C:\\x"},
                {"type": "call", "pid": "908", "cid": 3},
            ]
        }
        assert signature_pids(sig) == ["2100", "908"]

    def test_the_form_s_marks_and_a_process_id_key(self) -> None:
        assert signature_pids({"marks": [{"process_id": 7}, "text mark"]}) == ["7"]

    def test_the_stated_field_wins_over_the_marks(self) -> None:
        assert signature_pids({"pids": [1000], "marks": [{"pid": 2100}]}) == ["1000"]

    def test_nothing_that_is_no_whole_number_is_read_as_a_pid(self) -> None:
        for value in (0, "0", -4, True, None, "", "12a", "1\nx", "9" * 21, 10**5000, 3.5, "١٢"):
            assert pid_of(value) == "", value
        assert pid_of(" 0042 ") == "42"

    def test_a_signature_naming_none_has_none(self) -> None:
        assert signature_pids({"data": [{"ip": "203.0.113.5"}], "marks": []}) == []


class TestTheToolAnswer:
    def test_a_row_names_its_processes(self) -> None:
        answer = sandbox_signatures(
            _report({"name": "injection", "severity": 3, "data": [{"type": "call", "pid": 2100}]})
        )
        assert answer["signatures"][0]["pids"] == ["2100"]

    def test_a_row_naming_none_is_as_it_was(self) -> None:
        answer = sandbox_signatures(
            _report({"name": "net", "severity": 1, "data": [{"ip": "203.0.113.5"}]})
        )
        assert "pids" not in answer["signatures"][0]


class TestTheReaders:
    def test_the_form_leaves_an_unset_field_out_of_its_dump_and_document(self) -> None:
        row = SandboxSignatureRow(name="x")
        assert "pids" not in row.model_dump()
        stated = SandboxSignatureRow(name="x", pids=["5"])
        assert stated.model_dump()["pids"] == ["5"]

    def test_triage_indicators_name_the_process_its_list_keys(self) -> None:
        overview = {
            "sample": {"id": "s1", "sha256": "a" * 64},
            "signatures": [
                {
                    "name": "inject",
                    "score": 8,
                    "indicators": [
                        {"ioc": "x", "procid": 1000, "pid": 2100},
                        {"ioc": "y", "pid": 2200},
                        {"ioc": "z", "procid": 1000},
                    ],
                },
                {"name": "plain", "score": 3, "indicators": [{"ioc": "w"}]},
            ],
        }
        report = triage_overview_to_sandbox_report(
            overview, provider="triage", source_format="triage"
        )
        assert [s.pids for s in report.signatures] == [["1000", "2200"], []]
        answer = sandbox_signatures(sandbox_document(report))
        assert answer["signatures"][0]["pids"] == ["1000", "2200"]
        assert "pids" not in answer["signatures"][1]

    def test_a_declared_mapping_reads_the_field_it_names(self) -> None:
        compiled = compile_mapping(
            RestMappingConfig(
                target_sha256="",
                signatures="$.hits[*]",
                field_names={"signatures.pids": "process"},
            )
        )
        payload = {
            "hits": [
                {"name": "a", "process": 44},
                {"name": "b", "process": [5, "5", 6]},
                {"name": "c"},
            ]
        }
        report = apply_mapping(compiled, payload, provider="rest", task_id="t").report
        assert [s.pids for s in report.signatures] == [["44"], ["5", "6"], []]


_SIGNATURES = {
    "signatures": [
        {
            "name": "inject",
            "description": "Writes into another process.",
            "severity": 3,
            "pids": ["2100", "908"],
        },
        {"name": "net", "description": "Contacts a host.", "severity": 1},
    ]
}


class TestTheReport:
    def test_the_model_carries_the_pids_and_leaves_none_out(self) -> None:
        ledger = [entry("sandbox_signatures", _SIGNATURES, EvidenceCounter(), agent="dynamic")]
        dynamic = dynamic_from_ledger(ledger)
        assert dynamic is not None
        assert [s.pids for s in dynamic.sandbox_signatures] == [["2100", "908"], []]
        dumped = [s.model_dump() for s in dynamic.sandbox_signatures]
        assert dumped[0]["pids"] == ["2100", "908"]
        assert "pids" not in dumped[1]

    def test_the_evidence_table_has_a_processes_column_only_when_a_row_names_one(self) -> None:
        def table(data: dict[str, Any]) -> Any:
            ledger = [entry("sandbox_signatures", data, EvidenceCounter(), agent="dynamic")]
            return next(s for s in build_sections(ledger) if s.key == "sandbox_signatures")

        named = table(_SIGNATURES)
        assert named.columns == ["Name", "Severity", "Description", SIGNATURE_PROCESSES_COLUMN]
        assert [row[-1] for row in named.rows] == ["2100, 908", "-"]
        bare = table(
            {
                "signatures": [
                    {k: v for k, v in r.items() if k != "pids"} for r in _SIGNATURES["signatures"]
                ]
            }
        )
        assert bare.columns == ["Name", "Severity", "Description"]

    def test_the_markdown_report_has_no_processes_column(self) -> None:
        report = rich_report()
        assert report.dynamic is not None
        report.dynamic.sandbox_signatures = [
            SandboxSignature(name="inject", description="d", severity=3, pids=["2100"]),
            SandboxSignature(name="net", description="n", severity=1),
        ]
        table = MarkdownRenderer().render(report).split("### Sandbox signatures", 1)[1]
        assert "| Name | Severity | Techniques | Description |" in table
        assert "| inject | 3 | - | d |" in table
        assert "Processes" not in table.split("\n\n", 2)[1]
        assert "2100" not in table.split("\n\n", 2)[1]


def _many(count: int) -> dict[str, Any]:
    marks = [{"type": "call", "pid": 100 + n} for n in range(count)]
    return _report({"name": "enumerates", "severity": 2, "data": marks})


class TestTheCap:
    def test_an_answer_lists_the_first_pids_and_counts_them_all(self) -> None:
        row = sandbox_signatures(_many(14))["signatures"][0]
        assert row["pids"] == [str(100 + n) for n in range(SIGNATURE_PIDS_SHOWN)]
        assert row["pids_total"] == 14

    def test_a_list_at_the_cap_is_not_cut(self) -> None:
        row = sandbox_signatures(_many(SIGNATURE_PIDS_SHOWN))["signatures"][0]
        assert len(row["pids"]) == SIGNATURE_PIDS_SHOWN
        assert "pids_total" not in row

    def test_the_pack_answers_as_the_analysts_do(self) -> None:
        view = _SANDBOX_VIEWS["sandbox_signatures"]
        row = view(_many(14))["signatures"][0]
        assert len(row["pids"]) == SIGNATURE_PIDS_SHOWN
        assert row["pids_total"] == 14

    def test_the_report_states_the_count_beside_the_listed_pids(self) -> None:
        answer = sandbox_signatures(_many(14))
        ledger = [entry("sandbox_signatures", answer, EvidenceCounter(), agent="dynamic")]
        dynamic = dynamic_from_ledger(ledger)
        assert dynamic is not None
        (signature,) = dynamic.sandbox_signatures
        assert (len(signature.pids), signature.pids_total) == (SIGNATURE_PIDS_SHOWN, 14)
        assert signature.model_dump()["pids_total"] == 14
        table = next(s for s in build_sections(ledger) if s.key == "sandbox_signatures")
        assert table.rows[0][-1].endswith(", … (14 in all)")


class TestTheDedupe:
    def test_the_same_signature_with_the_same_pids_is_one_row(self) -> None:
        one = SandboxSignature(name="inject", description="d", severity=3, pids=["4", "9"])
        assert distinct_signatures([one, one.model_copy()]) == [one]

    def test_the_same_signature_with_other_pids_is_two_rows(self) -> None:
        one = SandboxSignature(name="inject", description="d", severity=3, pids=["4"])
        other = one.model_copy(update={"pids": ["9"]})
        assert distinct_signatures([one, other]) == [one, other]

    def test_the_markdown_table_prints_rows_differing_only_in_pids_once(self) -> None:
        report = rich_report()
        assert report.dynamic is not None
        one = SandboxSignature(name="inject", description="d", severity=3, pids=["4"])
        report.dynamic.sandbox_signatures = [one, one.model_copy(update={"pids": ["9"]})]
        table = MarkdownRenderer().render(report).split("### Sandbox signatures", 1)[1]
        assert table.split("\n\n", 2)[1].count("| inject |") == 1

    def test_the_narrative_prompt_gives_rows_differing_only_in_pids_one_line(self) -> None:
        report = rich_report()
        assert report.dynamic is not None
        one = SandboxSignature(name="inject", description="d", severity=3, pids=["4"])
        report.dynamic.sandbox_signatures = [one, one.model_copy(update={"pids": ["9"]})]
        block = build_prompt_text(report).split("Sandbox signatures:\n", 1)[1].split("\n\n", 1)[0]
        assert block.splitlines() == ['  - "inject" (severity 3, ATT&CK=-)']
