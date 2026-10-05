"""The report model states the host identifiers it read, each citing its entry.

Nine items a human analyst reports as host indicators — a marker, a folder, a
task name, a user agent, command words — were printed only as raw rows of the
decoded-strings dump, with no sentence about them. A vendor report has a host
indicator section. The report contract now has one: the report model decides
what goes in and cites the entry it read each value in; the platform copies no
string into it, asks about a row that cites nothing, and prints what the model
wrote under the model's voice.

The configuration section of the same run was dropped because its items
carried nulls, which the contract told the model it could write. The contract
now says how a list item is written.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    UNCITED_IDENTIFIER_CODE,
    identifier_citation_violations,
    schema_violations,
)
from maljan.reporting.composer import (
    ReportComposer,
    _ConfigOut,
    _HostIdentifiersOut,
    section_contract,
)
from maljan.reporting.evidence_bundles import bundle_for, is_empty
from maljan.reporting.models import (
    EvidenceIndexRow,
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

VALUE = "ExampleCorp\\Cache\\state.bin"


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        **over,
    )


class TestTheContract:
    def test_the_section_asks_for_what_it_needs_and_nothing_more(self) -> None:
        contract = section_contract("host_identifiers", _HostIdentifiersOut)

        assert '"identifiers": [{"kind": "...", "value": "...", "purpose": "..."' in contract
        assert "For example" in contract

    def test_the_example_is_valid_against_its_schema(self) -> None:
        from maljan.reporting.composer import _EXAMPLES

        _HostIdentifiersOut.model_validate(json.loads(_EXAMPLES["host_identifiers"]))

    def test_a_list_item_is_never_written_with_nulls(self) -> None:
        contract = section_contract("configuration", _ConfigOut)

        assert "never written with null in its fields" in contract
        assert "a number included" in contract

    def test_an_object_with_no_list_of_records_is_not_told_about_items(self) -> None:
        from maljan.reporting.composer import _IntroOut

        assert "An item of a list" not in section_contract("introduction", _IntroOut)

    def test_the_configuration_that_was_dropped_failed_on_exactly_those_nulls(self) -> None:
        # The shape the dropped section answered with: the key known, the value
        # and how it was obtained written as null.
        payload = {"items": [{"key": "Retry delay", "value": None, "how_obtained": None}]}

        found = schema_violations(_ConfigOut, payload, code="composer.schema")

        assert sorted(v.path for v in found) == ["items.0.how_obtained", "items.0.value"]


class TestTheCheck:
    def test_an_identifier_citing_nothing_is_asked_about(self) -> None:
        payload = {"identifiers": [{"kind": "File", "value": VALUE, "evidence_refs": []}]}

        (found,) = identifier_citation_violations(payload, ["ev_0012"])

        assert found.code == UNCITED_IDENTIFIER_CODE
        assert found.path == "identifiers.0.evidence_refs"

    def test_an_identifier_citing_an_unknown_entry_is_asked_about(self) -> None:
        payload = {"identifiers": [{"kind": "File", "value": VALUE, "evidence_refs": ["ev_0999"]}]}

        assert identifier_citation_violations(payload, ["ev_0012"])

    def test_a_cited_identifier_stands(self) -> None:
        payload = {"identifiers": [{"kind": "File", "value": VALUE, "evidence_refs": ["ev_0012"]}]}

        assert identifier_citation_violations(payload, ["ev_0012"]) == []

    def test_the_section_is_kept_with_the_finding(self) -> None:
        assert UNCITED_IDENTIFIER_CODE in KEPT_WITH_A_FINDING


class TestTheBundle:
    def test_a_run_with_a_strings_entry_asks_for_the_section(self) -> None:
        report = _report(
            evidence_index=[EvidenceIndexRow(id="ev_0012", tool="floss", ok=True)],
        )

        bundle = bundle_for("host_identifiers", report)

        assert not is_empty(bundle)
        assert bundle["facts"]["string_entries"] == ["ev_0012 (floss)"]

    def test_a_run_with_no_strings_skips_it(self) -> None:
        assert is_empty(bundle_for("host_identifiers", _report()))


class _RawLLM:
    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.prompts: list[str] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        prompt = str(messages[-1].content)
        self.prompts.append(prompt)
        for marker, answer in self.answers.items():
            if marker in prompt:
                return SimpleNamespace(content=answer)
        return SimpleNamespace(content='{"skip": null}')


class TestTheComposerWritesIt:
    def test_the_model_s_rows_land_in_the_report_as_written(self) -> None:
        report = _report(evidence_index=[EvidenceIndexRow(id="ev_0012", tool="floss", ok=True)])
        answer = json.dumps(
            {
                "identifiers": [
                    {
                        "kind": "State file",
                        "value": VALUE,
                        "purpose": "Holds the next stage",
                        "evidence_refs": ["ev_0012"],
                    }
                ]
            }
        )
        llm = _RawLLM({"host_identifiers section": answer})
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(comp.compose(report, facts_block="[ev_0012] floss: example"))

        assert report.technical_analysis is not None
        (row,) = report.technical_analysis.host_identifiers
        assert (row.kind, row.value, row.evidence_refs) == ("State file", VALUE, ["ev_0012"])


class TestTheReportPrintsIt:
    def test_the_rows_are_printed_under_the_model_s_voice(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                host_identifiers=[
                    HostIdentifier(
                        kind="State | file",
                        value=VALUE,
                        purpose="Holds\nthe next stage",
                        evidence_refs=["ev_0012"],
                    )
                ]
            )
        )

        text = MarkdownRenderer().render(report)

        assert "Host identifiers read by the report model · _Written by the report model_" in text
        row = next(line for line in text.splitlines() if VALUE in line)
        # Five cell borders once the escaped pipe inside the kind is taken out.
        assert "ev_0012" in row and row.replace("\\|", "").count("|") == 5
        assert "These rows are not published" in text

    def test_a_purpose_the_model_gave_none_is_said_to_be_not_stated(self) -> None:
        """A dash read as a cell nobody filled in, which is not what an empty purpose is."""
        report = _report(
            technical_analysis=TechnicalAnalysis(
                host_identifiers=[
                    HostIdentifier(kind="File", value=VALUE, evidence_refs=["ev_0012"])
                ]
            )
        )

        text = MarkdownRenderer().render(report)

        row = next(line for line in text.splitlines() if VALUE in line)
        assert "| not stated |" in row

    def test_the_section_is_asked_to_carry_a_purpose_an_analyst_stated(self) -> None:
        from maljan.reporting.composer import _INSTRUCTIONS

        assert (
            "an analyst claim above says what the sample uses the value for"
            in (_INSTRUCTIONS["host_identifiers"])
        )

    def test_a_row_the_model_kept_uncited_says_so(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                host_identifiers=[HostIdentifier(kind="File", value=VALUE, evidence_refs=[])]
            ),
            run_summary={
                "validation": {
                    "unresolved": [
                        {
                            "producer": "composer:host_identifiers",
                            "code": UNCITED_IDENTIFIER_CODE,
                            "message": "identifier 1 (x) cites no entry in this run's evidence.",
                        }
                    ]
                }
            },
        )

        text = MarkdownRenderer().render(report)

        assert "no evidence cited (unresolved: report.identifier_uncited)" in text

    def test_a_report_stored_before_the_field_existed_still_renders(self) -> None:
        stored = _report(technical_analysis=TechnicalAnalysis()).model_dump(mode="json")
        del stored["technical_analysis"]["host_identifiers"]
        text = MarkdownRenderer().render(MalwareReport.model_validate(stored))

        assert "Host identifiers read by the report model" not in text
