"""A row of the report model's tables states a value that an entry it cites holds.

A run's host-identifier table printed registry keys built by joining export
names, imports and string-dump fragments onto a registry path. No entry held
any of those keys. The citation check read only the pieces inside a row, found
them in other entries, and said nothing about the row itself. The same run's
configuration table printed a number cited to an entry that does not hold it,
and passed because a bare number was never decidable.

The rule now: a row's whole value, under the normalisation the citation check
already uses, has to be in at least one entry the row cites. A number counts
when the entry writes it in decimal or in hex. A row that fails is asked about
once, the model's answer stands, and a row it keeps is marked beside its
evidence.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    STATED_VALUE_UNHELD_CODE,
    EntryTexts,
    stated_value_violations,
)
from maljan.reporting.composer import ReportComposer, _ConfigOut, _HostIdentifiersOut
from maljan.reporting.models import (
    ConfigItem,
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import LedgerEntry

KEY = "Software\\ExampleVendor\\Updater"
JOINED = KEY + "\\ExampleExport"


def _entry(entry_id: str, tool: str, output: str, *, truncated: bool = False) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        agent="pipeline",
        server="pipeline",
        tool=tool,
        output=output,
        truncated=truncated,
    )


def _texts(*, partial: bool = False) -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry("ev_0005", "strings", json.dumps({"strings": [KEY, "beacon"]})),
            _entry("ev_0006", "list_exports", json.dumps({"exports": ["ExampleExport"]})),
            _entry("ev_0020", "decompile_function", "Sleep(0x3e8); retries = 12;"),
            _entry("ev_0022", "strings", "items: 5000", truncated=partial),
        ]
    )


def _identifiers(value: str, *refs: str) -> dict[str, Any]:
    return {"identifiers": [{"kind": "Registry key", "value": value, "evidence_refs": list(refs)}]}


def _items(value: str, *refs: str, how: str = "decrypted") -> dict[str, Any]:
    return {
        "items": [
            {"key": "Interval", "value": value, "how_obtained": how, "evidence_refs": list(refs)}
        ]
    }


class TestTheWholeValue:
    def test_a_value_built_from_pieces_no_entry_holds_whole_is_asked_about(self) -> None:
        (found,) = stated_value_violations(_identifiers(JOINED, "ev_0005", "ev_0006"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert found.message.startswith("identifier 1 ")
        assert "ev_0005 (strings)" in found.message

    def test_a_value_an_entry_it_cites_holds_stands(self) -> None:
        assert stated_value_violations(_identifiers(KEY, "ev_0006", "ev_0005"), _texts()) == []

    def test_the_value_is_found_as_the_entry_escapes_it(self) -> None:
        # The strings entry is JSON: the key's backslashes are doubled in it.
        assert "\\\\" in _texts().texts["ev_0005"]
        assert stated_value_violations(_identifiers(KEY, "ev_0005"), _texts()) == []

    def test_a_value_held_by_another_entry_is_left_to_the_citation_question(self) -> None:
        # ``wrong_entry_citations`` already asks this one, with the entry offered.
        assert stated_value_violations(_identifiers(KEY, "ev_0006"), _texts()) == []

    def test_a_partial_cited_entry_is_not_said_to_lack_it(self) -> None:
        assert stated_value_violations(_items("7000", "ev_0022"), _texts(partial=True)) == []

    def test_a_row_citing_no_known_entry_is_left_to_the_uncited_question(self) -> None:
        assert stated_value_violations(_identifiers(JOINED, "ev_0999"), _texts()) == []
        assert stated_value_violations(_identifiers(JOINED), _texts()) == []

    def test_rows_citing_the_same_entries_are_asked_about_together_by_number(self) -> None:
        payload = {
            "identifiers": [
                {"kind": "Registry key", "value": JOINED, "evidence_refs": ["ev_0005"]},
                {"kind": "Registry key", "value": KEY, "evidence_refs": ["ev_0005"]},
                {"kind": "Registry key", "value": JOINED + "2", "evidence_refs": ["ev_0005"]},
                {"kind": "Registry key", "value": JOINED + "3", "evidence_refs": ["ev_0006"]},
            ]
        }

        together, alone = stated_value_violations(payload, _texts())

        assert together.message.startswith("identifiers 1, 3 are each in none of the entries")
        assert alone.message.startswith("identifier 4 (")

    def test_nothing_is_judged_without_the_entries(self) -> None:
        assert stated_value_violations(_identifiers(JOINED, "ev_0005"), None) == []


class TestAStatedNumber:
    def test_a_number_the_cited_entry_does_not_hold_is_asked_about(self) -> None:
        (found,) = stated_value_violations(_items("7000", "ev_0020"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert found.message.startswith("configuration item 1 ")
        assert "ev_0020 (decompile_function)" in found.message

    def test_a_number_held_only_by_an_entry_not_cited_is_still_asked_about(self) -> None:
        # A number in another entry is a coincidence, not a source: no entry is offered.
        (found,) = stated_value_violations(_items("5000", "ev_0020"), _texts())

        assert "ev_0022" not in found.message

    def test_a_number_the_entry_writes_in_hex_is_held(self) -> None:
        assert stated_value_violations(_items("1000", "ev_0020"), _texts()) == []
        assert stated_value_violations(_items("0x3E8", "ev_0020"), _texts()) == []

    def test_a_number_with_its_unit_is_held_by_the_number(self) -> None:
        assert stated_value_violations(_items("1000 ms", "ev_0020"), _texts()) == []
        assert stated_value_violations(_items("12 retries", "ev_0020"), _texts()) == []

    def test_a_number_is_held_only_as_a_whole_value(self) -> None:
        # ``12`` is in the entry; ``2`` alone is not a value of its own there.
        assert stated_value_violations(_items("2", "ev_0020"), _texts())

    def test_an_inferred_value_is_left_to_its_own_mark(self) -> None:
        assert stated_value_violations(_items("7000", "ev_0020", how="inferred"), _texts()) == []


class TestTheFindingIsKept:
    def test_the_section_is_kept_with_the_finding(self) -> None:
        assert STATED_VALUE_UNHELD_CODE in KEPT_WITH_A_FINDING


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware", **over
    )


def _compose_section(section: str, schema: type, *answers: str) -> tuple[Any, _RawLLM, Any]:
    from langchain_core.messages import HumanMessage

    llm = _RawLLM(*answers)
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._entries = _texts()
    comp._citable = ["ev_0005", "ev_0006", "ev_0020", "ev_0022"]
    comp._report = _report()
    validators = [lambda p: stated_value_violations(p, comp._entries)]
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        result = asyncio.run(
            comp._invoke(
                [HumanMessage(content="write it")], schema, section=section, validators=validators
            )
        )
    return result, llm, comp


class TestTheComposerAsksOnce:
    def test_a_row_the_model_fixes_is_taken(self) -> None:
        wrong = json.dumps(_identifiers(JOINED, "ev_0005"))
        right = json.dumps(_identifiers(KEY, "ev_0005"))

        result, llm, comp = _compose_section("host_identifiers", _HostIdentifiersOut, wrong, right)

        assert len(llm.sent) == 2
        assert "identifier 1" in str(llm.sent[1][-1].content)
        assert result is not None and result.identifiers[0].value == KEY
        assert comp.validation_tally.unresolved == []

    def test_a_row_the_model_keeps_stands_and_is_recorded(self) -> None:
        wrong = json.dumps(_items("7000", "ev_0020"))

        result, llm, comp = _compose_section("configuration", _ConfigOut, wrong, wrong)

        assert len(llm.sent) == 2
        assert result is not None and result.items[0].value == "7000"
        (row,) = comp.validation_tally.unresolved
        assert row["code"] == STATED_VALUE_UNHELD_CODE

    def test_compose_puts_the_check_on_both_tables(self) -> None:
        seen: dict[str, list[Any]] = {}

        async def _author(self: Any, section: str, *args: Any, validators: Any = None) -> None:
            seen[section] = list(validators or [])

        comp = ReportComposer(llm=_RawLLM(), per_section_timeout=5)  # type: ignore[arg-type]
        with patch.object(ReportComposer, "_author", _author):
            asyncio.run(comp.compose(_report(), evidence=_texts()))

        config = [v for check in seen["configuration"] for v in check(_items("7000", "ev_0020"))]
        hosts = [
            v for check in seen["host_identifiers"] for v in check(_identifiers(JOINED, "ev_0005"))
        ]
        assert STATED_VALUE_UNHELD_CODE in [v.code for v in config]
        assert STATED_VALUE_UNHELD_CODE in [v.code for v in hosts]


class TestTheReportMarksAKeptRow:
    @staticmethod
    def _rendered(message: str) -> str:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[
                    ConfigItem(
                        key="Interval",
                        value="7000",
                        how_obtained="decrypted",
                        evidence_refs=["ev_0020"],
                    )
                ],
                host_identifiers=[
                    HostIdentifier(kind="Registry key", value=JOINED, evidence_refs=["ev_0005"])
                ],
            ),
            run_summary={
                "validation": {
                    "unresolved": [
                        {
                            "agent": "composer:x",
                            "code": STATED_VALUE_UNHELD_CODE,
                            "message": message,
                        }
                    ]
                }
            },
        )
        return MarkdownRenderer().render(report)

    def test_a_kept_configuration_row_is_marked_beside_its_evidence(self) -> None:
        text = self._rendered("configuration item 1 (Interval: '7000') is in none of …")

        row = next(line for line in text.splitlines() if line.startswith("| Interval"))
        assert f"ev_0020 (unresolved: {STATED_VALUE_UNHELD_CODE})" in row
        host = next(line for line in text.splitlines() if "ExampleExport" in line)
        assert STATED_VALUE_UNHELD_CODE not in host

    def test_rows_named_together_are_each_marked(self) -> None:
        text = self._rendered("configuration items 1, 4 are each in none of …")

        row = next(line for line in text.splitlines() if line.startswith("| Interval"))
        assert f"(unresolved: {STATED_VALUE_UNHELD_CODE})" in row

    def test_a_kept_identifier_row_is_marked_beside_its_evidence(self) -> None:
        text = self._rendered("identifier 1 (Registry key: 'x') is in none of …")

        host = next(line for line in text.splitlines() if "ExampleExport" in line)
        assert f"ev_0005 (unresolved: {STATED_VALUE_UNHELD_CODE})" in host
        row = next(line for line in text.splitlines() if line.startswith("| Interval"))
        assert STATED_VALUE_UNHELD_CODE not in row


class TestOddAndLargeInput:
    def test_odd_cells_raise_nothing(self) -> None:
        payload = {
            "items": [
                None,
                "a row that is a string",
                {"key": None, "value": None, "evidence_refs": None},
                {"key": 3, "value": 7000, "how_obtained": None, "evidence_refs": "ev_0020"},
                {"key": "Big", "value": "9" * 6000, "evidence_refs": ["ev_0020"]},
                {"key": "Wide", "value": "‮é\U0001f600" * 50, "evidence_refs": ["ev_0020"]},
                {"key": "Long", "value": "x\\" * 50000, "evidence_refs": ["ev_0020"]},
            ],
            "identifiers": {"not": "a list"},
        }

        found = stated_value_violations(payload, _texts())

        assert [v.code for v in found] == [STATED_VALUE_UNHELD_CODE]
        assert found[0].message.startswith("configuration items 2, 3, 4, 5 ")

    def test_a_large_table_against_a_large_ledger_finishes_quickly(self) -> None:
        import time

        entries = [
            _entry(
                f"ev_{n:04d}",
                "strings",
                json.dumps({"strings": [f"Software\\Vendor{n}\\Key{k}" for k in range(600)]}),
            )
            for n in range(300)
        ]
        texts = EntryTexts.from_ledger(entries)
        cited = [f"ev_{n:04d}" for n in range(0, 300, 3)]
        payload = {
            "identifiers": [
                {
                    "kind": "Registry key",
                    "value": f"Software\\Vendor{row % 300}\\Missing{row}",
                    "evidence_refs": cited,
                }
                for row in range(3000)
            ]
        }

        started = time.monotonic()
        found = stated_value_violations(payload, texts)
        elapsed = time.monotonic() - started

        (asked,) = found
        assert asked.message.startswith("identifiers 1, 2, 3, ")
        assert elapsed < 10, elapsed
