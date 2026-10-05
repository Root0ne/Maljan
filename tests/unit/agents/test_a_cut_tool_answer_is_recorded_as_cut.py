"""A tool answer the conversation had no room for is recorded as cut, never as ok and empty.

A decompile that answered after the reversing conversation ran out of room was
handed to the model as nothing and written to the ledger as a successful call
with an empty output. The decompiled-not-described check then asked the model
about a function it never read, the function map listed it as decompiled, and
the report's functions list counted it. The guardrail now says, for the call
it is answering, that none of the answer reached the conversation; the ledger
entry is marked ``truncated`` (the ledger's mark for an entry that is not the
whole answer) and holds the platform's statement of the cut in place of a tool
result. The readers that ask whether a function was read skip it.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.agents.function_map import build_function_map
from maljan.llm import context_window as cw
from maljan.pipeline.validation import decompiled_functions
from maljan.reporting.ledger_report import build_sections
from maljan.schemas.evidence import (
    answer_not_shown,
    apply_budget,
    build_entry,
    not_shown_record,
)

LISTING = "void FUN_00401000(void) {\n  return;\n}\n" * 40


def _full_budget() -> Any:
    budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
    budget.note_conversation("reverser", budget.tool_budget_chars() - 900)
    return budget


def _ghidra(budget: Any) -> Any:
    from maljan.agents.ghidra_http_client import GhidraHTTPClient

    client = GhidraHTTPClient.__new__(GhidraHTTPClient)
    client._max_output_chars = 0
    client._output_guardrail = None
    client._truncation_ledger = None
    client._context_budget = budget
    return client


def _decompile_tool(guardrail: Any) -> Any:
    from langchain_core.tools import StructuredTool

    def decompile_function(address: str) -> str:
        """Decompile the function at an address."""
        return guardrail(LISTING)

    return StructuredTool.from_function(func=decompile_function, name="decompile_function")


def _call(budget: Any) -> tuple[str, Any]:
    recorder = EvidenceRecorder("reverser")
    (tool,) = record_tools([_decompile_tool(_ghidra(budget)._apply_output_guardrail)], recorder)
    handed = tool.invoke({"address": "0x401000"})
    (entry,) = recorder.entries
    return str(handed), entry


class TestTheEntry:
    def test_an_answer_with_no_room_is_recorded_as_cut(self) -> None:
        handed, entry = _call(_full_budget())

        assert entry.ok is True
        assert entry.truncated is True
        assert entry.output == not_shown_record(len(LISTING))
        assert entry.structured is None
        assert answer_not_shown(entry) is True
        # The model is handed what it was handed before: the sentence.
        assert cw.no_room_sentence(len(LISTING)) in handed

    def test_an_answer_withheld_for_want_of_room_for_the_sentence_too(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("reverser", budget.tool_budget_chars() - 10)

        handed, entry = _call(budget)

        assert handed.strip() == f"[{entry.id}]"
        assert entry.truncated is True
        assert answer_not_shown(entry) is True

    def test_an_answer_that_fits_is_recorded_whole_as_before(self) -> None:
        roomy = cw.ContextBudget(cw.WindowFact(1_000_000, cw.PROBED, "props"), reply_tokens=8192)

        _handed, entry = _call(roomy)

        assert entry.output == LISTING
        assert entry.truncated is False
        assert answer_not_shown(entry) is False

    def test_an_entry_the_byte_budget_blanked_was_still_read(self) -> None:
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="reverser",
            tool="decompile_function",
            args={"address": "0x401000"},
            server=None,
            output=LISTING,
        )
        apply_budget([entry], 1)

        assert entry.truncated is True
        assert answer_not_shown(entry) is False


def _entries() -> list[Any]:
    read = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="reverser",
        tool="decompile_function",
        args={"address": "0x401000"},
        server=None,
        output=LISTING,
    )
    _handed, cut = _call(_full_budget())
    cut = cut.model_copy(
        update={"id": "ev_0002", "args": {"address": "0x402000"}, "symbol": "0x402000"}
    )
    return [read, cut]


class TestTheReaders:
    def test_the_decompiled_not_described_check_skips_a_cut_answer(self) -> None:
        found = decompiled_functions(_entries())

        assert [f.address for f in found] == [0x401000]

    def test_the_function_map_does_not_list_it_as_decompiled(self) -> None:
        found = build_function_map(_entries(), None, [])

        assert [e.address for e in found.visited] == [0x401000]

    def test_the_report_s_functions_list_says_it_was_not_shown(self) -> None:
        sections = build_sections(_entries())
        listed = next(s for s in sections if s.key == "functions_examined")
        items = [str(i) for i in listed.items]

        assert any("0x401000" in i and "not shown" not in i for i in items)
        assert any("0x402000" in i and "not shown" in i for i in items)


def test_the_record_is_a_statement_of_the_cut_and_never_parses_as_data() -> None:
    record = not_shown_record(12_345)

    assert "12,345" in record
    assert "no room" in record
    try:
        json.loads(record)
    except ValueError:
        pass
    else:  # pragma: no cover - the assertion is the point
        raise AssertionError("the record parsed as JSON")
