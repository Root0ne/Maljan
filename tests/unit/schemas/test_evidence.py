"""The ledger's own guarantees: ids, parsing, the byte budget, the converter."""

from __future__ import annotations

import json

from maljan.schemas.evidence import (
    EvidenceCounter,
    LedgerEntry,
    apply_budget,
    build_entry,
    format_entry_id,
    parse_structured,
)
from maljan.schemas.tool_evidence import MAX_OUTPUT_CHARS, CapturedToolOutput


class TestEntryIds:
    def test_ids_are_zero_padded_and_monotonic(self) -> None:
        counter = EvidenceCounter()
        assert counter.next_id() == ("ev_0001", 1)
        assert counter.next_id() == ("ev_0002", 2)
        assert counter.issued == 2

    def test_ids_sort_in_issue_order(self) -> None:
        ids = [format_entry_id(n) for n in (1, 2, 10, 100, 1000)]
        assert ids == sorted(ids)


class TestStructuredParsing:
    def test_json_object_becomes_structured(self) -> None:
        assert parse_structured('{"file_type": "PE"}') == {"file_type": "PE"}

    def test_json_array_becomes_structured(self) -> None:
        assert parse_structured('[{"dll": "KERNEL32.dll"}]') == [{"dll": "KERNEL32.dll"}]

    def test_scalar_json_is_not_structure(self) -> None:
        assert parse_structured("4") is None
        assert parse_structured('"a string"') is None

    def test_prose_is_not_structure(self) -> None:
        assert parse_structured("void FUN_00401310() { }") is None

    def test_entry_parses_its_own_output(self) -> None:
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="static",
            tool="identify_file",
            args={"path": "/samples/evil.exe"},
            server=None,
            output='{"file_type": "PE", "platform": "windows"}',
        )
        assert entry.structured == {"file_type": "PE", "platform": "windows"}
        assert entry.symbol == "/samples/evil.exe"


class TestBudget:
    def _entries(self, count: int, size: int) -> list[LedgerEntry]:
        return [
            build_entry(
                entry_id=format_entry_id(i + 1),
                seq=i + 1,
                agent="static",
                tool="strings",
                args={},
                server=None,
                output="A" * size,
            )
            for i in range(count)
        ]

    def test_entries_inside_the_budget_are_untouched(self) -> None:
        entries = self._entries(3, 100)
        assert apply_budget(entries, 1000) == (0, 300)
        assert all(entry.output and not entry.truncated for entry in entries)

    def test_entries_past_the_budget_keep_the_call_and_lose_the_output(self) -> None:
        entries = self._entries(4, 100)
        assert apply_budget(entries, 250) == (2, 200)
        assert [entry.truncated for entry in entries] == [False, False, True, True]
        assert entries[3].output == ""
        assert entries[3].structured is None
        # The call itself is still on the record.
        assert entries[3].tool == "strings"
        assert entries[3].ok is True

    def test_the_budget_belongs_to_the_agent_across_loops(self) -> None:
        # A chunked analysis re-enters the loop per chunk; the second loop
        # must not be handed the whole budget again.
        first = self._entries(2, 100)
        trimmed, spent = apply_budget(first, 250)
        assert (trimmed, spent) == (0, 200)

        second = self._entries(2, 100)
        trimmed, spent = apply_budget(second, 250, already_spent=spent)
        assert trimmed == 2
        assert spent == 200
        assert all(entry.truncated for entry in second)

    def test_a_zero_budget_keeps_everything(self) -> None:
        entries = self._entries(3, 100)
        assert apply_budget(entries, 0) == (0, 0)
        assert all(entry.output for entry in entries)


class TestConverter:
    def test_round_trip_through_the_previous_shape(self) -> None:
        entry = build_entry(
            entry_id="ev_0003",
            seq=3,
            agent="static",
            tool="decompile_function",
            args={"function_name": "FUN_00401310"},
            server="ghidra",
            output="void FUN_00401310() { }",
        )
        captured = entry.to_captured()
        assert isinstance(captured, CapturedToolOutput)
        assert captured.agent_id == "static"
        assert captured.tool_name == "decompile_function"
        assert captured.symbol == "FUN_00401310"
        # ``seq`` was 0-based in the previous shape and is 1-based here.
        assert captured.seq == 2

        back = LedgerEntry.from_captured(captured)
        assert back.id == "ev_0003"
        assert back.agent == "static"
        assert back.tool == "decompile_function"
        assert back.output == entry.output


class TestFailures:
    def test_a_failed_call_is_still_an_entry(self) -> None:
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output="RuntimeError: boom",
            ok=False,
            error="RuntimeError: boom",
            duration_ms=12,
        )
        assert entry.ok is False
        assert entry.error == "RuntimeError: boom"
        assert entry.duration_ms == 12


class TestTheFullResultSurvivesTheTextCut:
    """The record keeps what the model was handed, text and parsed result both.

    It used to keep only the first six thousand characters of the text. That
    was defensible while the guardrail handed the model the same six thousand;
    once the guardrail's cap came from the served context window the two
    diverged, and the durable record — the evidence API, the report sections —
    held a prefix of what the citation pointed at, with a trailing ellipsis and
    no flag.
    """

    def _pe_info(self) -> dict:
        return {
            "size": 4486656,
            "imports": [
                {"dll": "KERNEL32.dll", "function": f"Function{i:04d}"} for i in range(300)
            ],
            "sections": [{"name": ".text", "entropy": 6.1}],
        }

    def _capa(self) -> dict:
        return {
            "capabilities": [
                {
                    "namespace": f"host-interaction/process/inject/{i}",
                    "rule": f"inject code variant {i}",
                    "attck": [f"Defense Evasion::Process Injection [T1055.{i % 12 + 1:03d}]"],
                    "mbc": [],
                    "match_count": 1,
                }
                for i in range(80)
            ]
        }

    def _entry(self, payload: dict, tool: str):
        from maljan.schemas.evidence import build_entry, format_entry_id

        text = json.dumps(payload)
        assert len(text) > MAX_OUTPUT_CHARS
        return build_entry(
            entry_id=format_entry_id(1),
            seq=1,
            agent="pipeline",
            tool=tool,
            args={},
            server="pipeline",
            output=text,
        )

    def test_a_long_pe_info_result_is_stored_whole(self) -> None:
        payload = self._pe_info()
        entry = self._entry(payload, "pe_info")
        assert entry.output == json.dumps(payload)
        assert entry.truncated is False
        assert entry.structured == payload

    def test_a_caller_with_a_ceiling_of_its_own_gets_a_flagged_prefix(self) -> None:
        """No silent trailing ellipsis: a stored prefix says it is one."""
        from maljan.schemas.evidence import build_entry, format_entry_id

        text = json.dumps(self._pe_info())
        entry = build_entry(
            entry_id=format_entry_id(1),
            seq=1,
            agent="pipeline",
            tool="pe_info",
            args={},
            server="pipeline",
            output=text,
            max_chars=MAX_OUTPUT_CHARS,
        )
        assert len(entry.output) <= MAX_OUTPUT_CHARS
        assert entry.truncated is True

    def test_the_technique_ids_of_a_long_capa_result_are_readable(self) -> None:
        from maljan.pipeline.evidence_summary import _technique_ids

        entry = self._entry(self._capa(), "capa")
        assert entry.structured == self._capa()
        assert {"T1055.001", "T1055.012"} <= _technique_ids(entry.structured)

    def test_the_byte_budget_counts_the_result_that_is_kept(self) -> None:
        from maljan.schemas.evidence import apply_budget, stored_bytes

        entry = self._entry(self._pe_info(), "pe_info")
        size = stored_bytes(entry)
        assert size >= len(json.dumps(self._pe_info()).encode())
        trimmed, spent = apply_budget([entry], size - 1)
        assert (trimmed, spent) == (1, 0)
        assert entry.structured is None and entry.output == ""
        again = self._entry(self._pe_info(), "pe_info")
        trimmed, spent = apply_budget([again], size)
        assert (trimmed, spent) == (0, size)
        assert again.structured is not None
