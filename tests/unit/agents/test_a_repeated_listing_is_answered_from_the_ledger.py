"""A listing or a decompile the ledger already answers is answered from it, and said.

Failed reversing loops repeat themselves: they list the whole program again
and decompile a routine they already read, often under another spelling of
the same call (``limit`` 100 after ``limit`` 50, an address with ``0x`` after
one without, one function of a batch asked alone). The repeat guard counts
identical calls only. These are answered from the entry that holds the answer,
the call is not run, and the answer says so. What counts as covered is read
off the run: the earlier answer is whole when it held fewer items than it
asked for, and a call that adds an argument is run.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.evidence_recorder import EvidenceRecorder, RepeatGuard, record_tools
from maljan.agents.ledger_answers import (
    DECOMPILED_AGAIN,
    LISTED_AGAIN,
    LedgerAnswers,
    pivot_sentence,
)
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry

STRINGS = "\n".join(f'1360bc0e{n:03x}: "text {n}"' for n in range(11))


class _ListArgs(BaseModel):
    limit: int | None = None
    offset: int | None = None
    filter: str | None = None
    program: str | None = None


class _DecompileArgs(BaseModel):
    address: str | None = None
    program: str | None = None
    timeout: int | None = None


class _BatchArgs(BaseModel):
    functions: str = ""
    program: str | None = None


def _tool(name: str, schema: type[BaseModel], answer: Any, calls: list[dict[str, Any]]) -> Any:
    def _run(**kwargs: Any) -> str:
        calls.append(kwargs)
        return answer(kwargs) if callable(answer) else answer

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=name,
        args_schema=schema,
        infer_schema=False,
        metadata={"maljan_server": "ghidra"},
    )


class _Loop:
    """One loop's wrapped tools, over one recorder, one guard and one ledger reader."""

    def __init__(self, *tools: Any, earlier: list[LedgerEntry] | None = None) -> None:
        self.recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
        self.guard = RepeatGuard()
        self.ledger = LedgerAnswers(
            lambda: [*(earlier or []), *self.recorder.entries],
            decoders=(),
        )
        wrapped = record_tools(list(tools), self.recorder, self.guard, ledger=self.ledger)
        self.tools = {tool.name: tool for tool in wrapped}

    def __call__(self, name: str, **kwargs: Any) -> str:
        return str(self.tools[name].invoke(kwargs))


def _listing(calls: list[dict[str, Any]], answer: Any = STRINGS) -> Any:
    return _tool("list_strings", _ListArgs, answer, calls)


class TestAWholeProgramListingAskedAgain:
    def test_a_wider_page_after_a_whole_answer_is_answered_from_it(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", limit=50, program="a.exe")
        again = loop("list_strings", limit=100, offset=0, filter="", program="a.exe")

        assert len(calls) == 1
        assert again.startswith(f"[ev_0001]\n{STRINGS}")
        tail = again[len(f"[ev_0001]\n{STRINGS}") :]
        assert "was not run" in tail
        assert "up to 50 items and its answer held 11" in tail
        assert len(loop.recorder.entries) == 1
        assert loop.ledger.counts == {LISTED_AGAIN: 1}
        assert loop.guard.served_repeats == 0

    def test_the_same_scope_spelled_differently_is_answered_from_it(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", program="a.exe")
        again = loop("list_strings", program="a.exe", filter="", offset=0)

        assert len(calls) == 1
        assert "asks for the same scope as the call recorded in [ev_0001]" in again

    def test_an_answer_that_filled_its_page_does_not_answer_a_wider_one(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", limit=11, program="a.exe")
        loop("list_strings", limit=100, program="a.exe")

        assert len(calls) == 2

    def test_an_answer_with_no_limit_stated_is_not_taken_as_whole(self) -> None:
        """The server's own page size is not known, so a wider ask is run."""
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", program="a.exe")
        loop("list_strings", limit=100, program="a.exe")

        assert len(calls) == 2

    def test_a_narrower_filter_is_run(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", limit=50, program="a.exe")
        loop("list_strings", limit=50, filter="http", program="a.exe")

        assert len(calls) == 2

    def test_a_smaller_page_than_the_answer_held_is_run(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", limit=50, program="a.exe")
        loop("list_strings", limit=5, program="a.exe")

        assert len(calls) == 2

    def test_a_later_page_is_run(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", limit=50, program="a.exe")
        loop("list_strings", limit=50, offset=50, program="a.exe")

        assert len(calls) == 2

    def test_another_program_is_run(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", limit=50, program="a.exe")
        loop("list_strings", limit=50, program="b.exe")

        assert len(calls) == 2

    def test_a_failed_earlier_call_answers_nothing(self) -> None:
        calls: list[dict[str, Any]] = []

        def _fails(kwargs: dict[str, Any]) -> str:
            if len(calls) == 1:
                raise RuntimeError("no program")
            return STRINGS

        loop = _Loop(_listing(calls, _fails))

        loop("list_strings", limit=50, program="a.exe")
        loop("list_strings", limit=100, program="a.exe")

        assert len(calls) == 2

    def test_a_shortened_earlier_answer_answers_nothing_wider(self) -> None:
        from maljan.agents.output_shortening import shorten_json_document

        shortened = shorten_json_document(
            json.dumps({"rows": [{"n": n} for n in range(400)]}), 2000
        ).text
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls, shortened))

        loop("list_strings", limit=500, program="a.exe")
        loop("list_strings", limit=1000, program="a.exe")

        assert len(calls) == 2

    def test_an_earlier_loop_s_entry_answers_too(self) -> None:
        earlier = LedgerEntry(
            id="ev_0007",
            tool="list_strings",
            server="ghidra",
            args={"limit": 50, "program": "a.exe"},
            output=STRINGS,
        )
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls), earlier=[earlier])

        again = loop("list_strings", limit=100, program="a.exe")

        assert calls == []
        assert again.startswith(f"[ev_0007]\n{STRINGS}")

    def test_an_entry_the_byte_budget_blanked_answers_nothing(self) -> None:
        earlier = LedgerEntry(
            id="ev_0007",
            tool="list_strings",
            server="ghidra",
            args={"limit": 50, "program": "a.exe"},
            output="",
            truncated=True,
        )
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls), earlier=[earlier])

        loop("list_strings", limit=100, program="a.exe")

        assert len(calls) == 1

    def test_another_server_s_listing_answers_nothing(self) -> None:
        earlier = LedgerEntry(
            id="ev_0007",
            tool="list_strings",
            server="radare2",
            args={"limit": 50, "program": "a.exe"},
            output=STRINGS,
        )
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls), earlier=[earlier])

        loop("list_strings", limit=100, program="a.exe")

        assert len(calls) == 1

    def test_asking_again_after_the_ledger_answered_is_a_repeat(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_listing(calls))

        loop("list_strings", limit=50, program="a.exe")
        loop("list_strings", limit=100, program="a.exe")
        third = loop("list_strings", limit=100, program="a.exe")

        assert len(calls) == 1
        assert "[ev_0001]" in third
        assert STRINGS not in third
        assert loop.guard.served_repeats == 1

    def test_a_tool_that_neither_lists_nor_searches_is_left_to_the_repeat_guard(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_tool("get_current_program_info", _ListArgs, "{}", calls))

        loop("get_current_program_info", program="a.exe")
        loop("get_current_program_info", program="a.exe")

        assert len(calls) == 2


LISTING = "void FUN_1360bc0904c(void)\n{\n  lookup(0x572d5d8e);\n}\n"


def _decompiler(calls: list[dict[str, Any]]) -> Any:
    return _tool("decompile_function", _DecompileArgs, LISTING, calls)


class TestAFunctionDecompiledAgain:
    def test_another_spelling_of_the_same_address_is_answered_from_the_listing(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_decompiler(calls))

        loop("decompile_function", address="1360bc0904c")
        again = loop("decompile_function", address="0x1360bc0904c", program=None)

        assert len(calls) == 1
        assert again.startswith(f"[ev_0001]\n{LISTING}")
        tail = again[len(f"[ev_0001]\n{LISTING}") :]
        assert "0x1360bc0904c was already decompiled in [ev_0001]" in tail
        assert "function map" in tail
        assert pivot_sentence(()) in tail
        assert loop.ledger.counts == {DECOMPILED_AGAIN: 1}

    def test_the_pivot_is_said_once_in_a_loop(self) -> None:
        calls: list[dict[str, Any]] = []
        other = "void FUN_1360bc02200(void)\n{\n}\n"
        loop = _Loop(
            _tool(
                "decompile_function",
                _DecompileArgs,
                lambda kwargs: LISTING if "904c" in str(kwargs["address"]) else other,
                calls,
            )
        )

        loop("decompile_function", address="0x1360bc0904c")
        loop("decompile_function", address="0x1360bc02200")
        first = loop("decompile_function", address="1360bc0904c")
        second = loop("decompile_function", address="1360bc02200")

        assert len(calls) == 2
        assert pivot_sentence(()) in first
        assert pivot_sentence(()) not in second
        assert "0x1360bc02200 was already decompiled in [ev_0002]" in second

    def test_a_function_of_an_earlier_batch_asked_alone_is_answered_from_its_part(self) -> None:
        calls: list[dict[str, Any]] = []
        batch = json.dumps({"0x1360bc0904c": LISTING, "0x1360bc02200": "void b(void) {}"})
        loop = _Loop(_tool("batch_decompile", _BatchArgs, batch, calls), _decompiler(calls))

        loop("batch_decompile", functions="0x1360bc0904c,0x1360bc02200")
        again = loop("decompile_function", address="1360bc0904c")

        assert len(calls) == 1
        assert again.startswith(f"[ev_0001]\n{LISTING}")

    def test_a_batch_of_functions_all_read_before_is_answered_with_each_listing(self) -> None:
        calls: list[dict[str, Any]] = []
        other = "void FUN_1360bc02200(void)\n{\n}\n"
        loop = _Loop(
            _tool(
                "decompile_function",
                _DecompileArgs,
                lambda kwargs: LISTING if "904c" in str(kwargs["address"]) else other,
                calls,
            ),
            _tool("batch_decompile", _BatchArgs, "{}", calls),
        )

        loop("decompile_function", address="0x1360bc0904c")
        loop("decompile_function", address="0x1360bc02200")
        again = loop("batch_decompile", functions="1360bc0904c,1360bc02200")

        assert len(calls) == 2
        assert f"[ev_0001]\n{LISTING}" in again
        assert f"[ev_0002]\n{other}" in again
        assert "these 2 functions were already decompiled in [ev_0001], [ev_0002]" in again

    def test_a_batch_with_one_new_function_is_run(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_decompiler(calls), _tool("batch_decompile", _BatchArgs, "{}", calls))

        loop("decompile_function", address="0x1360bc0904c")
        loop("batch_decompile", functions="0x1360bc0904c,0x1360bc07b98")

        assert len(calls) == 2

    def test_a_new_argument_is_run(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_decompiler(calls))

        loop("decompile_function", address="0x1360bc0904c")
        loop("decompile_function", address="0x1360bc0904c", timeout=300)

        assert len(calls) == 2

    def test_a_failed_decompile_is_left_to_the_repeat_guard(self) -> None:
        calls: list[dict[str, Any]] = []

        def _fails(kwargs: dict[str, Any]) -> str:
            raise RuntimeError("No function found for 1360bc09040")

        loop = _Loop(_tool("decompile_function", _DecompileArgs, _fails, calls))

        loop("decompile_function", address="1360bc09040")
        loop("decompile_function", address="1360bc09040")
        refused = loop("decompile_function", address="1360bc09040")

        assert len(calls) == 2
        assert "failed" in refused

    def test_a_listing_the_byte_budget_blanked_is_run_again(self) -> None:
        earlier = LedgerEntry(
            id="ev_0003",
            tool="decompile_function",
            server="ghidra",
            args={"address": "0x1360bc0904c"},
            output="",
            truncated=True,
        )
        calls: list[dict[str, Any]] = []
        loop = _Loop(_decompiler(calls), earlier=[earlier])

        loop("decompile_function", address="0x1360bc0904c")

        assert len(calls) == 1

    def test_asking_again_after_the_ledger_answered_is_a_repeat(self) -> None:
        calls: list[dict[str, Any]] = []
        loop = _Loop(_decompiler(calls))

        loop("decompile_function", address="0x1360bc0904c")
        loop("decompile_function", address="1360bc0904c")
        third = loop("decompile_function", address="1360bc0904c")

        assert len(calls) == 1
        assert LISTING not in third
        assert "[ev_0001]" in third
        assert loop.guard.served_repeats == 1


class TestThePivot:
    def test_it_names_the_decoding_tools_the_loop_has(self) -> None:
        said = pivot_sentence(("emulate_function", "decode_string_blobs"))

        assert "emulate_function" in said and "decode_string_blobs" in said
        assert "state the constraint" in said
        assert "give your answer" in said

    def test_without_a_decoding_tool_it_asks_for_the_decoder_in_a_claim(self) -> None:
        said = pivot_sentence(())

        assert "name the decoder" in said
        assert "claim" in said


@pytest.mark.parametrize(
    "names, expected",
    [
        (["emulate_function", "list_strings", "decode_string_blobs"], ("emulate_function",)),
    ],
)
def test_the_loop_s_decoding_tools_are_read_off_their_names(
    names: list[str], expected: tuple[str, ...]
) -> None:
    from maljan.agents.ledger_answers import decoding_tools

    assert set(expected) <= set(decoding_tools(names))
    assert "list_strings" not in decoding_tools(names)
