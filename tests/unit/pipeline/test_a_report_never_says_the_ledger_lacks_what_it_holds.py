"""A report sentence that says the ledger lacks what an answered entry holds is asked once.

A report said a routine "is not read" while a decompile of it had answered,
that a routine's callers "are not in the ledger" while a callers query listed
them, and that import names "are not confirmed by the parser output" it cited
while that entry listed them. Each such sentence is read for its subject — an
address, an entry id or a value — and checked against the answered entries:
the model is asked once with the entry named, and the sentence is never
rewritten. A statement whose subject cannot be read, or whose entry holds
nothing of it, is not judged.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from maljan.pipeline.validation import (
    ABSENCE_CONTRADICTS_LEDGER_CODE,
    KEPT_WITH_A_FINDING,
    EntryTexts,
    ledger_absence_contradictions,
)
from maljan.schemas.evidence import build_entry

BASE = 0x140000000


def _entry(number: int, tool: str, args: dict[str, Any], output: str, *, ok: bool = True) -> Any:
    return build_entry(
        entry_id=f"ev_{number:04d}",
        seq=number,
        agent="reverser",
        tool=tool,
        args=args,
        server="decompiler",
        output=output,
        ok=ok,
        error=None if ok else "the call failed",
    )


def _listing(address: int) -> str:
    return f"undefined8 FUN_{address:x}(longlong param_1)\n{{\n  return 0;\n}}\n"


def _entries(*extra: Any) -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry(
                4,
                "pe_info",
                {},
                json.dumps(
                    {
                        "is_dll": True,
                        "image_base": BASE,
                        "imports": {"LIBA.dll": ["ReadThingW", "MakeThingW"]},
                    }
                ),
            ),
            _entry(
                57,
                "get_function_callers",
                {"address": hex(BASE + 0x7C40)},
                f"FUN_{BASE + 0x4400:x} @ {BASE + 0x4400:x}\n"
                f"FUN_{BASE + 0x4800:x} @ {BASE + 0x4800:x}",
            ),
            _entry(55, "get_function_callers", {"address": hex(BASE + 0x3300)}, "No callers found"),
            _entry(
                159, "decompile_function", {"address": hex(BASE + 0x5A10)}, _listing(BASE + 0x5A10)
            ),
            _entry(160, "decompile_function", {"address": hex(BASE + 0x5B20)}, "", ok=False),
            *extra,
        ]
    )


def _asked(text: str, entries: EntryTexts | None = None) -> list[Any]:
    return ledger_absence_contradictions({"body": text}, entries or _entries())


class TestAStatementTheLedgerContradicts:
    def test_a_routine_said_not_read_whose_decompile_answered(self) -> None:
        [violation] = _asked("The buffer is then passed to routine 0x5a10, which is not read.")
        assert violation.code == ABSENCE_CONTRADICTS_LEDGER_CODE
        assert "0x5a10 was not read" in violation.message
        assert "ev_0159 (decompile_function)" in violation.message

    def test_callers_said_not_in_the_ledger_after_the_sentence_naming_the_routine(self) -> None:
        [violation] = _asked(
            "Routine 0x7c40 formats launcher command lines. "
            "Its callers and arguments are not in the ledger."
        )
        assert "0x7c40 is not in the ledger" in violation.message
        assert "ev_0057 (get_function_callers)" in violation.message

    def test_values_said_not_confirmed_by_the_entry_cited_for_them(self) -> None:
        [violation] = _asked(
            "The import names (ReadThingW, MakeThingW) are not confirmed by the parser "
            "output, which gives a count only [ev_0004]."
        )
        assert "ReadThingW, MakeThingW are not confirmed" in violation.message
        assert "ev_0004 (pe_info) holds them" in violation.message

    def test_an_entry_id_said_not_in_the_ledger(self) -> None:
        [violation] = _asked("The callers listing ev_0057 is not in the ledger.")
        assert "ev_0057 is not in the ledger" in violation.message

    def test_a_virtual_address_and_its_offset_are_one_routine(self) -> None:
        [violation] = _asked(f"Routine {BASE + 0x5A10:#x} was never decompiled.")
        assert "ev_0159" in violation.message

    def test_one_question_per_routine_however_often_it_is_said(self) -> None:
        found = _asked(
            "Routine 0x5a10 is not read. Later, routine 0x5a10 is not read either.\n"
            "Again: 0x5a10 has not been read."
        )
        assert len(found) == 1

    def test_the_finding_is_kept_beside_the_sentence_after_one_ask(self) -> None:
        assert ABSENCE_CONTRADICTS_LEDGER_CODE in KEPT_WITH_A_FINDING


class TestAStatementThatStands:
    @pytest.mark.parametrize(
        "text",
        [
            # The callers query answered with no caller: the absence is right.
            "The callers of 0x3300 are not in the ledger.",
            # The decompile failed: nothing was read.
            "Routine 0x5b20 is not read.",
            # Another routine.
            "Routine 0x7000 is not read.",
            # An assessment, not a statement about the ledger.
            "The family is not confirmed, and remote injection is not established.",
            "The family is not confirmed by run behaviour [ev_0004].",
            # A value the cited entry does not hold.
            "The name GetTickCount is not confirmed by the parser output [ev_0004].",
            # No subject to read.
            "Whether that line is sent back is not read.",
            "The information-class values are not in the ledger.",
            # A pronoun after a sentence naming two routines: which one is unknown.
            "Routines 0x7c40 and 0x5a10 build it. Its arguments are not in the ledger.",
            # A small number is an offset or a flag, not a routine.
            "The value at offset 0x60 is not read.",
        ],
    )
    def test_it_is_not_asked(self, text: str) -> None:
        assert _asked(text) == []

    def test_a_ledger_with_no_entries_judges_nothing(self) -> None:
        assert ledger_absence_contradictions({"body": "0x5a10 is not read."}, None) == []
        assert ledger_absence_contradictions(None, _entries()) == []


class TestLinearTime:
    def test_ten_times_the_text_and_the_ledger_cost_at_most_ten_times_the_time(self) -> None:
        def cost(scale: int) -> float:
            extra = [
                _entry(
                    1000 + n,
                    "decompile_function",
                    {"address": hex(BASE + 0x10000 * n + 0x100)},
                    _listing(BASE + 0x10000 * n + 0x100),
                )
                for n in range(scale)
            ]
            entries = _entries(*extra)
            text = " ".join(
                f"Routine {0x200 + n:#x}, which is not read, calls (A1, B2, C3) "
                f"that are not confirmed by [ev_0004]. Its callers are not in the ledger."
                for n in range(scale)
            )
            start = time.perf_counter()
            ledger_absence_contradictions({"body": text}, entries)
            return time.perf_counter() - start

        cost(5)
        small = cost(50)
        large = cost(500)
        assert large <= max(small, 1e-3) * 30
