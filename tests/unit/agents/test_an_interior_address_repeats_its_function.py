"""A decompile through an address inside a function already read is a repeat of that entry.

The r2 analyst decompiled one function at its start and again at an address
inside it; both calls answered with the same listing under the same signature,
and the ledger saw two different calls because the guard keys on the address
argument. The function the answer prints is the key now: the second call is
filed as a repeat of the entry that holds the function, keeps a note rather
than a second copy, and the model is still handed the answer, stamped with
the entry to cite.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.evidence_recorder import (
    EvidenceRecorder,
    RepeatGuard,
    record_tools,
    seeded_repeat_guard,
)
from maljan.pipeline.validation import decompiled_functions, listed_function
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry

# A function as a decompiler prints it: a comment line, then the signature
# with the generic name that carries its start.
FIRST = "// callconv: rax ms (rcx, rdx);\nvoid fcn.00402200 (uint32_t arg1) {\n  return;\n}\n"
SECOND = "// callconv: rax ms (rcx, rdx);\nvoid fcn.00406988 (int64_t arg1) {\n  return;\n}\n"


class _Args(BaseModel):
    address: str = ""


def _decompiler(listings: dict[str, str], calls: list[str]) -> StructuredTool:
    def _run(address: str = "") -> str:
        calls.append(address)
        return listings[address]

    return StructuredTool.from_function(
        func=_run,
        name="decompile_function",
        description="Decompile the function containing an address.",
        args_schema=_Args,
        infer_schema=False,
    )


def _loop(listings: dict[str, str], guard: RepeatGuard | None = None) -> tuple[Any, Any, list]:
    calls: list[str] = []
    recorder = EvidenceRecorder("static_r2", counter=EvidenceCounter())
    tool = record_tools([_decompiler(listings, calls)], recorder, guard or RepeatGuard())[0]
    return tool, recorder, calls


class TestTheFunctionTheAnswerPrints:
    def test_a_generic_name_is_keyed_on_its_start(self) -> None:
        assert listed_function(FIRST) == ("start", 0x402200)
        assert listed_function("undefined8 FUN_00402200(void) {") == ("start", 0x402200)

    def test_another_name_is_keyed_on_the_name_and_no_signature_on_nothing(self) -> None:
        assert listed_function("int main(int argc) {\n}") == ("name", "main")
        assert listed_function('{"0x401000": "int a(void) {}"}') is None
        assert listed_function("Error: no function at that address") is None


class TestAnInteriorAddress:
    def test_it_is_filed_as_a_repeat_of_the_entry_holding_the_function(self) -> None:
        tool, recorder, calls = _loop({"0x402200": FIRST, "0x402616": FIRST})

        tool.invoke({"address": "0x402200"})
        answer = tool.invoke({"address": "0x402616"})

        assert calls == ["0x402200", "0x402616"], "the tool ran: the repeat is seen in its answer"
        first, second = recorder.entries
        assert first.repeated_of is None
        assert second.repeated_of == first.id
        assert FIRST not in second.output, "the repeat keeps a note, not a second copy"
        assert first.id in second.output
        # The model is still handed the listing, under the entry to cite.
        assert answer.startswith(f"[{first.id}]\n")
        assert FIRST in answer
        assert second.id not in answer

    def test_it_lists_no_function_of_its_own(self) -> None:
        tool, recorder, _calls = _loop({"0x402200": FIRST, "0x402616": FIRST})

        tool.invoke({"address": "0x402200"})
        tool.invoke({"address": "0x402616"})

        functions = decompiled_functions(recorder.entries)
        assert [f.address for f in functions] == [0x402200]

    def test_a_different_function_is_its_own_entry(self) -> None:
        tool, recorder, _calls = _loop({"0x402200": FIRST, "0x406a1f": SECOND})

        tool.invoke({"address": "0x402200"})
        tool.invoke({"address": "0x406a1f"})

        assert [e.repeated_of for e in recorder.entries] == [None, None]

    def test_an_answer_showing_more_of_the_function_is_new_evidence(self) -> None:
        cut = FIRST[: FIRST.index("{") + 1]
        tool, recorder, _calls = _loop({"0x402200": cut, "0x402616": FIRST, "0x402700": FIRST})

        tool.invoke({"address": "0x402200"})
        tool.invoke({"address": "0x402616"})
        tool.invoke({"address": "0x402700"})

        first, fuller, again = recorder.entries
        assert fuller.repeated_of is None
        assert again.repeated_of == fuller.id, "the fuller listing is the one named from then on"

    def test_an_earlier_chunk_s_listing_holds_the_function(self) -> None:
        earlier = LedgerEntry(
            id="ev_0007",
            tool="decompile_function",
            args={"address": "0x402200"},
            output=FIRST,
        )
        tool, recorder, _calls = _loop({"0x402616": FIRST}, seeded_repeat_guard([earlier]))

        answer = tool.invoke({"address": "0x402616"})

        assert recorder.entries[0].repeated_of == "ev_0007"
        assert answer.startswith("[ev_0007]\n") and FIRST in answer

    def test_without_a_guard_nothing_is_keyed(self) -> None:
        calls: list[str] = []
        recorder = EvidenceRecorder("static_r2", counter=EvidenceCounter())
        tool = record_tools([_decompiler({"a": FIRST, "b": FIRST}, calls)], recorder)[0]

        tool.invoke({"address": "a"})
        tool.invoke({"address": "b"})

        assert [e.repeated_of for e in recorder.entries] == [None, None]


class TestTheSameInteriorAddressAskedAgain:
    """Every repeat names the entry that holds the listing, however often it is asked."""

    def _asked(self, times: int) -> tuple[list[str], Any]:
        tool, recorder, _calls = _loop({"0x402200": FIRST, "0x402616": FIRST})
        answers = [tool.invoke({"address": "0x402200"})]
        answers += [tool.invoke({"address": "0x402616"}) for _ in range(times)]
        return answers, recorder

    def test_the_model_is_never_shown_a_repeat_s_id(self) -> None:
        answers, recorder = self._asked(4)

        holder = recorder.entries[0].id
        repeat_ids = [e.id for e in recorder.entries if e.repeated_of]
        assert len(repeat_ids) == len(recorder.entries) - 1
        for answer in answers:
            assert not any(f"[{rid}]" in answer for rid in repeat_ids), answer
        assert all(holder in answer for answer in answers[1:])

    def test_no_repeat_names_a_repeat_and_the_listing_is_held_once(self) -> None:
        _answers, recorder = self._asked(3)

        holder = recorder.entries[0]
        assert all(e.repeated_of == holder.id for e in recorder.entries[1:])
        assert [e.id for e in recorder.entries if FIRST in e.output] == [holder.id]

    def test_the_interior_address_is_never_a_function_of_its_own(self) -> None:
        _answers, recorder = self._asked(3)

        assert [f.address for f in decompiled_functions(recorder.entries)] == [0x402200]


class TestACitedRepeatReadsAsItsHolder:
    def _ledger(self) -> list[LedgerEntry]:
        return [
            LedgerEntry(id="ev_0001", tool="decompile_function", output="int y = 2;"),
            LedgerEntry(
                id="ev_0002", tool="decompile_function", output="a note", repeated_of="ev_0001"
            ),
            LedgerEntry(
                id="ev_0003",
                tool="decompile_function",
                output="another note",
                repeated_of="ev_0002",
            ),
        ]

    def test_the_citation_checker_reads_the_holder_s_text(self) -> None:
        from maljan.pipeline.validation import EntryTexts

        texts = EntryTexts.from_ledger(self._ledger())

        assert texts.texts["ev_0002"] == texts.texts["ev_0001"]
        assert texts.texts["ev_0003"] == texts.texts["ev_0001"]
        assert "note" not in texts.texts["ev_0003"]

    def test_the_judge_is_shown_the_holder_s_text(self) -> None:
        from maljan.agents.judge_agent import question_evidence

        shown = question_evidence(self._ledger())

        assert shown["ev_0002"].text == "int y = 2;"
        assert shown["ev_0003"].text == "int y = 2;"

    def test_a_repeat_whose_holder_is_absent_reads_as_nothing(self) -> None:
        from maljan.pipeline.validation import EntryTexts

        orphan = [LedgerEntry(id="ev_0009", tool="strings", output="a note", repeated_of="ev_0004")]

        assert "ev_0009" not in EntryTexts.from_ledger(orphan).texts


class TestTheSampleCannotForgeARepeat:
    """The printed name is text a sample can shape; only the listing itself decides."""

    def test_two_functions_printing_the_same_name_are_two_entries(self) -> None:
        other = FIRST.replace("return;", "beacon(0x2);")
        tool, recorder, _calls = _loop({"0x402200": FIRST, "0x409000": other})

        tool.invoke({"address": "0x402200"})
        answer = tool.invoke({"address": "0x409000"})

        assert [e.repeated_of for e in recorder.entries] == [None, None]
        assert recorder.entries[1].output == other, "its content is kept whole"
        assert answer.startswith(f"[{recorder.entries[1].id}]\n")

    def test_a_forged_generic_name_naming_an_earlier_start_is_new_evidence(self) -> None:
        forged = "void fcn.00402200 (void) {\n  wipe_shadow_copies();\n}\n"
        tool, recorder, _calls = _loop({"0x402200": FIRST, "0x40a000": forged})

        tool.invoke({"address": "0x402200"})
        tool.invoke({"address": "0x40a000"})

        assert recorder.entries[1].repeated_of is None
        assert recorder.entries[1].output == forged

    def test_a_cut_copy_of_the_held_listing_is_a_repeat(self) -> None:
        cut = FIRST[: FIRST.index("{") + 4] + "\n\n[OUTPUT TRUNCATED]"
        tool, recorder, _calls = _loop({"0x402200": FIRST, "0x402616": cut})

        tool.invoke({"address": "0x402200"})
        tool.invoke({"address": "0x402616"})

        assert recorder.entries[1].repeated_of == recorder.entries[0].id

    def test_a_cut_copy_that_differs_inside_the_kept_part_is_new_evidence(self) -> None:
        altered = FIRST.replace("uint32_t", "uint64_t")[: FIRST.index("{") + 4]
        tool, recorder, _calls = _loop({"0x402200": FIRST, "0x402616": altered})

        tool.invoke({"address": "0x402200"})
        tool.invoke({"address": "0x402616"})

        assert recorder.entries[1].repeated_of is None
