"""A function the analyst decompiled and no claim describes is listed to it, once.

A reverser decompiled two routines that held half of what the analysis needed,
kept both listings in its own ledger, and wrote no claim about either. The
functions are read off the analyst's own ledger entries:

- the address the call was given, as a hex string or as an integer;
- each function of a batch decompile, one per key of its answer;
- the name the decompiler printed.

A claim describes a function when its sentence or its evidence line names it.
It can name it by address: the same address, or one that differs by the image
base the run read, or, with no base known, by a multiple of 64 KiB. It can
write the address as ``0x…``, as ``…h`` or as bare hex. Or it can use a name
the decompiler gave.

The functions no claim names are listed in one question, asked once. What the
analyst answers stands. The functions its kept answer still names in no claim
are recorded as a finding, and the report prints it.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import (
    DECOMPILED_NOT_DESCRIBED_CODE,
    DecompiledFunction,
    decompiled_functions,
    decompiled_not_described_violation,
    image_bases_in,
    undescribed_decompiles,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

BASE = 0x140000000
FIRST_OFFSET = 0x1230
SECOND_OFFSET = 0x4AB0
FIRST_FN = BASE + FIRST_OFFSET
SECOND_FN = BASE + SECOND_OFFSET


def _r2(entry: str, address: int, name: str = "") -> LedgerEntry:
    shown = name or f"fcn.{address:x}"
    return LedgerEntry(
        id=entry,
        tool="decompile_function",
        args={"address": hex(address)},
        output=(
            "// callconv: rax ms (rcx, rdx, r8, r9, stack);\n"
            f"int {shown} (int rcx, int rdx) {{\n  return 0;\n}}\n"
        ),
    )


def _ghidra(entry: str, address: int, name: str = "") -> LedgerEntry:
    shown = name or f"FUN_{address:x}"
    return LedgerEntry(
        id=entry,
        tool="decompile_function",
        args={"address": f"{address:x}", "program": "s.exe"},
        output=f"\nundefined8 {shown}(void)\n\n{{\n  if (x) {{ return 1; }}\n  return 0;\n}}\n",
    )


def _claim(text: str, evidence: str = "[ev_0003]") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=evidence, confidence=0.8)


class TestWhatWasDecompiled:
    def test_the_address_and_the_decompiler_s_name_are_read_off_each_entry(self) -> None:
        found = decompiled_functions(
            [_r2("ev_0003", FIRST_FN), _ghidra("ev_0004", SECOND_FN, "InstallService")]
        )

        assert [(f.address, f.names, f.entries) for f in found] == [
            (FIRST_FN, (f"fcn.{FIRST_FN:x}",), ("ev_0003",)),
            (SECOND_FN, ("InstallService",), ("ev_0004",)),
        ]

    def test_a_failed_call_and_another_tool_are_not_decompiles(self) -> None:
        failed = _ghidra("ev_0005", FIRST_FN)
        failed.ok = False
        listing = LedgerEntry(id="ev_0006", tool="list_functions", args={}, output="x")

        assert decompiled_functions([failed, listing]) == []

    def test_one_function_decompiled_twice_is_one_function(self) -> None:
        found = decompiled_functions([_r2("ev_0003", FIRST_FN), _ghidra("ev_0007", FIRST_FN)])

        assert len(found) == 1
        assert found[0].entries == ("ev_0003", "ev_0007")

    def test_a_function_asked_for_by_name_keeps_its_name(self) -> None:
        entry = LedgerEntry(
            id="ev_0008",
            tool="decompile_function_by_name",
            args={"name": "ParseConfig"},
            output="int ParseConfig(char *p)\n{\n  return 0;\n}\n",
        )

        (found,) = decompiled_functions([entry])

        assert (found.address, found.names) == (None, ("ParseConfig",))

    def test_by_address_and_then_by_name_is_one_function(self) -> None:
        by_name = LedgerEntry(
            id="ev_0009",
            tool="decompile_function_by_name",
            args={"name": "InstallService"},
            output="int InstallService(void)\n{\n  return 0;\n}\n",
        )

        found = decompiled_functions([_ghidra("ev_0004", SECOND_FN, "InstallService"), by_name])

        assert [(f.address, f.names, f.entries) for f in found] == [
            (SECOND_FN, ("InstallService",), ("ev_0004", "ev_0009"))
        ]

    def test_an_integer_address_is_read_as_the_integer(self) -> None:
        entry = LedgerEntry(
            id="ev_0010",
            tool="decompile",
            args={"ea": FIRST_FN},
            output="int sub_x(void)\n{\n  return 0;\n}\n",
        )

        (found,) = decompiled_functions([entry])

        assert found.address == FIRST_FN

    def test_the_return_type_on_its_own_line_names_nothing_wrong(self) -> None:
        entry = LedgerEntry(
            id="ev_0011",
            tool="decompile_function",
            args={"address": hex(FIRST_FN)},
            output=f"undefined8\nFUN_{FIRST_FN:x}(void)\n{{\n  return 0;\n}}\n",
        )

        (found,) = decompiled_functions([entry])

        assert found.names == (f"FUN_{FIRST_FN:x}",)


class TestABatchDecompile:
    """One call, five functions asked for, one answer keyed by address."""

    ADDRESSES = [BASE + offset for offset in (0x1230, 0x2340, 0x3450, 0x4560, 0x5670)]

    def _entry(self) -> LedgerEntry:
        first, second, third, fourth, fifth = self.ADDRESSES
        answer = {
            hex(first): f"\nundefined8 FUN_{first:x}(void)\n\n{{\n  return 0;\n}}\n\n",
            hex(second): "Error: Function not found",
            hex(third): f"\nundefined8\nFUN_{third:x}(longlong p)\n\n{{\n  return 1;\n}}\n",
            hex(fourth): "\nint ReadSettings(char *path)\n\n{\n  return 2;\n}\n",
            hex(fifth): (
                f"\n/* a comment ( with a parenthesis */\nvoid FUN_{fifth:x}(void)\n{{\n}}\n"
            ),
        }
        return LedgerEntry(
            id="ev_0012",
            tool="batch_decompile",
            args={"functions": ",".join(hex(a) for a in self.ADDRESSES)},
            output=json.dumps(answer),
        )

    def test_every_function_it_answered_is_one_function_with_its_own_name(self) -> None:
        first, _second, third, fourth, fifth = self.ADDRESSES

        found = decompiled_functions([self._entry()])

        assert [(f.address, f.names, f.entries) for f in found] == [
            (first, (f"FUN_{first:x}",), ("ev_0012",)),
            (third, (f"FUN_{third:x}",), ("ev_0012",)),
            (fourth, ("ReadSettings",), ("ev_0012",)),
            (fifth, (f"FUN_{fifth:x}",), ("ev_0012",)),
        ]

    def test_an_answer_cut_short_keeps_what_it_shows(self) -> None:
        entry = self._entry()
        entry.output = entry.output[: entry.output.index("Error") + 40]
        first, second = self.ADDRESSES[:2]

        found = decompiled_functions([entry])

        assert [f.address for f in found] == [first]
        assert second not in [f.address for f in found]

    def test_an_answer_that_is_no_object_takes_the_addresses_it_was_given(self) -> None:
        entry = self._entry()
        entry.output = "listings follow"

        found = decompiled_functions([entry])

        assert [f.address for f in found] == self.ADDRESSES
        assert all(f.names == () for f in found)

    def test_keys_that_are_hex_words_are_no_batch(self) -> None:
        entry = LedgerEntry(
            id="ev_0014",
            tool="decompile_function",
            args={"address": hex(FIRST_FN)},
            output=json.dumps({"face": "int A(void)\n{\n}\n", "cafe": "x", "dead": "beef"}),
        )

        (found,) = decompiled_functions([entry])

        assert (found.address, found.names) == (FIRST_FN, ())

    def test_a_batch_keyed_by_bare_hex_addresses(self) -> None:
        first, second = self.ADDRESSES[:2]
        entry = LedgerEntry(
            id="ev_0013",
            tool="batch_decompile",
            args={"functions": [first, second]},
            output=json.dumps(
                {f"{first:x}": "int ReadSettings(void)\n{\n}\n", f"{second:x}": "Error: none"}
            ),
        )

        (found,) = decompiled_functions([entry])

        assert (found.address, found.names) == (first, ("ReadSettings",))


class TestAPlainListingIsOneFunction:
    """A listing whose text holds quoted strings is one function at its own address."""

    def _one(self, output: str, **args: Any) -> DecompiledFunction:
        entry = LedgerEntry(
            id="ev_0020",
            tool="decompile_function",
            args=args or {"address": hex(FIRST_FN)},
            output=output,
        )
        (found,) = decompiled_functions([entry])
        return found

    def test_string_literals_in_a_ternary(self) -> None:
        found = self._one(
            f'int FUN_{FIRST_FN:x}(int a)\n{{\n  printf(a ? "1" : "0");\n'
            '  puts(a ? "ab" : "cd");\n  return 0;\n}\n'
        )

        assert (found.address, found.names) == (FIRST_FN, (f"FUN_{FIRST_FN:x}",))

    def test_json_in_a_string_literal(self) -> None:
        found = self._one(
            "void ReportState(char *out)\n{\n"
            '  sprintf(out, "{\\"cd\\":\\"%s\\",\\"ab12\\":\\"%d\\"}", a, b);\n}\n'
        )

        assert (found.address, found.names) == (FIRST_FN, ("ReportState",))

    def test_a_json_answer_whose_keys_are_no_addresses(self) -> None:
        found = self._one(
            json.dumps({"ea": f"{FIRST_FN:x}", "f": "int helper(void)\n{\n}\n"}),
            ea=FIRST_FN,
        )

        assert found.address == FIRST_FN
        assert found.names == ()


class TestWhatAClaimNames:
    FUNCTIONS = [
        DecompiledFunction(address=FIRST_FN, names=(f"FUN_{FIRST_FN:x}",), entries=("ev_0003",)),
        DecompiledFunction(address=SECOND_FN, names=("InstallService",), entries=("ev_0004",)),
    ]

    def _left(self, *claims: ClaimEvidence, bases: tuple[int, ...] = ()) -> list[int | None]:
        isr = AgentISR(agent_id="reverser", domain="static", claims=list(claims))
        return [f.address for f in undescribed_decompiles(isr, self.FUNCTIONS, bases)]

    def test_an_offset_from_the_image_base_names_the_virtual_address(self) -> None:
        said = _claim(f"{FIRST_OFFSET:#x} exits when the event already exists.")
        assert self._left(said) == [SECOND_FN]
        assert self._left(said, bases=(BASE,)) == [SECOND_FN]

    def test_with_the_base_known_another_function_64_kib_away_does_not(self) -> None:
        said = _claim(f"{FIRST_FN + 0x10000:#x} is another routine.")
        assert self._left(said) == [SECOND_FN]
        assert self._left(said, bases=(BASE,)) == [FIRST_FN, SECOND_FN]

    def test_an_h_suffixed_and_a_bare_hex_address_name_it(self) -> None:
        assert self._left(_claim(f"{FIRST_OFFSET:X}h checks the event."), bases=(BASE,)) == [
            SECOND_FN
        ]
        assert self._left(_claim(f"{SECOND_FN:x} writes the copy."), bases=(BASE,)) == [FIRST_FN]

    def test_the_virtual_address_and_the_decompiler_s_name_both_name_it(self) -> None:
        assert (
            self._left(
                _claim(f"FUN_{FIRST_FN:x} checks the process count."),
                _claim("It registers a task.", f"[ev_0004] decompile of 0x{SECOND_FN:x}"),
            )
            == []
        )

    def test_a_given_name_names_it(self) -> None:
        assert self._left(_claim("InstallService writes the copy.")) == [FIRST_FN]

    def test_citing_the_entry_alone_does_not(self) -> None:
        assert self._left(_claim("The sample has update logic.", "[ev_0003], [ev_0004]")) == [
            FIRST_FN,
            SECOND_FN,
        ]

    def test_another_address_does_not(self) -> None:
        said = _claim(f"{FIRST_OFFSET + 1:#x} and {SECOND_OFFSET + 1:#x} are helpers.")
        assert self._left(said) == [FIRST_FN, SECOND_FN]

    def test_digits_alone_name_a_function_whose_hex_they_spell_exactly(self) -> None:
        assert f"{FIRST_FN:x}".isdigit()
        assert self._left(_claim(f"The routine at {FIRST_FN:x} checks the event.")) == [SECOND_FN]
        assert self._left(_claim(f"The routine at 00{FIRST_FN:x} checks it.")) == [SECOND_FN]
        assert self._left(_claim(f"The count is {FIRST_FN + 1:x} or {FIRST_OFFSET:x}.")) == [
            FIRST_FN,
            SECOND_FN,
        ]

    def _bases(self, output: str) -> tuple[int, ...]:
        return image_bases_in([LedgerEntry(id="ev_0001", tool="x", output=output)])

    def test_an_integer_base_is_the_integer(self) -> None:
        assert self._bases(json.dumps({"image_base": BASE})) == (BASE,)

    def test_a_base_written_in_hex_is_read_as_hex(self) -> None:
        assert self._bases(json.dumps({"image_base": hex(BASE)})) == (BASE,)
        assert self._bases(json.dumps({"image_base": f"{BASE:x}h"})) == (BASE,)
        lettered = 0x14AB0000
        assert self._bases(json.dumps({"image_base": f"{lettered:x}"})) == (lettered,)

    def test_a_string_of_decimal_digits_is_no_base(self) -> None:
        assert self._bases(json.dumps({"image_base": str(BASE)})) == ()
        assert self._bases(json.dumps({"image_base": f"{BASE:x}"})) == ()

    def test_a_base_off_a_64_kib_boundary_is_no_base(self) -> None:
        assert self._bases(json.dumps({"image_base": hex(BASE + 0x1000)})) == ()

    def test_the_image_base_is_read_off_the_run_s_entries(self) -> None:
        entries = [
            LedgerEntry(
                id="ev_0001",
                tool="resolve_api_hashes",
                output=json.dumps({"image_base": hex(BASE), "hits": []}),
            ),
            LedgerEntry(
                id="ev_0002",
                tool="get_current_program_info",
                output=json.dumps({"image_base": f"{BASE:x}"}),
            ),
            LedgerEntry(id="ev_0003", tool="strings", output="no base here"),
        ]
        assert image_bases_in(entries) == (BASE,)

    def test_every_agent_is_handed_the_base_the_pack_read(self) -> None:
        from maljan.pipeline.nodes import pack_image_bases

        state: Any = {
            "evidence_ledger": [
                LedgerEntry(
                    id="ev_0001",
                    agent="pipeline",
                    tool="decode_string_blobs",
                    output=json.dumps({"image_base": hex(BASE), "results": []}),
                ).model_dump(),
                LedgerEntry(
                    id="ev_0002",
                    agent="static",
                    tool="x",
                    output=json.dumps({"image_base": "0x10000000"}),
                ).model_dump(),
            ]
        }

        assert pack_image_bases(state) == (BASE,)


class TestTheQuestion:
    def test_it_lists_every_function_with_its_names_and_entries(self) -> None:
        violation = decompiled_not_described_violation(TestWhatAClaimNames.FUNCTIONS)

        assert violation is not None
        assert violation.code == DECOMPILED_NOT_DESCRIBED_CODE
        assert f"0x{FIRST_FN:x} (FUN_{FIRST_FN:x}; ev_0003)" in violation.message
        assert f"0x{SECOND_FN:x} (InstallService; ev_0004)" in violation.message
        assert violation.message.startswith("You decompiled 2 function(s) that no claim")
        assert "naming it by its address" in violation.message
        assert "?" not in violation.message

    def test_it_says_what_was_read_and_what_was_not(self) -> None:
        violation = decompiled_not_described_violation(TestWhatAClaimNames.FUNCTIONS)

        assert violation is not None
        assert (
            "that no claim of this answer names by a name the decompiler gave it, or by its "
            "address or its offset from the image base written in hex (with 0x, with a "
            "trailing h, as bare hex digits, or inside a name such as FUN_); an offset "
            "written in decimal digits alone is not read as one: "
        ) in violation.message

    def test_nothing_left_is_no_question(self) -> None:
        assert decompiled_not_described_violation([]) is None


FIRST = (
    "CLAIM 1: The sample has update logic.\n"
    "EVIDENCE: [ev_0003], [ev_0004]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
BOTH = FIRST + (
    f"CLAIM 2: 0x{FIRST_FN:x} returns -1 when the event already exists.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    f"CLAIM 3: 0x{SECOND_FN:x} passes a decoded name to the next routine.\n"
    "EVIDENCE: [ev_0004]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
ONE = FIRST + (
    f"CLAIM 2: {FIRST_OFFSET:#x} returns -1 when the event already exists.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str], entries: list[LedgerEntry]) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = list(entries)
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str = FIRST) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


ENTRIES = [_ghidra("ev_0003", FIRST_FN), _ghidra("ev_0004", SECOND_FN)]


class TestTheValidationTurn:
    def test_the_functions_are_listed_once_and_an_answer_describing_them_stands(self) -> None:
        analyst = _Analyst([BOTH], ENTRIES)

        result = _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert DECOMPILED_NOT_DESCRIBED_CODE in question
        assert f"0x{FIRST_FN:x}" in question and f"0x{SECOND_FN:x}" in question
        assert len(result.claims) == 3
        assert DECOMPILED_NOT_DESCRIBED_CODE not in [v.code for v in analyst.validation_findings]

    def test_a_function_the_kept_answer_still_does_not_name_is_the_report_s_line(self) -> None:
        analyst = _Analyst([ONE], ENTRIES)

        result = _check(analyst)

        assert len(result.claims) == 2
        (left,) = [
            v for v in analyst.validation_findings if v.code == DECOMPILED_NOT_DESCRIBED_CODE
        ]
        assert f"0x{SECOND_FN:x}" in left.message
        assert f"0x{FIRST_FN:x}" not in left.message

    def test_the_pack_s_image_base_decides_the_match(self) -> None:
        # A claim 64 KiB off the first function: with the base the pack read,
        # it is another function, and the first is still listed.
        off = FIRST + (
            f"CLAIM 2: {FIRST_FN + 0x10000:#x} is another routine.\n"
            "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
        )
        analyst = _Analyst([off], [_ghidra("ev_0003", FIRST_FN)])
        analyst.pack_image_bases = (BASE,)

        _check(analyst, off)

        (turns,) = analyst.seen_turns
        assert f"0x{FIRST_FN:x}" in str(turns[-1].content)

    def test_the_report_prints_the_line_naming_them(self) -> None:
        from maljan.pipeline.validation import validation_metrics
        from maljan.reporting.renderers.markdown import MarkdownRenderer
        from tests.unit.reporting._report_shapes import rich_report

        analyst = _Analyst([ONE], ENTRIES)
        _check(analyst)
        (left,) = [
            v for v in analyst.validation_findings if v.code == DECOMPILED_NOT_DESCRIBED_CODE
        ]
        report = rich_report()
        report.run_summary["validation"]["unresolved"].extend(
            validation_metrics(1, [("reverser", left)])["unresolved"]
        )

        markdown = MarkdownRenderer().render(report)

        (line,) = [text for text in markdown.splitlines() if DECOMPILED_NOT_DESCRIBED_CODE in text]
        assert "(reverser)" in line
        assert f"0x{SECOND_FN:x} (FUN_{SECOND_FN:x}; ev_0004)" in line

    def test_an_analyst_that_decompiled_nothing_is_not_asked(self) -> None:
        analyst = _Analyst([], [])

        _check(analyst)

        assert analyst.seen_turns == []

    def test_an_answer_that_names_every_function_is_not_asked(self) -> None:
        analyst = _Analyst([], ENTRIES)

        _check(analyst, BOTH)

        assert analyst.seen_turns == []
