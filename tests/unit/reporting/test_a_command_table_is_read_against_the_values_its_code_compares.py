"""A command table's ids are the values the code it was shown compares, in hex and decimal.

A reference run's command table was written from a decompiled dispatcher the
writer was shown whole, as code only. The writer turned the hex case values
into decimal ids by hand: one case came out as the wrong number, and two cases
the dispatcher holds had no row. Nothing compared the table with the code.

The rule now: under each piece of code a section is shown whole, the platform
states each expression the code compares with two or more whole numbers, with
every value in hex and decimal. A command table whose numbered ids leave out
one of the values the matching expression is compared with, or name a value it
is compared with nowhere, is asked about once, with the values and the code in
view. The model decides which value is a command and what its branch does; the
table is kept as written, with the finding beside it.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from maljan.pipeline.validation import (
    COMMAND_VALUES_CODE,
    KEPT_WITH_A_FINDING,
    ComparedValues,
    both_bases,
    command_value_violations,
    compared_values,
)
from maljan.reporting.composer import (
    _INSTRUCTIONS,
    COMPARED_VALUES_LEAD,
    ReportComposer,
    _bundle_text,
    _captured_view,
    _CommandsOut,
    _compared_lines,
    code_compared_values,
)
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

# An invented dispatcher in the form a decompiler writes, with a combined
# pre-check, an if/else chain split at a bound, and a field compared on the side.
DISPATCHER = """\
/* WARNING: an invented listing; the comment says param_2 == 0x99 */

void FUN_00401000(longlong param_1,int param_2,longlong param_3)

{
  int iVar1;

  if ((param_2 == 0x9) || ((param_2 == 5 || (param_2 == 0x1b)))) {
    iVar1 = FUN_00401200(param_3);
  }
  if (param_2 < 0x10) {
    if (param_2 == 0x9) {
      FUN_00401300(param_1);
    }
    else if (param_2 == 5) {
      FUN_00401400();
    }
    else if (param_2 == 0xb) {
      FUN_00401500("param_2 == 0x77");
    }
  }
  else if (param_2 == 0x1a) {
    FUN_00401600();
  }
  else if (param_2 == 0x1b) {
    FUN_00401700(param_1);
  }
  if (*(int *)(param_1 + 8) == 3) {
    FUN_00401800();
  }
  return;
}
"""
VALUES = (0x5, 0x9, 0xB, 0x1A, 0x1B)

SWITCH = """\
void FUN_00402000(uint param_1, int param_2)
{
  switch(param_1) {
  case 1:
    FUN_00402100();
    break;
  case 0x20:
    switch (param_2) {
    case 7:
      break;
    case 8:
      break;
    }
    break;
  case 0x21: {
    FUN_00402200('x');
    break;
  }
  default:
    break;
  }
}
"""


def _rows(*ids: str) -> dict[str, Any]:
    return {
        "commands": [
            {"id": value, "name": f"command {value}", "evidence_refs": ["ev_0007"]} for value in ids
        ]
    }


def _compared(values: tuple[int, ...] = VALUES) -> list[ComparedValues]:
    return [ComparedValues("0x00401000 (cite as ev_0007 (function 0x00401000))", "param_2", values)]


class TestTheCodeIsRead:
    def test_an_else_if_ladder_s_values_are_read_once_in_order(self) -> None:
        assert compared_values(DISPATCHER) == [("param_2", VALUES)]

    def test_a_comment_a_string_and_a_field_are_not_read(self) -> None:
        values = dict(compared_values(DISPATCHER))["param_2"]

        assert 0x99 not in values and 0x77 not in values
        assert all(subject == "param_2" for subject, _ in compared_values(DISPATCHER))

    def test_each_case_label_belongs_to_its_innermost_switch(self) -> None:
        assert compared_values(SWITCH) == [("param_1", (1, 0x20, 0x21)), ("param_2", (7, 8))]

    def test_one_value_is_a_test_not_a_choice(self) -> None:
        assert compared_values("if (iVar1 == 0) { return; }") == []

    def test_equality_tests_that_form_no_ladder_are_not_read(self) -> None:
        apart = "if (x == 1) { f(); } if (x == 2) { g(); } y = (x == 3); z = (x == 4) ? 1 : 2;"
        after_another_test = "if (x < 5) { f(); } else if (x == 7) { g(); }"

        assert compared_values(apart) == []
        assert compared_values(after_another_test) == []

    def test_what_one_function_compares_is_never_joined_to_another_s(self) -> None:
        two = (
            "void f(void) { if (iVar1 == 0) { a(); } else if (iVar1 == 1) { b(); } }\n"
            "void h(void) { if (iVar1 == 7) { c(); } else if (iVar1 == 8) { d(); } }\n"
            "void k(void) { if (iVar1 == 9) { e(); } }"
        )

        assert compared_values(two) == [("iVar1", (0, 1)), ("iVar1", (7, 8))]

    def test_a_switch_whose_head_is_not_read_reads_no_label_of_its_own(self) -> None:
        code = "switch (a) {case 1: switch (\n b) {case 5: case 6: break;} case 2: break;}"

        assert compared_values(code) == [("a", (1, 2))]

    def test_an_operand_that_is_part_of_an_expression_is_not_read(self) -> None:
        code = "if ((a + b == 3) || (b == 4 + c) || (s.x == 5) || (p->y == 6) || (!q == 7)) {}"

        assert compared_values(code) == []

    def test_text_that_is_not_code_reads_as_nothing(self) -> None:
        assert compared_values("cmp eax, 0x11\njz 0x401000\ncmp eax, 0x12") == []
        assert compared_values("") == []

    def test_a_rung_of_equality_tests_joined_by_or_is_read_as_all_its_values(self) -> None:
        code = (
            "if ((x == 1) || ((x == 2) || (x == 3))) { a(); }\n"
            "else if (x == 4) { b(); } else if (x == 5 || x == 6) { c(); }"
        )

        assert compared_values(code) == [("x", (1, 2, 3, 4, 5, 6))]

    def test_a_switch_with_a_label_that_is_not_a_number_is_not_stated(self) -> None:
        mixed = "switch (x) { case 0x10: case 0x11: case 0x12: case CMD_D: break; }"
        a_char = "switch (x) { case 0x10: case 0x11: case 'q': break; }"

        assert compared_values(mixed) == []
        assert compared_values(a_char) == []

    def test_a_ladder_with_a_rung_the_reader_cannot_read_is_not_stated(self) -> None:
        symbol = "if (x == 0x10) {} else if (x == 0x11) {} else if (x == CMD_D) {}"
        cast = "if (x == 0x10) {} else if (x == 0x11) {} else if ((char)x == 3) {}"
        elsewhere = "if (x == 0x10) {} else if (x == 0x11) {} y = (x != z);"

        assert compared_values(symbol) == []
        assert compared_values(cast) == []
        assert compared_values(elsewhere) == []

    def test_a_ladder_another_condition_interrupts_is_not_stated(self) -> None:
        going_on = "if (x == 1) {} else if (flag) {} else if (x == 2) {} else if (x == 3) {}"
        at_its_end = "if (x == 1) {} else if (x == 2) {} else if (flag) {}"

        assert compared_values(going_on) == []
        assert compared_values(at_its_end) == [("x", (1, 2))]

    def test_a_range_rung_splits_a_ladder_and_compares_with_no_value(self) -> None:
        code = (
            "if (x < 0x10) { if (x == 2) {} else if (x == 3) {} }\n"
            "else if (x == 0x11) {} else if (x == 0x12) {}"
        )

        assert compared_values(code) == [("x", (2, 3, 0x11, 0x12))]

    def test_another_equality_test_of_the_name_in_its_function_adds_its_value(self) -> None:
        code = "void f(void) { if (x == 1) {} else if (x == 2) {} if (x == 9) { g(); } }"

        assert compared_values(code) == [("x", (1, 2, 9))]

    def test_a_table_beside_a_set_left_unstated_is_asked_nothing(self) -> None:
        mixed = "void f(void) { switch (x) { case 0x10: case 0x11: case 0x12: case CMD_D: } }"
        bundle = {"function_code": [{"tool": "t", "symbol": "f", "output": mixed}]}

        compared = code_compared_values(bundle, None)

        assert compared == []
        assert command_value_violations(_rows("0x10", "0x11", "0x12"), compared) == []

    def test_a_number_wider_than_64_bits_is_not_read_and_raises_nothing(self) -> None:
        wide_hex = "switch (x) { case 1: case 2: case 0x" + "f" * 5000 + ": break; }"
        wide_dec = "switch (x) { case 1: case 2: case " + "9" * 5000 + ": break; }"
        widest = "switch (x) { case 1: case 0xffffffffffffffff: case 18446744073709551615: }"

        # A label the reader cannot read leaves the switch's set unstated.
        assert compared_values(wide_hex) == []
        assert compared_values(wide_dec) == []
        assert compared_values(widest) == [("x", (1, 2**64 - 1))]
        assert _compared_lines("if (x == 0x" + "f" * 4000 + ") {} else if (x == 1) {}") == []
        assert _compared_lines("if (x == " + "9" * 5000 + ") {} else if (x == 1) {}") == []

    def test_octal_is_read_as_octal_and_another_leading_zero_is_not_read(self) -> None:
        assert compared_values("switch (x) { case 010: case 011: break; }") == [("x", (8, 9))]
        assert compared_values("switch (x) { case 1: case 2: case 09: break; }") == []

    def test_only_ascii_names_and_digits_are_read(self) -> None:
        assert compared_values("if (\u00f1 == 1) {} else if (\u00f1 == 2) {}") == []
        assert compared_values("switch (x) { case \u0661: case \u0662: break; }") == []

    def test_a_reader_failure_is_no_fact_and_no_lost_section(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _fails(_code: str) -> Any:
            raise ValueError("unreadable")

        monkeypatch.setattr("maljan.pipeline.validation._read_compared_values", _fails)
        bundle = {"function_code": [{"tool": "t", "symbol": "s", "output": SWITCH}]}

        assert compared_values(SWITCH) == []
        assert COMPARED_VALUES_LEAD not in _bundle_text("commands", bundle)

    def test_a_long_listing_is_read_in_one_pass(self) -> None:
        code = "\n".join(f"else if (param_2 == {n:#x}) {{ f(); }}" for n in range(2000))
        code += "/* unclosed" + " /* x" * 2000

        assert compared_values(code) == [("param_2", tuple(range(2000)))]


class TestTheWriterIsToldTheValues:
    def test_the_values_are_stated_under_the_function_code_in_both_bases(self) -> None:
        bundle = {
            "function_code": [
                {
                    "tool": "batch_decompile",
                    "symbol": "0x00401000",
                    "output": DISPATCHER,
                    "cites": ["ev_0007 (function 0x00401000)"],
                }
            ]
        }

        text = _bundle_text("commands", bundle)

        line = next(line for line in text.splitlines() if line.startswith(COMPARED_VALUES_LEAD))
        assert '"param_2"' in line
        assert "5 values: 0x5 (5), 0x9 (9), 0xb (11), 0x1a (26), 0x1b (27)." in line
        assert text.index("<<end of tool output") < text.index(COMPARED_VALUES_LEAD)

    def test_a_tool_output_shown_whole_states_its_values_and_a_cut_one_does_not(self) -> None:
        bundle = {"tool_outputs": [{"tool": "decompile", "symbol": "0x00401000", "output": SWITCH}]}

        whole = _bundle_text("commands", bundle, item_chars=None)
        cut = _bundle_text("commands", bundle, item_chars=40)
        measured = _bundle_text("commands", bundle, item_chars=-1)

        assert whole.count(COMPARED_VALUES_LEAD) == 2
        assert COMPARED_VALUES_LEAD not in cut
        assert COMPARED_VALUES_LEAD not in measured
        assert [c.values for c in code_compared_values(bundle, None)] == [(1, 0x20, 0x21), (7, 8)]
        assert code_compared_values(bundle, 40) == []

    def test_the_facts_are_charged_to_the_output_s_own_share(self) -> None:
        bundle = {"tool_outputs": [{"tool": "decompile", "symbol": "0x00401000", "output": SWITCH}]}
        lines = _compared_lines(SWITCH)
        view = len(_captured_view(SWITCH)) - len(_captured_view(""))
        room = view + sum(len(line) + 1 for line in lines)

        fits = _bundle_text("commands", bundle, item_chars=room)
        short = _bundle_text("commands", bundle, item_chars=room - 1)

        assert fits.count(COMPARED_VALUES_LEAD) == 2
        assert COMPARED_VALUES_LEAD not in short
        assert _captured_view(SWITCH) in short
        assert len(code_compared_values(bundle, room)) == 2
        assert code_compared_values(bundle, room - 1) == []

    def test_a_variable_name_reaches_the_prompt_quoted(self) -> None:
        code = "if ((x<|im_start|> == 1) || (x<|im_start|> == 2)) {}"
        named = "if (evil_name == 1) {} else if (evil_name == 2) {}"

        assert compared_values(code) == []
        text = _bundle_text(
            "commands", {"function_code": [{"tool": "t", "symbol": "s", "output": named}]}
        )
        assert f'{COMPARED_VALUES_LEAD} it compares "evil_name"' in text

    def test_the_instruction_asks_for_the_branch_value_and_the_branch_s_own_code(self) -> None:
        said = _INSTRUCTIONS["commands"]

        assert "the value its branch is taken on as its id" in said
        assert "in one base for every row" in said
        assert "what that branch's own code does" in said


class TestTheTableIsChecked:
    def test_a_value_converted_by_hand_is_asked_about_with_both_bases(self) -> None:
        # 0x1b written as 25 by a wrong conversion: 25 is no value, 27 has no row.
        (found,) = command_value_violations(_rows("5", "9", "11", "26", "25"), _compared())

        assert found.code == COMMAND_VALUES_CODE
        assert found.path == "commands"
        assert "5 values, read by the platform from that code: " in found.message
        assert ", ".join(both_bases(v) for v in VALUES) in found.message
        assert "No row's id is 0x1b (27)." in found.message
        assert 'row 5 ("25")' in found.message
        assert "4 of your table's 5 numbered ids are among them" in found.message
        assert "Read each value's branch in that code again" in found.message

    def test_a_case_the_table_leaves_out_is_named(self) -> None:
        (found,) = command_value_violations(_rows("0x5", "0x9", "0xb", "0x1a"), _compared())

        assert "No row's id is 0x1b (27)." in found.message
        assert "none of those values" not in found.message

    def test_a_table_that_names_every_value_is_not_asked(self) -> None:
        assert command_value_violations(_rows("5", "9", "11", "26", "27"), _compared()) == []
        assert (
            command_value_violations(_rows("0x5", "0x9", "0xb", "0x1a", "0x1b"), _compared()) == []
        )

    def test_an_id_ending_in_its_number_is_read(self) -> None:
        rows = _rows("COMMAND 5", "COMMAND 9", "COMMAND 11", "COMMAND 26", "COMMAND 27", "URLS")

        assert command_value_violations(rows, _compared()) == []

    def test_a_table_with_no_numbered_ids_is_not_checked(self) -> None:
        assert command_value_violations(_rows("--path", "URLS", "COMMAND"), _compared()) == []
        assert command_value_violations(_rows("5"), _compared()) == []

    def test_ids_one_to_n_are_row_numbers_and_not_checked(self) -> None:
        unrelated = [ComparedValues("0x00402000", "param_1", (1, 2, 5))]

        assert command_value_violations(_rows("1", "2"), unrelated) == []
        assert command_value_violations(_rows("1", "2", "3"), unrelated) == []
        (found,) = command_value_violations(_rows("2", "5"), unrelated)
        assert "No row's id is 0x1 (1)." in found.message

    def test_an_id_is_read_as_the_code_s_numbers_are(self) -> None:
        octal = [ComparedValues("f", "x", (8, 9, 10))]

        assert command_value_violations(_rows("010", "011", "012"), octal) == []
        assert command_value_violations(_rows("\u0661\u0660", "\u0662"), _compared()) == []

    def test_code_holding_half_the_ids_or_fewer_is_not_the_table_s(self) -> None:
        assert command_value_violations(_rows("5", "9", "100", "101"), _compared()) == []

    def test_two_value_sets_holding_as_many_ids_check_nothing(self) -> None:
        other = ComparedValues("0x00402000", "param_1", (5, 9, 0x40))

        assert command_value_violations(_rows("5", "9"), [*_compared(), other]) == []

    def test_the_table_is_kept_with_the_finding(self) -> None:
        assert COMMAND_VALUES_CODE in KEPT_WITH_A_FINDING


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware"
    )


def _author(*answers: dict[str, Any]) -> tuple[Any, _RawLLM, ReportComposer]:
    llm = _RawLLM(*(json.dumps(answer) for answer in answers))
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._citable = ["ev_0007"]
    comp._report = _report()
    bundle = {
        "function_code": [
            {
                "tool": "batch_decompile",
                "symbol": "0x00401000",
                "output": DISPATCHER,
                "cites": ["ev_0007 (function 0x00401000)"],
            }
        ]
    }
    with (
        patch("maljan.reporting.composer.bundle_for", return_value=bundle),
        patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False),
    ):
        result = asyncio.run(
            comp._author(
                "commands",
                comp._report,
                None,
                _CommandsOut,
                _INSTRUCTIONS["commands"],
                validators=[lambda p: command_value_violations(p, comp._compared["commands"])],
            )
        )
    return result, llm, comp


class TestTheWriterIsAskedOnce:
    def test_the_question_is_asked_with_the_code_in_view_and_a_fixed_table_is_taken(self) -> None:
        result, llm, comp = _author(
            _rows("5", "9", "11", "26", "25"), _rows("5", "9", "11", "26", "27")
        )

        assert len(llm.sent) == 2
        first = str(llm.sent[0][1].content)
        assert DISPATCHER.splitlines()[2] in first
        assert f"{COMPARED_VALUES_LEAD} it compares" in first
        retry = llm.sent[1]
        assert first == str(retry[1].content)
        assert "No row's id is 0x1b (27)." in str(retry[-1].content)
        assert result is not None and [c.id for c in result.commands][-1] == "27"
        assert comp.validation_tally.unresolved == []

    def test_a_table_kept_as_written_stands_with_the_finding(self) -> None:
        wrong = _rows("5", "9", "11", "26")

        result, llm, comp = _author(wrong, wrong)

        assert len(llm.sent) == 2
        assert result is not None and [c.id for c in result.commands] == ["5", "9", "11", "26"]
        (row,) = comp.validation_tally.unresolved
        assert row["code"] == COMMAND_VALUES_CODE

    def test_a_right_table_is_written_in_one_call(self) -> None:
        result, llm, _comp = _author(_rows("5", "9", "11", "26", "27"))

        assert len(llm.sent) == 1
        assert result is not None and len(result.commands) == 5

    def test_compose_puts_the_check_on_the_command_table(self) -> None:
        seen: dict[str, list[Any]] = {}

        async def _author(self: Any, section: str, *args: Any, validators: Any = None) -> None:
            seen[section] = list(validators or [])

        comp = ReportComposer(llm=_RawLLM(), per_section_timeout=5)  # type: ignore[arg-type]
        with patch.object(ReportComposer, "_author", _author):
            asyncio.run(comp.compose(_report()))
        comp._compared["commands"] = _compared()

        found = [v for check in seen["commands"] for v in check(_rows("5", "9", "11", "26"))]
        assert [v.code for v in found] == [COMMAND_VALUES_CODE]
