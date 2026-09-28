"""A function the analyst decompiled and no claim describes is listed to it, once.

A reverser decompiled the start-up path and the installer of a loader, held
both in its own ledger, and wrote claims about neither. The functions an
analyst's own ledger entries decompiled are read off those entries (the
address the call was given, the name the decompiler printed), and a claim
describes one when its sentence or its evidence line names the function by
its address, as an offset from the image base or as a virtual address, or by
a name the decompiler gave it. The functions no claim names are listed in one
question, asked once; what the analyst answers stands, and the functions its
kept answer still names in no claim are recorded as a finding the report
prints.

Every address and name is synthetic.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import (
    DECOMPILED_NOT_DESCRIBED_CODE,
    DecompiledFunction,
    decompiled_functions,
    decompiled_not_described_violation,
    undescribed_decompiles,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

START_UP = 0x140003868
INSTALLER = 0x1400033AC


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
            [_r2("ev_0003", START_UP), _ghidra("ev_0004", INSTALLER, "InstallService")]
        )

        assert [(f.address, f.names, f.entries) for f in found] == [
            (START_UP, (f"fcn.{START_UP:x}",), ("ev_0003",)),
            (INSTALLER, ("InstallService",), ("ev_0004",)),
        ]

    def test_a_failed_call_and_another_tool_are_not_decompiles(self) -> None:
        failed = _ghidra("ev_0005", START_UP)
        failed.ok = False
        listing = LedgerEntry(id="ev_0006", tool="list_functions", args={}, output="x")

        assert decompiled_functions([failed, listing]) == []

    def test_one_function_decompiled_twice_is_one_function(self) -> None:
        found = decompiled_functions([_r2("ev_0003", START_UP), _ghidra("ev_0007", START_UP)])

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


class TestWhatAClaimNames:
    FUNCTIONS = [
        DecompiledFunction(address=START_UP, names=(f"FUN_{START_UP:x}",), entries=("ev_0003",)),
        DecompiledFunction(address=INSTALLER, names=("InstallService",), entries=("ev_0004",)),
    ]

    def _left(self, *claims: ClaimEvidence) -> list[int | None]:
        isr = AgentISR(agent_id="reverser", domain="static", claims=list(claims))
        return [f.address for f in undescribed_decompiles(isr, self.FUNCTIONS)]

    def test_an_offset_from_the_image_base_names_the_virtual_address(self) -> None:
        assert self._left(_claim("0x3868 exits when the mutex exists.")) == [INSTALLER]

    def test_the_virtual_address_and_the_decompiler_s_name_both_name_it(self) -> None:
        assert (
            self._left(
                _claim(f"FUN_{START_UP:x} checks the process count."),
                _claim("It registers a task.", f"[ev_0004] decompile of 0x{INSTALLER:x}"),
            )
            == []
        )

    def test_a_given_name_names_it(self) -> None:
        assert self._left(_claim("InstallService writes the copy.")) == [START_UP]

    def test_citing_the_entry_alone_does_not(self) -> None:
        assert self._left(
            _claim("The sample has update capabilities.", "[ev_0003], [ev_0004]")
        ) == [
            START_UP,
            INSTALLER,
        ]

    def test_another_address_does_not(self) -> None:
        assert self._left(_claim("0x3869 and 0x33a0 are helpers.")) == [START_UP, INSTALLER]


class TestTheQuestion:
    def test_it_lists_every_function_with_its_names_and_entries(self) -> None:
        violation = decompiled_not_described_violation(TestWhatAClaimNames.FUNCTIONS)

        assert violation is not None
        assert violation.code == DECOMPILED_NOT_DESCRIBED_CODE
        assert f"0x{START_UP:x} (FUN_{START_UP:x}; ev_0003)" in violation.message
        assert f"0x{INSTALLER:x} (InstallService; ev_0004)" in violation.message
        assert violation.message.startswith("You decompiled 2 function(s) that no claim")
        assert "naming it by its address" in violation.message
        assert "?" not in violation.message

    def test_nothing_left_is_no_question(self) -> None:
        assert decompiled_not_described_violation([]) is None


FIRST = (
    "CLAIM 1: The sample has update capabilities.\n"
    "EVIDENCE: [ev_0003], [ev_0004]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
BOTH = FIRST + (
    f"CLAIM 2: 0x{START_UP:x} returns -1 when the mutex already exists.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    f"CLAIM 3: 0x{INSTALLER:x} passes the decoded task name to the task routine.\n"
    "EVIDENCE: [ev_0004]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
ONE = FIRST + (
    "CLAIM 2: 0x3868 returns -1 when the mutex already exists.\n"
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


ENTRIES = [_ghidra("ev_0003", START_UP), _ghidra("ev_0004", INSTALLER)]


class TestTheValidationTurn:
    def test_the_functions_are_listed_once_and_an_answer_describing_them_stands(self) -> None:
        analyst = _Analyst([BOTH], ENTRIES)

        result = _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert DECOMPILED_NOT_DESCRIBED_CODE in question
        assert f"0x{START_UP:x}" in question and f"0x{INSTALLER:x}" in question
        assert len(result.claims) == 3
        assert DECOMPILED_NOT_DESCRIBED_CODE not in [v.code for v in analyst.validation_findings]

    def test_a_function_the_kept_answer_still_does_not_name_is_the_report_s_line(self) -> None:
        analyst = _Analyst([ONE], ENTRIES)

        result = _check(analyst)

        assert len(result.claims) == 2
        (left,) = [
            v for v in analyst.validation_findings if v.code == DECOMPILED_NOT_DESCRIBED_CODE
        ]
        assert f"0x{INSTALLER:x}" in left.message
        assert f"0x{START_UP:x}" not in left.message

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
        assert f"0x{INSTALLER:x} (FUN_{INSTALLER:x}; ev_0004)" in line

    def test_an_analyst_that_decompiled_nothing_is_not_asked(self) -> None:
        analyst = _Analyst([], [])

        _check(analyst)

        assert analyst.seen_turns == []

    def test_an_answer_that_names_every_function_is_not_asked(self) -> None:
        analyst = _Analyst([], ENTRIES)

        _check(analyst, BOTH)

        assert analyst.seen_turns == []
