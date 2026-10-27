"""A failed static call given an address outside the loaded image is told the image's range.

A reversing model dropped a hex digit and asked Ghidra's ``read_memory`` for
``0x1360bcfa00``, below the image start ``0x1360bc00000``; the answer said only
"Unable to read bytes", and it could not correct itself. The range comes from
facts the run holds (the server's program statement, else the pack's image
base and size) and the call is read by its tool's declared ``address``
argument, never by its name. An address inside the image, a call that
answered, and a run that holds no range are left exactly as they were.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.agents.image_range import (
    ImageRange,
    ImageRangeReader,
    image_range_of,
    out_of_image_note,
)
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.agents.tool_pinning import declared_facts_of
from maljan.core.token_ledger import TokenLedger
from maljan.schemas.evidence import EvidenceCounter, build_entry
from maljan.tools.errors import tool_error

REPORT = "CLAIM: it reads memory\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"

PROGRAM = "6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef.exe"
# The run's own program statement (haiku5, ev_0056), cut to the fields read here.
PROGRAM_INFO = {
    "name": PROGRAM,
    "image_base": "1360bc00000",
    "min_address": "ff00000000",
    "max_address": "1360bc131ff",
}
GHIDRA_FAILURE = {"error": "Failed to read memory: Unable to read bytes at ram:1360bcfa00"}
NOTE = (
    "address 0x1360bcfa00 is outside the image 0x1360bc00000–0x1360bc131ff "
    "(did a digit drop? in-image addresses here have 11 hex digits); "
    "pass an address inside the image"
)


def _entry(tool: str, source: str, output: Any, **extra: Any) -> Any:
    return build_entry(
        entry_id=extra.pop("entry_id", "ev_0001"),
        seq=1,
        agent="a",
        tool=tool,
        args=extra.pop("args", {}),
        server=extra.pop("server", None),
        source=source,
        output=output if isinstance(output, str) else json.dumps(output),
        **extra,
    )


def _program_info() -> Any:
    return _entry("get_current_program_info", "provider:ghidra", PROGRAM_INFO)


def _pack() -> list[Any]:
    """The pack's answers that state the image (haiku5, ev_0004 and ev_0024), cut."""
    sections = [
        {"name": ".text", "virtual_address": "0x00001000", "virtual_size": 50176},
        {"name": ".reloc", "virtual_address": "0x00013000", "virtual_size": 512},
    ]
    return [
        _entry("pe_info", "pack", {"sections": sections}, server="pipeline", entry_id="ev_0004"),
        _entry(
            "function_index",
            "pack",
            {"tool": "function_index", "image_base": "0x1360bc00000", "rows": []},
            server="pipeline",
            entry_id="ev_0024",
        ),
    ]


def _tool(name: str, answer: Any, source: str = "provider:ghidra") -> Any:
    def _answer(address: str = "", length: int = 0, program: str | None = None) -> str:
        if isinstance(answer, BaseException):
            raise answer
        return answer if isinstance(answer, str) else json.dumps(answer)

    built = StructuredTool.from_function(func=_answer, name=name, description="d")
    (stamped,) = stamp_source([built], PROVIDER_FAMILY, declared=source)
    return stamped


def _call(tool: Any, args: dict[str, Any], image: ImageRange | None) -> tuple[str, Any]:
    recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
    (recorded,) = record_tools([tool], recorder, image_range=lambda: image)
    text = recorded.invoke(args)
    return text, recorder.entries[-1]


def _plain(tool: Any, args: dict[str, Any]) -> tuple[str, Any]:
    recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
    (recorded,) = record_tools([tool], recorder)
    return recorded.invoke(args), recorder.entries[-1]


# -- the range, from facts the run holds ---------------------------------------------


def test_the_range_is_the_program_statements_image_base_to_its_last_address() -> None:
    assert image_range_of([], [_program_info()]) == ImageRange(
        0x1360BC00000, 0x1360BC131FF, PROGRAM
    )


def test_with_no_program_statement_the_range_is_the_packs_base_and_last_section() -> None:
    assert image_range_of(_pack()) == ImageRange(0x1360BC00000, 0x1360BC131FF)


def test_a_stated_image_size_is_read_as_the_extent() -> None:
    pack = [
        _entry("x", "mcp:other", {"image_base": "0x400000", "size_of_image": "0x5000"}),
    ]
    assert image_range_of(pack) == ImageRange(0x400000, 0x404FFF)


def test_no_range_without_a_base_an_extent_or_with_two_bases() -> None:
    assert image_range_of([]) is None
    assert image_range_of(_pack()[:1]) is None
    assert image_range_of(_pack()[1:]) is None
    other = _entry("y", "mcp:other", {"image_base": "0x400000"}, entry_id="ev_0009")
    assert image_range_of([*_pack(), other]) is None


def test_a_failed_program_statement_states_no_range() -> None:
    failed = _entry("get_current_program_info", "provider:ghidra", {"error": "no program"})
    assert image_range_of([], [failed]) is None


# -- the failed call is told ----------------------------------------------------------


def test_a_failed_read_below_the_image_is_told_the_range_and_the_dropped_digit() -> None:
    image = image_range_of([], [_program_info()])
    text, entry = _call(
        _tool("read_memory", GHIDRA_FAILURE), {"address": "0x1360bcfa00", "length": 32}, image
    )
    assert not entry.ok
    assert entry.remediation == NOTE
    assert text.count(NOTE) == 1
    assert f"[platform] {NOTE}" in text
    # The server's own words stay as they were, in the entry and the answer.
    assert entry.error == GHIDRA_FAILURE["error"]
    assert "Unable to read bytes at ram:1360bcfa00" in text


def test_the_packs_range_serves_a_server_that_states_no_program() -> None:
    _text, entry = _call(
        _tool("read_memory", GHIDRA_FAILURE), {"address": "0x1360bcfac0"}, image_range_of(_pack())
    )
    assert entry.remediation is not None
    assert entry.remediation.startswith("address 0x1360bcfac0 is outside the image")


def test_the_note_follows_the_servers_own_remediation() -> None:
    # The server's words keep the headline (the console's summary of a failure).
    failure = tool_error("tool_failed", "Invalid address", remediation="check the address")
    image = ImageRange(0x400000, 0x404FFF)
    _text, entry = _call(_tool("disassemble", failure, "provider:r2"), {"address": "0x40"}, image)
    assert entry.remediation == (
        "check the address; address 0x40 is outside the image 0x400000–0x404fff (did a digit "
        "drop? in-image addresses here have 6 hex digits); pass an address inside the image"
    )


def test_digits_alone_that_read_as_decimal_inside_the_image_are_told_nothing() -> None:
    facts = declared_facts_of(_tool("read_memory", ""))
    image = ImageRange(0x400000, 0x404FFF)
    # 4198400 is 0x401000: inside the image read as decimal, outside read as hex.
    assert out_of_image_note(facts, {"address": "4198400"}, image) == ""
    # Read as decimal it is outside too: told, as hex.
    assert out_of_image_note(facts, {"address": "1234"}, image).startswith("address 0x1234 is")


@pytest.mark.parametrize("value", ["fade", "beef", "dead", "  cafe  ", "main"])
def test_a_string_of_letters_alone_is_a_name_never_an_address(value: str) -> None:
    facts = declared_facts_of(_tool("read_memory", ""))
    assert out_of_image_note(facts, {"address": value}, ImageRange(0x400000, 0x404FFF)) == ""


@pytest.mark.parametrize("value", ["0xfade", "fade1", "0x0fade"])
def test_a_string_with_0x_or_a_digit_is_read_as_hex(value: str) -> None:
    facts = declared_facts_of(_tool("read_memory", ""))
    assert out_of_image_note(facts, {"address": value}, ImageRange(0x400000, 0x404FFF))


def test_an_address_with_an_extra_digit_is_asked_about_it() -> None:
    note = out_of_image_note(
        declared_facts_of(_tool("read_memory", "")),
        {"address": "0x4000000"},
        ImageRange(0x400000, 0x404FFF),
    )
    assert "(is a digit extra? in-image addresses here have 6 hex digits)" in note


def test_an_address_with_as_many_digits_is_told_the_range_alone() -> None:
    note = out_of_image_note(
        declared_facts_of(_tool("read_memory", "")),
        {"address": "0x500000"},
        ImageRange(0x400000, 0x404FFF),
    )
    assert note == (
        "address 0x500000 is outside the image 0x400000–0x404fff; pass an address inside the image"
    )


def test_a_raised_call_outside_the_image_is_told_too() -> None:
    image = ImageRange(0x400000, 0x404FFF)
    text, entry = _call(
        _tool("read_memory", RuntimeError("cannot read")), {"address": "0x4000"}, image
    )
    assert not entry.ok
    assert entry.remediation is not None and entry.remediation.startswith("address 0x4000 is")
    assert "[platform] address 0x4000 is outside the image" in text


# -- and nothing else changes ---------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "args"),
    [
        # Inside the image: failed as on dev.
        (GHIDRA_FAILURE, {"address": "0x1360bc0fa00"}),
        # Answered: a server that maps more than the image keeps its answer.
        ("00 01 02", {"address": "0xff00000010"}),
        # Not a number: a name the server resolves itself.
        (GHIDRA_FAILURE, {"address": "FUN_1360bc0fa00"}),
        # Another program than the one the range was read for.
        (GHIDRA_FAILURE, {"address": "0x1360bcfa00", "program": "carved.bin"}),
    ],
)
def test_a_call_the_range_does_not_concern_is_as_on_dev(answer: Any, args: dict[str, Any]) -> None:
    image = image_range_of([], [_program_info()])
    text, entry = _call(_tool("read_memory", answer), args, image)
    plain_text, plain_entry = _plain(_tool("read_memory", answer), args)
    assert text == plain_text
    assert entry.remediation == plain_entry.remediation
    assert entry.ok == plain_entry.ok


def test_the_program_the_range_was_read_for_is_still_told() -> None:
    image = image_range_of([], [_program_info()])
    _text, entry = _call(
        _tool("read_memory", GHIDRA_FAILURE),
        {"address": "0x1360bcfa00", "program": f"/{PROGRAM}"},
        image,
    )
    assert entry.remediation == NOTE


def _naming(program: str) -> Any:
    """A call of the agent's own that named ``program`` by its declared argument."""
    return _entry(
        "decompile_function",
        "provider:ghidra",
        "void f(void) {}",
        args={"address": "0x1", "program": program},
        entry_id="ev_0002",
    )


def test_a_call_naming_no_program_after_another_was_named_is_told_nothing() -> None:
    # The range was read for one program, then a call named another: a call
    # that names none may be about that one, whose image this is not.
    image = image_range_of([], [_program_info(), _naming("b.dll")])
    assert image is not None and image.others
    args = {"address": "0x1360bcfa00"}
    text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), args, image)
    plain_text, plain_entry = _plain(_tool("read_memory", GHIDRA_FAILURE), args)
    assert (text, entry.remediation) == (plain_text, plain_entry.remediation)


def test_a_call_naming_the_ranges_own_program_keeps_the_note() -> None:
    image = image_range_of([], [_program_info(), _naming(f"/{PROGRAM}")])
    _text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), {"address": "0x1360bcfa00"}, image)
    assert entry.remediation == NOTE


def test_the_packs_range_holds_only_while_no_program_is_named() -> None:
    image = image_range_of(_pack(), [_naming(PROGRAM)])
    _text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), {"address": "0x1360bcfa00"}, image)
    assert entry.remediation is None


# Each call of a declared kind that opens or selects a program, by the argument
# its declaration names for the file or the program (never by the tool's name).
OPENS = [
    ("provider:ghidra", "open_program", "path"),
    ("provider:ghidra", "load_program", "file"),
    ("provider:ghidra", "load_program_from_project", "path"),
    ("provider:ghidra", "import_file", "file_path"),
    ("provider:ghidra", "switch_program", "program"),
    ("provider:r2", "open_file", "file_path"),
]


def _opening(source: str, tool: str, argument: str, file: str) -> Any:
    return _entry(tool, source, "ok", args={argument: file}, entry_id="ev_0003")


@pytest.mark.parametrize(("source", "tool", "argument"), OPENS)
def test_opening_another_program_by_path_ends_the_ranges_note(
    source: str, tool: str, argument: str
) -> None:
    opened = _opening(source, tool, argument, "/data/samples/.work/b.dll")
    image = image_range_of([], [_program_info(), opened])
    assert image is not None and image.others
    args = {"address": "0x1360bcfa00"}
    text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), args, image)
    plain_text, plain_entry = _plain(_tool("read_memory", GHIDRA_FAILURE), args)
    assert (text, entry.remediation) == (plain_text, plain_entry.remediation)


@pytest.mark.parametrize(("source", "tool", "argument"), OPENS)
def test_opening_the_ranges_own_program_keeps_the_note(
    source: str, tool: str, argument: str
) -> None:
    opened = _opening(source, tool, argument, f"/data/samples/.work/{PROGRAM}")
    image = image_range_of([], [_program_info(), opened])
    _text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), {"address": "0x1360bcfa00"}, image)
    assert entry.remediation == NOTE


SHA = "6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef"
WORKING_COPY = f"{SHA}.a58dae16-a151-4943-b0b3-aa4c491d34ff.exe"


def _pack_with_names() -> list[Any]:
    """The pack, with the entries that record the sample's names (haiku5, ev_0001 and ev_0023)."""
    identity = _entry(
        "identify_file",
        "pack",
        {"file_type": "pe"},
        args={"path": f"/srv/data/samples/.tmp/{SHA}.exe"},
        server="pipeline",
        entry_id="ev_0005",
    )
    scan = _entry(
        "anti_analysis_scan",
        "pack",
        {"tool": "find_anti_analysis_techniques", "program": WORKING_COPY},
        args={"program": f"/data/samples/.work/{WORKING_COPY}", "provider": "ghidra"},
        server="pipeline",
        entry_id="ev_0006",
    )
    return [*_pack(), identity, scan]


def test_the_packs_range_carries_the_samples_own_names() -> None:
    image = image_range_of(_pack_with_names())
    assert image is not None
    assert image.names == (f"{SHA}.exe", WORKING_COPY)


@pytest.mark.parametrize(
    "path",
    [f"/srv/data/samples/r2-work/{WORKING_COPY}", f"/elsewhere/{SHA}.exe"],
)
def test_opening_the_sample_itself_keeps_the_packs_range(path: str) -> None:
    opened = _opening("provider:r2", "open_file", "file_path", path)
    image = image_range_of(_pack_with_names(), [opened])
    assert image is not None and not image.others
    _text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), {"address": "0x1360bcfa00"}, image)
    assert entry.remediation == NOTE


def test_opening_another_file_ends_the_packs_range_note() -> None:
    opened = _opening("provider:r2", "open_file", "file_path", "/srv/data/samples/r2-work/b.dll")
    image = image_range_of(_pack_with_names(), [opened])
    assert image is not None and image.others
    args = {"address": "0x1360bcfa00"}
    text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), args, image)
    plain_text, plain_entry = _plain(_tool("read_memory", GHIDRA_FAILURE), args)
    assert (text, entry.remediation) == (plain_text, plain_entry.remediation)


def test_a_path_of_a_call_that_opens_nothing_names_no_program() -> None:
    # A pack tool's ``path`` is the file it reads, not a program the server opened.
    read = _entry("pe_info", "pack", {"sections": []}, args={"path": "/x/b.dll"})
    image = image_range_of([], [_program_info(), read])
    assert image is not None and not image.others


def test_a_range_that_cannot_be_read_leaves_the_call_as_on_dev() -> None:
    def _raises() -> ImageRange | None:
        raise RuntimeError("unreadable")

    args = {"address": "0x1360bcfa00"}
    recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
    (recorded,) = record_tools(
        [_tool("read_memory", GHIDRA_FAILURE)], recorder, image_range=_raises
    )
    text = recorded.invoke(args)
    plain_text, plain_entry = _plain(_tool("read_memory", GHIDRA_FAILURE), args)
    entry = recorder.entries[-1]
    assert text == plain_text
    assert (entry.ok, entry.error, entry.remediation) == (
        plain_entry.ok,
        plain_entry.error,
        plain_entry.remediation,
    )


def test_the_reader_reads_again_only_when_the_entries_grew() -> None:
    reader = ImageRangeReader()
    own: list[Any] = []
    assert reader([], own) is None
    own.append(_program_info())
    assert reader([], own) == ImageRange(0x1360BC00000, 0x1360BC131FF, PROGRAM)


def test_no_range_known_changes_nothing() -> None:
    args = {"address": "0x1360bcfa00"}
    text, entry = _call(_tool("read_memory", GHIDRA_FAILURE), args, None)
    plain_text, plain_entry = _plain(_tool("read_memory", GHIDRA_FAILURE), args)
    assert (text, entry.remediation) == (plain_text, plain_entry.remediation)
    assert entry.remediation is None


def test_a_tool_that_declares_no_address_argument_is_not_read() -> None:
    # Undeclared: the same argument name, no declared role, so no reading.
    undeclared = _tool("read_memory", GHIDRA_FAILURE, source="mcp:unknown_server")
    _text, entry = _call(
        undeclared, {"address": "0x1360bcfa00"}, ImageRange(0x1360BC00000, 0x1360BC131FF)
    )
    assert entry.remediation is None


# -- in an analyst's loop -------------------------------------------------------------


READ_BELOW = {"name": "read_memory", "args": {"address": "0x1360bcfa00"}}
PROGRAM_STATEMENT = {"name": "get_current_program_info", "args": {}}


class _Model(BaseChatModel):
    """Makes its scripted calls, one a turn, then writes its answer."""

    script: list[dict[str, Any]] = []
    seen: list[str] = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        answers = [str(m.content) for m in messages if isinstance(m, ToolMessage)]
        self.seen[:] = answers
        if len(answers) < len(self.script):
            step = len(answers)
            call = {**self.script[step], "id": f"c{step}"}
            turn = AIMessage(content="", tool_calls=[call])
        else:
            turn = AIMessage(content=REPORT)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "out-of-image-stub"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


def _loop(script: list[dict[str, Any]], pack: list[Any]) -> tuple[_Analyst, _Model]:
    model = _Model(script=script)
    agent = _Analyst(llm=model, name="reverser")
    agent.logger = logging.getLogger("test.out_of_image")
    agent.tools = [
        _tool("get_current_program_info", PROGRAM_INFO),
        _tool("read_memory", GHIDRA_FAILURE),
    ]
    agent.token_ledger = TokenLedger()
    agent.pack_entries = pack
    with patch("maljan.agents.base_agent.loop_limits", return_value=(None, None)):
        agent.execute_tool_loop([("system", "s"), ("human", "look at it")])
    return agent, model


def test_an_analysts_loop_tells_a_failed_call_the_packs_range() -> None:
    agent, model = _loop([READ_BELOW], _pack())
    (entry,) = [e for e in agent._evidence_entries if e.tool == "read_memory"]
    assert entry.remediation == NOTE
    assert any(f"[platform] {NOTE}" in answer for answer in model.seen)


def test_an_analysts_loop_reads_the_program_statement_it_made_itself() -> None:
    agent, model = _loop([PROGRAM_STATEMENT, READ_BELOW], [])
    (entry,) = [e for e in agent._evidence_entries if e.tool == "read_memory"]
    assert entry.remediation == NOTE
    assert any(f"[platform] {NOTE}" in answer for answer in model.seen)


def test_an_analysts_loop_with_no_range_is_as_on_dev() -> None:
    agent, model = _loop([READ_BELOW], [])
    (entry,) = [e for e in agent._evidence_entries if e.tool == "read_memory"]
    assert entry.remediation is None
    assert not any("[platform] address" in answer for answer in model.seen)
