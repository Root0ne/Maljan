"""An undeclared tool's answer that only says the call failed is filed as a failed call.

A server that declares no error patterns answers a failure as ordinary text
("Error: binary not found", "Invalid params: …"), and the ledger filed it as a
successful call that then entered the grounding corpus. For a tool its source
declares nothing for, one line of prose opening with an error word is filed as
failed; any answer holding data, any declared tool and any call recorded with
no source read as before.
"""

from __future__ import annotations

import time

import pytest

from maljan.core.undeclared_tools import PROSE_ERROR_CHARS, prose_error
from maljan.schemas.evidence import build_entry


def _entry(output: str, *, source: str | None = "mcp:other", tool: str = "load_binary") -> object:
    return build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="reverser",
        tool=tool,
        args={},
        server="other",
        source=source,
        output=output,
    )


@pytest.mark.parametrize(
    "said",
    [
        "Error: binary 'x.exe' is not in the project",
        "Error: binary not loaded",
        "error: no program is open",
        "Fatal error: the project is locked",
        "Error executing tool decompile_function: no function at 0x1000",
        "Cannot find function at 0x1000",
        "Could not open the file",
        "[ERROR] analysis is not complete",
        "[Errno 2] No such file or directory",
        "Failed to decompile: no function there",
        "Failed to open file",
        "Unable to open the file",
        "Permission denied",
        "ValueError: invalid literal for int() with base 16",
        "pkg.ToolError: the binary was not imported",
    ],
)
def test_a_one_line_failure_is_filed_failed(said: str) -> None:
    entry = _entry(said)
    assert entry.ok is False
    assert entry.error == said
    assert entry.output == said


@pytest.mark.parametrize(
    "said",
    [
        '{"error": null, "functions": []}',
        "int main(void) {\n  return 0;\n}",
        "Functions: 3\nentry 0x1000\nmain 0x1040",
        "The binary was imported; error handling paths: 2",
        "Found 0 strings",
        "Error: " + "x" * PROSE_ERROR_CHARS,
        "[1, 2, 3]",
        # An error word at the head of a datum is not an error's form.
        "Error handling routine at 0x401000",
        "Failed logins: 0",
        "Invalid signature",
        "Invalid PE checksum (0x0)",
        "Invalid PE checksum (0x1234 expected 0x5678)",
        "Exception handler installed at 0x401000",
        "errors: 0",
        "Errors: 0",
        "Error: 0",
        "Failures: 3",
        "Not found in VirusTotal",
        "No such export",
        "LastError: ERROR_SUCCESS",
        "Exception count: 2",
        "Cannot",
    ],
)
def test_an_answer_holding_data_stays_an_answer(said: str) -> None:
    assert _entry(said).ok is True


def test_a_traceback_is_filed_failed_with_its_last_line() -> None:
    said = (
        "Traceback (most recent call last):\n"
        '  File "server.py", line 12, in decompile\n'
        "    raise ValueError('no function')\n"
        "ValueError: no function"
    )
    entry = _entry(said)
    assert entry.ok is False
    assert entry.error == "ValueError: no function"


def test_a_declared_tool_is_read_by_its_declaration() -> None:
    entry = _entry("Error: nothing", source="mcp:analysis", tool="pe_info")
    assert entry.ok is True


def test_a_call_with_no_source_is_read_as_before() -> None:
    assert _entry("Error: nothing", source=None).ok is True


def test_the_reading_is_one_pass_over_a_line() -> None:
    def _timed(n: int) -> float:
        text = "Error: " + "a" * n
        start = time.perf_counter()
        for _ in range(200):
            prose_error(text)
        return time.perf_counter() - start

    assert _timed(39_000) < max(_timed(3_900) * 30, 0.5)
    assert prose_error("x\n" * 100_000) is None
    big = "Traceback (most recent call last):\n" + "  frame\n" * 100_000 + "ValueError: x"
    start = time.perf_counter()
    assert prose_error(big) == "ValueError: x"
    assert time.perf_counter() - start < 1.0
