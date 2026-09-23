"""``maljan.tools.emulated_strings`` reads FLOSS's result document row by row.

FLOSS itself is not run here: the runner is replaced by one that answers with
a result document in FLOSS's own shape, so what these tests pin is the reading
of that document — every string with the function that produced it, paging
that counts rows, one emulation however many pages are read, and an error in
the tool's words for every way the child can fail.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import emulated_strings as tool

IMAGEBASE = 0x180000000


def _document() -> dict[str, Any]:
    """A result document in FLOSS's shape, with made-up strings."""
    return {
        "metadata": {
            "version": "3.1.1",
            "imagebase": IMAGEBASE,
            "language": "unknown",
            "runtime": {"total": 12.5},
        },
        "analysis": {"functions": {"discovered": 40, "analyzed_decoded_strings": 5}},
        "strings": {
            "decoded_strings": [
                {
                    "address": 0x7FFE0010,
                    "address_type": "STACK",
                    "string": "example-mutex",
                    "encoding": "ASCII",
                    "decoded_at": IMAGEBASE + 0x5C02,
                    "decoding_routine": IMAGEBASE + 0xAE78,
                },
                {
                    "address": IMAGEBASE + 0xD000,
                    "address_type": "GLOBAL",
                    "string": "https://c2.example.org/path/",
                    "encoding": "UTF-16LE",
                    "decoded_at": IMAGEBASE + 0x6A1F,
                    "decoding_routine": IMAGEBASE + 0xAE78,
                },
            ],
            "stack_strings": [
                {
                    "function": IMAGEBASE + 0x1000,
                    "string": "stackbuilt",
                    "encoding": "ASCII",
                    "program_counter": IMAGEBASE + 0x1044,
                    "stack_pointer": 0,
                    "original_stack_pointer": 0,
                    "offset": 8,
                    "frame_offset": 32,
                }
            ],
            "tight_strings": [],
            "static_strings": [],
        },
    }


class _Runner:
    """Answers every call with one completed process and counts the calls."""

    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.calls: list[list[str]] = []
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(list(argv), self.returncode, self.stdout, self.stderr)


@pytest.fixture(autouse=True)
def _nothing_remembered() -> None:
    tool.forget_documents()


def _pe(tmp_path: Path, name: str = "s.dll") -> str:
    target = tmp_path / name
    target.write_bytes(b"MZ" + b"\x00" * 62)
    return str(target)


class TestTheDocumentIsRead:
    def test_a_decoded_string_carries_the_function_that_decoded_it(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))

        rows = tool.floss(_pe(tmp_path), runner=runner)["strings"]

        assert rows[0] == {
            "kind": "decoded",
            "string": "example-mutex",
            "encoding": "ASCII",
            "function": hex(IMAGEBASE + 0xAE78),
            "function_rva": "0xae78",
            "called_at": hex(IMAGEBASE + 0x5C02),
            "called_at_rva": "0x5c02",
            "address": hex(0x7FFE0010),
            "address_type": "STACK",
        }

    def test_a_stack_string_carries_its_function_and_frame_offset(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))

        rows = tool.floss(_pe(tmp_path), runner=runner)["strings"]
        stack = [row for row in rows if row["kind"] == "stack"]

        assert stack == [
            {
                "kind": "stack",
                "string": "stackbuilt",
                "encoding": "ASCII",
                "function": hex(IMAGEBASE + 0x1000),
                "function_rva": "0x1000",
                "program_counter": hex(IMAGEBASE + 0x1044),
                "frame_offset": 32,
            }
        ]

    def test_counts_and_meta_say_what_floss_found(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), runner=_Runner(json.dumps(_document())))

        assert answer["counts"] == {"decoded": 2, "stack": 1, "tight": 0}
        assert answer["total"] == 3
        assert answer["meta"] == {
            "floss_version": "3.1.1",
            "imagebase": hex(IMAGEBASE),
            "language": "unknown",
            "functions_discovered": 40,
            "functions_emulated_for_decoding": 5,
            "runtime_s": 12.5,
        }

    def test_floss_is_asked_for_the_emulated_kinds_only_and_as_json(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        tool.floss(path, min_len=5, runner=runner)

        argv = runner.calls[0]
        assert argv[1:3] == ["-m", "floss"]
        assert "--json" in argv
        assert argv[argv.index("--minimum-length") + 1] == "5"
        only = argv[argv.index("--only") + 1 : argv.index("--")]
        assert only == ["decoded", "stack", "tight"]
        assert argv[-1] == path

    def test_an_empty_answer_is_no_strings_rather_than_an_error(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), runner=_Runner(""))

        assert answer["strings"] == []
        assert answer["counts"] == {"decoded": 0, "stack": 0, "tight": 0}


class TestPaging:
    def test_pages_count_rows_and_say_where_the_next_one_starts(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        first = tool.floss(path, limit=2, runner=runner)
        second = tool.floss(path, limit=2, offset=first["next_offset"], runner=runner)

        assert [row["string"] for row in first["strings"]] == [
            "example-mutex",
            "https://c2.example.org/path/",
        ]
        assert first["next_offset"] == 2
        assert first["truncated"] is True
        assert [row["string"] for row in second["strings"]] == ["stackbuilt"]
        assert second["next_offset"] is None

    def test_reading_every_page_costs_one_emulation(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        for offset in range(3):
            tool.floss(path, limit=1, offset=offset, runner=runner)

        assert len(runner.calls) == 1

    def test_pattern_and_kinds_narrow_the_rows(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        by_pattern = tool.floss(path, pattern="MUTEX", runner=runner)
        by_kind = tool.floss(path, kinds=["stack"], runner=runner)

        assert [row["string"] for row in by_pattern["strings"]] == ["example-mutex"]
        assert by_pattern["total_matched"] == 1
        assert by_pattern["total"] == 3
        assert [row["string"] for row in by_kind["strings"]] == ["stackbuilt"]


class TestFailuresAreAnswers:
    def test_a_file_that_is_not_a_pe_is_refused_before_floss_runs(self, tmp_path: Path) -> None:
        target = tmp_path / "script.txt"
        target.write_bytes(b"#!/bin/sh\n")
        runner = _Runner(json.dumps(_document()))

        answer = tool.floss(str(target), runner=runner)

        assert "not a PE" in answer["error"]
        assert runner.calls == []

    def test_an_overrun_is_a_timeout_the_error_codes_recognise(self, tmp_path: Path) -> None:
        from maljan.tools.errors import TIMEOUT, error_parts

        def runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(list(argv), timeout)

        answer = tool.floss(_pe(tmp_path), timeout_s=7, runner=runner)

        parts = error_parts(answer)
        assert parts is not None
        assert parts[0] == TIMEOUT
        assert "7 s" in answer["error"]

    def test_a_failed_child_is_answered_with_its_last_stderr_line(self, tmp_path: Path) -> None:
        stderr = "loading\nfailed to analyze sample: bad header\n"
        runner = _Runner("", returncode=255, stderr=stderr)

        answer = tool.floss(_pe(tmp_path), runner=runner)

        assert answer["error"].endswith("failed to analyze sample: bad header")
        assert "255" in answer["error"]

    def test_output_that_is_not_the_document_is_an_error(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), runner=_Runner("not json"))

        assert "JSON document" in answer["error"]

    def test_an_unknown_kind_is_named(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), kinds=["static"], runner=_Runner("{}"))

        assert "static" in answer["error"]

    def test_a_missing_file_is_named(self, tmp_path: Path) -> None:
        answer = tool.floss(str(tmp_path / "absent.dll"), runner=_Runner("{}"))

        assert answer["error"].startswith("no such file")

    def test_without_floss_installed_the_answer_names_the_extra(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools.errors import MISSING_DEPENDENCY, error_parts

        monkeypatch.setattr(tool.importlib.util, "find_spec", lambda _name: None)

        answer = tool.floss(_pe(tmp_path))

        parts = error_parts(answer)
        assert parts is not None
        assert parts[0] == MISSING_DEPENDENCY
        assert "floss extra" in answer["error"]
