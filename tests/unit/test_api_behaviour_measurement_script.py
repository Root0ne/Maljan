"""The measurement the Linux behaviour block's discipline rests on.

The block's tiers and rules are decided by counting how often they fire on
software that is not a sample, and a rule kept that way is only as good as the
count being repeatable. The script is operator-run and reads whatever binaries
it is pointed at, so what is checked here is the counting itself: two ELFs
built in the test, one ordinary and one reaching into another process, and the
threshold that turns the count into an exit status.

No host binary is read. That is the whole reason the script is not a test.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from tests.unit.tools.test_binary import _elf, _elf_with_imports

_SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "knowledge" / "measure_api_behaviour_block.py"
)


def _script() -> Any:
    spec = importlib.util.spec_from_file_location("measure_api_behaviour_block", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """One ordinary program and one that reaches into another process."""
    (tmp_path / "ordinary").write_bytes(
        _elf_with_imports("open", "read", "write", "getenv", "socket", "setuid")
    )
    (tmp_path / "reaches-in").write_bytes(
        _elf_with_imports("ptrace", "process_vm_writev", "open", "read")
    )
    (tmp_path / "not-an-elf").write_bytes(b"#!/bin/sh\nexit 0\n")
    (tmp_path / "no-symbols").write_bytes(_elf())
    return tmp_path


class TestWhatTheScriptReads:
    def test_only_the_elf_binaries_with_a_symbol_table_are_counted(self, corpus: Path) -> None:
        script = _script()
        read = dict(script.walk([str(corpus)]))
        assert sorted(read) == ["ordinary", "reaches-in"]
        assert "ptrace" in read["reaches-in"]

    def test_a_directory_that_is_not_there_is_skipped_rather_than_fatal(
        self, tmp_path: Path
    ) -> None:
        assert list(_script().walk([str(tmp_path / "absent")])) == []

    def test_a_file_that_is_not_an_elf_yields_nothing(self, corpus: Path) -> None:
        assert _script().elf_imports(corpus / "not-an-elf") is None


class TestWhatTheScriptCounts:
    def test_the_ordinary_program_is_described_and_never_labelled(self, corpus: Path) -> None:
        script = _script()
        result = script.measure(
            [str(corpus)], "linux", "data/api_behaviour_map_v1.json", "data/api_attck_map_v1.json"
        )
        assert result["total"] == 2
        # Both are described; only the one reaching into another process is
        # labelled, and only it clears a rule.
        assert result["group_seen"]["filesystem"] == 2
        assert result["labelled_binaries"] == 1
        assert result["ruled_binaries"] == 1
        assert result["labelled_names"]["process_injection"] == ["reaches-in"]
        assert result["ruled_names"]["T1055.008"] == ["reaches-in"]
        assert dict(result["group_labelled"]) == {"process_injection": 1}

    def test_the_threshold_is_what_turns_a_count_into_an_answer(
        self, corpus: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        script = _script()
        result = script.measure(
            [str(corpus)], "linux", "data/api_behaviour_map_v1.json", "data/api_attck_map_v1.json"
        )
        # One of two binaries is half the corpus, which is far over any bar
        # worth setting; with no bar the script only reports.
        assert script.report(result, None) == 0
        assert script.report(result, 1.0) == 1
        assert script.report(result, 90.0) == 0
        printed = capsys.readouterr()
        assert "binaries with a dynamic symbol table: 2" in printed.out
        assert "T1055.008" in printed.out

    def test_an_empty_corpus_is_not_a_pass(self, tmp_path: Path) -> None:
        script = _script()
        result = script.measure(
            [str(tmp_path)], "linux", "data/api_behaviour_map_v1.json", "data/api_attck_map_v1.json"
        )
        assert script.report(result, 1.0) == 1
