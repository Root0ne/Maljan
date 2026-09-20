"""The measurement both behaviour blocks' discipline rests on.

A block's tiers and rules are decided by counting how often they fire on
software that is not a sample, and a rule kept that way is only as good as the
count being repeatable. Every rate the catalogue now carries beside an
association is this script's output. It is operator-run and reads whatever
binaries it is pointed at, so what is checked here is the counting itself:
binaries built in the test, one ordinary and one reaching into another process,
the PE reader that has to keep an ordinal-only import in the denominator, the
inventory that lets a corpus be measured again after the files are gone, and
the threshold that turns the count into an exit status.

No host binary is read. That is the whole reason the script is not a test.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.tools.test_binary import _elf, _elf_with_imports, _pe

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
        read = {row["name"]: row["imports"] for row in script.walk_elf([str(corpus)])}
        assert sorted(read) == ["ordinary", "reaches-in"]
        assert "ptrace" in read["reaches-in"]

    def test_a_directory_that_is_not_there_is_skipped_rather_than_fatal(
        self, tmp_path: Path
    ) -> None:
        assert list(_script().walk_elf([str(tmp_path / "absent")])) == []

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
        assert "distinct binaries with an import table: 2" in printed.out
        assert "T1055.008" in printed.out

    def test_an_empty_corpus_is_not_a_pass(self, tmp_path: Path) -> None:
        script = _script()
        result = script.measure(
            [str(tmp_path)], "linux", "data/api_behaviour_map_v1.json", "data/api_attck_map_v1.json"
        )
        assert script.report(result, 1.0) == 1


class TestTheWindowsCorpus:
    """The same table, off PE import tables, read the way production reads them.

    Without this the Windows half of the catalogue could only be measured by a
    script nobody kept, which is how it came to carry a label that appeared on
    97.73% of ordinary software.
    """

    def test_a_pe_is_read_and_a_file_that_is_not_one_is_not_counted(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        script = _script()
        (tmp_path / "clean.exe").write_bytes(_pe())
        (tmp_path / "notes.txt").write_bytes(_pe())
        (tmp_path / "penguin.exe").write_bytes(_elf_with_imports("open"))
        read = {row["name"]: row["imports"] for row in script.walk_pe([str(tmp_path)])}
        assert read == {"clean.exe": ["CreateFileA"]}

    def test_an_ordinal_only_import_stays_in_the_denominator(self, tmp_path: Path) -> None:
        """``pe_extractor`` records it as ``Ordinal_<n>`` and so does this. A
        reader that dropped it would shrink the corpus it is quoting a share
        of, silently and only for the binaries that import that way."""
        pytest.importorskip("pefile")
        assert _script().pe_imports(_pe(ordinal=42)) == ["CreateFileA", "Ordinal_42"]

    def test_a_file_that_is_not_a_pe_yields_nothing(self) -> None:
        pytest.importorskip("pefile")
        assert _script().pe_imports(_elf()) is None

    def test_the_same_content_under_two_names_is_one_binary(self, tmp_path: Path) -> None:
        """A suite ships the same runtime library in twenty packages. Every
        rate the catalogue carries is a share of distinct binaries."""
        pytest.importorskip("pefile")
        script = _script()
        (tmp_path / "a.dll").write_bytes(_pe())
        (tmp_path / "copy-of-a.dll").write_bytes(_pe())
        (tmp_path / "b.dll").write_bytes(_pe(ordinal=42))
        read = [row["name"] for row in script.corpus([str(tmp_path)], "windows")]
        assert read == ["a.dll", "b.dll"]


class TestAnInventoryOutlivesTheCorpus:
    """Two gigabytes of installers unpack once; the measurement runs many
    times, including after the rules change."""

    def test_what_a_run_read_is_written_back_out_and_measured_again(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        script = _script()
        (tmp_path / "clean.exe").write_bytes(_pe())
        saved = tmp_path / "corpus.jsonl.gz"
        first = script.measure(
            [str(tmp_path)],
            "windows",
            "data/api_behaviour_map_v1.json",
            "data/api_attck_map_v1.json",
            str(saved),
        )
        again = script.measure(
            [str(saved)], "windows", "data/api_behaviour_map_v1.json", "data/api_attck_map_v1.json"
        )
        assert first["total"] == again["total"] == 1

    def test_a_row_with_no_imports_and_a_line_that_is_not_a_row_are_skipped(
        self, tmp_path: Path
    ) -> None:
        script = _script()
        inventory = tmp_path / "corpus.jsonl.gz"
        with gzip.open(inventory, "wt", encoding="utf-8") as handle:
            handle.write(json.dumps({"name": "a.dll", "imports": ["GetDIBits"]}) + "\n")
            handle.write(json.dumps({"name": "empty.dll", "skip": "no-import-table"}) + "\n")
            handle.write("not a row at all\n\n")
        assert [row["name"] for row in script.read_inventory(inventory)] == ["a.dll"]
