"""The pack keeps the emulator's whole rows for its own job, and says what it could not use.

The decoded-blobs step compares the platform's decodings with the rows the
emulator recovered. Those rows are held by the pack for its own job, so a
second job filling the emulator's process-wide memory does not take them
away; and where only a page of a decoder's rows is at hand, the comparison
says so instead of reading as complete. A ledger row the pack cannot read is
logged, and an answer its renderer fails on is said to be unrendered rather
than "recorded".
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

import pytest

from maljan.core.logger import logger as maljan_logger
from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import PIPELINE, pack_entries, render_pack
from maljan.schemas.evidence import build_entry, format_entry_id
from maljan.tools import api_hashes, emulated_strings, string_blobs
from tests.unit.pipeline.test_decoded_strings_in_the_pack import (
    _answer,
    _fake_capa,  # noqa: F401 — the autouse fixture, applied here too
    _installed,
    _pack,
    _row,
)
from tests.unit.tools.test_string_blobs import _with_blob, _xor8

WHOLE = [_row(f"text-{n}", "0x66e0", f"0x{0x2000 + n:x}") for n in range(5)]


@pytest.fixture(autouse=True)
def _forgotten() -> Any:
    emulated_strings.forget_documents()
    yield
    emulated_strings.forget_documents()


@pytest.fixture
def caplog_maljan(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """``caplog`` with the project logger propagating into it."""
    propagate = maljan_logger.propagate
    maljan_logger.propagate = True
    caplog.set_level(logging.DEBUG)
    yield caplog
    maljan_logger.propagate = propagate


def _compared(monkeypatch: pytest.MonkeyPatch) -> list[list[Any]]:
    """Records the rows each decode_string_blobs call was handed to compare with."""
    seen: list[list[Any]] = []
    real = string_blobs.decode_string_blobs

    def spy(path: str, **kwargs: Any) -> dict[str, Any]:
        seen.append(list(kwargs.get("recovered") or []))
        return real(path, **kwargs)

    monkeypatch.setattr(string_blobs, "decode_string_blobs", spy)
    return seen


class TestTheWholeRowsAreTheJobs:
    def test_the_rows_compared_are_the_result_the_entry_was_paged_from(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Never a second read of the emulator's process-wide memory, which another
        job's run may have cleared by the time the blob decoder runs."""
        _installed(monkeypatch, _answer(WHOLE[:2], total=len(WHOLE)))
        monkeypatch.setattr(
            emulated_strings,
            "recovered",
            lambda path, **_: {"rows": list(WHOLE), "meta": {}},
        )

        def never(*_: Any, **__: Any) -> Any:
            raise AssertionError("the process-wide memory was read")

        monkeypatch.setattr(emulated_strings, "remembered_rows", never)
        seen = _compared(monkeypatch)
        result = _pack(tmp_path)
        assert seen == [WHOLE]
        (blobs,) = [e for e in result.entries if e.tool == "decode_string_blobs"]
        assert "decoder_rows_partial" not in blobs.args
        assert string_blobs.NOT_COMPARED not in blobs.structured

    def test_a_whole_page_is_not_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _installed(monkeypatch, _answer(WHOLE))
        seen = _compared(monkeypatch)
        result = _pack(tmp_path)
        assert seen == [WHOLE]
        (blobs,) = [e for e in result.entries if e.tool == "decode_string_blobs"]
        assert "decoder_rows_partial" not in blobs.args
        assert triage_pack.DECODED_BLOBS_PARTIAL_COMPARE not in render_pack([blobs], 0)


def _floss_document(count: int) -> dict[str, Any]:
    """A result document in FLOSS's shape with ``count`` decoded strings."""
    base = 0x180000000
    return {
        "metadata": {"version": "3.1.1", "imagebase": base, "runtime": {"total": 1.0}},
        "analysis": {"functions": {"discovered": 4, "analyzed_decoded_strings": 1}},
        "strings": {
            "decoded_strings": [
                {
                    "address": base + 0xD000 + n,
                    "address_type": "GLOBAL",
                    "string": f"decoded-{n}",
                    "encoding": "ASCII",
                    "decoded_at": base + 0x5C00 + n,
                    "decoding_routine": base + 0xAE78,
                }
                for n in range(count)
            ],
            "stack_strings": [],
            "tight_strings": [],
            "static_strings": [],
        },
    }


class TestTheRealEmulatorModule:
    def test_memory_cleared_between_floss_and_the_blobs_neither_reruns_nor_shrinks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """emulated_strings as shipped, its child process alone stood in for."""
        document = json.dumps(_floss_document(5))
        runs: list[list[str]] = []

        def run(argv: Any, timeout: Any, pinned: Any = None, scratch: Any = None) -> Any:
            runs.append(list(argv))
            return subprocess.CompletedProcess(list(argv), 0, document, "")

        monkeypatch.setattr(
            emulated_strings, "find_floss", lambda environ=None: (Path("/opt/floss/floss"), "")
        )
        monkeypatch.setattr(emulated_strings, "_run", run)
        monkeypatch.setattr(triage_pack, "DECODED_STRINGS_ROWS", 2)
        real_resolve = api_hashes.resolve_api_hashes

        def resolve(*args: Any, **kwargs: Any) -> Any:
            # Another job's run clears the emulator's process-wide memory.
            emulated_strings.forget_documents()
            return real_resolve(*args, **kwargs)

        monkeypatch.setattr(api_hashes, "resolve_api_hashes", resolve)
        seen = _compared(monkeypatch)
        result = _pack(tmp_path)
        assert len(runs) == 1
        (floss,) = [e for e in result.entries if e.tool == "floss"]
        sample = floss.args["path"]
        emulated_strings.forget_documents()
        whole = emulated_strings.recovered(
            sample, runner=lambda argv, timeout: subprocess.CompletedProcess(argv, 0, document, "")
        )
        assert seen == [whole["rows"]]
        assert len(whole["rows"]) == 5
        # The entry's page is the page dev's single floss call gave.
        expected = emulated_strings.floss(
            sample,
            limit=2,
            runner=lambda argv, timeout: subprocess.CompletedProcess(argv, 0, document, ""),
        )
        assert floss.structured == json.loads(json.dumps(expected))
        (blobs,) = [e for e in result.entries if e.tool == "decode_string_blobs"]
        assert "decoder_rows_partial" not in blobs.args


class TestAPartialCompareSetIsSaid:
    def test_a_truncated_site_source_with_no_held_rows_is_flagged_and_counted_apart(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def page_only(pack: Any, step: Any) -> None:
            pack.record(
                "floss",
                {"path": pack.inputs.sample_path},
                lambda: _answer(WHOLE[:2], total=len(WHOLE)),
            )

        monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: None)
        monkeypatch.setitem(triage_pack._BUILTIN_STEPS, "floss", page_only)
        monkeypatch.setitem(triage_pack._EARLY_BUILTINS, page_only, lambda pack, step: None)
        seen = _compared(monkeypatch)
        result = _pack(tmp_path, blob=_blob_file(tmp_path).read_bytes())
        assert seen == [WHOLE[:2]]
        (blobs,) = [e for e in result.entries if e.tool == "decode_string_blobs"]
        assert "page" in blobs.args["decoder_rows_partial"]
        assert blobs.structured[string_blobs.NOT_COMPARED] == 1
        assert blobs.structured["unreferenced"] == 0
        assert triage_pack.DECODED_BLOBS_PARTIAL_COMPARE in render_pack([blobs], 0)

    def test_a_page_only_answer_gives_its_page_and_says_why(self) -> None:
        page = {"strings": WHOLE[:2], "total": 5, "next_offset": 2, "truncated": True}
        entry = _entry("some_decoder", json.dumps(page))
        rows, why = triage_pack._site_rows_held(entry, WHOLE[:2], None)
        assert rows == WHOLE[:2]
        assert "page" in why

    def test_held_whole_rows_are_used_and_nothing_is_said(self) -> None:
        page = {"strings": WHOLE[:2], "total": 5, "next_offset": 2, "truncated": True}
        entry = _entry("floss", json.dumps(page))
        rows, why = triage_pack._site_rows_held(entry, WHOLE[:2], lambda: list(WHOLE))
        assert (rows, why) == (WHOLE, "")

    def test_the_line_says_the_comparison_was_partial_and_counts_the_rows_apart(self) -> None:
        answer = {
            "tool": "decode_string_blobs",
            "results": [],
            "total": 0,
            "unreferenced": 0,
            string_blobs.NOT_COMPARED: 3,
        }
        entry = _entry(
            "decode_string_blobs",
            json.dumps(answer),
            args={"decoder_rows_partial": "ev_0005 some_decoder: the entry holds a page"},
        )
        line = render_pack([entry], 0)
        assert triage_pack.DECODED_BLOBS_PARTIAL_COMPARE in line
        assert "3 more decodings no code refers to and not compared" in line
        assert "the entry holds a page" in line


def _blob_file(tmp_path: Path) -> Path:
    """A PE with one encoded text no code refers to."""
    image = _with_blob(_xor8(b"open the settings file\0", 0x9C), referred=False)
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return target


class TestTheDecoderKeepsAPartialComparisonApart:
    def test_an_unreferenced_decoding_is_not_compared_when_the_rows_are_partial(
        self, tmp_path: Path
    ) -> None:
        target = _blob_file(tmp_path)
        answer = string_blobs.decode_string_blobs(
            str(target),
            recovered=[],
            recovered_partial="a page of the rows",
            include_unreferenced=True,
        )
        word = string_blobs.decoder_word()
        assert answer["unreferenced"] == 0
        assert answer[string_blobs.NOT_COMPARED] == 1
        assert answer[f"{word}_rows_partial"] == "a page of the rows"
        assert answer["unreferenced_results"] == []
        assert [row["text"] for row in answer["not_compared_results"]] == ["open the settings file"]

    def test_whole_rows_count_it_as_unreferenced_as_before(self, tmp_path: Path) -> None:
        answer = string_blobs.decode_string_blobs(str(_blob_file(tmp_path)), recovered=[])
        assert answer["unreferenced"] == 1
        assert string_blobs.NOT_COMPARED not in answer
        assert "not_compared_results" not in answer
        assert f"{string_blobs.decoder_word()}_rows_partial" not in answer

    def test_a_decoding_the_partial_rows_recovered_is_still_reported(self, tmp_path: Path) -> None:
        recovered = [
            {
                "kind": "decoded",
                "string": "open the settings file",
                "function_rva": "0x1100",
                "called_at_rva": "0x1180",
            }
        ]
        answer = string_blobs.decode_string_blobs(
            str(_blob_file(tmp_path)), recovered=recovered, recovered_partial="a page"
        )
        assert answer["total"] == 1
        assert answer[string_blobs.NOT_COMPARED] == 0

    def test_no_rows_held_in_the_process_is_said(self, tmp_path: Path) -> None:
        answer = string_blobs.decode_string_blobs(str(_blob_file(tmp_path)))
        assert answer[f"{string_blobs.decoder_word()}_rows_not_held"] == string_blobs.ROWS_NOT_HELD


class TestTheServedIndexReadsTheMemoryOnce:
    def test_the_decoder_compares_with_the_rows_the_index_joins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools import artefact_index

        reads: list[str] = []
        rows = [
            {
                "kind": "decoded",
                "string": "open the settings file",
                "function_rva": "0x1100",
                "called_at_rva": "0x1180",
            }
        ]

        def remembered(path: str) -> list[dict[str, Any]]:
            reads.append(path)
            return list(rows) if len(reads) == 1 else []

        monkeypatch.setattr(emulated_strings, "remembered_rows", remembered)
        handed: list[Any] = []
        real = string_blobs.decode_string_blobs

        def spy(path: str, **kwargs: Any) -> dict[str, Any]:
            handed.append(kwargs.get("recovered"))
            return real(path, **kwargs)

        monkeypatch.setattr(string_blobs, "decode_string_blobs", spy)
        artefact_index.served_index(str(_blob_file(tmp_path)))
        assert len(reads) == 1
        assert handed == [rows]

    def test_rows_that_cannot_be_read_are_none_with_the_reason_read_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools import artefact_index

        reads: list[str] = []

        def broken(path: str) -> list[dict[str, Any]]:
            reads.append(path)
            raise OSError("gone")

        monkeypatch.setattr(emulated_strings, "remembered_rows", broken)
        handed: list[tuple[Any, Any]] = []
        answers: list[dict[str, Any]] = []
        real = string_blobs.decode_string_blobs

        def spy(path: str, **kwargs: Any) -> dict[str, Any]:
            handed.append((kwargs.get("recovered"), kwargs.get("recovered_partial")))
            answers.append(real(path, **kwargs))
            return answers[-1]

        monkeypatch.setattr(string_blobs, "decode_string_blobs", spy)
        served = artefact_index.served_index(str(_blob_file(tmp_path)))
        assert len(reads) == 1
        ((recovered, reason),) = handed
        assert recovered == []
        assert reason == "FLOSS's rows for this file could not be read (OSError)"
        assert answers[0][string_blobs.NOT_COMPARED] == 1
        assert "could not be read" in str(served.get("absent") or served)


def _entry(tool: str, output: str, args: dict[str, Any] | None = None, **over: Any) -> Any:
    return build_entry(
        entry_id=format_entry_id(3),
        seq=3,
        agent=PIPELINE,
        tool=tool,
        args=args or {},
        server=PIPELINE,
        output=output,
        stage="triage_pack",
        **over,
    )


class TestWhatThePackCouldNotRead:
    def test_an_unreadable_ledger_row_is_logged_as_a_warning(
        self, caplog_maljan: pytest.LogCaptureFixture
    ) -> None:
        good = _entry("strings", '{"strings": []}').model_dump()
        bad = {"id": "ev_0009", "agent": PIPELINE, "seq": "not a number"}
        assert [e.id for e in pack_entries([good, bad])] == [good["id"]]
        warned = [r for r in caplog_maljan.records if r.levelno >= logging.WARNING]
        assert warned, "the skipped row is not said"
        assert "ev_0009" in warned[0].getMessage()

    def test_the_block_counts_the_rows_left_out_and_why(self) -> None:
        good = _entry("strings", '{"strings": []}').model_dump()
        bad = {"id": "ev_0009", "agent": PIPELINE, "seq": "not a number"}
        entries = pack_entries([good, bad, "not a row"])
        assert entries.unread == ["ValidationError", "ValidationError"]
        rendered = render_pack(entries, 0)
        assert rendered.splitlines()[-1] == (
            "2 ledger rows could not be read and are left out (ValidationError)"
        )
        only = triage_pack.pack_block(pack_entries([bad]), 0)
        assert only.splitlines() == [
            triage_pack.PACK_HEADING,
            "1 ledger row could not be read and is left out (ValidationError)",
        ]
        assert render_pack(pack_entries([good]), 0) == render_pack(
            [_entry("strings", '{"strings": []}')], 0
        )

    def test_a_small_room_never_holds_more_than_its_limit(self) -> None:
        long = json.dumps({"strings": [{"string": "x" * 400, "offset": "0x10"}]})
        one = _entry("strings", long)
        rows = [
            one.model_copy(update={"id": format_entry_id(n), "seq": n}).model_dump()
            for n in range(3, 9)
        ]
        entries = pack_entries([*rows, {"seq": "bad"}])
        # The entries alone already overflow the room the sentence leaves them.
        body = triage_pack._render_entries(entries, triage_pack._entries_room(entries, 150))
        assert len(body) + 1 + len(triage_pack.unread_rows_sentence(entries)) > 150
        rendered = render_pack(entries, 150)
        assert len(rendered) <= 150
        assert rendered.splitlines()[-1] == (
            "1 ledger row could not be read and is left out (ValidationError)"
        )

    def test_the_left_out_record_is_read_in_the_room_the_pack_renders_in(self) -> None:
        from tests.unit.pipeline.test_deobfuscation_passes_in_the_pack import _synthetic_pack

        plain = _synthetic_pack()
        entries = triage_pack.PackEntries(plain, ["ValidationError"])
        sentence = triage_pack.unread_rows_sentence(entries)
        for budget in (6_000, 18_432):
            room = budget - len(sentence) - 1
            assert triage_pack.pack_unsaid(entries, budget) == triage_pack.pack_unsaid(plain, room)
            assert render_pack(entries, budget) == f"{render_pack(plain, room)}\n{sentence}"

    def test_a_renderer_failure_is_said_with_its_reason_not_as_recorded(
        self, monkeypatch: pytest.MonkeyPatch, caplog_maljan: pytest.LogCaptureFixture
    ) -> None:
        entry = _entry("floss", '{"strings": [], "total": 0}')
        shown, _data = triage_pack._shown(entry)

        def broken(_data: Any) -> str:
            raise ValueError("boom")

        monkeypatch.setitem(triage_pack._RENDERERS, shown, broken)
        line = render_pack([entry], 0)
        assert not line.rstrip().endswith(": recorded")
        assert "ValueError" in line
        assert any(r.levelno >= logging.WARNING for r in caplog_maljan.records)
