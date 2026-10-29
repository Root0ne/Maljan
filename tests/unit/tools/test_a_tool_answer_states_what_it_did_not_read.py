"""A tool answer is right or says what it did not read; it never reads an unread part as empty.

The string scan reads every run, the UTF-16LE pass included, and its pages
run to the last run; YARA's literal fallback says it is one and gives byte
offsets; a fat Mach-O is walked slice by slice and an unwalkable header is
"unknown", not "unsigned"; FLOSS's streams go to files and only its rows are
remembered; a damaged archive or package is an answer, not an exception; a
gzip name is read past an extra field; a carved payload is written whole or
not at all; and a decoder's rows that could not be read leave the comparison
unknown rather than zero. Every input here is synthetic.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from maljan.pipeline import triage_pack
from maljan.tools import binary, emulated_strings, identify, rules, string_blobs, strings
from maljan.tools.ioc_spans import string_iocs_with_spans
from tests.linear_cost import assert_scales

from .synthetic_pe import TEXT_RVA, SyntheticPE

# More ASCII runs than the scan bound the scan used to stop at (200,000).
_MANY_RUNS = 200_010
_WIDE_HOST = "wide-c2.example.org"


def _many_short_runs() -> bytes:
    return b"abcdef\x00" * _MANY_RUNS


class TestEveryRunIsRead:
    def test_a_wide_host_after_many_ascii_runs_is_found(self) -> None:
        blob = _many_short_runs() + f"http://{_WIDE_HOST}/x".encode("utf-16-le") + b"\x00\x00"

        values = {row["value"] for row in strings.iter_string_iocs(blob)}
        spans = {row["value"] for row in string_iocs_with_spans(blob)}

        assert f"http://{_WIDE_HOST}/x" in values
        assert values == spans

    def test_a_page_past_the_old_bound_is_read_and_the_set_goes_on(self, tmp_path: Path) -> None:
        target = tmp_path / "runs.bin"
        target.write_bytes(_many_short_runs())

        answer = strings.strings(str(target), encodings=("ascii",), limit=5, offset=200_000)

        assert answer["total"] == _MANY_RUNS
        assert answer["total_matched"] == _MANY_RUNS
        assert len(answer["strings"]) == 5
        assert answer["next_offset"] == 200_005
        last = strings.strings(str(target), encodings=("ascii",), limit=5, offset=200_005)
        assert len(last["strings"]) == 5 and last["next_offset"] is None


class _Rule:
    def __init__(self, rule_id: str, patterns: tuple[str, ...]) -> None:
        self.id = rule_id
        self.patterns = patterns
        self.all_of: tuple[str, ...] = ()
        self.technique_id = "T0000"
        self.description = "synthetic"


class _Layer:
    def __init__(self, compiled: Any = None) -> None:
        self._rules = [_Rule("marker_rule", ("MARKER",))]
        self._yara_rules = compiled

    def literal_matches(self, rule: _Rule, text: str) -> list[str]:
        return [p for p in rule.patterns if p.lower() in text.lower()]


class _Failing:
    def match(self, **_kwargs: Any) -> list[Any]:
        raise TimeoutError("scan timed out")


class TestTheYaraFallbackSaysItIsOne:
    def test_a_native_failure_is_named_and_the_fallback_is_said(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(rules, "_yara_layer", lambda _ruleset: _Layer(_Failing()))
        target = tmp_path / "s.bin"
        target.write_bytes(b"xx MARKER yy")

        answer = rules.yara_scan(path=str(target))

        assert answer["engine"] == "literal_fallback"
        assert answer["native_error"] == "TimeoutError: scan timed out"
        assert answer["engine_note"] == rules.LITERAL_FALLBACK_NOTE
        assert [row["rule"] for row in answer["matches"]] == ["marker_rule"]

    def test_fallback_offsets_are_byte_offsets_and_the_hex_is_the_file_s(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(rules, "_yara_layer", lambda _ruleset: _Layer())
        # Undecodable bytes and a two-byte character before each match: a
        # character index would land short of the byte offset.
        data = b"\xff\xfe\xc3\xa9 MARKER \x80\x81 marker"
        target = tmp_path / "s.bin"
        target.write_bytes(data)

        answer = rules.yara_scan(path=str(target))

        assert answer["engine"] == "literal_fallback" and "native_error" not in answer
        found = answer["matches"][0]["strings"]
        assert [row["offset"] for row in found] == [data.find(b"MARKER"), data.find(b"marker")]
        for row in found:
            raw = data[row["offset"] : row["offset"] + row["length"]]
            assert row["data_hex"] == raw.hex()

    def test_the_pack_line_says_the_rules_were_not_run(self) -> None:
        line = triage_pack._yara(
            {
                "matches": [],
                "rule_count": 3,
                "engine": "literal_fallback",
                "native_error": "TimeoutError: scan timed out",
            }
        )

        assert "the YARA engine failed (TimeoutError: scan timed out)" in line
        assert "rule conditions not checked" in line


_LC_UUID = 0x1B
_LC_CODE_SIGNATURE = 0x1D


def _thin(signed: bool) -> bytes:
    commands = struct.pack("<II", _LC_UUID, 24) + bytes(16)
    count = 1
    if signed:
        commands += struct.pack("<IIII", _LC_CODE_SIGNATURE, 16, 0, 0)
        count += 1
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, count, len(commands), 0, 0)
    return header + commands


def _fat(*slices: bytes, offsets: list[int] | None = None) -> bytes:
    """A fat header and its slices, one per 0x1000 bytes, or at ``offsets`` (not written)."""
    places = offsets or [0x1000 * (index + 1) for index in range(len(slices))]
    blob = bytearray(struct.pack(">II", 0xCAFEBABE, len(slices)))
    for place, piece in zip(places, slices, strict=True):
        blob += struct.pack(">iiIII", 0x01000007, 3, place, len(piece), 12)
    if offsets is None:
        for place, piece in zip(places, slices, strict=True):
            blob += bytes(place - len(blob)) + piece
    return bytes(blob)


class TestAFatMachOIsWalkedSliceBySlice:
    def test_one_signed_slice_makes_the_binary_signed(self) -> None:
        answer = identify._macho_signing(_fat(_thin(False), _thin(True)))

        assert answer["present"] is True
        assert [row["present"] for row in answer["slices"]] == [False, True]

    def test_every_slice_unsigned_is_unsigned(self) -> None:
        assert identify._macho_signing(_fat(_thin(False), _thin(False)))["present"] is False

    def test_a_slice_past_the_end_is_unknown_not_unsigned(self) -> None:
        answer = identify._macho_signing(_fat(_thin(False), offsets=[0x9000]))

        assert answer["present"] is None
        assert answer["reason"]

    def test_a_cut_thin_header_is_unknown(self) -> None:
        answer = identify._macho_signing(_thin(True)[:20])

        assert answer["present"] is None

    def test_ten_thousand_slices_at_one_offset_are_refused_fast(self) -> None:
        piece = _thin(True)

        def fat(count: int) -> bytes:
            start = 8 + 20 * count
            blob = struct.pack(">II", 0xCAFEBABE, count)
            blob += struct.pack(">iiIII", 0x01000007, 3, start, len(piece), 12) * count
            return blob + piece

        answer = identify._macho_signing(fat(10_000))

        assert_scales(fat, 1250, identify._macho_signing)
        assert answer["present"] is None and "slices" not in answer
        assert answer["reason"].startswith(f"{identify.NOT_A_FAT_HEADER}: the slices at")

    def test_slices_shifted_by_one_byte_overlap_and_are_refused(self) -> None:
        piece = _thin(True)
        blob = struct.pack(">II", 0xCAFEBABE, 2)
        blob += struct.pack(">iiIII", 0x01000007, 3, 0x100, len(piece), 12)
        blob += struct.pack(">iiIII", 0x01000007, 3, 0x101, len(piece), 12)
        blob += bytes(0x100 - len(blob)) + piece + bytes(8)

        answer = identify._macho_signing(blob)

        assert answer["present"] is None
        assert answer["reason"] == (
            f"{identify.NOT_A_FAT_HEADER}: the slices at 256 and 257 overlap"
        )

    def test_millions_of_commands_stop_at_the_slice_end(self) -> None:
        commands = struct.pack("<II", _LC_UUID, 8) * 100

        def claiming(count: int) -> bytes:
            header = struct.pack(
                "<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, count, len(commands), 0, 0
            )
            return header + commands

        answer = identify._macho_signing(claiming(5_000_000))

        # The commands claimed do not set the work: the slice's end does.
        assert_scales(claiming, 625_000, identify._macho_signing)
        assert answer["present"] is None
        assert answer["reason"].startswith("load commands unread:")

    def test_a_command_ending_past_its_slice_is_unread_not_unsigned(self) -> None:
        piece = _thin(False)
        cut = piece[:-8]
        answer = identify._macho_signing(_fat(cut, _thin(False)))

        assert answer["present"] is None
        assert answer["slices"][0]["reason"] == (
            "load commands unread: a command's end runs past the slice's end"
        )

    def test_the_bytes_walked_are_at_most_the_file_s_size(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        walked: list[int] = []
        real = struct

        class _Counted:
            @staticmethod
            def unpack_from(layout: str, data: bytes, offset: int = 0) -> tuple[Any, ...]:
                walked.append(real.calcsize(layout))
                return real.unpack_from(layout, data, offset)

        monkeypatch.setattr(identify, "struct", _Counted)
        # Many small commands in each of three slices, and a huge ncmds.
        commands = struct.pack("<II", _LC_UUID, 8) * 500
        thin = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 10**6, 0, 0, 0)
        blob = _fat(thin + commands, thin + commands, thin + commands)

        identify._macho_signing(blob)

        assert sum(walked) <= len(blob)

    def test_the_reason_stands_before_the_slices(self) -> None:
        # Two thousand zero-size slices, each at its own offset: none holds a
        # header, so every slice is unread and the reason must survive a cut.
        count = 2000
        start = 8 + 20 * count
        blob = struct.pack(">II", 0xCAFEBABE, count)
        for index in range(count):
            blob += struct.pack(">iiIII", 0x01000007, 3, start + index, 0, 12)
        blob += bytes(count)

        answer = identify._macho_signing(blob)

        assert list(answer)[:2] == ["present", "reason"]
        assert answer["present"] is None and len(answer["slices"]) == count

    def test_a_java_class_file_is_not_called_a_malformed_fat_header(self) -> None:
        java = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(64)

        answer = identify._macho_signing(java)

        assert answer["present"] is None
        assert answer["reason"].startswith(f"{identify.NOT_A_FAT_HEADER}: ")
        line = triage_pack._signature({"format": "mach-o", "macho": answer})
        assert line.startswith("unknown (not a readable fat Mach-O: ")

    def test_signing_info_and_the_pack_line(self, tmp_path: Path) -> None:
        target = tmp_path / "fat.bin"
        target.write_bytes(_fat(_thin(False), offsets=[0x9000]))

        answer = identify.signing_info(str(target))

        assert answer["format"] == "mach-o"
        assert triage_pack._signature(answer).startswith("unknown (")
        assert not triage_pack._carries_signature(answer)


def _floss_document() -> dict[str, Any]:
    return {
        "metadata": {"version": "3.1.1", "imagebase": 0x10000000, "runtime": {"total": 1.0}},
        "analysis": {"functions": {"discovered": 3, "analyzed_decoded_strings": 1}},
        "strings": {
            "decoded_strings": [
                {"string": "decoded-text", "decoding_routine": 0x10001000, "decoded_at": 0x10001010}
            ],
            "stack_strings": [],
            "tight_strings": [],
        },
    }


class TestFlossStreamsAndWhatIsRemembered:
    @pytest.fixture(autouse=True)
    def _scratch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        emulated_strings.forget_documents()

    def test_stdout_is_read_whole_and_stderr_only_its_tail(self, tmp_path: Path) -> None:
        script = (
            "import sys; sys.stderr.write('w' * 300000 + '\\nlast line\\n'); "
            "sys.stdout.write('{\"ok\": 1}')"
        )
        finished = emulated_strings._run([sys.executable, "-c", script], 30)

        assert json.loads(finished.stdout) == {"ok": 1}
        assert len(finished.stderr) <= emulated_strings._STDERR_TAIL_BYTES
        assert finished.stderr.endswith("last line\n")

    def test_only_the_rows_and_run_facts_are_remembered(self, tmp_path: Path) -> None:
        target = tmp_path / "s.dll"
        target.write_bytes(b"MZ" + bytes(62))

        def runner(argv: Any, _timeout: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(list(argv), 0, json.dumps(_floss_document()), "")

        answer = emulated_strings.floss(str(target), runner=runner)

        assert answer["strings"][0]["string"] == "decoded-text"
        (kept,) = emulated_strings._REMEMBERED.values()
        assert set(kept) == {"rows", "meta"}
        paged = emulated_strings.floss(str(target), offset=0, emulate=False)
        assert paged["strings"] == answer["strings"] and paged["meta"] == answer["meta"]

    def test_a_caller_waiting_when_the_server_ends_starts_no_child(self, tmp_path: Path) -> None:
        import threading

        from maljan.tools import children

        target = tmp_path / "s.dll"
        target.write_bytes(b"MZ" + bytes(62))
        started: list[int] = []

        def runner(argv: Any, _timeout: Any) -> subprocess.CompletedProcess[str]:
            started.append(1)
            return subprocess.CompletedProcess(list(argv), 0, json.dumps(_floss_document()), "")

        key = emulated_strings.remembered_key(target, 4)
        held = emulated_strings._IN_FLIGHT.setdefault(key, threading.Lock())
        answers: list[dict[str, Any]] = []
        try:
            with held:
                waiter = threading.Thread(
                    target=lambda: answers.append(
                        emulated_strings.floss(str(target), runner=runner)
                    )
                )
                waiter.start()
                time.sleep(0.1)
                children.kill_all()
            waiter.join(5)
        finally:
            children.reopen()

        assert started == []
        assert answers[0]["error"] == emulated_strings.SERVER_ENDING

    def test_a_child_registered_after_the_end_is_killed_at_once(self) -> None:
        from maljan.tools import children

        killed: list[int] = []
        children.kill_all()
        try:
            with children.running_as(("late", 1)):
                children.register(lambda: killed.append(1))
        finally:
            children.reopen()

        assert killed == [1]

    def test_a_page_with_nothing_remembered_does_not_emulate(self, tmp_path: Path) -> None:
        target = tmp_path / "s.dll"
        target.write_bytes(b"MZ" + bytes(62))

        def runner(*_args: Any) -> subprocess.CompletedProcess[str]:
            raise AssertionError("emulated")

        answer = emulated_strings.floss(str(target), runner=runner, emulate=False)

        assert answer["error"] == emulated_strings.NOT_REMEMBERED


def _zip_with_a_broken_directory() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("word/document.xml", "<w/>")
        archive.writestr("word/_rels/document.xml.rels", "<Relationships/>")
    blob = bytearray(out.getvalue())
    at = blob.rfind(b"PK\x01\x02")
    blob[at : at + 4] = b"XXXX"
    return bytes(blob)


class TestADamagedArchiveIsAnAnswer:
    def test_a_zip_whose_directory_does_not_read(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.zip"
        target.write_bytes(_zip_with_a_broken_directory())

        answer = binary.archive_list(str(target))

        assert answer["tool"] == "archive_list"
        assert answer["error"].startswith("zip read failed: BadZipFile")

    def test_a_package_whose_directory_does_not_read(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.docx"
        target.write_bytes(_zip_with_a_broken_directory())

        answer = binary.document_info(str(target))

        assert answer["tool"] == "document_info"
        assert answer["error"].startswith("OOXML read failed: BadZipFile")

    def test_a_truncated_compressed_tar_lists_what_it_read(self, tmp_path: Path) -> None:
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as archive:
            for index in range(3):
                payload = os.urandom(20_000)
                info = tarfile.TarInfo(f"member{index}")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        whole = out.getvalue()
        target = tmp_path / "cut.tgz"
        target.write_bytes(whole[: len(whole) // 2])

        answer = binary.archive_list(str(target))

        assert answer["format"] == "tar" and answer["truncated"] is True
        assert answer["members"][0]["name"] == "member0"
        assert "the tar stream broke there" in answer["listing_stopped"]


def _gzip_with(flags: int, tail: bytes) -> bytes:
    plain = gzip.compress(b"payload")
    header = bytearray(plain[:10])
    header[3] = flags
    return bytes(header) + tail + plain[10:]


class TestTheGzipName:
    def test_the_name_is_read_after_the_extra_field(self, tmp_path: Path) -> None:
        target = tmp_path / "x.gz"
        extra = struct.pack("<H", 6) + b"AB\x02\x00\x00\x00"
        target.write_bytes(_gzip_with(0x04 | 0x08, extra + b"inner.exe\x00"))

        (member,) = binary.archive_list(str(target))["members"]

        assert member["name"] == "inner.exe"

    def test_a_name_with_no_end_is_not_stated(self, tmp_path: Path) -> None:
        target = tmp_path / "x.gz"
        target.write_bytes(bytes(_gzip_with(0x08, b""))[:10] + b"no-zero-byte-here")

        answer = binary._gzip_member(target)

        assert answer["members"][0]["name"] == ""
        assert answer["name_unread"] == binary.GZIP_NAME_UNENDED.format(room=8)

    def test_a_name_that_leaves_the_member_no_room_is_cut_and_said(self, tmp_path: Path) -> None:
        target = tmp_path / "x.gz"
        # 3 MB with no zero byte: read once, not held, the room stated.
        target.write_bytes(bytes(_gzip_with(0x08, b""))[:10] + b"A" * (3 * 1024 * 1024))

        answer = binary._gzip_member(target)

        assert answer["members"][0]["name"] == ""
        room = 3 * 1024 * 1024 - binary._GZIP_AFTER_NAME
        assert answer["name_unread"] == binary.GZIP_NAME_UNENDED.format(room=room)

    def test_a_zero_byte_inside_the_trailer_does_not_end_a_name(self, tmp_path: Path) -> None:
        target = tmp_path / "x.gz"
        target.write_bytes(bytes(_gzip_with(0x08, b""))[:10] + b"abcdef\x00" + b"123456789")

        answer = binary._gzip_member(target)

        assert answer["members"][0]["name"] == "abcdef"
        target.write_bytes(bytes(_gzip_with(0x08, b""))[:10] + b"abcdef" + b"1234\x00678")
        assert "name_unread" in binary._gzip_member(target)

    def test_an_extra_field_past_the_end_is_said(self, tmp_path: Path) -> None:
        target = tmp_path / "x.gz"
        target.write_bytes(bytes(_gzip_with(0x04 | 0x08, b""))[:10] + struct.pack("<H", 9000))

        answer = binary._gzip_member(target)

        assert answer["name_unread"] == "the gzip header ends inside its extra field"


class TestACarvedPayloadIsWrittenWhole:
    def test_short_writes_are_continued(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = os.write
        monkeypatch.setattr(binary.os, "write", lambda fd, data: real(fd, bytes(data[:3])))
        child = tmp_path / "payload"
        blob = bytes(range(256)) * 4

        assert binary._write_carved(child, blob) is None
        assert child.read_bytes() == blob

    def test_a_failed_write_leaves_no_part_behind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = os.write
        calls: list[int] = []

        def _write(fd: int, data: Any) -> int:
            calls.append(1)
            if len(calls) > 1:
                raise OSError("disk full")
            return real(fd, bytes(data[:3]))

        monkeypatch.setattr(binary.os, "write", _write)
        child = tmp_path / "payload"

        assert binary._write_carved(child, b"x" * 100) == "cannot write payload: OSError"
        assert not child.exists()


def test_unread_decoder_rows_leave_the_comparison_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _broken(_path: Any) -> list[dict[str, Any]]:
        raise RuntimeError("remembered store unreadable")

    monkeypatch.setattr(emulated_strings, "remembered_rows", _broken)
    image = SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 0x100)])
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())

    answer = string_blobs.decode_string_blobs(str(target))

    row_field, compared, also = string_blobs.decoder_fields(string_blobs.decoder_word())
    assert answer[compared] is None and answer[also] is None
    assert answer[f"{row_field}_rows_unread"] == "RuntimeError: remembered store unreadable"


class TestTheGzipNameAtTheBlockEdge:
    def _answer(self, tmp_path: Path, name_length: int) -> dict[str, Any]:
        target = tmp_path / "x.gz"
        target.write_bytes(
            bytes(_gzip_with(0x08, b""))[:10] + b"n" * name_length + b"\x00" + b"D" * 9
        )
        return binary._gzip_member(target)

    def test_a_zero_byte_exactly_at_the_block_size(self, tmp_path: Path) -> None:
        size = binary._GZIP_NAME_BLOCK
        answer = self._answer(tmp_path, size)
        assert answer["members"][0]["name"] == "n" * size
        assert "name_unread" not in answer

    def test_a_zero_byte_one_past_the_block_size(self, tmp_path: Path) -> None:
        size = binary._GZIP_NAME_BLOCK + 1
        answer = self._answer(tmp_path, size)
        assert answer["members"][0]["name"] == "n" * size

    def test_a_zero_byte_one_before_the_block_size(self, tmp_path: Path) -> None:
        size = binary._GZIP_NAME_BLOCK - 1
        answer = self._answer(tmp_path, size)
        assert answer["members"][0]["name"] == "n" * size


def test_a_fifty_megabyte_name_is_cut_by_the_answer_guardrail(tmp_path: Path) -> None:
    """A name with a zero byte is stated whole by the tool; the answer layer cuts it.

    Every tool answer meets the output guardrail before a model reads it or the
    ledger stores it (``MCPLangChainToolkit._apply_output_guardrail``): the
    operator's ``max_output_chars`` or, without one, the served model's room. An
    answer too large for the document shortener (``MAX_SHORTENABLE_CHARS``) is cut
    by characters there, so the tool holds no limit of its own.
    """
    from maljan.agents.mcp_client import MCPLangChainToolkit

    length = 50 * 1024 * 1024
    target = tmp_path / "big.gz"
    target.write_bytes(bytes(_gzip_with(0x08, b""))[:10] + b"n" * length + b"\x00" + b"D" * 9)

    answer = binary.archive_list(str(target))
    assert len(answer["members"][0]["name"]) == length

    limit = 20_000
    kept = MCPLangChainToolkit(
        max_output_chars=limit, truncation_ledger=None
    )._apply_output_guardrail(json.dumps(answer))

    assert len(kept) <= limit
    assert len(kept) < length
