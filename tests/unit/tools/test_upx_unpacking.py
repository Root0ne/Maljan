"""UPX unpacking reads a packed PE back into the program, from UPX's own records.

Every packed file here is synthetic: ``synthetic_upx`` writes a small program,
lays it out as UPX's PE packer does and compresses it with encoders written
for the tests (NRV2B, NRV2D, NRV2E) or the standard library's LZMA1. The
unpacked program is compared with what was packed, byte for byte where the
bytes are the program's own and through the PE reader where UPX rebuilds a
table. The hostile inputs are packed files of the same kind with one fact
made untrue.
"""

from __future__ import annotations

import os
import random
import stat
import struct
import time
import tracemalloc
import zlib
from pathlib import Path

import pefile
import pytest

from maljan.tools import binary, upx
from tests.unit.tools import synthetic_upx as su
from tests.unit.tools.synthetic_pe import SyntheticPE


def _sample(seed: int = 7) -> bytes:
    """Bytes with literals, near and far repeats, a repeated offset and a long run."""
    rng = random.Random(seed)
    head = bytes(rng.randrange(256) for _ in range(5000))
    words = b"".join(rng.choice([b"call ", b"push ", b"mov eax, ", b"ret\n"]) for _ in range(600))
    return head + words + b"\0" * 3000 + head[:900] + head[100:400] + b"ab" * 700 + head[-200:]


# ---------------------------------------------------------------------------
# The decoders, round trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", sorted([*su.METHOD_ENCODERS, 14]))
def test_each_method_decodes_what_its_encoder_wrote(method: int) -> None:
    data = _sample()
    stream = su.compress(method, data)
    assert len(stream) < len(data)
    assert bytes(upx.decompress(method, stream, len(data))) == data


def test_the_nrv_encoders_reach_every_form_the_decoders_read() -> None:
    # Far offsets (past 0xd00 and 0x500), the repeated offset and overlapping
    # copies are all in the sample: a decoder that got one form wrong fails here.
    data = _sample(11)
    for kind in ("2b", "2d", "2e"):
        for width in (1, 2, 4):
            stream = su.nrv_compress(data, kind, width)
            assert bytes(upx._nrv(kind, width, stream, len(data))) == data


def test_a_single_byte_and_a_long_run_round_trip() -> None:
    for data in (b"Z", b"Z" * 70000, bytes(range(256)) * 300):
        for kind in ("2b", "2d", "2e"):
            assert bytes(upx._nrv(kind, 4, su.nrv_compress(data, kind), len(data))) == data


# ---------------------------------------------------------------------------
# The whole unpack
# ---------------------------------------------------------------------------


def _section(pe: pefile.PE, name: bytes) -> pefile.SectionStructure:
    return next(s for s in pe.sections if s.Name.rstrip(b"\0") == name)


def _imports(pe: pefile.PE) -> dict[str, list[str | int]]:
    found: dict[str, list[str | int]] = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        found[entry.dll.decode()] = [
            int(imp.ordinal) if imp.import_by_ordinal else imp.name.decode()
            for imp in entry.imports
        ]
    return found


def _expected_imports(packed: su.Packed) -> dict[str, list[str | int]]:
    return {
        dll: [77 if e == "#packed-ordinal" else e for e in entries]
        for dll, entries in packed.imports.items()
    }


def _check_program(packed: su.Packed, image: bytes) -> pefile.PE:
    pe = pefile.PE(data=image)
    assert _section(pe, b".text").get_data()[: len(packed.text)] == packed.text
    assert _section(pe, b".data").get_data()[: len(packed.data_section)] == packed.data_section
    assert _imports(pe) == _expected_imports(packed)
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == su.ENTRY
    assert pe.OPTIONAL_HEADER.ImageBase == packed.image_base
    return pe


def test_a_packed_program_comes_back_whole() -> None:
    packed = su.build()
    result = upx.unpack(packed.data)
    pe = _check_program(packed, result.image)
    # Relocations: every slot, as HIGHLOW, in the rebuilt table.
    slots = sorted(e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type == 3)
    assert slots == sorted(packed.relocated)
    # Exports: the moved table written back at its place, forwarder included.
    exports = {e.name.decode(): e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols}
    assert exports["Alpha"].address == su.TEXT + 0x20
    assert exports["Beta"].address == su.TEXT + 0x40
    assert exports["Gamma"].forwarder == b"NTDLL.RtlZeroMemory"
    assert pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions > su.EXPORT_TABLE
    # Resources: the directory rebuilt, the kept data in place, the moved icon
    # group back with UPX's icon count written into it.
    types = {e.id: e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries}
    assert set(types) == {10, 14}
    icon_entry = types[14].directory.entries[0]
    assert str(icon_entry.name) == "ICONS"
    icon_data = icon_entry.directory.entries[0].data.struct
    assert icon_data.OffsetToData == su.ICON_AT
    icon = pe.get_data(su.ICON_AT, len(packed.icon))
    assert icon[:4] == packed.icon[:4] and icon[6:] == packed.icon[6:]
    assert struct.unpack("<H", icon[4:6])[0] == packed.icon_count
    assert pe.get_data(su.RCDATA_AT, len(packed.rcdata)) == packed.rcdata
    assert result.checksum_reading == "the data as decompressed, before the filter is undone"
    assert result.rebuilt["imports"] == "from UPX's import records: 3 libraries, 7 functions"
    assert result.rebuilt["relocations"] == "from UPX's relocation records: 41 relocations"
    assert "directory rebuilt" in result.rebuilt["resources"]
    assert [w for w in pe.get_warnings() if not w.startswith("Byte 0x00 makes up")] == []


@pytest.mark.parametrize(
    ("method", "filter_id"),
    [(2, 0x26), (5, 0x26), (8, 0x26), (14, 0x26), (3, 0x24), (7, 0x25), (10, 0), (9, 0x26)],
)
def test_every_method_and_filter_unpacks(method: int, filter_id: int) -> None:
    packed = su.build(su.Program(method=method, filter_id=filter_id))
    result = upx.unpack(packed.data)
    _check_program(packed, result.image)
    assert result.header.method == method
    assert result.c_adler == result.header.c_adler
    assert result.u_adler == result.header.u_adler


def test_the_checksum_over_the_unfiltered_data_is_read_and_said() -> None:
    packed = su.build(su.Program(checksum_unfiltered=True))
    result = upx.unpack(packed.data)
    _check_program(packed, result.image)
    assert result.checksum_reading == "the data with the filter undone"


def test_a_64_bit_program_comes_back() -> None:
    for filter_id in (0, 0x26):
        packed = su.build(su.Program(is64=True, filter_id=filter_id, method=8))
        pe = _check_program(packed, upx.unpack(packed.data).image)
        slots = sorted(
            e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type == 10
        )
        assert slots == sorted(packed.relocated)


def test_a_resource_directory_left_whole_is_kept() -> None:
    packed = su.build(su.Program(wipe_resource_directory=False))
    result = upx.unpack(packed.data)
    assert result.rebuilt["resources"].endswith("the directory kept as stored")
    pe = pefile.PE(data=result.image)
    assert {e.id for e in pe.DIRECTORY_ENTRY_RESOURCE.entries} == {10, 14}


def test_no_relocations_and_no_exports_are_said() -> None:
    packed = su.build(su.Program(relocate=False, exports=[], forwarders=[]))
    result = upx.unpack(packed.data)
    _check_program(packed, result.image)
    assert result.rebuilt["relocations"].startswith("none:")
    assert result.rebuilt["exports"].startswith("none:")


def test_the_overlay_is_carried_over() -> None:
    packed = su.build(su.Program(overlay=b"OVERLAY-BYTES" * 10))
    result = upx.unpack(packed.data)
    assert result.overlay == 130
    assert result.image.endswith(b"OVERLAY-BYTES" * 10)


# ---------------------------------------------------------------------------
# The file tool
# ---------------------------------------------------------------------------


def test_the_tool_writes_the_program_private_and_states_the_facts(tmp_path: Path) -> None:
    packed = su.build()
    sample = tmp_path / "packed.exe"
    sample.write_bytes(packed.data)
    where = tmp_path / "carved"
    answer = upx.unpack_upx(str(sample), where)
    child = answer["child"]
    written = Path(child["carved_path"])
    assert written.parent == where
    assert written.name == binary.carved_file_name(upx.UNPACKED_LABEL, child["sha256"])
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert stat.S_IMODE(where.stat().st_mode) == 0o700
    image = written.read_bytes()
    _check_program(packed, image)
    assert answer["unpacked"] == "yes"
    assert answer["pack_header"]["method"] == "NRV2B_LE32 (2)"
    assert answer["pack_header"]["filter"] == "0x26"
    assert answer["unpacked_size"] == packed.u_len
    assert answer["compressed_size"] < packed.u_len
    assert answer["checksums"]["compressed"]["matched"] is True
    assert answer["checksums"]["unpacked"]["matched"] is True
    assert answer["import_count"] == 7 and answer["import_libraries"] == 3
    assert [s["name"] for s in answer["sections"]] == [
        ".text",
        ".rdata",
        ".data",
        ".rsrc",
        ".reloc",
    ]
    assert answer["entry_point"] == hex(su.ENTRY)
    # A second run finds its own file and answers the same.
    assert upx.unpack_upx(str(sample), where) == answer


def test_a_file_that_is_not_upx_packed_says_why(tmp_path: Path) -> None:
    plain = tmp_path / "plain.exe"
    plain.write_bytes(SyntheticPE(is64=False, image_base=0x400000).build())
    assert upx.unpack_upx(str(plain), tmp_path / "c") == {"unpacked": upx.NO_HEADER}
    text = tmp_path / "notes.txt"
    text.write_bytes(b"just text, no header at all, long enough to be read" * 3)
    said = upx.unpack_upx(str(text), tmp_path / "c")["unpacked"]
    assert said.startswith("no: the file is not a PE image")
    assert not (tmp_path / "c").exists()


# ---------------------------------------------------------------------------
# Hostile inputs
# ---------------------------------------------------------------------------


def _with_header(packed: su.Packed, **fields: int) -> bytes:
    """``packed`` with its pack header rewritten (checksum byte recomputed)."""
    data = bytearray(packed.data)
    at = packed.header_offset
    old = data[at : at + 32]
    u_adler, c_adler, u_len, c_len, u_file_size = struct.unpack_from("<IIIII", old, 8)
    values = {
        "version": old[4],
        "format_id": old[5],
        "method": old[6],
        "level": old[7],
        "u_adler": u_adler,
        "c_adler": c_adler,
        "u_len": u_len,
        "c_len": c_len,
        "u_file_size": u_file_size,
        "filter_id": old[28],
        "cto": old[29],
    }
    values.update(fields)
    data[at : at + 32] = su.pack_header(**values)
    return bytes(data)


def _peak(call: object) -> tuple[object, int]:
    tracemalloc.start()
    try:
        try:
            outcome: object = call()  # type: ignore[operator]
        except (upx.NotRead, upx.Damaged) as exc:
            outcome = exc
        return outcome, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_a_header_claiming_4_gib_is_answered_with_the_cap() -> None:
    packed = su.build()
    data = _with_header(packed, u_len=0xFFFFFFFF)
    outcome, peak = _peak(lambda: upx.unpack(data))
    assert isinstance(outcome, upx.NotRead)
    assert str(outcome) == upx.OVER_CAP.format(size=0xFFFFFFFF, cap=upx.UNPACKED_CAP)
    assert outcome.header is not None and outcome.header.u_len == 0xFFFFFFFF
    assert peak < 4 * len(data) + (1 << 20)


def test_a_header_larger_than_the_image_it_maps_is_an_error() -> None:
    packed = su.build()
    data = _with_header(packed, u_len=upx.UNPACKED_CAP)
    with pytest.raises(upx.Damaged, match="more than the .* bytes of image the packed file maps"):
        upx.unpack(data)


def test_a_file_cut_inside_the_stream_is_an_error() -> None:
    packed = su.build()
    with pytest.raises(upx.Damaged, match="the file is cut short"):
        upx.unpack(packed.data[: su.UPX1_RAW + 100])


def test_a_stream_that_ends_before_its_marker_is_an_error() -> None:
    packed = su.build()
    start = packed.header_offset + 32
    stream = su.compress(2, packed.obuf)[:-40]
    data = bytearray(packed.data)
    data[start : start + len(stream) + 40] = stream + bytes(40)
    fixed = _with_header(
        su.Packed(**{**packed.__dict__, "data": bytes(data)}),
        c_len=len(stream),
        c_adler=zlib.adler32(stream),
    )
    with pytest.raises(upx.Damaged, match="before its end marker"):
        upx.unpack(fixed)


def test_a_compressed_checksum_mismatch_is_an_error_and_writes_nothing(tmp_path: Path) -> None:
    packed = su.build()
    data = bytearray(packed.data)
    data[packed.header_offset + 32 + 50] ^= 0x01
    sample = tmp_path / "s.exe"
    sample.write_bytes(bytes(data))
    answer = upx.unpack_upx(str(sample), tmp_path / "c")
    assert answer["error"]["code"] == "tool_failed"
    assert "the compressed data's adler32 is" in answer["error"]["message"]
    assert answer["error"]["remediation"] == upx.REMEDIATION
    assert answer["pack_header"]["method"] == "NRV2B_LE32 (2)"
    assert not (tmp_path / "c").exists()


def test_an_unpacked_checksum_mismatch_names_both_readings() -> None:
    packed = su.build()
    data = _with_header(packed, u_adler=0x12345678)
    with pytest.raises(upx.Damaged) as raised:
        upx.unpack(data)
    message = str(raised.value)
    assert "as decompressed and" in message and "with the filter undone" in message
    assert "0x12345678" in message


def test_a_header_whose_checksum_byte_is_wrong_is_an_error() -> None:
    packed = su.build()
    data = bytearray(packed.data)
    data[packed.header_offset + 31] ^= 0xFF
    with pytest.raises(upx.Damaged, match="states checksum byte"):
        upx.unpack(bytes(data))


def test_an_unknown_filter_and_method_are_not_read_here() -> None:
    packed = su.build()
    for fields, said in (
        ({"filter_id": 0x49}, upx.FILTER_NOT_READ.format(filter=0x49)),
        ({"method": 15}, upx.METHOD_NOT_READ.format(method=15)),
        (
            {"format_id": 12},
            upx.FORMAT_NOT_READ.format(offset=hex(packed.header_offset), format=12),
        ),
        ({"version": 9}, upx.OLD_VERSION.format(offset=hex(packed.header_offset), version=9)),
    ):
        with pytest.raises(upx.NotRead) as raised:
            upx.unpack(_with_header(packed, **fields))
        assert str(raised.value) == said


def _stream_2b(*tokens: tuple[str, int, int]) -> bytes:
    """An NRV2B stream from literal and match tokens, with no end marker unless asked."""
    bits = su._Bits(4)
    last = 1
    for kind, a, b in tokens:
        if kind == "lit":
            bits.bit(1)
            bits.byte(a)
        elif kind == "match":
            su._match(bits, "2b", a, b, last, 0xD00)
            last = a
        elif kind == "end":
            bits.bit(0)
            su._gamma(bits, su.END_PREFIX)
            bits.byte(0xFF)
    return bits.finish()


def test_back_references_are_held_to_the_output_and_its_start() -> None:
    # A copy longer than the stated size stops before it is made.
    stream = _stream_2b(("lit", 0x41, 0), ("match", 1, 10_000_000), ("end", 0, 0))
    outcome, peak = _peak(lambda: upx._nrv("2b", 4, stream, 1000))
    assert isinstance(outcome, upx.Damaged)
    assert "runs past the 1000 unpacked bytes the header states" in str(outcome)
    assert peak < 1 << 20
    # A copy from before the first byte is refused.
    stream = _stream_2b(("lit", 0x41, 0), ("match", 5, 3), ("end", 0, 0))
    with pytest.raises(upx.Damaged, match="before the start of the output"):
        upx._nrv("2b", 4, stream, 100)
    # A loop of back-references to one byte fills exactly the stated size.
    tokens = [("lit", 0x41, 0)] + [("match", 1, 999)] * 100 + [("end", 0, 0)]
    stream = _stream_2b(*tokens)
    out, peak = _peak(lambda: upx._nrv("2b", 4, stream, 1 + 999 * 100))
    assert out == bytearray(b"A" * (1 + 999 * 100))
    assert peak < 4 * (1 + 999 * 100) + (1 << 20)
    with pytest.raises(upx.Damaged, match="past the"):
        upx._nrv("2b", 4, stream, 999 * 100)


def test_an_endless_length_prefix_stops_at_the_room_left() -> None:
    bits = su._Bits(4)
    bits.bit(1)
    bits.byte(0x41)
    bits.bit(0)
    su._gamma(bits, 3)
    bits.byte(0)  # offset 1
    bits.bit(0)
    bits.bit(0)
    for _ in range(200_000):
        bits.bit(1)
        bits.bit(0)
    stream = bits.finish()
    began = time.monotonic()
    with pytest.raises(
        upx.Damaged, match="a length at output byte 1 runs past the 4096 unpacked bytes"
    ):
        upx._nrv("2b", 4, stream, 4096)
    assert time.monotonic() - began < 1.0


def test_random_bytes_as_a_stream_fail_in_linear_time() -> None:
    noise = os.urandom(200_000)
    for kind in ("2b", "2d", "2e"):
        began = time.monotonic()
        with pytest.raises(upx.Damaged):
            upx._nrv(kind, 4, noise, 2_000_000)
        assert time.monotonic() - began < 10.0


def test_a_truncated_lzma_stream_is_an_error() -> None:
    data = _sample()
    stream = su.lzma_compress(data)
    with pytest.raises(upx.Damaged, match="the LZMA stream ends after"):
        upx.decompress(14, stream[: len(stream) // 2], len(data))
    with pytest.raises(upx.Damaged, match="properties bytes"):
        upx.decompress(14, b"\xff\xff" + stream[2:], len(data))


def test_a_resource_tree_that_shares_its_directories_is_held_to_its_section() -> None:
    packed = su.build()
    pe = pefile.PE(data=packed.data, fast_load=True)
    third = pe.sections[2]
    tree = third.PointerToRawData + 0x400
    data = bytearray(packed.data)
    count = 60

    def directory(at: int, child: int, flag: int) -> None:
        data[at : at + 16] = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, count)
        for index in range(count):
            struct.pack_into("<II", data, at + 16 + 8 * index, index + 1, child | flag)

    directory(tree, 0x200, 0x80000000)
    directory(tree + 0x200, 0x400, 0x80000000)
    directory(tree + 0x400, 0x600, 0)
    data[tree + 0x600 : tree + 0x610] = struct.pack("<IIII", su.RCDATA_AT, 4, 0, 0)
    outcome, peak = _peak(lambda: upx.unpack(bytes(data)))
    assert isinstance(outcome, upx.Damaged)
    assert "more entries than its section holds" in str(outcome)


def test_records_pointing_outside_the_image_are_errors() -> None:
    packed = su.build(su.Program(filter_id=0))
    obuf = bytearray(packed.obuf)
    # The last four bytes name where the stored header is: point them past the end.
    obuf[-4:] = struct.pack("<I", len(obuf) + 100)
    stream = su.compress(2, bytes(obuf))
    data = bytearray(packed.data)
    start = packed.header_offset + 32
    data[start : start + len(stream)] = stream
    patched = su.Packed(**{**packed.__dict__, "data": bytes(data)})
    fixed = _with_header(
        patched, c_len=len(stream), c_adler=zlib.adler32(stream), u_adler=zlib.adler32(obuf)
    )
    with pytest.raises(upx.Damaged, match="stored PE header .* lies outside the unpacked data"):
        upx.unpack(fixed)
