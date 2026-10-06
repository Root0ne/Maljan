"""What the capture reader reads is bounded by facts, and it says where it stopped.

A record's bytes are read up to the snapshot length the capture declares; a
gzip capture is decompressed no further than the byte cap the platform puts on
a capture it downloads, and the answer says so; a gzip stream cut in its
header is not a capture.
"""

from __future__ import annotations

import gzip
import struct
from pathlib import Path

import pytest

from maljan.analysis import capture_reader
from maljan.analysis.pcap_summary import capture_facts, each_packet
from maljan.providers.sandbox import limits


def _pcap(records: list[bytes], snaplen: int = 65535) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 101)
    for index, data in enumerate(records):
        out += struct.pack("<IIII", 1_700_000_000 + index, 0, len(data), len(data)) + data
    return out


def _udp_to(dst: bytes, dport: int, payload: bytes = b"") -> bytes:
    udp = struct.pack("!HHHH", 40000, dport, 8 + len(payload), 0) + payload
    return (
        struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, b"\x0a\x00\x00\x02", dst
        )
        + udp
    )


def test_a_record_is_read_up_to_the_declared_snapshot_length(tmp_path: Path) -> None:
    long_record = _udp_to(b"\x08\x08\x08\x08", 9, b"x" * 400)
    target = tmp_path / "snap.pcap"
    target.write_bytes(_pcap([long_record, _udp_to(b"\x01\x01\x01\x01", 7)], snaplen=100))

    read = list(capture_reader.packets(str(target)))

    assert [p.length for p in read] == [100, 28]
    assert [p.ip_dst for p in read] == ["8.8.8.8", "1.1.1.1"]


def test_a_gzip_capture_stops_at_the_platform_cap_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [_udp_to(b"\x08\x08\x08\x08", 9, b"y" * 100) for _ in range(50)]
    target = tmp_path / "big.pcap.gz"
    target.write_bytes(gzip.compress(_pcap(records)))
    monkeypatch.setattr(limits, "MAX_RESPONSE_BYTES", 24 + 5 * (16 + 128) + 10)

    seen: list[object] = []
    read = each_packet(str(target), seen.append)

    assert read.packets_read == 5
    assert read.byte_cap == limits.MAX_RESPONSE_BYTES
    assert not read.whole
    assert "5 packets read" in read.statement()
    assert "reading stopped at the" in read.statement()
    facts = capture_facts(str(target))
    assert facts is not None and facts["byte_cap"] == limits.MAX_RESPONSE_BYTES


def test_a_gzip_capture_under_the_cap_reads_whole(tmp_path: Path) -> None:
    target = tmp_path / "small.pcap.gz"
    target.write_bytes(gzip.compress(_pcap([_udp_to(b"\x08\x08\x08\x08", 9)] * 3)))

    read = each_packet(str(target), lambda _p: None)

    assert read.whole and read.byte_cap is None
    assert read.statement() == "3 of 3 packets in the capture read"


@pytest.mark.parametrize("cut", [6, 12, 20])
def test_a_gzip_stream_cut_in_its_header_is_not_a_capture(tmp_path: Path, cut: int) -> None:
    target = tmp_path / "cut.pcap.gz"
    target.write_bytes(gzip.compress(_pcap([_udp_to(b"\x08\x08\x08\x08", 9)]))[:cut])

    with pytest.raises(capture_reader.CaptureFormatError):
        list(capture_reader.packets(str(target)))


def test_a_long_pcapng_option_list_is_walked_once() -> None:
    options = struct.pack("<HH", 2, 0) * 100_000 + struct.pack("<HH", 9, 1) + b"\x09\x00\x00\x00"

    found = capture_reader._pcapng_options(options, "<")

    assert found[9] == b"\x09"
