"""A capture whose framing ends early says where, and BSD loopback reads each family.

A pcapng block cut short, or whose trailing length disagrees with its leading
one, and a pcap file cut inside a record header or a record, end the capture
there: every packet before is read, and the answer now states the byte the
framing ended at and why, instead of reading as the whole capture.

A BSD loopback frame's family is written in the capturing host's byte order
(``DLT_NULL``) or in network order (``DLT_LOOP``), and the IPv6 family has a
different number on each BSD (24, 28, 30) and on Linux (10). The IP header is
read by its own version nibble, and a header whose version is not the one its
reader reads gives no addresses: the addresses are right or absent.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from maljan.analysis import capture_reader
from maljan.analysis.capture_reader import Record, decode
from maljan.analysis.pcap_summary import CaptureRead, capture_facts, each_packet

PUBLIC = b"\x08\x08\x08\x08"


def _ipv4(dst: bytes = PUBLIC) -> bytes:
    udp = struct.pack("!HHHH", 40000, 9, 8, 0)
    return (
        struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0, b"\x0a\x00\x00\x02", dst) + udp
    )


def _ipv6() -> bytes:
    udp = struct.pack("!HHHH", 40000, 9, 8, 0)
    src = bytes.fromhex("20010db8000000000000000000000001")
    dst = bytes.fromhex("20010db8000000000000000000000002")
    return struct.pack("!IHBB", 0x60000000, len(udp), 17, 64) + src + dst + udp


def _pcap(frames: list[bytes], linktype: int = 101) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, linktype)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)) + frame
    return out


def _block(kind: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    return struct.pack("<II", kind, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))


def _pcapng(blocks: list[bytes]) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 28) + shb_body + struct.pack("<I", 28)
    idb = _block(1, struct.pack("<HHI", 101, 0, 0))
    return shb + idb + b"".join(blocks)


def _epb(data: bytes) -> bytes:
    return _block(6, struct.pack("<IIIII", 0, 0, 0, len(data), len(data)) + data)


def _read(tmp_path: Path, name: str, data: bytes) -> CaptureRead:
    target = tmp_path / name
    target.write_bytes(data)
    return each_packet(str(target), lambda _p: None)


# ---------------------------------------------------------------- framing


def test_a_pcapng_block_with_a_wrong_trailing_length_is_stated(tmp_path: Path) -> None:
    good = _epb(_ipv4())
    bad = bytearray(_epb(_ipv4()))
    bad[-4:] = struct.pack("<I", 999)
    data = _pcapng([good, bytes(bad), good, good])
    read = _read(tmp_path, "tail.pcapng", data)
    assert read.packets_read == 1
    assert not read.whole
    at = len(_pcapng([good]))
    assert read.framing_end is not None
    assert f"byte {at}" in read.framing_end
    assert "trailing length" in read.framing_end
    assert "1 packets read" in read.statement()
    assert read.framing_end in read.statement()
    facts = capture_facts(str(tmp_path / "tail.pcapng"))
    assert facts is not None and facts["framing_end"] == read.framing_end


def test_a_pcapng_file_cut_inside_a_block_is_stated(tmp_path: Path) -> None:
    good = _epb(_ipv4())
    data = _pcapng([good, good])[:-10]
    read = _read(tmp_path, "cut.pcapng", data)
    assert read.packets_read == 1
    assert read.framing_end is not None
    assert f"byte {len(_pcapng([good]))}" in read.framing_end
    assert "cut short by the end of the file" in read.framing_end
    assert not read.whole


def test_a_pcap_file_cut_inside_a_record_header_is_stated(tmp_path: Path) -> None:
    data = _pcap([_ipv4(), _ipv4()])
    cut = data[: len(_pcap([_ipv4()])) + 7]
    read = _read(tmp_path, "head.pcap", cut)
    assert read.packets_read == 1
    assert read.framing_end is not None
    assert f"byte {len(_pcap([_ipv4()]))}" in read.framing_end
    assert "7 of its 16 bytes" in read.framing_end
    assert not read.whole


def test_a_pcap_record_cut_short_is_kept_and_stated(tmp_path: Path) -> None:
    data = _pcap([_ipv4(), _ipv4()])[:-5]
    read = _read(tmp_path, "record.pcap", data)
    assert read.packets_read == 2
    assert read.framing_end is not None
    assert "23 of its 28 bytes" in read.framing_end
    assert not read.whole


def test_a_capture_that_ends_on_a_boundary_is_whole(tmp_path: Path) -> None:
    for name, data in (
        ("whole.pcap", _pcap([_ipv4(), _ipv4()])),
        ("whole.pcapng", _pcapng([_epb(_ipv4()), _epb(_ipv4())])),
    ):
        read = _read(tmp_path, name, data)
        assert read.packets_read == 2 and read.framing_end is None
        assert read.whole
        assert read.statement() == "2 of 2 packets in the capture read"


def test_the_framing_end_round_trips_through_the_fields() -> None:
    read = CaptureRead(packets_read=3, packets_in_capture=3, framing_end="reading stopped")
    again = CaptureRead.from_fields(read.as_fields())
    assert again.framing_end == "reading stopped"
    assert not again.whole


# ---------------------------------------------------------------- loopback


def _loopback(family: bytes, packet: bytes, linktype: int) -> Record:
    return Record(0.0, family + packet, linktype)


@pytest.mark.parametrize("family", [24, 28, 30, 10])
@pytest.mark.parametrize("order", ["<", ">"])
def test_a_null_loopback_ipv6_frame_reads_its_addresses(family: int, order: str) -> None:
    packet = decode(_loopback(struct.pack(order + "I", family), _ipv6(), 0))
    assert packet.ip_src is None  # IPv6 addresses are not read into the IPv4 fields
    assert packet.udp is not None and packet.udp.dport == 9


@pytest.mark.parametrize("order", ["<", ">"])
def test_a_null_loopback_ipv4_frame_in_either_byte_order(order: str) -> None:
    packet = decode(_loopback(struct.pack(order + "I", 2), _ipv4(), 0))
    assert (packet.ip_src, packet.ip_dst) == ("10.0.0.2", "8.8.8.8")


@pytest.mark.parametrize("family", [24, 28, 30, 10])
def test_a_loop_ipv6_frame_reads_its_transport(family: int) -> None:
    packet = decode(_loopback(struct.pack(">I", family), _ipv6(), 108))
    assert packet.ip_src is None
    assert packet.udp is not None and packet.udp.dport == 9


def test_a_big_endian_ipv6_family_never_gives_made_up_ipv4_addresses() -> None:
    packet = decode(_loopback(struct.pack(">I", 30), _ipv6(), 0))
    assert packet.ip_src is None and packet.ip_dst is None


def test_a_header_whose_version_is_not_four_gives_no_ipv4_addresses() -> None:
    raw = bytearray(_ipv4())
    raw[0] = 0x55  # version 5, header length 20
    packet = decode(Record(0.0, bytes(raw), 101))
    assert packet.ip_src is None and packet.ip_dst is None and packet.udp is None


def test_an_unknown_loopback_family_reads_no_header() -> None:
    packet = decode(_loopback(struct.pack("<I", 7), _ipv4(), 0))
    assert packet.ip_src is None and packet.udp is None


def test_an_ipv6_datagram_is_counted_by_its_next_header_and_names_no_conversation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "six.pcap"
    target.write_bytes(_pcap([_ipv6(), _ipv6(), _ipv4()]))
    facts = capture_facts(str(target))
    assert facts is not None
    assert facts["protocols"] == {"udp": 3}
    assert [c["dst"] for c in facts["conversations"]] == ["8.8.8.8"]
    assert facts["conversations"][0]["packets"] == 1


def test_the_reader_module_still_reads_a_plain_capture(tmp_path: Path) -> None:
    target = tmp_path / "plain.pcap"
    target.write_bytes(_pcap([_ipv4()]))
    assert [p.ip_dst for p in capture_reader.packets(str(target))] == ["8.8.8.8"]
