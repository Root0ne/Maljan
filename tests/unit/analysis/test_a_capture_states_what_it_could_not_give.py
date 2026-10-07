"""What a hostile capture cannot do to the reader, and what the answer says instead.

- Unreadable pcapng blocks are told by kind of reason, each once with its
  count and its first occurrence, so the statement does not grow with them.
- An IP datagram is read only as far as its own header says, so a packet's
  payload is never larger than what its IP header declares. A total below the
  header length is what segmentation offload writes: the payload is the rest
  of the frame, up to the 65,535 octets an IPv4 header can state.
- A DNS name longer than DNS allows is stated as malformed with its length.
- A value that cannot be written is counted and stated and costs no other.
- A gzip stream that is corrupt, or followed by bytes that are not gzip, is
  stated, and the read is not called the whole capture.
- Bytes that are not UTF-8 in a name or request are written as escapes.
"""

from __future__ import annotations

import gzip
import importlib.util
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

from maljan.analysis import capture_reader
from maljan.analysis.pcap_summary import capture_facts, each_packet, summarize_pcap

ROOT = Path(__file__).resolve().parents[3]
NETWORK_SERVER = ROOT / "services" / "network-mcp" / "server.py"
JOB_LEAF = "job-states00"
PUBLIC = b"\x08\x08\x08\x08"


def _ip(protocol: int, payload: bytes, total: int | None = None) -> bytes:
    length = 20 + len(payload) if total is None else total
    return (
        struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, length, 0, 0, 64, protocol, 0, b"\x0a\x00\x00\x02", PUBLIC
        )
        + payload
    )  # fmt: skip


def _udp(dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", 40000, dport, 8 + len(payload), 0) + payload


def _tcp(dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHIIBBHHH", 40001, dport, 0, 0, 0x50, 0x18, 1024, 0, 0) + payload


def _dns(labels: list[bytes]) -> bytes:
    name = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + name + b"\x00\x01\x00\x01"


def _pcap(frames: list[bytes], snaplen: int = 0) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 101)
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


def _epb(interface: int, data: bytes) -> bytes:
    return _block(6, struct.pack("<IIIII", interface, 0, 0, len(data), len(data)) + data)


@pytest.fixture
def network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    base = tmp_path / "staging"
    (base / JOB_LEAF / "captures").mkdir(parents=True)
    monkeypatch.setenv("MALJAN_STAGING_DIR", str(base))
    monkeypatch.setenv("MALJAN_STAGING_JOB", JOB_LEAF)
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", "")
    spec = importlib.util.spec_from_file_location("network_mcp_states", NETWORK_SERVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.captures = base / JOB_LEAF / "captures"
    return module


def test_unreadable_blocks_are_told_by_kind_whatever_their_number(tmp_path: Path) -> None:
    good = _epb(0, _ip(17, _udp(53, _dns([b"evil", b"example"]))))
    statements = []
    for bad in (10, 2_000):
        target = tmp_path / f"bad_{bad}.pcapng"
        blocks = [good, *(_epb(1_000 + n, b"") for n in range(bad)), good]
        target.write_bytes(_pcapng(blocks))
        read = each_packet(str(target), lambda _p: None)
        assert read.packets_read == 2 and read.blocks_unreadable == bad
        assert not read.whole
        statements.append(read.statement())
    reason = "an enhanced packet block names an interface no interface description declared"
    assert statements[1].count(reason) == 1
    assert f"{reason} (2000, the first at byte " in statements[1]
    assert "interface 1000)" in statements[1] and "interface 1001" not in statements[1]
    assert len(statements[1]) - len(statements[0]) <= 4  # the count's digits, nothing else


def test_a_datagram_is_read_only_as_far_as_its_header_says(tmp_path: Path, network: Any) -> None:
    request = b"GET /declared HTTP/1.1\r\nHost: real.example\r\n\r\n"
    trailing = b"GET /trailer HTTP/1.1\r\nHost: smuggled.example\r\n\r\n"
    declared = _ip(6, _tcp(80, request))
    target = network.captures / "bounded.pcap"
    target.write_bytes(_pcap([declared + trailing]))

    answer = network.extract_http(str(target))

    assert answer.splitlines()[1:] == ["GET /declared HTTP/1.1 | Host: real.example"]


def test_an_offloaded_segment_is_the_rest_of_its_frame(network: Any) -> None:
    request = b"GET /offloaded HTTP/1.1\r\nHost: tso.example\r\n\r\n"
    frames = [
        _ip(6, _tcp(80, request), total=0),
        _ip(17, _udp(53, _dns([b"tso", b"example"])), total=0),
        _ip(17, _udp(5353, _dns([b"below", b"example"])), total=19),
    ]
    target = network.captures / "offloaded.pcap"
    target.write_bytes(_pcap(frames))

    assert network.extract_http(str(target)).splitlines()[1:] == [
        "GET /offloaded HTTP/1.1 | Host: tso.example"
    ]
    assert network.extract_dns(str(target)).splitlines()[1:] == [
        "tso.example.",
        "below.example.",
    ]
    facts = capture_facts(str(target))
    assert facts is not None and facts["protocols"] == {"tcp": 1, "udp": 2}
    ports = {(c["dport"], c["proto"]) for c in facts["conversations"]}
    assert ports == {(80, "tcp"), (53, "udp"), (5353, "udp")}


def test_an_offloaded_segment_ends_where_an_ipv4_header_could_end_it() -> None:
    segment = _tcp(80, b"GET /big HTTP/1.1\r\n" + b"X" * 70_000)
    packet = capture_reader.decode(capture_reader.Record(0.0, _ip(6, segment, total=0), 101))
    assert packet.tcp is not None
    assert len(packet.tcp.data) == 65_535 - 20 - 20


def test_a_jumbogram_is_read_to_the_length_its_option_states() -> None:
    payload = _udp(53, _dns([b"jumbo", b"example"]))
    hop_by_hop = bytes([17, 0]) + bytes([0xC2, 4]) + struct.pack("!I", 8 + len(payload))
    ipv6 = (
        struct.pack("!IHBB16s16s", 0x60000000, 0, 0, 64, bytes(16), b"\x20\x01" + bytes(14))
        + hop_by_hop
        + payload
    )
    packet = capture_reader.decode(capture_reader.Record(0.0, ipv6, 101))
    assert packet.dns_qname == b"jumbo.example."

    without = ipv6[:40] + bytes([17, 0, 1, 4, 0, 0, 0, 0]) + payload
    packet = capture_reader.decode(capture_reader.Record(0.0, without, 101))
    assert packet.udp is None and packet.dns_qname is None


def test_a_name_longer_than_dns_allows_is_stated_not_extracted(network: Any) -> None:
    long_name = _ip(17, _udp(53, _dns([b"\x01" * 63] * 5)))  # 321 octets
    fine = _ip(17, _udp(53, _dns([b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61])))  # 255
    target = network.captures / "names.pcap"
    target.write_bytes(_pcap([long_name, fine]))

    answer = network.extract_dns(str(target))

    lines = answer.splitlines()
    assert lines[0] == (
        "2 of 2 packets in the capture read, 1 DNS question names malformed: longer "
        "than the 255 octets DNS allows (the first 321 octets)."
    )
    assert lines[1:] == [f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 61}."]


def test_a_value_that_cannot_be_written_costs_no_other(
    network: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    frames = [_ip(17, _udp(53, _dns([name, b"example"]))) for name in (b"one", b"two", b"three")]
    target = network.captures / "three.pcap"
    target.write_bytes(_pcap(frames))
    real = network.pack_escaped

    def failing(text: str) -> str:
        if text.startswith("two"):
            raise MemoryError
        return str(real(text))

    monkeypatch.setattr(network, "pack_escaped", failing)
    answer = network.extract_dns(str(target))

    assert answer.splitlines() == [
        "3 of 3 packets in the capture read, 1 values read but not written (MemoryError).",
        "one.example.",
        "three.example.",
    ]


@pytest.mark.parametrize("damage", ["trailing_junk", "bad_crc"])
def test_a_damaged_gzip_stream_is_stated(tmp_path: Path, damage: str) -> None:
    frames = [_ip(17, _udp(9, b"x")) for _ in range(3)]
    packed = gzip.compress(_pcap(frames, snaplen=65535))
    if damage == "trailing_junk":
        packed += b"this is not a gzip member" * 4
    else:
        packed = packed[:-8] + bytes(4) + packed[-4:]  # the CRC32 zeroed
    target = tmp_path / f"{damage}.pcap.gz"
    target.write_bytes(packed)

    read = each_packet(str(target), lambda _p: None)

    assert read.stream_error is not None
    assert not read.whole
    assert "reading stopped where the gzip stream could not be decompressed" in read.statement()
    summary = summarize_pcap(str(target))
    assert summary is not None and "part of the capture" in summary


def test_bytes_that_are_not_utf8_are_written_not_dropped(network: Any) -> None:
    dns = _ip(17, _udp(53, _dns([b"goo\xffgle", b"com"])))
    http = _ip(6, _tcp(80, b"GET /\xfe HTTP/1.1\r\nHost: a\xffb.example\r\n\r\n"))
    target = network.captures / "bytes.pcap"
    target.write_bytes(_pcap([dns, http]))

    assert network.extract_dns(str(target)).splitlines()[1:] == ["goo\\xffgle.com."]
    assert network.extract_http(str(target)).splitlines()[1:] == [
        "GET /\\xfe HTTP/1.1 | Host: a\\xffb.example"
    ]
