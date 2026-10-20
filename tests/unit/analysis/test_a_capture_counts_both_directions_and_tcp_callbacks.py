"""A conversation counts both directions, and a TCP beacon is seen by its connections.

A conversation with an external host is the packets to it and the packets from
it. Counting only the packets toward the host left a download's bytes, and any
flow the external host opened, out of the summary; the replies are now counted
in the same conversation, and the part from the host is stated beside the total
whenever there is one.

A TCP callback is a connection: a handshake, a request, a reply and a close,
packets milliseconds apart. Measured over every packet, the interval between
callbacks drowns in those milliseconds and a TCP heartbeat never reads as
regular. The connections the sandbox opened are measured too, one per SYN its
side sent (a retransmitted SYN of the same connection counted once), so a
periodic TCP callback reads as a beacon whatever its packets look like.
"""

from __future__ import annotations

import struct
from pathlib import Path

from maljan.analysis.pcap_summary import capture_facts, conversation_line, summary_text

HOST = b"\x0a\x00\x00\x02"  # the sandbox
C2 = b"\x08\x08\x08\x08"
SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def _tcp(src: bytes, dst: bytes, sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, src, dst) + tcp


def _udp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes = b"") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0, src, dst) + udp


def _pcap(records: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 101)
    for at, frame in records:
        seconds = int(at)
        micros = int(round((at - seconds) * 1_000_000))
        out += struct.pack("<IIII", 1_700_000_000 + seconds, micros, len(frame), len(frame))
        out += frame
    return out


def _connection(at: float, sport: int, reply: bytes = b"ok") -> list[tuple[float, bytes]]:
    """One HTTPS-shaped callback: handshake, request, reply, close."""
    return [
        (at, _tcp(HOST, C2, sport, 443, SYN)),
        (at + 0.020, _tcp(C2, HOST, 443, sport, SYN | ACK)),
        (at + 0.021, _tcp(HOST, C2, sport, 443, ACK)),
        (at + 0.022, _tcp(HOST, C2, sport, 443, PSH | ACK, b"GET /task")),
        (at + 0.060, _tcp(C2, HOST, 443, sport, PSH | ACK, reply)),
        (at + 0.061, _tcp(HOST, C2, sport, 443, FIN | ACK)),
        (at + 0.080, _tcp(C2, HOST, 443, sport, FIN | ACK)),
    ]


def _facts(tmp_path: Path, records: list[tuple[float, bytes]]) -> dict:
    target = tmp_path / "c.pcap"
    target.write_bytes(_pcap(records))
    facts = capture_facts(str(target))
    assert facts is not None
    return facts


# ------------------------------------------------------------- B-M6 beacons


def test_a_periodic_tcp_callback_reads_as_a_beacon_by_its_connections(tmp_path: Path) -> None:
    records = [r for i in range(6) for r in _connection(30.0 * i, 50000 + i)]
    facts = _facts(tmp_path, records)
    assert facts["beacons"] == [
        {
            "dst": "8.8.8.8",
            "dport": 443,
            "proto": "tcp",
            "callbacks": 6,
            "interval_s": 30.0,
            "unit": "connection",
        }
    ]
    text = summary_text(facts)
    assert "8.8.8.8:443/tcp — 6 connections opened, ~30.0s interval" in text


def test_a_retransmitted_syn_is_one_connection(tmp_path: Path) -> None:
    records: list[tuple[float, bytes]] = []
    for i in range(5):
        records += _connection(60.0 * i, 51000 + i)
        # The same connection's SYN sent again a second later: not a callback.
        records.append((60.0 * i + 1.0, _tcp(HOST, C2, 51000 + i, 443, SYN)))
    records.sort(key=lambda r: r[0])
    facts = _facts(tmp_path, records)
    assert [(b["callbacks"], b["interval_s"], b.get("unit")) for b in facts["beacons"]] == [
        (5, 60.0, "connection")
    ]


def test_irregular_connections_are_no_beacon(tmp_path: Path) -> None:
    starts = [0.0, 3.0, 50.0, 52.0, 200.0, 201.0]
    records = [r for i, at in enumerate(starts) for r in _connection(at, 52000 + i)]
    assert _facts(tmp_path, records)["beacons"] == []


def test_a_regular_packet_beacon_answers_as_before(tmp_path: Path) -> None:
    records = [(10.0 * i, _udp(HOST, C2, 40000, 53, b"q")) for i in range(5)]
    beacons = _facts(tmp_path, records)["beacons"]
    assert beacons == [
        {"dst": "8.8.8.8", "dport": 53, "proto": "udp", "callbacks": 5, "interval_s": 10.0}
    ]
    assert "8.8.8.8:53/udp — 5 callbacks, ~10.0s interval" in summary_text(
        _facts(tmp_path, records)
    )


# ------------------------------------------------- B-M8 both directions


def test_a_conversation_counts_the_packets_from_the_host(tmp_path: Path) -> None:
    reply = b"x" * 1000
    records = _connection(0.0, 50000, reply)
    facts = _facts(tmp_path, records)
    sent = [len(f) for _, f in records if f[12:16] == HOST]
    got = [len(f) for _, f in records if f[12:16] == C2]
    assert facts["conversations"] == [
        {
            "dst": "8.8.8.8",
            "dport": 443,
            "proto": "tcp",
            "packets": len(records),
            "bytes": sum(sent) + sum(got),
            "packets_from_host": len(got),
            "bytes_from_host": sum(got),
        }
    ]
    line = conversation_line(facts["conversations"][0])
    assert line == (
        f"8.8.8.8:443/tcp — {len(records)} pkts, {sum(sent) + sum(got)} bytes "
        f"({len(got)} pkts, {sum(got)} bytes from the host)"
    )


def test_a_one_way_conversation_answers_as_before(tmp_path: Path) -> None:
    records = [(float(i), _udp(HOST, C2, 40000, 9, b"abc")) for i in range(2)]
    facts = _facts(tmp_path, records)
    assert facts["conversations"] == [
        {"dst": "8.8.8.8", "dport": 9, "proto": "udp", "packets": 2, "bytes": 62}
    ]
    assert conversation_line(facts["conversations"][0]) == "8.8.8.8:9/udp — 2 pkts, 62 bytes"


def test_a_flow_the_external_host_opened_is_a_conversation(tmp_path: Path) -> None:
    records = [(float(i), _udp(C2, HOST, 6000, 40000, b"push")) for i in range(3)]
    facts = _facts(tmp_path, records)
    assert facts["conversations"] == [
        {
            "dst": "8.8.8.8",
            "dport": 6000,
            "proto": "udp",
            "packets": 3,
            "bytes": 96,
            "packets_from_host": 3,
            "bytes_from_host": 96,
            "inbound_only": True,
        }
    ]
    assert conversation_line(facts["conversations"][0]).endswith(
        "(3 pkts, 96 bytes from the host; inbound only)"
    )


def test_an_inbound_only_host_is_no_sandbox_contact_in_the_ledger() -> None:
    from maljan.reporting.ledger_projection import network_from_ledger
    from maljan.schemas.evidence import LedgerEntry

    rows = [
        {"dst": "8.8.4.4", "dport": 6000, "proto": "udp", "packets": 3, "bytes": 96,
         "packets_from_host": 3, "bytes_from_host": 96, "inbound_only": True},
        {"dst": "185.220.101.5", "dport": 443, "proto": "tcp", "packets": 7, "bytes": 900,
         "packets_from_host": 3, "bytes_from_host": 500},
    ]  # fmt: skip
    entry = LedgerEntry(
        id="ev_0001", agent="pipeline", tool="pcap_summary", structured={"conversations": rows}
    )
    network = network_from_ledger([entry])
    assert network is not None
    assert [ip.address for ip in network.ips] == ["185.220.101.5"]


def test_the_replies_do_not_move_a_packet_beacon(tmp_path: Path) -> None:
    records: list[tuple[float, bytes]] = []
    for i in range(5):
        records.append((10.0 * i, _udp(HOST, C2, 40000, 53, b"q")))
        records.append((10.0 * i + 0.01, _udp(C2, HOST, 53, 40000, b"a")))
    beacons = _facts(tmp_path, records)["beacons"]
    assert beacons == [
        {"dst": "8.8.8.8", "dport": 53, "proto": "udp", "callbacks": 5, "interval_s": 10.0}
    ]
