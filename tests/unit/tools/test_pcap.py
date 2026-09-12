"""``maljan.tools.pcap`` is the whole-capture view, and it never raises.

The summary itself belongs to ``analysis/pcap_summary`` and is tested there.
What is this module's own is the tool contract: a missing file, an unreadable
capture and an empty one are three different answers, and none of them is an
exception across the MCP boundary.
"""

from __future__ import annotations

from pathlib import Path

from maljan.tools import pcap


def test_a_missing_capture_is_an_error_and_not_an_exception() -> None:
    result = pcap.pcap_summary("/nonexistent/capture.pcap")
    assert result["tool"] == "pcap_summary"
    assert "no such file" in result["error"]


def test_a_file_that_is_not_a_capture_comes_back_empty_rather_than_raising(
    tmp_path: Path,
) -> None:
    """scapy answers ``None`` for anything it cannot parse, and the tool passes
    that on as "nothing in it" — the caller learns the capture is useless
    without having to catch anything."""
    target = tmp_path / "not.pcap"
    target.write_bytes(b"this is not a capture at all")

    result = pcap.pcap_summary(str(target))

    assert result["empty"] is True
    assert result["summary"] == ""


def test_an_empty_capture_reports_the_packet_limit_it_was_given(tmp_path: Path) -> None:
    # A libpcap file header and no packet records.
    target = tmp_path / "empty.pcap"
    target.write_bytes(
        b"\xd4\xc3\xb2\xa1"  # magic, little-endian
        b"\x02\x00\x04\x00"  # version 2.4
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # thiszone, sigfigs
        b"\xff\xff\x00\x00"  # snaplen
        b"\x01\x00\x00\x00"  # DLT_EN10MB
    )

    result = pcap.pcap_summary(str(target), packet_limit=100)

    assert result["empty"] is True
    assert result["packet_limit"] == 100
