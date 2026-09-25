"""The network server reads every packet of a capture, and says how many it read.

A live capture held 14,887 packets and every tool here stopped at the 5,000th,
so "No DNS queries found" would have been a statement about a third of it. The
tools stream the whole capture, a limit applies only when the caller passes
one, and every answer states the packets read and the packets in the capture.

A refusal names the captures this run holds, relative to the job's own
directory, and is written from the tools' own signature: ``pcap_path`` is
required, so it never says to leave the argument out.
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
NETWORK_SERVER = ROOT / "services" / "network-mcp" / "server.py"
JOB_LEAF = "job-0123abcd"

scapy_all = pytest.importorskip("scapy.all")


@pytest.fixture(scope="module")
def network() -> Any:
    spec = importlib.util.spec_from_file_location("network_mcp_whole_capture", NETWORK_SERVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """This job's own staging directory, and no other root."""
    base = tmp_path / "staging"
    (base / JOB_LEAF / "captures").mkdir(parents=True)
    monkeypatch.setenv("MALJAN_STAGING_DIR", str(base))
    monkeypatch.setenv("MALJAN_STAGING_JOB", JOB_LEAF)
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", "")
    return base / JOB_LEAF


def _capture(target: Path, dns_at: int, total: int) -> Path:
    """``total`` UDP packets to a documentation address, one DNS query at ``dns_at``."""
    packets = []
    for index in range(total):
        if index == dns_at:
            packets.append(
                scapy_all.IP(src="10.0.2.15", dst="192.0.2.53")
                / scapy_all.UDP(sport=50000, dport=53)
                / scapy_all.DNS(rd=1, qd=scapy_all.DNSQR(qname="late.example.net"))
            )
        else:
            packets.append(
                scapy_all.IP(src="10.0.2.15", dst="198.51.100.7")
                / scapy_all.UDP(sport=50001, dport=9)
            )
    scapy_all.wrpcap(str(target), packets)
    return target


class TestTheWholeCaptureIsRead:
    def test_no_tool_has_a_default_count(self, network: Any) -> None:
        for tool in ("read_pcap_summary", "extract_dns", "extract_http", "pcap_summary"):
            parameter = inspect.signature(getattr(network, tool)).parameters["packet_limit"]
            assert parameter.default is None, tool

    def test_a_query_past_the_old_ceiling_is_found(self, network: Any, job: Path) -> None:
        capture = _capture(job / "captures" / "run.pcap", dns_at=5_200, total=5_210)

        answer = network.extract_dns(str(capture))

        assert "late.example.net" in answer
        assert answer.startswith("5210 of 5210 packets in the capture read.")

    def test_a_limit_applies_only_when_the_caller_passes_one(self, network: Any, job: Path) -> None:
        capture = _capture(job / "captures" / "run.pcap", dns_at=50, total=60)

        answer = network.extract_dns(str(capture), packet_limit=10)

        assert answer == (
            "10 of 60 packets in the capture read (the caller asked for 10). "
            "No DNS queries in them."
        )

    def test_every_answer_states_what_it_read(self, network: Any, job: Path) -> None:
        capture = _capture(job / "captures" / "run.pcap", dns_at=0, total=3)

        assert "3 of 3 packets in the capture read" in network.read_pcap_summary(str(capture))
        assert network.extract_http(str(capture)).startswith("3 of 3 packets")
        summary = network.pcap_summary(str(capture))
        assert summary["packets_read"] == summary["packets_in_capture"] == 3
        assert summary["packet_limit"] is None
        assert "3 of 3 packets in the capture read" in summary["summary"]


class TestThePacketListing:
    def test_with_no_limit_the_answer_is_the_capture_s_facts(self, network: Any, job: Path) -> None:
        capture = _capture(job / "captures" / "run.pcap", dns_at=0, total=40)

        answer = network.read_pcap_summary(str(capture))

        assert "40 of 40 packets in the capture read" in answer
        assert "Packet 0:" not in answer

    def test_a_listing_is_paged_and_names_the_next_page(self, network: Any, job: Path) -> None:
        capture = _capture(job / "captures" / "run.pcap", dns_at=0, total=40)

        answer = network.read_pcap_summary(str(capture), packet_limit=10, offset=5)

        lines = answer.splitlines()
        assert lines[0] == (
            "Packets 5 to 14 of the 40 in the capture; the next page starts at offset 15."
        )
        assert lines[1].startswith("Packet 5:") and lines[-1].startswith("Packet 14:")


class TestARefusalNamesTheRealCaptures:
    def test_an_invented_name_is_told_the_captures_this_run_holds(
        self, network: Any, job: Path
    ) -> None:
        _capture(job / "captures" / "triage_one.pcap", dns_at=0, total=1)
        _capture(job / "captures" / "triage_two.pcap", dns_at=0, total=1)

        for tool in ("read_pcap_summary", "extract_dns", "extract_http", "pcap_summary"):
            answer = getattr(network, tool)("capture.pcap")
            parsed = json.loads(answer) if isinstance(answer, str) else answer
            remediation = parsed["error"]["remediation"]

            assert "captures/triage_one.pcap, captures/triage_two.pcap" in remediation, tool
            assert "leave the argument out" not in remediation, tool
            assert str(job) not in json.dumps(parsed), tool

    def test_a_listed_name_is_read(self, network: Any, job: Path) -> None:
        _capture(job / "captures" / "triage_one.pcap", dns_at=0, total=2)

        answer = network.extract_dns("captures/triage_one.pcap")

        assert answer.startswith("2 of 2 packets")
        assert "late.example.net" in answer

    def test_a_run_with_no_capture_says_there_is_none(self, network: Any, job: Path) -> None:
        answer = json.loads(network.extract_dns("capture.pcap"))

        assert "holds no packet capture" in answer["error"]["remediation"]

    def test_a_relative_name_never_reaches_another_job_s_capture(
        self, network: Any, job: Path
    ) -> None:
        other = job.parent / "job-9999ffff" / "captures"
        other.mkdir(parents=True)
        _capture(other / "theirs.pcap", dns_at=0, total=1)
        _capture(job / "captures" / "mine.pcap", dns_at=0, total=1)

        for spelling in (
            "../job-9999ffff/captures/theirs.pcap",
            "../../job-9999ffff/captures/theirs.pcap",
            "captures/../../job-9999ffff/captures/theirs.pcap",
        ):
            answer = json.loads(network.extract_dns(spelling))
            assert answer["error"]["code"] == "path_outside_roots", spelling
