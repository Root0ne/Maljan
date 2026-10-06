"""Every capture in the fixture corpus reads to the values it read before.

The capture reader changed library. ``tests/fixtures/pcap/expected.json`` holds
what every surface that reads a capture answered for every fixture with the
reader it replaced: the facts, the markdown summary, the tool's dict and the
network server's four tools, with and without a packet limit. The fixtures
cover the link layers a sandbox writes (Ethernet, VLAN, cooked Linux v1 and
v2, raw IP, BSD loopback, an unknown link type), pcap in both byte orders and
both resolutions, gzip, pcapng with two interfaces of different link types,
tunnels, ICMP errors, malformed IP, TCP, UDP and DNS headers, captures cut
short in a record, in a record header and in a pcapng block, and files that
are empty or not a capture at all.

An error answer is compared by its code, not its text: the text named the old
library's exception class. Where the new reader answers better than the old
one, the fixture is listed in ``IMPROVED`` with why and the surfaces that
changed: those answers are pinned in ``improved.json`` and proven to differ
from the old ones, and every other surface of the fixture must still answer
exactly as before, so an improvement cannot pass for parity or the reverse.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "fixtures" / "pcap"
EXPECTED = FIXTURES / "expected.json"
IMPROVED_ANSWERS = FIXTURES / "improved.json"
NETWORK_SERVER = ROOT / "services" / "network-mcp" / "server.py"
JOB_LEAF = "job-parity00"

CAPTURES = sorted(
    p.name
    for p in FIXTURES.iterdir()
    if p.is_file() and p.name not in (EXPECTED.name, IMPROVED_ANSWERS.name)
)

_FACTS = ("capture_facts", "summarize_pcap", "tool_pcap_summary", "read_pcap_summary")
_FACTS_ALL = (*_FACTS, "network_pcap_summary")
_FACTS_LIMITED = ("capture_facts_limit_3", *_FACTS_ALL)
_EVERY_SURFACE = (
    *_FACTS_LIMITED,
    "read_pcap_summary_page",
    "extract_dns",
    "extract_dns_limit_5",
    "extract_http",
)
_SNI = (
    "the TLS server name is read: the old code decoded it with a codec that always "
    "raised, so ``sni`` was always empty"
)

# Each improved capture: why, and the surfaces whose answer changed. Every
# other surface of it must still answer exactly as before.
IMPROVED: dict[str, tuple[str, tuple[str, ...]]] = {
    "ethernet_mixed.pcap": (_SNI, _FACTS_ALL),
    "ethernet_mixed.pcap.gz": (_SNI, _FACTS_ALL),
    "ethernet_mixed_be_nano.pcap": (_SNI, _FACTS_ALL),
    "truncated_in_header.pcap": (_SNI, _FACTS_ALL),
    "truncated_in_record.pcap": (_SNI, _FACTS_ALL),
    "two_interfaces.pcapng": (_SNI, _FACTS_ALL),
    "truncated_block.pcapng": (
        "a pcapng file cut inside a block: the old reader raised and every surface "
        "answered that the capture could not be read; the new one ends the capture "
        "at the cut and reads the six packets before it, as a pcap file cut short "
        "always was",
        _EVERY_SURFACE,
    ),
    "odd_records.pcap": (
        "an IPv4 header length of 0 and an empty record: the old reader read a TCP "
        "header out of the IP header's own bytes and counted 14 bytes for the empty "
        "record; the new one reads no transport header past an invalid header "
        "length and counts the empty record as 0 bytes",
        _FACTS_LIMITED,
    ),
    "hostile_vlan_stack.pcap": (
        "a frame under 500 stacked 802.1Q tags: the old reader dropped its IP "
        "header; the new walk is a loop and reads the DNS query beneath the tags",
        _FACTS_LIMITED,
    ),
    "deep_ipip_tunnels.pcap": (
        "a datagram under 1,000 nested IPv4-in-IPv4 headers, each stating its total "
        "length: the old reader stopped at the outer header; the new walk is a loop "
        "and reaches the UDP datagram at the bottom",
        _FACTS_LIMITED,
    ),
    "edge_layers.pcap": (
        "two IPv4 headers whose total length (0, 10) is below their own header "
        "length: the old reader read the bytes after them as a TCP segment carrying "
        "an HTTP request; the new one reads an IP datagram only up to the length its "
        "header declares, so neither carries a payload",
        (*_FACTS_ALL, "extract_http"),
    ),
    "unreadable_blocks.pcapng": (
        "three correctly framed pcapng blocks that cannot be read: the old reader "
        "ended the capture at the first and said the 2 packets before it were the "
        "whole capture; the new one skips each by its length, reads the 2 packets "
        "after them and says 3 blocks were unreadable and why",
        _EVERY_SURFACE,
    ),
    "pcapng_without_interface.pcapng": (
        "a packet block naming an interface no description declared: skipped and "
        "stated instead of ending the capture in silence",
        (
            "capture_facts",
            "capture_facts_limit_3",
            "read_pcap_summary",
            "read_pcap_summary_page",
            "extract_dns",
            "extract_dns_limit_5",
            "extract_http",
        ),
    ),
    "spb_snaplen0.pcapng": (
        "simple packet blocks on an interface whose snapshot length is 0, which "
        "pcapng defines as no limit: the old reader read 0 bytes of each; the new "
        "one reads the packets",
        tuple(x for x in _EVERY_SURFACE if x != "read_pcap_summary_page"),
    ),
}


def _network() -> Any:
    spec = importlib.util.spec_from_file_location("network_mcp_reader_parity", NETWORK_SERVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _answer(value: Any) -> Any:
    """A tool answer, with an error reduced to its code and tool."""
    parsed = value
    if isinstance(value, str) and value.startswith("{"):
        parsed = json.loads(value)
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
        return {"error_code": parsed["error"].get("code"), "tool": parsed.get("tool")}
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        return {"error": True, "tool": parsed.get("tool")}
    return value


def observed(capture: Path, network: Any) -> dict[str, Any]:
    """Every surface's answer for one capture, as JSON-shaped data."""
    from maljan.analysis.pcap_summary import capture_facts, summarize_pcap
    from maljan.tools.pcap import pcap_summary

    path = str(capture)
    return json.loads(
        json.dumps(
            {
                "capture_facts": capture_facts(path),
                "capture_facts_limit_3": capture_facts(path, 3),
                "summarize_pcap": summarize_pcap(path),
                "tool_pcap_summary": _answer(pcap_summary(path)),
                "read_pcap_summary": _answer(network.read_pcap_summary(path)),
                "read_pcap_summary_page": _answer(
                    network.read_pcap_summary(path, packet_limit=7, offset=3)
                ),
                "extract_dns": _answer(network.extract_dns(path)),
                "extract_dns_limit_5": _answer(network.extract_dns(path, packet_limit=5)),
                "extract_http": _answer(network.extract_http(path)),
                "network_pcap_summary": _answer(network.pcap_summary(path)),
            }
        )
    )


def staged(base: Path) -> Path:
    """The corpus copied into one job's captures directory, where the server reads."""
    captures = base / JOB_LEAF / "captures"
    captures.mkdir(parents=True)
    for name in CAPTURES:
        shutil.copyfile(FIXTURES / name, captures / name)
    return captures


@pytest.fixture(scope="module")
def answers(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    base = tmp_path_factory.mktemp("staging")
    captures = staged(base)
    with pytest.MonkeyPatch.context() as env:
        env.setenv("MALJAN_STAGING_DIR", str(base))
        env.setenv("MALJAN_STAGING_JOB", JOB_LEAF)
        env.setenv("MALJAN_SAMPLE_ROOTS", "")
        network = _network()
        return {name: observed(captures / name, network) for name in CAPTURES}


def _load(path: Path) -> dict[str, dict[str, Any]]:
    return dict(json.loads(path.read_text(encoding="utf-8")))


def test_the_expected_values_name_every_capture_of_the_corpus() -> None:
    assert sorted(_load(EXPECTED)) == CAPTURES
    assert sorted(_load(IMPROVED_ANSWERS)) == sorted(IMPROVED)
    assert set(IMPROVED) <= set(CAPTURES)


@pytest.mark.parametrize("name", [c for c in CAPTURES if c not in IMPROVED])
def test_every_surface_answers_as_before(name: str, answers: dict[str, dict[str, Any]]) -> None:
    expected = _load(EXPECTED)[name]
    got = answers[name]
    assert list(got) == list(expected)
    for surface, value in expected.items():
        assert got[surface] == value, f"{name}: {surface}"


@pytest.mark.parametrize("name", sorted(IMPROVED))
def test_an_improved_capture_changes_only_the_surfaces_it_names(
    name: str, answers: dict[str, dict[str, Any]]
) -> None:
    before = _load(EXPECTED)[name]
    pinned = _load(IMPROVED_ANSWERS)[name]
    got = answers[name]
    changed = IMPROVED[name][1]
    assert list(got) == list(before)
    for surface in got:
        if surface in changed:
            assert got[surface] == pinned[surface], f"{name}: {surface}"
            assert got[surface] != before[surface], f"{name}: {surface}"
        else:
            assert got[surface] == before[surface], f"{name}: {surface}"


def test_the_server_name_comes_out_and_nothing_else_moves(
    answers: dict[str, dict[str, Any]],
) -> None:
    before = _load(EXPECTED)
    for name, sni in (
        ("ethernet_mixed.pcap", {"cdn.example.net": 2}),
        ("two_interfaces.pcapng", {"ng.example.net": 1}),
    ):
        facts = answers[name]["capture_facts"]
        assert facts["sni"] == sni
        assert before[name]["capture_facts"]["sni"] == {}
        assert {**facts, "sni": {}} == before[name]["capture_facts"]
        assert "TLS SNI (encrypted destinations):" in answers[name]["summarize_pcap"]


@pytest.mark.parametrize("name", ["hostile_vlan_stack.pcap", "deep_ipip_tunnels.pcap"])
def test_a_deeply_nested_frame_costs_no_other_packet(
    name: str, answers: dict[str, dict[str, Any]]
) -> None:
    facts = answers[name]["capture_facts"]
    assert facts["packets_read"] == facts["packets_in_capture"] == 5
    conversations = {
        (c["dst"], c["dport"], c["proto"]): c["packets"] for c in facts["conversations"]
    }
    # The two good packets on each side of the hostile frame, and the hostile
    # frame's own DNS query read beneath its nesting.
    assert conversations == {("8.8.8.8", 53, "udp"): 3, ("8.8.8.8", 4444, "tcp"): 2}
    assert "evil.example." in answers[name]["extract_dns"]


def test_skipped_blocks_are_never_called_the_whole_capture(
    answers: dict[str, dict[str, Any]],
) -> None:
    facts = answers["unreadable_blocks.pcapng"]["capture_facts"]
    assert facts["blocks_unreadable"] == 3
    summary = answers["unreadable_blocks.pcapng"]["summarize_pcap"]
    assert "part of the capture" in summary
    assert "4 packets read, 3 blocks unreadable: " in summary
    assert " of 4 packets in the capture read" not in summary
    assert (
        "an enhanced packet block names an interface no interface description declared "
        "(1, the first at byte 252, interface 7)"
    ) in summary


def test_nested_headers_that_declare_no_payload_are_read_no_further(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Every level of this nesting says its total length is 0: the outer header
    is the datagram, as the old reader read it, and the packets around it stay."""
    facts = answers["hostile_ipip_nesting.pcap"]["capture_facts"]
    conversations = {
        (c["dst"], c["dport"], c["proto"]): c["packets"] for c in facts["conversations"]
    }
    assert conversations == {
        ("8.8.8.8", 0, "other"): 1,
        ("8.8.8.8", 53, "udp"): 2,
        ("8.8.8.8", 4444, "tcp"): 2,
    }
