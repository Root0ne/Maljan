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
one, the fixture is listed in ``IMPROVED`` with what changed: its answers are
pinned in ``improved.json``, and the test also proves they differ from the old
ones, so an improvement cannot pass for parity or the reverse.
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

IMPROVED = {
    "truncated_block.pcapng": (
        "a pcapng file cut inside a block: the old reader raised and every surface "
        "answered that the capture could not be read; the new one ends the capture "
        "at the cut and reads the six packets before it, as a pcap file cut short "
        "always was"
    ),
    "odd_records.pcap": (
        "an IPv4 header length of 0 and an empty record: the old reader read a TCP "
        "header out of the IP header's own bytes and counted 14 bytes for the empty "
        "record; the new one reads no transport header past an invalid header "
        "length and counts the empty record as 0 bytes"
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
def test_an_improved_capture_answers_its_pinned_better_values(
    name: str, answers: dict[str, dict[str, Any]]
) -> None:
    got = answers[name]
    assert got == _load(IMPROVED_ANSWERS)[name]
    assert got != _load(EXPECTED)[name]
