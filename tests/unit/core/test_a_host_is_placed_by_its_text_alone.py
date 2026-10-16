"""A host is local, remote or unknown by its text alone, by one rule every reader shares.

Loopback, private, link-local and shared addresses, the names only a local
resolver answers and a compose service's single label are local; a public
address and a dotted name nothing here resolves are remote; no host at all is
unknown, never local. The analyst-mode decision reads the same address and
name rules before it resolves a name.
"""

from __future__ import annotations

import time

import pytest

from maljan.core import host_locality
from maljan.core.host_locality import LOCAL, REMOTE, UNKNOWN, host_of
from maljan.core.host_locality import host_locality as locality


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.8.9.10",
        "::1",
        "[::1]",
        "10.65.0.40",
        "172.18.0.5",
        "192.168.1.20",
        "169.254.1.1",
        "fe80::1",
        "fd12:3456::1",
        "100.64.0.1",
        "100.127.255.254",
        "::ffff:10.0.0.1",
        "localhost",
        "LOCALHOST.",
        "localhost.localdomain",
        "host.docker.internal",
        "gateway.docker.internal",
        "host.containers.internal",
        "host.lima.internal",
        "api.localhost",
        "printer.local",
        "metadata.google.internal",
        "qdrant",
        "ghidra-mcp",
        "llama_cpp",
        "2130706433",
        "0x7f000001",
        "017700000001",
    ],
)
def test_a_local_host(host: str) -> None:
    assert locality(host) == LOCAL


@pytest.mark.parametrize(
    "host",
    [
        "8.8.8.8",
        "100.128.0.1",
        "2606:4700::1111",
        "::ffff:8.8.8.8",
        "api.deepseek.com",
        "tria.ge",
        "ai.virustotal.com",
        "llm.corp.example",
        "localhost.evil.example",
        "3627733018",
        "0xd83ad21a",
    ],
)
def test_a_remote_host(host: str) -> None:
    assert locality(host) == REMOTE


@pytest.mark.parametrize("host", ["", "   ", None, "."])
def test_no_host_is_unknown_and_never_local(host: object) -> None:
    assert locality(host) == UNKNOWN


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://api.deepseek.com", "api.deepseek.com"),
        ("http://user:secret@LLM.Example.org:8443/v1?key=x", "llm.example.org"),
        ("http://[::1]:8080/v1", "::1"),
        ("box:8080", "box"),
        ("qdrant:6333", "qdrant"),
        ("https://tria.ge./api/v0", "tria.ge"),
        ("", ""),
        ("http://", ""),
        ("http://[::1", ""),
    ],
)
def test_an_address_gives_its_host_and_nothing_else(url: str, host: str) -> None:
    assert host_of(url) == host


def test_a_number_past_32_bits_is_no_address_and_no_service_name() -> None:
    assert locality("99999999999") == REMOTE
    assert locality("0x1ffffffff") == REMOTE
    # Far past the interpreter's own limit on converting a digit string.
    assert locality("9" * 60_000) == REMOTE
    assert locality("0" * 60_000 + "1") == LOCAL


def test_the_analyst_mode_reads_the_same_address_and_name_rules() -> None:
    from maljan.pipeline import analyst_mode

    assert analyst_mode.local_address is host_locality.local_address
    assert analyst_mode.named_locally is host_locality.named_locally
    for literal in ("http://10.0.0.5:8080/v1", "http://100.64.1.1/v1", "http://localhost:1"):
        assert analyst_mode.locality(literal)[0] == "local"
    assert analyst_mode.locality("http://8.8.8.8/v1")[0] == "hosted"


def test_the_rule_stays_linear_on_a_hostile_host() -> None:
    def took(host: str) -> float:
        started = time.perf_counter()
        for _ in range(20):
            locality(host)
        return time.perf_counter() - started

    small = took("a" * 6_000 + ".example")
    large = took("a" * 60_000 + ".example")
    assert large < max(small, 1e-3) * 40
