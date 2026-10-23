"""A host is local, remote or unknown by its text alone, by one rule every reader shares.

Loopback, private (RFC 1918, unique local), link-local, shared and unspecified
addresses, the names only a local resolver answers and a compose service's
single label are local; an address of a transition range is read as the IPv4
address it carries; every other address, and a dotted or absolute name nothing
here resolves, is remote; no host, or a malformed address, is unknown and never
local. The analyst-mode decision reads the same address and name rules before
it resolves a name.
"""

from __future__ import annotations

import time

import pytest
from tests.credential_shapes import password

from maljan.core import host_locality
from maljan.core.host_locality import LOCAL, REMOTE, UNKNOWN, host_of, taken_as_service_name
from maljan.core.host_locality import host_locality as locality

# Built at run time: a credential written down is a secret to a scanner.
PW = password()


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
        "0.0.0.0",
        "::",
        "[::]",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "fe80::1%eth0",
        "[fe80::1%25eth0]",
        # 6to4, Teredo and NAT64 carrying a local IPv4 address are read as it.
        "2002:a00:5::1",
        "2001:0:4136:e378:8000:63bf:f5ff:fffa",
        "64:ff9b::a00:5",
        "64:ff9b:1::c0a8:101",
        "localhost",
        "LOCALHOST.",
        "localhost.localdomain",
        "host.docker.internal",
        "gateway.docker.internal",
        "host.containers.internal",
        "host.lima.internal",
        "api.localhost",
        "printer.local",
        "corp.local",
        "metadata.google.internal",
        "qdrant",
        "ghidra-mcp",
        "llama_cpp",
        "ai",
        "to",
        "llm",
        "metadata",
        "xn--localhost",
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
        # The transition ranges route to the IPv4 address they carry.
        "2002:808:808::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::808:808",
        "64:ff9b:1::808:808",
        # A local-use NAT64 address that is not a /96 address carries nothing readable.
        "64:ff9b:1:a00:5::",
        # Reserved, documentation, benchmarking, multicast and other ranges are not local.
        "0.0.0.1",
        "192.0.0.8",
        "192.0.0.9",
        "192.0.2.1",
        "198.18.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "224.0.0.1",
        "2001:db8::1",
        "2001:2::1",
        "2001:10::1",
        "100::1",
        "fec0::1",
        "ff02::1",
        "::127.0.0.1",
        "::ffff:0:7f00:1",
        # Names nothing here places.
        "api.deepseek.com",
        "tria.ge",
        "ai.virustotal.com",
        "llm.corp.example",
        "localhost.evil.example",
        "nas.home.arpa",
        "box.lan",
        "ai.",
        "localhost:8080",
        "ｌｏｃａｌｈｏｓｔ",
        # Numbers past 32 bits, and forms the strict parser does not read.
        "3627733018",
        "0xd83ad21a",
        "08",
        "127.1",
        "0177.0.0.1",
        "10.0.0.010",
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
        (f"http://user:{PW}@LLM.Example.org:8443/v1?key=x", "llm.example.org"),
        ("http://[::1]:8080/v1", "::1"),
        ("http://[fe80::1%25eth0]:8080/", "fe80::1"),
        ("http://[::ffff:127.0.0.1]/", "::ffff:127.0.0.1"),
        ("box:8080", "box"),
        ("qdrant:6333", "qdrant"),
        ("localhost", "localhost"),
        ("ws://localhost:1", "localhost"),
        ("https://tria.ge./api/v0", "tria.ge."),
        ("http://evil.com#@localhost/", "evil.com"),
        (f"http://user:{PW}@ss@evil.com/", "evil.com"),
        ("http://127.0.0.1:80@evil.com/", "evil.com"),
        ("http://0x7f.1/", "0x7f.1"),
        # Malformed: no host is named, so nothing is placed.
        ("", ""),
        ("http://", ""),
        ("http://[::1", ""),
        ("http:/x/", ""),
        ("http:/localhost/", ""),
        ("http:localhost:8080", ""),
        ("//evil.com", ""),
        ("unix:///var/run/x.sock", ""),
        ("file:///etc/passwd", ""),
        ("http://localhost\\@evil.com/", ""),
        ("http://evil.com:80\\@127.0.0.1/", ""),
        ("http://local\thost/", ""),
    ],
)
def test_an_address_gives_its_host_and_nothing_else(url: str, host: str) -> None:
    assert host_of(url) == host


def test_a_malformed_address_cannot_be_told() -> None:
    assert locality(host_of("http:/x/")) == UNKNOWN


def test_a_single_label_is_said_to_be_taken_as_a_service_name() -> None:
    assert taken_as_service_name("qdrant")
    assert not taken_as_service_name("qdrant.")
    assert not taken_as_service_name("localhost")
    assert not taken_as_service_name("127.0.0.1")
    assert not taken_as_service_name("2130706433")
    assert not taken_as_service_name("box.lan")


def test_a_number_past_32_bits_is_no_address_and_no_service_name() -> None:
    assert locality("99999999999") == REMOTE
    assert locality("0x1ffffffff") == REMOTE
    # Far past the interpreter's own limit on converting a digit string.
    assert locality("9" * 60_000) == REMOTE
    assert locality("0" * 60_001) == LOCAL, "0.0.0.0, the unspecified address"


def test_the_analyst_mode_reads_the_same_address_and_name_rules() -> None:
    from maljan.pipeline import analyst_mode

    assert analyst_mode.local_address is host_locality.local_address
    assert analyst_mode.named_locally is host_locality.named_locally
    for literal in ("http://10.0.0.5:8080/v1", "http://100.64.1.1/v1", "http://localhost:1"):
        assert analyst_mode.locality(literal)[0] == "local"
    assert analyst_mode.locality("http://8.8.8.8/v1")[0] == "hosted"


def test_the_analyst_mode_reads_a_transition_address_by_the_ipv4_address_it_carries() -> None:
    """Stricter than before, on purpose: a 6to4 address of a public IPv4 is hosted."""
    from maljan.pipeline import analyst_mode

    assert analyst_mode.locality("http://[2002:808:808::1]:8080/v1")[0] == "hosted"
    assert analyst_mode.locality("http://[2002:a00:5::1]:8080/v1")[0] == "local"


def test_the_rule_stays_linear_on_a_hostile_host() -> None:
    def took(host: str) -> float:
        started = time.perf_counter()
        for _ in range(20):
            locality(host)
            host_of(f"http://{host}/v1")
        return time.perf_counter() - started

    small = took("a" * 6_000 + ".example")
    large = took("a" * 60_000 + ".example")
    assert large < max(small, 1e-3) * 40


@pytest.mark.parametrize(
    ("url", "compat_local", "placed"),
    [
        # Where the two agree.
        ("http://127.0.0.1:8080/v1", True, LOCAL),
        ("http://10.0.0.5:8080/v1", True, LOCAL),
        ("http://localhost:8080/v1", True, LOCAL),
        ("http://box.local:8080/v1", True, LOCAL),
        ("https://api.example.org/v1", False, REMOTE),
        # Where they differ on purpose: a compose service, a runtime's host
        # name and the shared range may be a proxy in front of a hosted API,
        # which refuses llama.cpp's fields, yet they are inside the deployment.
        ("http://llama:8080/v1", False, LOCAL),
        ("http://host.docker.internal:8080/v1", False, LOCAL),
        ("http://100.64.1.1:8080/v1", False, LOCAL),
        # A documentation address: private to the cautious filter, not local here.
        ("http://[2001:db8::1]:8080/v1", True, REMOTE),
    ],
)
def test_the_compat_guess_is_not_the_disclosure_rule(
    url: str, compat_local: bool, placed: str
) -> None:
    """``compat: auto`` guesses the server software; the disclosure rule places the host."""
    from maljan.llm.openai_provider import is_local_endpoint

    assert is_local_endpoint(url) is compat_local
    assert locality(host_of(url)) == placed
