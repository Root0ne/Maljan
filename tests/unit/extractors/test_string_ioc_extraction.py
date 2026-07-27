"""The IOC extractor kept the wrong 80 strings, and could not see half of them.

Three defects, all of them silent — the extractor returned a plausible-looking
list every time, and nothing anywhere said what had been dropped.

**A global budget consumed in extraction order.** ``_MAX_IOC_STRINGS = 80`` was
one pool, filled url → ip → registry → path → email → mutex → **domain last**.
A binary carrying a few dozen embedded file paths exhausted it before a single
domain was considered, so the C2 host — the one string an analyst is actually
looking for — lost its slot to ``C:\\Windows\\System32\\``. Per-kind quotas make
that failure survivable and local instead of global.

**UTF-16LE strings were invisible.** Every ...W API call site and every resource
string in a Windows binary is wide, and the ASCII scan cannot see them: the
interleaved NULs break each run at the first character. A C2 host stored as a
wide string simply did not exist as far as the report was concerned.

**Dotted identifiers were reported as domains.** ``System.Collections.Generic``
is dot-separated labels ending in a word — the same shape as a hostname — and a
purely negative filter has no way to reject it. Every .NET sample produced them.

Also here: the dead ``_PRINTABLE_RE``/``_MAX_STRINGS_KEPT`` pair is now wired,
so the extractor makes one pass over the blob instead of one per pattern.
"""

from __future__ import annotations

from maljan.extractors.pe_extractor import _extract_string_iocs


def _kinds(blob: bytes) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ioc in _extract_string_iocs(blob):
        out.setdefault(ioc.kind, []).append(ioc.value)
    return out


def _pad(payload: bytes) -> bytes:
    """Wrap in NULs so each item is its own printable run."""
    return b"\x00" + payload + b"\x00"


class TestTheBudgetNoLongerStarvesDomains:
    def test_a_pile_of_paths_does_not_evict_the_c2_host(self) -> None:
        """The exact shape that lost C2 hosts: paths are extracted early and
        there were plenty of them."""
        noise = b"".join(
            _pad(f"C:\\Windows\\System32\\driver{i:03d}.sys".encode()) for i in range(200)
        )
        blob = noise + _pad(b"evil-c2-host.top") + noise

        found = _kinds(blob)
        assert "evil-c2-host.top" in found.get("domain", []), (
            "the domain lost its slot to file paths"
        )

    def test_each_kind_has_its_own_ceiling(self) -> None:
        blob = b"".join(_pad(f"host{i:04d}.example.com".encode()) for i in range(500))
        domains = _kinds(blob).get("domain", [])
        assert domains, "domains extracted"
        assert len(domains) <= 25, "a single kind must not consume the whole report"

    def test_the_overall_cap_still_holds(self) -> None:
        blob = b"".join(
            _pad(f"http://host{i:04d}.example.com/a".encode()) for i in range(200)
        ) + b"".join(_pad(f"C:\\dir\\file{i:04d}.dat".encode()) for i in range(200))
        assert len(_extract_string_iocs(blob)) <= 80


class TestWideStringsAreVisible:
    def test_a_utf16le_domain_is_extracted(self) -> None:
        wide = "malicious-host.top".encode("utf-16-le")
        assert "malicious-host.top" in _kinds(b"\x00\x00" + wide + b"\x00\x00").get("domain", [])

    def test_a_utf16le_url_is_extracted(self) -> None:
        wide = "http://evil.example.com/beacon".encode("utf-16-le")
        assert "http://evil.example.com/beacon" in _kinds(b"\x00\x00" + wide).get("url", [])

    def test_ascii_still_works(self) -> None:
        assert "http://evil.example.com/x" in _kinds(_pad(b"http://evil.example.com/x")).get(
            "url", []
        )


class TestNamespacesAreNotDomains:
    def test_a_dotnet_type_name_is_not_reported_as_a_c2_domain(self) -> None:
        blob = _pad(b"System.Collections.Generic.Dictionary") + _pad(b"System.Net")
        assert not _kinds(blob).get("domain")

    def test_a_real_domain_beside_it_still_is(self) -> None:
        blob = _pad(b"System.Collections.Generic") + _pad(b"real-c2.top")
        assert _kinds(blob).get("domain") == ["real-c2.top"]


class TestSecretsAndWallets:
    def test_an_aws_key_is_typed_not_dumped_into_other(self) -> None:
        blob = _pad(b"AKIAIOSFODNN7EXAMPLE")
        found = _extract_string_iocs(blob)
        secrets = [i for i in found if i.kind == "secret"]
        assert secrets, "a leaked AWS key must be extracted"
        assert secrets[0].value == "AKIAIOSFODNN7EXAMPLE"
        assert secrets[0].notes == "aws_access_key", "the kind of secret must be recorded"

    def test_a_github_token(self) -> None:
        token = "ghp_" + "a" * 36
        found = _extract_string_iocs(_pad(token.encode()))
        assert any(i.kind == "secret" and i.value == token for i in found)

    def test_a_private_key_header(self) -> None:
        found = _extract_string_iocs(_pad(b"-----BEGIN RSA PRIVATE KEY-----"))
        assert any(i.kind == "secret" for i in found)

    def test_an_ethereum_address(self) -> None:
        addr = "0x" + "a1b2c3d4" * 5
        found = _extract_string_iocs(_pad(addr.encode()))
        wallets = [i for i in found if i.kind == "crypto_wallet"]
        assert wallets and wallets[0].notes == "ethereum"

    def test_an_onion_address_is_a_domain_with_a_note(self) -> None:
        onion = "abcdefghijklmnop234567.onion"
        found = _extract_string_iocs(_pad(onion.encode()))
        hits = [i for i in found if i.value == onion]
        assert hits, "a hidden service is an IOC"
        assert hits[0].notes == "tor_hidden_service"

    def test_ordinary_text_produces_no_secrets(self) -> None:
        blob = _pad(b"Copyright (C) 2026 Example Corporation. All rights reserved.")
        assert not [i for i in _extract_string_iocs(blob) if i.kind == "secret"]


class TestTheExistingKindsAreUnchanged:
    def test_registry_paths(self) -> None:
        blob = _pad(rb"HKLM\Software\Microsoft\Windows\CurrentVersion\Run")
        assert _kinds(blob).get("registry")

    def test_mutexes(self) -> None:
        assert _kinds(_pad(rb"\BaseNamedObjects\MyEvilMutex")).get("mutex")

    def test_private_ips_are_still_filtered(self) -> None:
        blob = _pad(b"192.168.1.1") + _pad(b"127.0.0.1") + _pad(b"10.0.0.5")
        assert not _kinds(blob).get("ip")

    def test_a_routable_ip_survives(self) -> None:
        assert "203.0.113.9" not in _kinds(_pad(b"203.0.113.9")).get("ip", []), (
            "RFC5737 documentation blocks stay filtered"
        )
        assert "45.83.220.11" in _kinds(_pad(b"45.83.220.11")).get("ip", [])

    def test_an_empty_blob_is_handled(self) -> None:
        assert _extract_string_iocs(b"") == []
