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


class TestPathFragmentsAreNotPaths:
    """Found by reading real output, not by reasoning about it.

    One sample returned ``/Users``, ``/rd_lee``, ``/.vscode``, ``/extensions``,
    ``/plugin``, ``/const``, ``/errors`` as ``path`` IOCs — plus ``/Vundo.gen``,
    ``/Ryuk.P`` and ``/Obfuse.VAL``, which are AV signature names lifted out of
    an embedded definition database. All of them are what ``/[A-Za-z0-9_...]+``
    matches when it meets ordinary text containing a slash.

    They were not merely ugly: ``path`` has a 20-slot quota, so the fragments
    crowded out real paths — the starvation the quotas were introduced to stop,
    reappearing inside a single kind.
    """

    def test_a_single_segment_is_not_a_path(self) -> None:
        blob = b"".join(_pad(p) for p in [b"/Users", b"/extensions", b"/const", b"/errors"])
        assert not _kinds(blob).get("path")

    def test_an_av_signature_name_is_not_a_path(self) -> None:
        blob = _pad(b"/Vundo.gen") + _pad(b"/Ryuk.P") + _pad(b"/Obfuse.VAL")
        assert not _kinds(blob).get("path")

    def test_a_windows_path_survives(self) -> None:
        blob = _pad(rb"C:\Users\victim\AppData\Roaming\svchost.exe")
        assert _kinds(blob).get("path")

    def test_a_posix_path_survives(self) -> None:
        assert _kinds(_pad(b"/etc/cron.d/persistence")).get("path")

    def test_one_separator_plus_an_extension_does_not_qualify(self) -> None:
        """The exemption that was tried and reverted: it readmitted every AV
        signature name, which is exactly ``/Word.ext`` shaped."""
        assert not _kinds(_pad(b"/payload.dll")).get("path")
        assert _kinds(_pad(b"/tmp/payload.dll")).get("path")

    def test_a_real_single_backslash_windows_path_is_extracted(self) -> None:
        """``_PATH_RE`` required *doubled* backslashes, so a plain
        ``C:\\Users\\...`` — how a path actually appears in a binary — matched
        nothing at all. Windows filesystem IOCs were missing from every report
        unless the sample happened to embed escaped text."""
        found = _kinds(_pad(rb"C:\Users\victim\AppData\Roaming\svchost.exe")).get("path", [])
        assert found, "single-backslash Windows paths must be extracted"
        assert "svchost.exe" in found[0]


class TestCodeIdentifiersAreNotDomains:
    """``self.id`` was reported as a C2 domain.

    ``.id`` is Indonesia's ccTLD and ``self`` clears every structural check
    there is — length, label count, TLD validity, casing. No rule about *shape*
    separates ``self.id`` from ``evil.id``, so the honest fix is a short list of
    the identifiers that actually collide, applied only to two-label candidates.
    """

    def test_self_dot_id_is_not_a_domain(self) -> None:
        assert not _kinds(_pad(b"self.id")).get("domain")

    def test_other_common_identifiers(self) -> None:
        blob = b"".join(_pad(s) for s in [b"result.io", b"config.co", b"data.me"])
        assert not _kinds(blob).get("domain")

    def test_a_three_label_host_starting_with_one_survives(self) -> None:
        """`self.example.com` is an ordinary hostname."""
        assert "self.example.com" in _kinds(_pad(b"self.example.com")).get("domain", [])

    def test_a_real_short_cctld_domain_survives(self) -> None:
        assert "evil-panel.id" in _kinds(_pad(b"evil-panel.id")).get("domain", [])


class TestTheReAnalysedSample:
    """Locked in from re-running a sample that had already been analysed.

    Its stored report listed 13 ``interesting_strings``. Every one was noise:
    ``/requestedPrivileges``, ``/security``, ``/trustInfo``, ``/assembly`` — XML
    manifest element names — and nine .NET namespaces (``System.Net.Http``,
    ``System.Reflection``, …) reported as **domains**.

    What the report did *not* contain was the sample's actual staging URL, a
    Google Drive download link. The binary is .NET, so its strings are wide, and
    the ASCII-only scan could not see it. Thirteen indicators, none real, and
    the one that mattered was missing.
    """

    def test_xml_manifest_elements_are_not_paths(self) -> None:
        blob = b"".join(
            _pad(p) for p in [b"/requestedPrivileges", b"/security", b"/trustInfo", b"/assembly"]
        )
        assert not _kinds(blob).get("path")

    def test_dotnet_namespaces_are_not_domains(self) -> None:
        blob = b"".join(
            _pad(n)
            for n in [
                b"System.Net.Http",
                b"System.Threading.Tasks",
                b"System.Reflection",
                b"System.Runtime.InteropServices",
            ]
        )
        assert not _kinds(blob).get("domain")

    def test_an_assembly_name_is_not_a_domain(self) -> None:
        """`MyApplication.app` — CamelCase wearing a real TLD."""
        assert not _kinds(_pad(b"MyApplication.app")).get("domain")

    def test_the_wide_staging_url_is_found(self) -> None:
        """The indicator the old report missed entirely."""
        url = "https://drive.google.com/uc?export=download&id=1VDmK_scFxGROc"
        blob = b"\x00\x00" + url.encode("utf-16-le") + b"\x00\x00"
        found = _kinds(blob)
        assert url in found.get("url", [])
        assert "drive.google.com" in found.get("domain", [])

    def test_a_url_slice_is_not_also_reported_as_a_path(self) -> None:
        """`s://drive.google.com/uc` appeared beside the URL it was carved from
        — the same indicator twice, once mangled."""
        blob = _pad(b"https://drive.google.com/uc?export=download")
        assert not _kinds(blob).get("path")
