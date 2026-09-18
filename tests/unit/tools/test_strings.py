"""``maljan.tools.strings`` finds the wide runs and types what it finds.

The IOC scan moved here from ``pe_extractor``; ``test_string_ioc_extraction``
still pins its behaviour through the extractor's re-export, so what these tests
cover is the tool surface the extractor never had — the paged ``strings`` view
with real offsets, and the typed extraction over free text rather than bytes.
"""

from __future__ import annotations

from pathlib import Path

from maljan.tools import strings as tool


def _pad(payload: bytes) -> bytes:
    """Wrap in NULs so each item is its own printable run."""
    return b"\x00" + payload + b"\x00"


class TestStrings:
    def test_an_ascii_run_comes_back_at_the_offset_it_was_found_at(self, tmp_path: Path) -> None:
        blob = b"\x00" * 16 + b"HelloMalware" + b"\x00" * 8
        target = tmp_path / "s.bin"
        target.write_bytes(blob)

        result = tool.strings(str(target))

        assert result["strings"] == [{"offset": 16, "enc": "ascii", "text": "HelloMalware"}]
        assert result["total"] == 1
        assert result["truncated"] is False

    def test_a_utf16le_run_is_decoded_and_labelled(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_pad("evil-c2.example".encode("utf-16-le")))

        rows = tool.strings(str(target), encodings=("utf16le",))["strings"]

        assert [r["text"] for r in rows] == ["evil-c2.example"]
        assert rows[0]["enc"] == "utf16le"
        assert rows[0]["offset"] == 1

    def test_min_len_drops_the_short_runs(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_pad(b"abc") + _pad(b"abcdefghij"))

        short = tool.strings(str(target), min_len=3)
        long_only = tool.strings(str(target), min_len=8)

        assert [r["text"] for r in short["strings"]] == ["abc", "abcdefghij"]
        assert [r["text"] for r in long_only["strings"]] == ["abcdefghij"]

    def test_offset_and_limit_page_through_the_runs(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(b"".join(_pad(f"marker{i:03d}".encode()) for i in range(10)))

        page = tool.strings(str(target), limit=3, offset=4)

        assert [r["text"] for r in page["strings"]] == ["marker004", "marker005", "marker006"]
        assert page["total"] == 10
        assert page["truncated"] is True

    def test_an_unknown_encoding_is_named_rather_than_silently_ignored(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(b"anything")

        result = tool.strings(str(target), encodings=("ebcdic",))

        assert result["tool"] == "strings"
        assert "ebcdic" in result["error"] and "ascii" in result["error"]

    def test_a_pattern_finds_a_marker_anywhere_in_the_file(self, tmp_path: Path) -> None:
        """The live run's model passed byte offsets to ``offset`` and got empty
        pages back; what it wanted was to search for a family marker."""
        target = tmp_path / "s.bin"
        target.write_bytes(
            b"".join(_pad(f"filler{i:03d}".encode()) for i in range(200))
            + _pad(b"AsyncRAT client v0.5.7B")
        )

        found = tool.strings(str(target), pattern="asyncrat")

        assert [r["text"] for r in found["strings"]] == ["AsyncRAT client v0.5.7B"]
        assert found["total_matched"] == 1
        assert found["total"] == 201

    def test_a_regex_pattern_is_written_with_the_re_prefix(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_pad(b"host: c2-01.example") + _pad(b"nothing to see"))

        found = tool.strings(str(target), pattern=r"re:c2-\d+\.")

        assert [r["text"] for r in found["strings"]] == ["host: c2-01.example"]

    def test_a_pattern_that_does_not_compile_is_named(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_pad(b"anything at all"))

        result = tool.strings(str(target), pattern="re:(unclosed")

        assert result["tool"] == "strings"
        assert "bad pattern" in result["error"]

    def test_a_byte_range_narrows_the_scan_to_one_region(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        blob = _pad(b"first-run-here") + _pad(b"second-run-here")
        target.write_bytes(blob)

        tail = tool.strings(str(target), start=16)
        head = tool.strings(str(target), end=16)

        assert [r["text"] for r in tail["strings"]] == ["second-run-here"]
        assert [r["text"] for r in head["strings"]] == ["first-run-here"]
        assert (tail["total"], tail["total_matched"]) == (2, 1)

    def test_the_page_the_answer_was_cut_with_is_echoed(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(b"".join(_pad(f"marker{i:03d}".encode()) for i in range(10)))

        page = tool.strings(str(target), limit=3, offset=4)

        assert page["page_offset"] == 4
        assert page["page_limit"] == 3
        assert page["total_matched"] == 10

    def test_paging_counts_matches_rather_than_every_run(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(
            b"".join(_pad(f"marker{i:03d}".encode()) for i in range(10))
            + b"".join(_pad(f"other{i:03d}".encode()) for i in range(10))
        )

        page = tool.strings(str(target), pattern="marker", offset=8)

        assert [r["text"] for r in page["strings"]] == ["marker008", "marker009"]
        assert page["total_matched"] == 10
        assert page["truncated"] is False


class TestIocsFromText:
    def test_a_url_a_host_and_a_public_ip_are_each_typed(self) -> None:
        result = tool.iocs_from_text(
            "beacon to http://evil-c2-host.top/gate.php then 203.0.113.9 via mail@evil-c2-host.top"
        )

        by_kind = {row["kind"]: row["value"] for row in result["iocs"]}
        assert by_kind["url"] == "http://evil-c2-host.top/gate.php"
        assert by_kind["domain"] == "evil-c2-host.top"
        assert by_kind["email"] == "mail@evil-c2-host.top"
        # 203.0.113.0/24 is TEST-NET-3 and the filter drops it as documentation
        # noise, which is the point: the filter is on and this proves it.
        assert "ip" not in by_kind

    def test_a_routable_address_survives_the_noise_filter(self) -> None:
        result = tool.iocs_from_text("callback 45.77.12.34:8080")
        assert [row["value"] for row in result["iocs"] if row["kind"] == "ip"] == ["45.77.12.34"]

    def test_a_dotnet_type_name_is_not_reported_as_a_domain(self) -> None:
        result = tool.iocs_from_text("System.Collections.Generic.Dictionary")
        assert [row for row in result["iocs"] if row["kind"] == "domain"] == []

    def test_a_secret_carries_the_pattern_that_matched_it(self) -> None:
        result = tool.iocs_from_text("key AKIAIOSFODNN7EXAMPLE in the config")
        secrets = [row for row in result["iocs"] if row["kind"] == "secret"]
        assert secrets == [
            {
                "kind": "secret",
                "value": "AKIAIOSFODNN7EXAMPLE",
                "notes": "aws_access_key",
                "source": "strings",
            }
        ]

    def test_kinds_narrows_the_answer_without_changing_the_scan(self) -> None:
        text = "http://evil-c2-host.top/a and 45.77.12.34"
        everything = tool.iocs_from_text(text)
        just_urls = tool.iocs_from_text(text, kinds=["url"])

        assert set(everything["kinds"]) >= {"url", "ip", "domain"}
        assert just_urls["kinds"] == ["url"]
        assert [row["value"] for row in just_urls["iocs"]] == ["http://evil-c2-host.top/a"]


class TestDomainsReadOutOfStrings:
    """A printable run cut mid-word still ends in a real TLD.

    Every case here was produced by a real sample in a live run: the scan
    returned twenty-five "domains" for one PE, of which fifteen were fragments
    of longer names, identifier tables or detection labels. Each was published
    as a STIX indicator and each cost a reputation lookup.
    """

    def _domains(self, text: str) -> list[str]:
        return [
            row["value"] for row in tool.iocs_from_text(text)["iocs"] if row["kind"] == "domain"
        ]

    def test_a_longer_look_alike_does_not_delete_the_real_name(self) -> None:
        """Which of two names is the fragment is about where they sit, not how
        they are spelled. Asking by spelling deleted the real one."""
        assert self._domains("visit microsoft.com and xmicrosoft.com") == [
            "microsoft.com",
            "xmicrosoft.com",
        ]

    def test_a_leading_byte_does_not_delete_the_host_it_was_stuck_to(self) -> None:
        assert self._domains("M000webhostapp.com and 000webhostapp.com") == [
            "M000webhostapp.com",
            "000webhostapp.com",
        ]

    def test_a_name_inside_a_longer_one_is_the_fragment(self) -> None:
        """The rule keys on spans: a match that lies within a longer host's
        span, cut inside a label, is the fragment."""
        found = [(0, 13, "microsoft.com"), (2, 13, "crosoft.com")]
        assert tool._inside_a_longer_host(2, 13, found) is True
        assert tool._inside_a_longer_host(0, 13, found) is False

    def test_a_cut_on_a_label_boundary_is_a_name_of_its_own(self) -> None:
        found = [(0, 15, "crl.example.com"), (4, 15, "example.com")]
        assert tool._inside_a_longer_host(4, 15, found) is False

    def test_a_parent_domain_at_a_label_boundary_is_kept(self) -> None:
        """`sectigo.com` under `crl.sectigo.com` is a registrable name, not a fragment."""
        found = self._domains("http://crl.sectigo.com/a.crl and https://sectigo.com/CPS")
        assert "crl.sectigo.com" in found
        assert "sectigo.com" in found

    def test_a_detection_label_wearing_a_country_code_is_not_a_host(self) -> None:
        """`Bifrose.IE`, `jector.SA`, `workbench.nL` — a host is written in one case."""
        found = self._domains("Trojan:Bifrose.IE jector.SA =[workbench.nL mucod.FR")
        assert found == []

    def test_a_host_written_wholly_in_capitals_survives_the_case_check(self) -> None:
        """One case throughout is a spelling; a lowercase name with a shouted
        country code is a label out of a table."""
        assert self._domains("connect to WWW.EXAMPLE-C2.TOP now") == ["WWW.EXAMPLE-C2.TOP"]

    def test_a_bare_public_suffix_has_nothing_registrable_in_it(self) -> None:
        assert self._domains("suffixes are co.uk and com.br and ne.jp") == []

    def test_a_match_that_begins_after_an_underscore_is_an_identifier(self) -> None:
        """An underscore cannot appear in a hostname label, so the run is code."""
        assert self._domains("field_name evil_payload.com beside real-c2.top") == ["real-c2.top"]

    def test_every_row_says_where_it_came_from(self) -> None:
        rows = tool.iocs_from_text("http://evil-c2-host.top/gate.php from 45.77.12.34")["iocs"]
        assert rows
        assert {row["source"] for row in rows} == {"strings"}


class TestIocsFromFile:
    def test_a_wide_string_host_is_found_where_an_ascii_scan_would_miss_it(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_pad("wide-c2-host.top".encode("utf-16-le")))

        result = tool.iocs_from_file(str(target))

        assert "wide-c2-host.top" in [row["value"] for row in result["iocs"]]

    def test_a_missing_file_is_an_error_and_not_an_exception(self) -> None:
        result = tool.iocs_from_file("/nonexistent/sample.bin")
        assert result["tool"] == "iocs_from_file"
