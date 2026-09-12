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
            {"kind": "secret", "value": "AKIAIOSFODNN7EXAMPLE", "notes": "aws_access_key"}
        ]

    def test_kinds_narrows_the_answer_without_changing_the_scan(self) -> None:
        text = "http://evil-c2-host.top/a and 45.77.12.34"
        everything = tool.iocs_from_text(text)
        just_urls = tool.iocs_from_text(text, kinds=["url"])

        assert set(everything["kinds"]) >= {"url", "ip", "domain"}
        assert just_urls["kinds"] == ["url"]
        assert [row["value"] for row in just_urls["iocs"]] == ["http://evil-c2-host.top/a"]


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
