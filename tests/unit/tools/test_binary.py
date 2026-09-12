"""``maljan.tools.binary`` reports structure, and reports it as facts.

Synthetic inputs throughout: a hand-built ELF header, a zip with an
``AndroidManifest.xml``, a PDF carrying ``/JS`` and ``/OpenAction``. They are
small enough to read in the test and real enough that the parser has to
actually parse them.

The optional-dependency tools skip when their library is absent rather than
asserting the degraded answer, because both answers are correct — which one a
box gives depends on whether ``uv sync --extra tools`` has run there.
"""

from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from maljan.tools import binary as tool


def _elf(machine: int = 0x3E) -> bytes:
    """A 64-bit little-endian ELF header with no section table."""
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    return ident + struct.pack("<HHI", 2, machine, 1) + b"\x00" * 512


class TestPeInfo:
    def test_a_file_without_the_mz_magic_is_refused_by_name(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        result = tool.pe_info(str(target))
        assert result == {"error": "not a PE file (no MZ magic)", "tool": "pe_info"}

    def test_a_missing_file_is_an_error_and_not_an_exception(self) -> None:
        assert tool.pe_info("/nonexistent/s.exe")["tool"] == "pe_info"


class TestPackerSectionMatches:
    def test_a_upx_section_layout_is_reported_as_a_match_and_nothing_more(self) -> None:
        """A fact, not a verdict: the row names the catalog entry and the
        section names that hit, and carries no confidence and no "packed"."""
        matches = tool.packer_section_matches(["UPX0", "UPX1", ".rsrc"])
        assert matches, "the vendored catalog should carry a UPX entry"
        upx = next(row for row in matches if row["name"].lower().startswith("upx"))
        assert set(upx) == {"name", "kind", "sections"}
        assert "UPX0" in upx["sections"]

    def test_an_ordinary_section_layout_matches_nothing(self) -> None:
        assert tool.packer_section_matches([".text", ".data", ".rdata"]) == []

    def test_a_missing_catalog_is_an_empty_list_rather_than_a_failure(self) -> None:
        assert tool.packer_section_matches(["UPX0"], catalog_path="data/nope.json") == []


class TestElfInfo:
    def test_the_bitness_and_endianness_come_from_the_ident_bytes(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        result = tool.elf_info(str(target))
        assert result["bitness"] == 64
        assert result["endianness"] == "little"

    def test_a_real_system_binary_reports_its_interpreter_and_needed_libraries(self) -> None:
        binary = Path("/bin/ls")
        if not binary.is_file():
            pytest.skip("no /bin/ls on this box")
        result = tool.elf_info(str(binary))
        assert result["sections"], "a system binary has sections"
        # A dynamically linked binary names its loader; a static one would not,
        # and then there is nothing to assert about linkage.
        if result["interp"]:
            assert result["interp"].startswith("/")
            assert result["needed"], "a dynamic binary needs at least one library"

    def test_a_file_without_the_elf_magic_is_refused_by_name(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        assert tool.elf_info(str(target))["tool"] == "elf_info"


class TestMachoInfo:
    def test_a_non_macho_file_is_refused_before_the_library_is_needed(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        assert tool.macho_info(str(target))["error"] == "not a Mach-O file"

    def test_a_macho_without_macholib_says_which_library_is_missing(self, tmp_path: Path) -> None:
        try:
            import macholib  # noqa: F401
        except ImportError:
            target = tmp_path / "s.bin"
            target.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            assert tool.macho_info(str(target)) == {
                "error": "macholib is not installed",
                "tool": "macho_info",
            }
        else:
            pytest.skip("macholib is installed; the degraded path is not the one taken")


class TestApkInfo:
    def _apk(self, tmp_path: Path) -> Path:
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
            archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
            archive.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 32)
            archive.writestr("lib/arm64-v8a/libnative.so", _elf())
            archive.writestr("META-INF/CERT.RSA", b"\x30\x82 fake pkcs7")
        return apk

    def test_the_zip_level_facts_are_reported_with_or_without_androguard(
        self, tmp_path: Path
    ) -> None:
        result = tool.apk_info(str(self._apk(tmp_path)))

        assert result["manifest_present"] is True
        assert result["dex_count"] == 2
        assert result["abis"] == ["arm64-v8a"]
        assert result["cert_files"] == ["META-INF/CERT.RSA"]

    def test_without_androguard_the_missing_library_is_named(self, tmp_path: Path) -> None:
        try:
            import androguard  # noqa: F401
        except ImportError:
            result = tool.apk_info(str(self._apk(tmp_path)))
            assert result["error"] == "androguard is not installed"
            assert result["degraded"] == "zip-level facts only"
        else:
            pytest.skip("androguard is installed; the degraded path is not the one taken")

    def test_a_file_that_is_not_a_zip_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        assert tool.apk_info(str(target))["error"] == "not a zip-based APK"


class TestArchiveList:
    def test_a_zip_member_carries_its_size_and_crc(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "a.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.exe", b"MZ" + b"A" * 1000)

        result = tool.archive_list(str(archive_path))

        assert result["format"] == "zip"
        assert result["total"] == 1
        member = result["members"][0]
        assert member["name"] == "payload.exe"
        assert member["size"] == 1002
        assert member["compressed"] < member["size"]
        assert len(member["crc"]) == 8

    def test_a_tar_member_is_listed_by_name_and_size(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "a.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("dropper.sh")
            payload = b"#!/bin/sh\necho hi\n"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

        result = tool.archive_list(str(archive_path))

        assert result["format"] == "tar"
        assert result["members"] == [{"name": "dropper.sh", "size": 18, "is_dir": False}]

    def test_a_gzip_stream_reports_the_original_name_it_recorded(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "payload.gz"
        with (
            archive_path.open("wb") as raw,
            gzip.GzipFile(filename="payload.bin", mode="wb", fileobj=raw) as fh,
        ):
            fh.write(b"content")

        result = tool.archive_list(str(archive_path))

        assert result["format"] == "gzip"
        assert result["members"][0]["name"] == "payload.bin"

    def test_limit_truncates_and_says_so(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "a.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            for i in range(10):
                archive.writestr(f"f{i}.txt", b"x")

        result = tool.archive_list(str(archive_path), limit=3)

        assert len(result["members"]) == 3
        assert result["total"] == 10
        assert result["truncated"] is True

    def test_an_unsupported_format_is_named_rather_than_guessed_at(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        assert tool.archive_list(str(target))["error"] == "unsupported archive format"


class TestDocumentInfo:
    def test_a_pdf_reports_its_action_markers_and_object_count(self, tmp_path: Path) -> None:
        pdf = tmp_path / "doc.pdf"
        pdf.write_bytes(
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n"
            b"endobj\n"
            b"2 0 obj\n<< /Type /Page >>\nendobj\n"
            b"trailer\n%%EOF\n"
        )

        result = tool.document_info(str(pdf))

        assert result["format"] == "pdf"
        assert result["markers"]["/OpenAction"] == 1
        assert result["markers"]["/JavaScript"] == 1
        assert result["markers"]["/JS"] == 1
        assert result["object_count"] == 2
        assert result["encrypted"] is False

    def test_an_ooxml_document_reports_its_parts_and_the_vba_project(self, tmp_path: Path) -> None:
        docm = tmp_path / "doc.docm"
        with zipfile.ZipFile(docm, "w") as archive:
            archive.writestr("[Content_Types].xml", b"<Types/>")
            archive.writestr("word/document.xml", b"<w:document/>")
            archive.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0")
            archive.writestr("word/_rels/document.xml.rels", b"<Relationships/>")

        result = tool.document_info(str(docm))

        assert result["format"] == "ooxml"
        assert result["vba_project_present"] is True
        assert "word/document.xml" in result["parts"]
        assert result["external_relationships"] == 1

    def test_an_ooxml_document_without_macros_says_so(self, tmp_path: Path) -> None:
        docx = tmp_path / "doc.docx"
        with zipfile.ZipFile(docx, "w") as archive:
            archive.writestr("word/document.xml", b"<w:document/>")
        assert tool.document_info(str(docx))["vba_project_present"] is False

    def test_a_file_that_is_none_of_the_three_formats_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        assert "not an OLE2" in tool.document_info(str(target))["error"]


class TestCarvePayloads:
    def test_a_file_with_nothing_embedded_carves_nothing(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        out = tmp_path / "carved"

        result = tool.carve_payloads(str(target), str(out))

        assert result == {"payloads": [], "count": 0}
        assert out.is_dir(), "the output directory is created even when nothing lands in it"

    def test_a_missing_file_is_an_error_and_not_an_exception(self, tmp_path: Path) -> None:
        assert tool.carve_payloads("/nonexistent/s.bin", str(tmp_path))["tool"] == "carve_payloads"
