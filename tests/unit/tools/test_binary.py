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


def _pe(import_rva: int = 0x1000, delay: bool = True, delay_rva: int = 0x2000) -> bytes:
    """A 32-bit PE with one real import and, optionally, one delay-load import.

    Hand-built rather than checked in as a fixture: the point of the damaged
    case is that the import directory RVA is wrong and everything else is
    right, and that is one argument here instead of a second binary nobody can
    read in a diff.
    """
    idata = bytearray(0x200)
    idata[0x00:0x14] = struct.pack("<IIIII", 0x1028, 0, 0, 0x1060, 0x1030)
    idata[0x28:0x30] = struct.pack("<II", 0x1040, 0)
    idata[0x30:0x38] = struct.pack("<II", 0x1040, 0)
    idata[0x40:0x4E] = struct.pack("<H", 0) + b"CreateFileA\x00"
    idata[0x60:0x6D] = b"KERNEL32.dll\x00"

    didat = bytearray(0x200)
    didat[0x00:0x20] = struct.pack("<IIIIIIII", 1, 0x2080, 0x2090, 0x2048, 0x2040, 0, 0, 0)
    didat[0x40:0x48] = struct.pack("<II", 0x2060, 0)
    didat[0x48:0x50] = struct.pack("<II", 0x2060, 0)
    didat[0x60:0x73] = struct.pack("<H", 0) + b"HttpSendRequestA\x00"
    didat[0x80:0x8C] = b"WININET.dll\x00"

    sections = 2 if delay else 1
    opt = bytearray()
    opt += struct.pack("<HBB", 0x10B, 14, 29)
    opt += struct.pack("<III", 0x200, 0, 0)
    opt += struct.pack("<III", 0x1000, 0x1000, 0x1000)
    opt += struct.pack("<III", 0x400000, 0x1000, 0x200)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<II", 0x1000 * (sections + 1), 0x200)
    # Subsystem 3 (console), DllCharacteristics = DYNAMIC_BASE | NX_COMPAT |
    # NO_SEH | TERMINAL_SERVER_AWARE.
    opt += struct.pack("<IHH", 0, 3, 0x8140)
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    directories = [(0, 0)] * 16
    directories[1] = (import_rva, 40)
    if delay:
        directories[13] = (delay_rva, 64)
    for rva, size in directories:
        opt += struct.pack("<II", rva, size)

    # Characteristics = EXECUTABLE_IMAGE | 32BIT_MACHINE.
    file_header = struct.pack("<HHIIIHH", 0x14C, sections, 0x5F5E0FF, 0, 0, len(opt), 0x0102)
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    headers[0x3C:0x40] = struct.pack("<I", 0x40)
    at = 0x40
    headers[at : at + 4] = b"PE\x00\x00"
    at += 4
    headers[at : at + len(file_header)] = file_header
    at += len(file_header)
    headers[at : at + len(opt)] = opt
    at += len(opt)

    def _section(name: bytes, rva: int, raw: int) -> bytes:
        return struct.pack("<8sIIIIIIHHI", name, 0x200, rva, 0x200, raw, 0, 0, 0, 0, 0xC0000040)

    headers[at : at + 40] = _section(b".idata\x00\x00", 0x1000, 0x200)
    at += 40
    if delay:
        headers[at : at + 40] = _section(b".didat\x00\x00", 0x2000, 0x400)
    return bytes(headers) + bytes(idata) + (bytes(didat) if delay else b"")


class TestPeInfo:
    def test_a_file_without_the_mz_magic_is_refused_by_name(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        result = tool.pe_info(str(target))
        assert result == {"error": "not a PE file (no MZ magic)", "tool": "pe_info"}

    def test_a_missing_file_is_an_error_and_not_an_exception(self) -> None:
        assert tool.pe_info("/nonexistent/s.exe")["tool"] == "pe_info"

    def test_a_healthy_pe_reports_its_header_facts(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        target = tmp_path / "clean.exe"
        target.write_bytes(_pe())

        result = tool.pe_info(str(target))

        assert result["warnings"] == []
        assert result["import_table_damaged"] is False
        assert [row["function"] for row in result["imports"]] == ["CreateFileA"]
        assert result["characteristics"] == [
            "IMAGE_FILE_EXECUTABLE_IMAGE",
            "IMAGE_FILE_32BIT_MACHINE",
        ]
        assert "IMAGE_DLLCHARACTERISTICS_NX_COMPAT" in result["dll_characteristics"]
        assert result["linker_version"] == "14.29"
        assert result["rich_header_present"] is False

    def test_a_damaged_import_table_is_said_out_loud(self, tmp_path: Path) -> None:
        """The live sample's import directory RVA pointed nowhere and the tool
        answered ``imports: []`` — indistinguishable from a binary that imports
        nothing at all."""
        pytest.importorskip("pefile")
        target = tmp_path / "damaged.exe"
        target.write_bytes(_pe(import_rva=0x9000))

        result = tool.pe_info(str(target))

        assert result["imports"] == []
        assert result["import_table_damaged"] is True
        assert any("import directory" in w for w in result["warnings"])

    def test_a_benign_import_warning_is_not_a_damaged_table(self, tmp_path: Path) -> None:
        """A healthy binary whose delay-load descriptor pefile cannot walk still
        has a perfectly good import table. Matching the bare word "import" in
        the warning list called that a damaged one."""
        pytest.importorskip("pefile")
        target = tmp_path / "delay-broken.exe"
        target.write_bytes(_pe(delay_rva=0x9000))

        result = tool.pe_info(str(target))

        assert [row["function"] for row in result["imports"]] == ["CreateFileA"]
        assert any("import" in w.lower() for w in result["warnings"]), result["warnings"]
        assert result["import_table_damaged"] is False

    def test_delay_load_imports_are_reported_too(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        target = tmp_path / "delay.exe"
        target.write_bytes(_pe())

        result = tool.pe_info(str(target))

        (row,) = result["delay_imports"]
        assert (row["dll"], row["function"]) == ("WININET.dll", "HttpSendRequestA")

    def test_an_import_row_carries_the_table_s_facts_and_no_label(self, tmp_path: Path) -> None:
        """A row that called BitBlt "keylogging" was the tool doing the analysis,
        and an analyst wrote the label up as its first claim on a signed binary.
        What an API is used for is the knowledge server's question."""
        pytest.importorskip("pefile")
        target = tmp_path / "sample.exe"
        target.write_bytes(_pe())

        result = tool.pe_info(str(target))

        for row in [*result["imports"], *result["delay_imports"]]:
            assert set(row) == {"dll", "function", "ordinal", "hint", "address"}
        (row,) = result["imports"]
        assert (row["function"], row["hint"]) == ("CreateFileA", 0)
        assert isinstance(row["address"], int)

    def test_the_import_blocks_are_omitted_when_imports_are_not_asked_for(
        self, tmp_path: Path
    ) -> None:
        pytest.importorskip("pefile")
        target = tmp_path / "clean.exe"
        target.write_bytes(_pe())

        result = tool.pe_info(str(target), imports=False)

        assert "imports" not in result
        assert "delay_imports" not in result


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

    def test_without_androguard_the_answer_is_a_success_that_says_what_is_missing(
        self, tmp_path: Path
    ) -> None:
        """The zip facts were returned beside an `error` key, so the ledger
        recorded the call as failed and the pack showed none of them. The
        degraded subset is an answer; what it could not add is said in
        `degraded`, with the remedy."""
        try:
            import androguard  # noqa: F401
        except ImportError:
            result = tool.apk_info(str(self._apk(tmp_path)))
            assert "error" not in result
            assert result["manifest_present"] is True
            assert result["dex_count"] == 2
            assert "androguard is not installed" in result["degraded"]
            assert "uv sync --extra tools" in result["remediation"]
        else:
            pytest.skip("androguard is installed; the degraded path is not the one taken")

    def test_a_parse_failure_does_not_tell_the_operator_to_install_what_is_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The remedy belongs to the reason: a library that refused a file is
        not fixed by installing it again."""
        import sys
        import types

        module = types.ModuleType("androguard.core.apk")

        class _Refuses:
            def __init__(self, _path: str) -> None:
                raise ValueError("not a manifest")

        module.APK = _Refuses  # type: ignore[attr-defined]
        package = types.ModuleType("androguard")
        core = types.ModuleType("androguard.core")
        monkeypatch.setitem(sys.modules, "androguard", package)
        monkeypatch.setitem(sys.modules, "androguard.core", core)
        monkeypatch.setitem(sys.modules, "androguard.core.apk", module)

        result = tool.apk_info(str(self._apk(tmp_path)))

        assert "androguard parse failed" in result["degraded"]
        assert "remediation" not in result
        assert result["manifest_present"] is True

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
    """The private carver: the destination is the caller's, and it is made private."""

    def test_a_file_with_nothing_embedded_carves_nothing(self, tmp_path: Path) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(_elf())
        out = tmp_path / "carved"

        result = tool._carve_into(str(target), out)

        assert result == {"payloads": [], "count": 0}
        assert out.is_dir(), "the output directory is created even when nothing lands in it"
        assert out.stat().st_mode & 0o777 == 0o700

    def test_a_missing_file_is_an_error_and_not_an_exception(self, tmp_path: Path) -> None:
        assert tool._carve_into("/nonexistent/s.bin", tmp_path)["tool"] == "carve_payloads"

    def test_the_module_offers_no_model_facing_carver(self) -> None:
        """The sidecar decides where carved files land; nothing here takes a
        directory from a caller that could be a model."""
        assert not hasattr(tool, "carve_payloads")


class TestWhichImportWarningMeansDamage:
    """pefile writes "Error parsing the import table" both for a walk it had to
    abandon and for one thunk it could not read, so the words "directory" and
    "table" do not separate them. Each sentence is classified by what it does
    to the parse: a truncated import list presented as a complete one is the
    claim worth flagging."""

    @pytest.mark.parametrize(
        "warning",
        [
            "Error parsing the import directory at RVA: 0x9000",
            "Too many errors parsing the import directory. Invalid import data at RVA: 0x1000",
            "Damaged Import Table information. ILT and/or IAT appear to be broken. "
            "OriginalFirstThunk: 0x0 FirstThunk: 0x0",
            "Error parsing the import table. Entries go beyond bounds.",
            "Error parsing the import table. AddressOfData overlaps with THUNK_DATA "
            "for THUNK at RVA 0x2040",
        ],
    )
    def test_a_walk_that_stopped_is_damage(self, warning: str) -> None:
        assert tool._import_table_damaged([warning]) is True

    @pytest.mark.parametrize(
        "warning",
        [
            "Error parsing the import directory. Invalid Import data at RVA: 0x1000 (bad)",
            "Error parsing the import table. Invalid data at RVA: 0x1040",
            "Error parsing the Delay import directory at RVA: 0x9000",
            "Error parsing the Delay import directory. Invalid import data at RVA: 0x2000",
        ],
    )
    def test_one_bad_entry_is_not(self, warning: str) -> None:
        assert tool._import_table_damaged([warning]) is False

    def test_a_bad_entry_repeated_across_the_table_is(self) -> None:
        repeated = [
            f"Error parsing the import table. Invalid data at RVA: 0x{rva:x}"
            for rva in (0x1040, 0x1048, 0x1050)
        ]
        assert tool._import_table_damaged(repeated) is True
        assert tool._import_table_damaged(repeated[:2]) is False

    def test_no_warnings_at_all(self) -> None:
        assert tool._import_table_damaged([]) is False
