"""A macro document produced a confident report over a payload nobody read.

`.docm`, `.ps1`, `.vbs`, `.js` and `.jar` are accepted by the upload allow-list
and no format is refused. That is the right call — a macro document is among
the commonest malware carriers, and refusing it would be worse than analysing
it thinly.

What was wrong is that nothing said it *was* thin. ``build_static_analysis``
returns empty sections, imports and exports for a `.docm`; only the raw-byte
string sweep runs. The analysis completes, the report renders, the verdict
carries its normal confidence, and the macro stream — the entire payload — was
never opened. A reader cannot distinguish that from a sample that was fully
examined and found unremarkable.

So this does not reject anything. It returns a degradation reason, which feeds
the existing ``degradation_reasons`` list, which caps the report's confidence
and prints what was not looked at.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from maljan.extractors.sample_identity import unparsed_container_reason


def _write(tmp_path: Path, name: str, magic: bytes = b"\x00\x01\x02\x03") -> Path:
    p = tmp_path / name
    p.write_bytes(magic + b"\x00" * 64)
    return p


class TestContainersAreDeclaredNotRejected:
    @pytest.mark.parametrize(
        ("name", "fragment"),
        [
            ("invoice.docm", "Office macro document"),
            ("report.xlsm", "Office macro spreadsheet"),
            ("dropper.ps1", "PowerShell script"),
            ("stage.vbs", "VBScript"),
            ("loader.js", "JScript"),
            ("payload.hta", "HTML application"),
            ("shortcut.lnk", "Windows shortcut"),
            ("setup.msi", "Windows Installer package"),
            ("bundle.jar", "Java archive"),
            ("archive.7z", "7-Zip archive"),
        ],
    )
    def test_each_carrier_declares_itself(self, tmp_path: Path, name: str, fragment: str) -> None:
        reason = unparsed_container_reason(_write(tmp_path, name))
        assert reason is not None, f"{name} produced no degradation reason"
        assert fragment in reason
        assert "raw-byte string sweep" in reason

    def test_declaring_a_container_is_not_refusing_it(self, tmp_path: Path) -> None:
        """A degradation reason describes the analysis, it does not stop it: the
        reason names the sweep that ran, never a refusal."""
        for name in ("invoice.docm", "dropper.ps1"):
            reason = unparsed_container_reason(_write(tmp_path, name)) or ""
            assert "raw-byte string sweep" in reason
            assert "unsupported" not in reason.lower()

    def test_a_pdf_by_magic_is_declared(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "doc.bin", b"%PDF-1.7")
        assert "PDF" in (unparsed_container_reason(p) or "")

    def test_a_zip_by_magic_is_declared(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "blob.bin", b"PK\x03\x04")
        assert "ZIP" in (unparsed_container_reason(p) or "")


class TestParsedFormatsStaySilent:
    def test_a_pe_declares_nothing(self, tmp_path: Path) -> None:
        """The whole point is to flag what was *not* parsed. A PE was."""
        assert unparsed_container_reason(_write(tmp_path, "sample.exe", b"MZ\x90\x00")) is None

    def test_an_elf_declares_nothing(self, tmp_path: Path) -> None:
        assert unparsed_container_reason(_write(tmp_path, "sample.elf", b"\x7fELF")) is None

    def test_a_pe_with_a_misleading_extension_declares_nothing(self, tmp_path: Path) -> None:
        """Magic bytes decide. A PE named .docm was still parsed as a PE."""
        assert unparsed_container_reason(_write(tmp_path, "evil.docm", b"MZ\x90\x00")) is None

    def test_an_unknown_blob_declares_nothing(self, tmp_path: Path) -> None:
        """No claim either way — this is for formats we can name and cannot
        open, not for anything unrecognised."""
        assert unparsed_container_reason(_write(tmp_path, "mystery.dat")) is None


class TestItNeverBreaksARun:
    def test_a_missing_path_is_safe(self, tmp_path: Path) -> None:
        assert unparsed_container_reason(tmp_path / "ghost.docm") is None

    def test_none_is_safe(self) -> None:
        assert unparsed_container_reason(None) is None
        assert unparsed_container_reason("") is None

    def test_a_directory_is_safe(self, tmp_path: Path) -> None:
        assert unparsed_container_reason(tmp_path) is None


class TestAContainerThatWasOpenedIsNotCalledUnparsed:
    """The reason was decided from the file type alone.

    A ZIP whose members `archive_list` had listed — sizes, CRCs, both entries
    in the report — still carried "container was not parsed … findings come
    from a raw-byte string sweep only", and the run capped its confidence on
    the strength of it. The question the reason answers is whether the format
    tool for this sample produced a result, so it is asked of the ledger.
    """

    def _ledger(self, tool: str, payload: dict[str, object], *, ok: bool = True) -> list[dict]:
        return [{"tool": tool, "ok": ok, "structured": payload}]

    def test_an_archive_whose_members_were_listed_is_not_unparsed(self, tmp_path: Path) -> None:
        archive = _write(tmp_path, "bundle.zip", b"PK\x03\x04")
        listed = self._ledger(
            "archive_list", {"members": [{"name": "payload.elf", "size": 202928}]}
        )
        assert unparsed_container_reason(archive, ledger=listed) is None

    def test_an_archive_whose_format_tool_failed_is_still_declared(self, tmp_path: Path) -> None:
        archive = _write(tmp_path, "bundle.zip", b"PK\x03\x04")
        failed = self._ledger("archive_list", {"error": "the call failed"}, ok=False)
        assert "ZIP archive" in (unparsed_container_reason(archive, ledger=failed) or "")

    def test_a_result_carrying_an_error_is_not_a_result(self, tmp_path: Path) -> None:
        archive = _write(tmp_path, "bundle.zip", b"PK\x03\x04")
        errored = self._ledger("archive_list", {"error": "not a zip file"})
        assert "ZIP archive" in (unparsed_container_reason(archive, ledger=errored) or "")

    def test_an_android_package_whose_tool_failed_is_declared(self, tmp_path: Path) -> None:
        """The true case: `apk_info` could not load, so nothing opened it."""
        import zipfile

        package = tmp_path / "app.apk"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
        failed = self._ledger(
            "apk_info", {"error": "install the optional tool libraries"}, ok=False
        )
        assert "Android package" in (unparsed_container_reason(package, ledger=failed) or "")

    def test_another_tool_answering_says_nothing_about_the_container(self, tmp_path: Path) -> None:
        document = _write(tmp_path, "invoice.docm")
        elsewhere = self._ledger("strings", {"strings": [{"text": "anything"}]})
        assert "Office macro document" in (
            unparsed_container_reason(document, ledger=elsewhere) or ""
        )

    def test_a_caller_with_no_ledger_answers_from_the_type_as_before(self, tmp_path: Path) -> None:
        assert "ZIP archive" in (unparsed_container_reason(_write(tmp_path, "a.zip")) or "")


class TestOnlyTheRoutedFormatsOwnToolCounts:
    """An APK, a .jar and a .docm are all zips, and an analyst may call
    `archive_list` on any of them. Listing the zip members is not opening the
    Android package: the manifest, the permissions and the components are what
    `apk_info` reads, and when it could not load there is still no permissions
    channel. Accepting any format tool let an analyst's call lift the cap on a
    payload nobody had read."""

    def _ledger(self, tool: str, payload: dict[str, object]) -> list[dict]:
        return [{"tool": tool, "ok": True, "structured": payload}]

    def _apk(self, tmp_path: Path) -> Path:
        import zipfile

        package = tmp_path / "app.apk"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
        return package

    def test_listing_an_android_packages_zip_members_does_not_open_it(self, tmp_path: Path) -> None:
        listed = self._ledger("archive_list", {"members": [{"name": "classes.dex"}]})
        reason = unparsed_container_reason(self._apk(tmp_path), ledger=listed)
        assert "Android package" in (reason or "")

    def test_the_packages_own_tool_does_open_it(self, tmp_path: Path) -> None:
        opened = self._ledger("apk_info", {"package": "com.example.app", "permissions": []})
        assert unparsed_container_reason(self._apk(tmp_path), ledger=opened) is None

    def test_a_documents_own_tool_is_document_info(self, tmp_path: Path) -> None:
        document = _write(tmp_path, "invoice.docm", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        listed = self._ledger("archive_list", {"members": []})
        assert "OLE2 document" in (unparsed_container_reason(document, ledger=listed) or "")
        opened = self._ledger("document_info", {"format": "ole2", "macros_present": True})
        assert unparsed_container_reason(document, ledger=opened) is None

    def test_an_archives_own_tool_is_archive_list(self, tmp_path: Path) -> None:
        archive = _write(tmp_path, "bundle.zip", b"PK\x03\x04")
        opened = self._ledger("archive_list", {"members": [{"name": "payload.elf"}]})
        assert unparsed_container_reason(archive, ledger=opened) is None


def test_the_container_reason_and_the_pack_route_to_the_same_tool() -> None:
    """Two tables, one routing decision.

    `sample_identity._FORMAT_TOOL_FOR` says which tool's answer silences the
    container reason and `triage_pack._FORMAT_TOOLS` says which tool the pack
    actually calls. A format added to one and forgotten in the other makes the
    report state something about the run that did not happen.
    """
    from maljan.extractors.sample_identity import _FORMAT_TOOL_FOR
    from maljan.pipeline.triage_pack import _FORMAT_TOOLS

    routed = {file_type: tool for file_type, (tool, _call) in _FORMAT_TOOLS.items()}
    assert _FORMAT_TOOL_FOR == routed
