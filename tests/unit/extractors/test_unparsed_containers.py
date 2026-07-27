"""A macro document produced a confident report over a payload nobody read.

`.docm`, `.ps1`, `.vbs`, `.js` and `.jar` are accepted by the upload allow-list
and are not rejected by ``unsupported_os_reason``. That is the right call — a
macro document is among the commonest Windows malware carriers, and refusing it
would be worse than analysing it thinly.

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

from maljan.extractors.sample_identity import unparsed_container_reason, unsupported_os_reason


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

    def test_they_are_still_accepted_for_analysis(self, tmp_path: Path) -> None:
        """Refusing a macro document would be the wrong fix — they are exactly
        what a Windows analyst needs to look at."""
        assert unsupported_os_reason(_write(tmp_path, "invoice.docm")) is None
        assert unsupported_os_reason(_write(tmp_path, "dropper.ps1")) is None

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
