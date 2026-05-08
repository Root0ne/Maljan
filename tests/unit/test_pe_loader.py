"""Tests for PELoader static analysis."""

from pathlib import Path
from unittest.mock import patch

import pytest

from maljan.loaders.pe_loader import PELoader, _detect_file_type


class TestDetectFileType:
    """Tests for file type detection fallback."""

    def test_pe_file_detected_by_header(self, tmp_path: Path) -> None:
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 100)
        assert "EXE" in _detect_file_type(pe_file)

    def test_elf_file_detected_by_header(self, tmp_path: Path) -> None:
        elf_file = tmp_path / "test.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert "ELF" in _detect_file_type(elf_file)

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.exe"
        assert "Unknown" in _detect_file_type(missing)


class TestPELoader:
    """Tests for PELoader PE parsing."""

    def test_pe_loader_with_non_pe_file(self, tmp_path: Path) -> None:
        """PELoader gracefully handles non-PE files."""
        fake_file = tmp_path / "fake.exe"
        fake_file.write_text("This is not a PE file")
        loader = PELoader(fake_file)
        result = loader.parse()
        assert result["file_path"] == str(fake_file)
        assert result["file_size"] == len("This is not a PE file")
        assert "entry_point" in result

    def test_pe_loader_to_markdown_structure(self, tmp_path: Path) -> None:
        fake_file = tmp_path / "fake.exe"
        fake_file.write_text("fake")
        loader = PELoader(fake_file)
        md = loader.to_markdown()
        assert "### Static PE Analysis" in md
        assert "**File:**" in md
        assert "**Size:**" in md
        assert "#### Sections" in md
        assert "#### Imports" in md
        assert "#### Exports" in md
        assert "#### Interesting Strings" in md

    def test_string_extraction(self, tmp_path: Path) -> None:
        fake_file = tmp_path / "fake.exe"
        fake_file.write_bytes(b"http://evil.com/c2\x00registry\x00cmd.exe\x00")
        loader = PELoader(fake_file)
        strings = loader._get_strings(min_length=4)
        assert any("http://evil.com/c2" in s for s in strings)

    def test_interesting_strings_filter(self, tmp_path: Path) -> None:
        fake_file = tmp_path / "fake.exe"
        fake_file.write_bytes(
            b"http://evil.com/c2\x00normal_text\x00HKLM\\Software\x00"
        )
        loader = PELoader(fake_file)
        data = loader.parse()
        interesting = data["strings"]
        assert any("http://evil.com/c2" in s for s in interesting)
        assert any("HKLM\\Software" in s for s in interesting)
