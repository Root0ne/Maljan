"""Unit tests for the platform-inference helper added in Wave 4."""

from __future__ import annotations

from pathlib import Path

import pytest

from maljan.extractors.sample_identity import _infer_platform, unsupported_os_reason


# OS-support scope (2026-06-02): Windows + Linux only. Every other executable
# format (Mach-O, APK/DEX, IPA, jar) resolves to "unknown".
@pytest.mark.parametrize(
    ("file_type", "expected"),
    [
        ("PE", "windows"),
        ("pe", "windows"),
        ("ELF", "linux"),
        ("Mach-O", "unknown"),
        ("ZIP/APK", "unknown"),
        ("ZIP/IPA", "unknown"),
        ("ZIP/JAR", "unknown"),
        ("PDF", "unknown"),
        ("ZIP", "unknown"),
        ("unknown", "unknown"),
        ("", "unknown"),
    ],
)
def test_infer_platform_from_file_type(file_type: str, expected: str) -> None:
    assert _infer_platform(file_type, None, None) == expected


def test_infer_platform_sandbox_fallback_windows() -> None:
    sb = {"target": {"os": "windows10"}}
    assert _infer_platform("unknown", None, sb) == "windows"


def test_infer_platform_foreign_sandbox_hint_is_unknown() -> None:
    # A foreign (non-Win/Linux) sandbox hint resolves to unknown / out of scope.
    sb = {"target": {"platform": "android-11"}}
    assert _infer_platform("unknown", None, sb) == "unknown"


def test_infer_platform_mime_fallback_windows() -> None:
    # Sandbox said nothing but MIME hints at PE.
    assert _infer_platform("unknown", "application/x-msdownload", None) == "windows"


def test_infer_platform_file_type_wins_over_sandbox() -> None:
    # Magic bytes beat a misrouted sandbox: an ELF in a Windows profile is linux.
    sb = {"target": {"os": "windows10"}}
    assert _infer_platform("ELF", None, sb) == "linux"


def test_infer_platform_unknown_when_nothing_disambiguates() -> None:
    assert _infer_platform("unknown", None, None) == "unknown"
    assert _infer_platform("unknown", "application/octet-stream", {}) == "unknown"


# ---------------------------------------------------------------------------
# unsupported_os_reason — OS-support scope (2026-06-02): Windows + Linux only.
# Definitely-foreign samples are rejected; Win/Linux samples are never blocked.
# ---------------------------------------------------------------------------
class TestUnsupportedOsReason:
    def _write(self, tmp_path: Path, name: str, magic: bytes) -> Path:
        p = tmp_path / name
        p.write_bytes(magic + b"\x00" * 32)
        return p

    def test_mach_o_magic_rejected(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "evil.bin", b"\xcf\xfa\xed\xfe")
        assert unsupported_os_reason(p) == "unsupported format (Mach-O)"

    def test_apk_magic_rejected(self, tmp_path: Path) -> None:
        # PK zip magic + .apk suffix -> ZIP/APK.
        p = self._write(tmp_path, "evil.apk", b"PK\x03\x04")
        assert unsupported_os_reason(p) == "unsupported format (APK)"

    def test_dmg_by_extension_rejected(self, tmp_path: Path) -> None:
        # No distinctive header -> extension fallback.
        p = self._write(tmp_path, "evil.dmg", b"\x00\x01\x02\x03")
        assert unsupported_os_reason(p) == "unsupported format (.dmg)"

    def test_dex_by_extension_rejected(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "evil.dex", b"dex\n")
        assert unsupported_os_reason(p) == "unsupported format (.dex)"

    def test_pe_accepted(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "evil.exe", b"MZ")
        assert unsupported_os_reason(p) is None

    def test_elf_accepted(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "evil.elf", b"\x7fELF")
        assert unsupported_os_reason(p) is None

    def test_unknown_windowsish_accepted(self, tmp_path: Path) -> None:
        # Unknown magic + non-foreign extension must NOT be rejected.
        p = self._write(tmp_path, "evil.dat", b"\x00\x01\x02\x03")
        assert unsupported_os_reason(p) is None

    def test_none_and_phantom_path_return_none(self, tmp_path: Path) -> None:
        assert unsupported_os_reason(None) is None
        # A non-existent .apk path is not a file -> not rejected here (the
        # metadata-only path handles missing samples).
        assert unsupported_os_reason(tmp_path / "ghost.apk") is None
