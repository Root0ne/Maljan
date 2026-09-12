"""Unit tests for the platform-inference helper added in Wave 4."""

from __future__ import annotations

from pathlib import Path

import pytest

from maljan.extractors.sample_identity import (
    _detect_file_type,
    _detect_language_or_compiler,
    _infer_platform,
    file_type_category,
)


class TestCompilerDetection:
    """2026-07 round 2: compiler/language fingerprint via byte markers + PE
    Rich header / linker version / import heuristics (was a 6-marker stub that
    returned None for ordinary MSVC PEs)."""

    def test_byte_markers(self) -> None:
        assert _detect_language_or_compiler(b"MZ..Go build ID: abc") == "Go"
        assert _detect_language_or_compiler(b"MZ.." + b"UPX!" + b"x" * 100) == "C/C++ (UPX packed)"

    def test_one_suggestive_string_is_not_an_identification(self) -> None:
        """Changed 2026-07-27, deliberately.

        This used to assert that ``b"MZ..rustc-1.70 stuff"`` identifies Rust.
        It does not, and should not: ``rustc`` appears in anything that merely
        *mentions* the Rust toolchain — a scanner carrying Rust signatures, a
        build log embedded in a resource, this repository. The scored catalog
        weights it as a weak marker worth 1 against a minimum of 3, so a real
        Rust binary (which carries ``rust_begin_unwind`` and
        ``core::panicking`` as well) still resolves, and a passing mention no
        longer does.
        """
        assert _detect_language_or_compiler(b"MZ..rustc-1.70 stuff") is None
        assert (
            _detect_language_or_compiler(b"MZ..rustc-1.70..rust_begin_unwind..core::panicking..")
            == "Rust"
        )

    def test_none_for_empty_or_non_pe(self) -> None:
        assert _detect_language_or_compiler(b"") is None
        assert _detect_language_or_compiler(b"not a binary at all") is None

    def test_real_mfc_sample_detected(self) -> None:
        sample = (
            Path(__file__).resolve().parents[3]
            / "data"
            / "samples"
            / "11e77149273cd76c7184bb3e71495fa96c500b3464c6db24d73a40396f591b00.exe"
        )
        if not sample.exists():
            pytest.skip("sample not present in this checkout")
        result = _detect_language_or_compiler(sample.read_bytes())
        assert result is not None
        assert "Visual C++" in result
        assert "MFC" in result


# Every recognised format routes to a platform; nothing is refused.
@pytest.mark.parametrize(
    ("file_type", "expected"),
    [
        ("PE", "windows"),
        ("pe", "windows"),
        ("ELF", "linux"),
        ("mach-o", "macos"),
        ("apk", "android"),
        ("dex", "android"),
        ("ipa", "ios"),
        ("jar", "multi"),
        ("ole2", "multi"),
        ("ooxml", "multi"),
        ("pdf", "multi"),
        ("lnk", "windows"),
        ("ps1", "windows"),
        ("sh", "linux"),
        ("py", "multi"),
        ("zip", "unknown"),
        ("7z", "unknown"),
        ("iso", "unknown"),
        ("unknown", "unknown"),
        ("", "unknown"),
    ],
)
def test_infer_platform_from_file_type(file_type: str, expected: str) -> None:
    assert _infer_platform(file_type, None, None) == expected


def test_infer_platform_sandbox_fallback_windows() -> None:
    sb = {"target": {"os": "windows10"}}
    assert _infer_platform("unknown", None, sb) == "windows"


@pytest.mark.parametrize(
    ("hint", "expected"),
    [
        ("android-11", "android"),
        # "win" is a substring of "darwin"; a macOS guest must not read as one.
        ("darwin-22", "macos"),
        ("macos-14", "macos"),
        ("osx-10.15", "macos"),
        ("ios-17", "ios"),
        ("ubuntu-22.04", "linux"),
        ("windows10", "windows"),
        ("win7x64", "windows"),
        ("winxp", "windows"),
    ],
)
def test_infer_platform_sandbox_hint_names_the_guest(hint: str, expected: str) -> None:
    assert _infer_platform("unknown", None, {"target": {"platform": hint}}) == expected


class TestACrossPlatformFormatDefersToTheGuest:
    """A macro document or a JAR binds to no OS by format, but it ran on one.

    Returning "multi" before consulting the sandbox threw that away, and
    downstream that cost a .docm detonated on Windows its whole registry,
    service and scheduled-task persistence sweep.
    """

    @pytest.mark.parametrize("file_type", ["ole2", "ooxml", "pdf", "jar", "py", "pl"])
    def test_the_guest_refines_a_cross_platform_format(self, file_type: str) -> None:
        sb = {"target": {"os": "windows7"}}
        assert _infer_platform(file_type, None, sb) == "windows"

    def test_a_linux_guest_refines_it_too(self) -> None:
        assert _infer_platform("jar", None, {"target": {"os": "ubuntu-22"}}) == "linux"

    def test_multi_is_the_answer_when_nothing_else_says_otherwise(self) -> None:
        assert _infer_platform("ole2", None, None) == "multi"
        assert _infer_platform("ole2", None, {"target": {}}) == "multi"

    def test_a_single_os_format_still_beats_the_guest(self) -> None:
        # Magic bytes remain authoritative for a format that names one OS.
        sb = {"target": {"os": "windows10"}}
        assert _infer_platform("elf", None, sb) == "linux"
        assert _infer_platform("apk", None, sb) == "android"


def test_infer_platform_mime_fallback_windows() -> None:
    # Sandbox said nothing but MIME hints at PE.
    assert _infer_platform("unknown", "application/x-msdownload", None) == "windows"


def test_infer_platform_file_type_wins_over_sandbox() -> None:
    # Magic bytes beat a misrouted sandbox: an ELF in a Windows profile is linux.
    sb = {"target": {"os": "windows10"}}
    assert _infer_platform("ELF", None, sb) == "linux"


def test_toolchain_hint_never_overrides_a_detected_platform() -> None:
    # A .NET marker may upgrade an undetermined platform, never a detected one.
    assert _infer_platform("unknown", None, None, ".NET") == "windows"
    assert _infer_platform("mach-o", None, None, ".NET") == "macos"
    assert _infer_platform("apk", None, None, "Delphi") == "android"


def test_infer_platform_unknown_when_nothing_disambiguates() -> None:
    assert _infer_platform("unknown", None, None) == "unknown"
    assert _infer_platform("unknown", "application/octet-stream", {}) == "unknown"


# ---------------------------------------------------------------------------
# File-type detection: synthetic headers for every routed format.
# ---------------------------------------------------------------------------
def _write(tmp_path: Path, name: str, blob: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(blob)
    return target


@pytest.mark.parametrize(
    ("name", "blob", "file_type", "platform"),
    [
        ("a.exe", b"MZ" + b"\x00" * 64, "pe", "windows"),
        ("a.bin", b"\x7fELF" + b"\x00" * 64, "elf", "linux"),
        ("a.bin", b"\xfe\xed\xfa\xce" + b"\x00" * 64, "mach-o", "macos"),
        ("a.bin", b"\xfe\xed\xfa\xcf" + b"\x00" * 64, "mach-o", "macos"),
        ("a.bin", b"\xce\xfa\xed\xfe" + b"\x00" * 64, "mach-o", "macos"),
        ("a.bin", b"\xcf\xfa\xed\xfe" + b"\x00" * 64, "mach-o", "macos"),
        # Fat Mach-O: 0xCAFEBABE plus a small architecture count.
        ("a.bin", b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 32, "mach-o", "macos"),
        # A Java class file shares the magic; its version field is far larger.
        ("a.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\x00" * 32, "unknown", "unknown"),
        ("a.dex", b"dex\n035\x00" + b"\x00" * 32, "dex", "android"),
        ("a.pdf", b"%PDF-1.7\n" + b"\x00" * 32, "pdf", "multi"),
        ("a.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32, "ole2", "multi"),
        (
            "a.lnk",
            b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 32,
            "lnk",
            "windows",
        ),
        ("a.bin", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32, "7z", "unknown"),
        ("a.bin", b"Rar!\x1a\x07\x00" + b"\x00" * 32, "rar", "unknown"),
        ("a.bin", b"\x1f\x8b\x08" + b"\x00" * 32, "gz", "unknown"),
        ("a.bin", b"BZh9" + b"\x00" * 32, "bz2", "unknown"),
        ("a.bin", b"\xfd7zXZ\x00" + b"\x00" * 32, "xz", "unknown"),
        ("a.ps1", b"Write-Host hi\n", "ps1", "windows"),
        ("a.bat", b"@echo off\n", "bat", "windows"),
        ("a.cmd", b"@echo off\n", "cmd", "windows"),
        ("a.vbs", b"WScript.Echo 1\n", "vbs", "windows"),
        ("a.js", b"eval(1)\n", "js", "windows"),
        ("a.hta", b"<html></html>\n", "hta", "windows"),
        ("a.wsf", b"<job></job>\n", "wsf", "windows"),
        ("a.txt", b"#!/bin/bash\necho hi\n", "sh", "linux"),
        ("a.txt", b"#!/usr/bin/env python3\nprint(1)\n", "py", "multi"),
        ("a.txt", b"#!/usr/bin/perl\nprint 1;\n", "pl", "multi"),
        # An interpreter the table does not name falls through to the
        # extension rather than being labelled a shell script.
        ("a.dat", b"#!/usr/bin/env node\nrequire(1)\n", "unknown", "unknown"),
        ("a.js", b"#!/usr/bin/env node\nrequire(1)\n", "js", "windows"),
        ("a.sh", b"echo hi\n", "sh", "linux"),
        ("a.dat", b"\x00\x01\x02\x03" + b"\x00" * 32, "unknown", "unknown"),
    ],
)
def test_detect_file_type_table(
    tmp_path: Path, name: str, blob: bytes, file_type: str, platform: str
) -> None:
    path = _write(tmp_path, name, blob)
    detected = _detect_file_type(path, blob)
    assert detected == file_type
    assert _infer_platform(detected, None, None) == platform


def test_iso_is_recognised_by_its_volume_descriptor(tmp_path: Path) -> None:
    blob = bytearray(b"\x00" * 40000)
    blob[32769:32774] = b"CD001"
    path = _write(tmp_path, "image.bin", bytes(blob))
    assert _detect_file_type(path, bytes(blob)) == "iso"
    assert _infer_platform("iso", None, None) == "unknown"


def _zip_with(tmp_path: Path, name: str, entries: dict[str, str]) -> Path:
    import zipfile

    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        for entry, content in entries.items():
            archive.writestr(entry, content)
    return path


@pytest.mark.parametrize(
    ("entries", "file_type", "platform"),
    [
        ({"AndroidManifest.xml": "x", "classes.dex": "x"}, "apk", "android"),
        ({"classes.dex": "x"}, "apk", "android"),
        ({"[Content_Types].xml": "x", "word/document.xml": "x"}, "ooxml", "multi"),
        ({"META-INF/MANIFEST.MF": "x", "Main.class": "x"}, "jar", "multi"),
        ({"Payload/Evil.app/Info.plist": "x"}, "ipa", "ios"),
        ({"readme.txt": "x"}, "zip", "unknown"),
    ],
)
def test_zip_containers_route_by_their_entries(
    tmp_path: Path, entries: dict[str, str], file_type: str, platform: str
) -> None:
    path = _zip_with(tmp_path, "sample.zip", entries)
    blob = path.read_bytes()
    detected = _detect_file_type(path, blob)
    assert detected == file_type
    assert _infer_platform(detected, None, None) == platform


def test_an_apk_wins_over_the_jar_manifest_it_also_carries(tmp_path: Path) -> None:
    path = _zip_with(
        tmp_path,
        "sample.apk",
        {"META-INF/MANIFEST.MF": "x", "AndroidManifest.xml": "x"},
    )
    assert _detect_file_type(path, path.read_bytes()) == "apk"


@pytest.mark.parametrize(
    ("file_type", "category"),
    [
        ("pe", "executable"),
        ("apk", "executable"),
        ("pdf", "document"),
        ("ooxml", "document"),
        ("ps1", "script"),
        ("7z", "archive"),
        ("iso", "archive"),
        ("nonsense", "unknown"),
    ],
)
def test_file_type_category(file_type: str, category: str) -> None:
    assert file_type_category(file_type) == category
