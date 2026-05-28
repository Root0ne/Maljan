"""Unit tests for the platform-inference helper added in Wave 4."""

from __future__ import annotations

import pytest

from maljan.extractors.sample_identity import _infer_platform


@pytest.mark.parametrize(
    ("file_type", "expected"),
    [
        ("PE", "windows"),
        ("pe", "windows"),
        ("ELF", "linux"),
        ("Mach-O", "macos"),
        ("ZIP/APK", "android"),
        ("ZIP/IPA", "ios"),
        ("ZIP/JAR", "crossplatform"),
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


def test_infer_platform_sandbox_fallback_android() -> None:
    sb = {"target": {"platform": "android-11"}}
    assert _infer_platform("unknown", None, sb) == "android"


def test_infer_platform_mime_fallback_windows() -> None:
    # Sandbox said nothing but MIME hints at PE.
    assert _infer_platform("unknown", "application/x-msdownload", None) == "windows"


def test_infer_platform_file_type_wins_over_sandbox() -> None:
    # APK accidentally routed to a Windows sandbox should still be android.
    sb = {"target": {"os": "windows10"}}
    assert _infer_platform("ZIP/APK", None, sb) == "android"


def test_infer_platform_unknown_when_nothing_disambiguates() -> None:
    assert _infer_platform("unknown", None, None) == "unknown"
    assert _infer_platform("unknown", "application/octet-stream", {}) == "unknown"
