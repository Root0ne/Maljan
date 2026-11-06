"""``ru_maxrss`` is kibibytes on Linux and bytes on macOS; the helper gives bytes on both."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from maljan.utils.peak_memory import maxrss_bytes, rss_to_bytes


class TestPeakMemoryInBytes:
    def test_linux_counts_kibibytes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        assert rss_to_bytes(10) == 10 * 1024
        assert maxrss_bytes(SimpleNamespace(ru_maxrss=7)) == 7 * 1024

    def test_macos_counts_bytes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        assert rss_to_bytes(10) == 10
        assert maxrss_bytes(SimpleNamespace(ru_maxrss=7168)) == 7168

    def test_a_usage_without_the_field_is_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        assert maxrss_bytes(object()) == 0
