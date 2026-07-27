"""``build_static_analysis`` is called nine times per run and parsed nine times.

Three of those calls live in the judge node alone — the import-capability
Layer 0, the family-feature RAG hint and the ATT&CK-case RAG hint — with the
analyst node, the report builder and three static-analyst sites making up the
rest. Every one of them re-read the sample from disk and re-ran ``pefile``.

That was merely wasteful while this module only classified 51 imports. It stops
being merely wasteful once per-string IOC classification and overlay carving run
inside the same function, so the memo lands before either of those.

The key is deliberately a ``(path, mtime_ns, size)`` triple. Keying on the path
alone would be wrong twice over: the Ghidra container mirror makes one logical
sample visible at two paths, and a sample whose bytes changed under a reused
path would serve a stale analysis — worse than no cache.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from maljan.extractors.pe_extractor import (
    build_static_analysis,
    reset_static_analysis_cache,
)

_STUB = b"MZ" + b"\x00" * 512


class TestTheMemoAvoidsRepeatedParsing:
    def setup_method(self) -> None:
        reset_static_analysis_cache()

    def test_a_second_call_does_not_reparse(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(_STUB)

        with patch("maljan.extractors.pe_extractor._build_static_analysis_uncached") as uncached:
            uncached.return_value = None
            build_static_analysis(sample_path=str(sample))
            build_static_analysis(sample_path=str(sample))
            build_static_analysis(sample_path=str(sample))

        assert uncached.call_count == 1, "nine callers, one parse"

    def test_the_result_is_identical_across_calls(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(_STUB)

        first = build_static_analysis(sample_path=str(sample))
        second = build_static_analysis(sample_path=str(sample))
        assert first is second, "the cached object is returned, not a rebuild"

    def test_none_is_cached_too(self, tmp_path: Path) -> None:
        """A file that yields nothing must not be re-parsed on every call."""
        sample = tmp_path / "empty.bin"
        sample.write_bytes(b"")

        with patch(
            "maljan.extractors.pe_extractor._build_static_analysis_uncached",
            return_value=None,
        ) as uncached:
            assert build_static_analysis(sample_path=str(sample)) is None
            assert build_static_analysis(sample_path=str(sample)) is None

        assert uncached.call_count == 1


class TestTheKeyIsContentSensitive:
    def setup_method(self) -> None:
        reset_static_analysis_cache()

    def test_rewriting_the_file_invalidates_the_entry(self, tmp_path: Path) -> None:
        """The failure this guards against is silent: same path, new bytes,
        stale analysis. Keying on the path alone would produce exactly that."""
        sample = tmp_path / "s.exe"
        sample.write_bytes(_STUB)

        with patch(
            "maljan.extractors.pe_extractor._build_static_analysis_uncached",
            return_value=None,
        ) as uncached:
            build_static_analysis(sample_path=str(sample))
            # Different size => different key, regardless of mtime granularity.
            sample.write_bytes(_STUB + b"appended")
            build_static_analysis(sample_path=str(sample))

        assert uncached.call_count == 2

    def test_two_distinct_samples_do_not_share_an_entry(self, tmp_path: Path) -> None:
        a = tmp_path / "a.exe"
        b = tmp_path / "b.exe"
        a.write_bytes(_STUB)
        b.write_bytes(_STUB + b"\x01")

        with patch(
            "maljan.extractors.pe_extractor._build_static_analysis_uncached",
            return_value=None,
        ) as uncached:
            build_static_analysis(sample_path=str(a))
            build_static_analysis(sample_path=str(b))

        assert uncached.call_count == 2

    def test_the_memo_is_bounded(self, tmp_path: Path) -> None:
        """An unbounded memo in a long-lived worker is a leak by another name."""
        from maljan.extractors import pe_extractor

        for i in range(pe_extractor._MEMO_MAX_ENTRIES + 3):
            sample = tmp_path / f"s{i}.exe"
            sample.write_bytes(_STUB + bytes([i]))
            build_static_analysis(sample_path=str(sample))

        assert len(pe_extractor._MEMO) <= pe_extractor._MEMO_MAX_ENTRIES


class TestUnreadableInputsStillDegrade:
    def setup_method(self) -> None:
        reset_static_analysis_cache()

    def test_a_missing_path_returns_none_without_caching(self, tmp_path: Path) -> None:
        assert build_static_analysis(sample_path=str(tmp_path / "nope.exe")) is None

    def test_an_empty_path_returns_none(self) -> None:
        assert build_static_analysis(sample_path=None) is None
        assert build_static_analysis(sample_path="") is None
