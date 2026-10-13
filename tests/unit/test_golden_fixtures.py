"""A golden case skipped for want of its source is counted, and the count is said aloud."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.golden_fixtures import (
    ABSENT_FIXTURE_REASON,
    absent_fixture_skips,
    absent_fixture_summary,
    report_absent_fixture_skips,
    skip_absent_fixture,
)


def _skipped(reason: str) -> SimpleNamespace:
    return SimpleNamespace(longrepr=("tests/x.py", 1, f"Skipped: {reason}"))


class _Reporter:
    def __init__(self, skipped: list[Any]) -> None:
        self.stats = {"skipped": skipped}
        self.lines: list[str] = []

    def write_sep(self, sep: str, title: str, **_markup: Any) -> None:
        self.lines.append(title)

    def write_line(self, line: str, **_markup: Any) -> None:
        self.lines.append(line)


def test_the_skip_carries_the_reason_the_count_reads() -> None:
    with pytest.raises(pytest.skip.Exception) as caught:
        skip_absent_fixture("raw report r1.json")
    assert str(caught.value).startswith(f"{ABSENT_FIXTURE_REASON}: ")


def test_only_skips_for_an_absent_source_are_counted() -> None:
    skipped = [
        _skipped(f"{ABSENT_FIXTURE_REASON}: raw report a.json"),
        _skipped(f"{ABSENT_FIXTURE_REASON}: raw report b.json"),
        _skipped("needs a live service"),
        SimpleNamespace(longrepr=None),
    ]
    assert absent_fixture_skips(skipped) == 2


def test_the_summary_names_the_number() -> None:
    assert absent_fixture_summary(1).startswith("1 golden test skipped: ")
    assert absent_fixture_summary(776).startswith("776 golden tests skipped: ")


def test_a_session_without_such_skips_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    reporter = _Reporter([_skipped("needs a live service")])
    assert report_absent_fixture_skips(reporter) == 0
    assert reporter.lines == []


def test_off_ci_the_count_closes_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    reporter = _Reporter([_skipped(f"{ABSENT_FIXTURE_REASON}: x")] * 3)
    assert report_absent_fixture_skips(reporter) == 3
    assert reporter.lines == [absent_fixture_summary(3)]


def test_on_github_actions_the_count_is_an_annotation_and_a_summary_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    reporter = _Reporter([_skipped(f"{ABSENT_FIXTURE_REASON}: x")] * 2)

    assert report_absent_fixture_skips(reporter) == 2

    line = absent_fixture_summary(2)
    assert reporter.lines == [line, f"::warning title=Golden fixtures absent::{line}"]
    assert summary.read_text(encoding="utf-8") == f"- {line}\n"


def test_a_skip_list_ten_times_larger_with_long_reasons_is_counted_whole() -> None:
    reason = f"{ABSENT_FIXTURE_REASON}: " + "x" * 1000
    small = [_skipped(reason)] * 2_000
    large = [_skipped(reason)] * 20_000
    assert absent_fixture_skips(small) == 2_000
    assert absent_fixture_skips(large) == 20_000
