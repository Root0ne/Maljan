"""A sample's own format outranks a sandbox process tree for the affected platform (RC-12)."""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import (
    DynamicBehavior,
    FileHashes,
    ProcessNode,
    SampleIdentity,
    StaticAnalysis,
)


def _builder() -> MalwareReportBuilder:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="x",
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports={},
        stix_output=None,
        run_summary=None,
        discussion_history=None,
        final_decision="Malware",
    )


def _identity(**over: Any) -> SampleIdentity:
    return SampleIdentity(hashes=FileHashes(sha256="a" * 64), **over)


_RAN = DynamicBehavior(process_tree=[ProcessNode(pid=1, name="sample")])


def test_an_elf_that_ran_is_linux() -> None:
    got = _builder()._guess_platforms(None, _RAN, _identity(file_type="ELF", platform="linux"))
    assert got == ["Linux"]


def test_an_apk_that_ran_is_android() -> None:
    got = _builder()._guess_platforms(None, _RAN, _identity(platform="android"))
    assert got == ["Android"]


def test_a_pe_that_ran_is_windows() -> None:
    assert _builder()._guess_platforms(None, _RAN, _identity(file_type="PE")) == ["Windows"]


def test_a_sample_saying_nothing_that_ran_is_windows_as_before() -> None:
    assert _builder()._guess_platforms(None, _RAN, _identity()) == ["Windows"]


def test_nothing_known_is_unknown() -> None:
    assert _builder()._guess_platforms(StaticAnalysis(), None, _identity()) == ["Unknown"]
