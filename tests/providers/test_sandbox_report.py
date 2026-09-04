"""The neutral sandbox-report model: empty defaults, one required field, one identity.

``SandboxReport`` is the vocabulary every sandbox adapter will produce and every
consumer keeps working against, so three properties matter on their own,
separately from the CAPE round trip covered in
``test_cape_normalization_golden.py``:

  * every collection defaults to empty, never ``None`` — a consumer iterating
    ``report.processes`` should never need a null check;
  * ``SandboxRun.report`` is the one field with no safe empty value (a run
    without a report is not a run);
  * ``cape_report_to_sandbox_report`` carries the input dict through as
    ``raw`` untouched — the same object, not a copy — because that identity is
    what lets ``to_cape_shaped_dict`` short-circuit later.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.schemas.sandbox_report import (
    SandboxNetwork,
    SandboxReport,
    SandboxRun,
    SandboxTarget,
    cape_report_to_sandbox_report,
)


def test_every_collection_on_a_bare_report_is_empty_not_none():
    report = SandboxReport(provider="cape2", source_format="cape2")
    assert report.processes == []
    assert report.apistats == {}
    assert report.generic_events == []
    assert report.signatures == []
    assert report.dropped_files == []
    assert report.registry == []
    assert report.screenshots == []
    assert report.cti == {}
    assert report.unavailable == []
    assert report.raw == {}
    assert report.summary == {}
    assert report.file_writes == []
    assert report.target == SandboxTarget()
    assert report.network == SandboxNetwork()


def test_unavailable_round_trips():
    report = SandboxReport(
        provider="triage", source_format="triage", unavailable=["apistats", "calls"]
    )
    assert report.unavailable == ["apistats", "calls"]
    assert report.model_dump()["unavailable"] == ["apistats", "calls"]


def test_sandbox_run_report_is_required():
    with pytest.raises(ValidationError):
        SandboxRun(task_id="1", raw={})


def test_sandbox_run_holds_the_report_once_given_one():
    report = SandboxReport(provider="mock", source_format="mock")
    run = SandboxRun(task_id="1", report=report, raw={})
    assert run.status == "reported"
    assert run.report is report


def test_cape_report_to_sandbox_report_keeps_raw_is_raw():
    raw = {"target": {"file": {"sha256": "a" * 64}}}
    report = cape_report_to_sandbox_report(raw, provider="cape2")
    assert report.raw is raw


def test_target_reads_the_real_cape_nesting_under_file():
    # The real CAPE corpus nests hashes under target.file.*, not directly on
    # target (empirically confirmed against data/cape_reports/*.json).
    raw = {
        "target": {
            "file": {
                "sha256": "b" * 64,
                "md5": "c" * 32,
                "name": "sample.exe",
                "type": "PE32",
                "size": 10,
            }
        }
    }
    report = cape_report_to_sandbox_report(raw, provider="cape2")
    assert report.target.sha256 == "b" * 64
    assert report.target.md5 == "c" * 32
    assert report.target.name == "sample.exe"
    assert report.target.file_type == "PE32"
    assert report.target.size == 10


def test_network_domains_accepts_both_shapes_cape_emits():
    # CAPEv2 reports mix bare strings and {"domain": ...} dicts in the same
    # network.domains array; a strict list[dict] would reject the first.
    network = SandboxNetwork(domains=["evil.example", {"domain": "also-evil.example"}])
    assert network.domains == ["evil.example", {"domain": "also-evil.example"}]


def test_summary_and_file_writes_carry_the_linux_persistence_evidence():
    # Ruled in during the pre-flight scan, beyond the brief's own field list:
    # persistence_extractor's Linux path rules read behavior.summary.{files,
    # write_files,modified_files,wrote_files} and the top-level file_writes /
    # files_written arrays directly.
    raw = {
        "behavior": {"summary": {"write_files": ["/etc/cron.d/x"]}},
        "file_writes": [{"path": "/etc/cron.d/x"}],
    }
    report = cape_report_to_sandbox_report(raw, provider="cape2")
    assert report.summary["write_files"] == ["/etc/cron.d/x"]
    assert report.summary["files"] == []
    assert report.file_writes == [{"path": "/etc/cron.d/x"}]
