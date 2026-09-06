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


def test_report_raw_preserves_identity_for_a_dict():
    # A plain ``dict[str, Any]`` field does not hold this on its own —
    # pydantic-core rebuilds the container even when every value already
    # validates — so ``raw`` carries a wrap validator specifically for this.
    raw = {"target": {"sha256": "a" * 64}}
    report = SandboxReport(provider="cape2", source_format="cape2", raw=raw)
    assert report.raw is raw


def test_report_raw_rejects_a_non_dict():
    # The wrap validator's other half: identity is not the same as "accepts
    # anything". A bare ``SkipValidation`` would let a string or ``None``
    # through, and ``to_cape_shaped_dict`` would hand it to every consumer as
    # if it were the CAPE dict.
    with pytest.raises(ValidationError):
        SandboxReport(provider="cape2", source_format="cape2", raw="not-a-dict")  # type: ignore[arg-type]


def test_sandbox_run_raw_preserves_identity_for_a_dict():
    raw = {"target": {"sha256": "a" * 64}}
    report = SandboxReport(provider="mock", source_format="mock")
    run = SandboxRun(task_id="1", report=report, raw=raw)
    assert run.raw is raw


def test_sandbox_run_raw_rejects_a_non_dict():
    report = SandboxReport(provider="mock", source_format="mock")
    with pytest.raises(ValidationError):
        SandboxRun(task_id="1", report=report, raw="not-a-dict")  # type: ignore[arg-type]


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


def test_registry_keeps_the_real_string_shape_not_just_dict_rows():
    # behavior.summary.keys is a flat array of registry-path strings in every
    # one of the 97 real reports under data/cape_reports/ (139,056 string
    # entries, zero dicts). No consumer reads SandboxReport.registry today,
    # but a dict-only filter here would silently drop 100% of that data the
    # moment one does — the same mistake file_writes had, fixed the same way.
    raw = {"behavior": {"summary": {"keys": ["HKEY_LOCAL_MACHINE\\Software\\Run"]}}}
    report = cape_report_to_sandbox_report(raw, provider="cape2")
    assert report.registry == ["HKEY_LOCAL_MACHINE\\Software\\Run"]


def test_summary_and_file_writes_carry_the_linux_persistence_evidence():
    # Ruled in during the pre-flight scan, beyond the brief's own field list:
    # persistence_extractor's Linux path rules read behavior.summary.{files,
    # write_files,modified_files,wrote_files} and the top-level file_writes /
    # files_written arrays directly — and keep only the *string* entries of
    # each (its own `isinstance(p, str)` guard), which is also the shape the
    # real CAPE corpus carries (behavior.summary.keys is 139,056/139,056 plain
    # strings across data/cape_reports/, never a dict). A dict-shaped entry
    # is not richer evidence, it is a shape the consumer already discards, so
    # both fields are coerced to ``list[str]`` rather than filtered to dicts.
    raw = {
        "behavior": {"summary": {"write_files": ["/etc/cron.d/x"]}},
        "file_writes": ["/etc/rc.local"],
    }
    report = cape_report_to_sandbox_report(raw, provider="cape2")
    assert report.summary["write_files"] == ["/etc/cron.d/x"]
    assert report.summary["files"] == []
    assert report.file_writes == ["/etc/rc.local"]
