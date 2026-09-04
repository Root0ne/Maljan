"""No detonation: the operator's report is the run."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core.config import Settings
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.upload import UploadSandboxProvider

ROOT = Path(__file__).resolve().parents[3]


def _blob() -> bytes:
    path = sorted((ROOT / "data" / "cape_reports").glob("*.json"))[0]
    return path.read_bytes()


def _provider() -> UploadSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "upload"
    return UploadSandboxProvider.from_settings(cfg)


def test_capabilities():
    caps = _provider().capabilities
    assert caps.accepts_uploaded_report is True and caps.can_fetch_report is True
    assert caps.can_submit is False and caps.can_poll is False and caps.can_fetch_pcap is False
    assert caps.provides_tools is False


def test_submitting_is_refused_with_a_legible_message():
    with pytest.raises(ProviderError) as exc:
        _provider().submit("/tmp/sample.exe")
    assert "does not detonate" in str(exc.value)


def test_a_cape_upload_re_sniffs_and_keeps_identity():
    raw = json.loads(_blob().decode())
    run = _provider().attach_report(_blob(), filename="report.json")
    assert run.report.source_format == "cape2"
    assert run.status == "reported"
    assert to_cape_shaped_dict(run.report) == raw
    # Real CAPE reports nest sample identity under target.file.sha256, never a
    # flat target.sha256 — confirmed against every file under data/cape_reports/
    # and already the shape the cape2 provider's own golden test reads.
    assert run.sample_sha256 == raw["target"]["file"]["sha256"]


def test_a_format_outside_the_allow_list_is_refused():
    cfg = Settings(_env_file=None)
    cfg.sandbox.upload.allowed_formats = ["triage"]
    provider = UploadSandboxProvider.from_settings(cfg)
    with pytest.raises(ProviderError) as exc:
        provider.attach_report(_blob(), filename="report.json")
    assert "cape2" in str(exc.value)


def test_an_unrecognisable_payload_is_refused_even_with_a_misconfigured_allow_list():
    """``sniff_format`` can return "unknown", which has no member in
    ``SandboxReport.source_format``'s Literal. That must be refused before the
    allow-list check ever runs, so an operator who misconfigures
    ``allowed_formats`` to include "unknown" still gets a clean, worded
    ``ProviderError`` instead of a raw pydantic ``ValidationError`` out of
    ``cape_report_to_sandbox_report``."""
    cfg = Settings(_env_file=None)
    cfg.sandbox.upload.allowed_formats = ["unknown", "cape2", "cuckoo", "triage"]
    provider = UploadSandboxProvider.from_settings(cfg)
    with pytest.raises(ProviderError) as exc:
        provider.attach_report(b'{"nothing": "recognisable"}', filename="weird.json")
    assert "Could not recognise" in str(exc.value)


def test_a_triage_upload_is_refused_narrowly_until_task_16():
    """The refusal names only the triage format; a cape2 upload right after
    still succeeds, so the gate is not accidentally catching every upload."""
    payload = {
        "version": "0.3.0",
        "sample": {"id": "260903-abcdef", "target": "x.exe", "sha256": "a" * 64},
        "tasks": [{"name": "behavioral1", "kind": "behavioral"}],
        "analysis": {"score": 10, "family": ["qakbot"]},
        "signatures": [{"name": "s", "score": 10}],
    }
    provider = _provider()
    with pytest.raises(ProviderError) as exc:
        provider.attach_report(json.dumps(payload).encode(), filename="triage.json")
    assert "the Triage reader lands in the next task" in str(exc.value)
    assert provider.attach_report(_blob()).report.source_format == "cape2"


def test_fetch_returns_the_attached_run():
    provider = _provider()
    provider.set_pending_blob(_blob(), filename="report.json")
    assert provider.fetch("uploaded").report.source_format == "cape2"
