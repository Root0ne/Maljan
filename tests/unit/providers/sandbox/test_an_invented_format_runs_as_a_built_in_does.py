"""A sandbox format nobody shipped, registered only as a reader, runs as a built-in one does.

The reader below is the whole of what an operator writes: an id, how it
recognises a payload, how it reads one into the neutral form, and its
signature scale. Nothing else in the platform names it. Its upload is sniffed
and read, the app hands the dynamic analyst its document, the triage pack
indexes and records its sections, the report's dynamic section and the run
summary's scale (what the console's Dynamic tab reads) carry it, and the REST
provider reads a body through it too. A reader an installed package names by
entry point is registered the same way.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from maljan.core.config import Settings
from maljan.core.report_formats import SignatureScale, recorded_signature_scale
from maljan.providers.sandbox import readers
from maljan.providers.sandbox.formats import sniff_format
from maljan.providers.sandbox.readers import (
    ReportReader,
    register_report_reader,
    report_reader,
    unregister_report_reader,
)
from maljan.schemas.sandbox_report import (
    SandboxNetwork,
    SandboxProcess,
    SandboxReport,
    SandboxSignatureRow,
    SandboxTarget,
)

ACME_SCALE = SignatureScale(name="Acme 1–4", rungs=["Low", "Medium", "High", "Critical"])


class AcmeBoxReader(ReportReader):
    """The invented sandbox's reader, as an operator would write it."""

    id = "acmebox"
    display_name = "Acme Box"

    def sniff(self, payload: Any) -> bool:
        return isinstance(payload.get("acmebox"), dict)

    def signature_scale(self) -> SignatureScale | None:
        return ACME_SCALE

    def task_id(self, payload: Any) -> str | None:
        return str(payload["acmebox"].get("job") or "") or None

    def target_sha256(self, payload: Any) -> str:
        return str((payload.get("subject") or {}).get("sha256") or "")

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **context: Any,
    ) -> SandboxReport:
        box = payload["acmebox"]
        subject = payload.get("subject") or {}
        report = SandboxReport(
            provider=provider,
            source_format=self.id,
            task_id=task_id or str(box.get("job") or ""),
            target=SandboxTarget(sha256=subject.get("sha256", ""), name=subject.get("name", "")),
            processes=[
                SandboxProcess(
                    pid=p["id"],
                    ppid=p["parent"],
                    name=p["image"],
                    command_line=p["cmdline"],
                    extra={"integrity": p["integrity"]},
                )
                for p in box["procs"]
            ],
            signatures=[
                SandboxSignatureRow(name=r["rule"], description=r["text"], severity=r["level"])
                for r in box["rules"]
            ],
            network=SandboxNetwork(
                dns=[{"request": q, "type": "A", "answers": []} for q in box["lookups"]],
                tcp=[{"dst": c["to"], "dport": c["port"]} for c in box["conns"]],
            ),
            extracted=[{"config": c} for c in box["configs"]],
            unavailable=["api_calls", "apistats", "events", "registry", "screenshots"],
            # The sandbox's own run notes, which no place of the form names.
            extras={"acmebox_notes": box["notes"]},
        )
        return self._scaled(report, fmt)


def _payload() -> dict[str, Any]:
    return {
        "subject": {"sha256": "c" * 64, "name": "invoice.bin"},
        "acmebox": {
            "job": 77,
            "procs": [
                {
                    "id": 10,
                    "parent": 1,
                    "image": "invoice.bin",
                    "cmdline": "invoice.bin /run",
                    "integrity": "medium",
                },
                {
                    "id": 11,
                    "parent": 10,
                    "image": "helper.exe",
                    "cmdline": "helper.exe --stay",
                    "integrity": "medium",
                },
            ],
            "rules": [
                {"rule": "acme_persistence_task", "text": "Schedules itself", "level": 3},
                {"rule": "acme_beacon", "text": "Beacons to one address", "level": 4},
            ],
            "lookups": ["relay.acme-test.example"],
            "conns": [{"to": "192.0.2.44", "port": 8443}],
            "configs": [{"family": "invented", "port": 8443}],
            "notes": ["guest rebooted once"],
        },
    }


@pytest.fixture
def acme() -> Any:
    replaced = report_reader(AcmeBoxReader.id)
    register_report_reader(AcmeBoxReader)
    yield AcmeBoxReader
    unregister_report_reader(AcmeBoxReader.id)
    if replaced is not None:
        register_report_reader(replaced)


def _upload_provider() -> Any:
    from maljan.providers.sandbox.upload import UploadSandboxProvider

    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "upload"
    cfg.sandbox.upload.allowed_formats = ["acmebox"]
    provider = UploadSandboxProvider.from_settings(cfg)
    provider.set_pending_blob(json.dumps(_payload()).encode())
    return provider


def _submitted(tmp_path: Path, provider: Any) -> tuple[Any, dict[str, Any] | None]:
    import asyncio

    from maljan.app import MaljanApp

    sample = tmp_path / "invoice.bin"
    sample.write_bytes(b"payload")
    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    return app, asyncio.run(app._submit_to_sandbox(str(sample)))


class TestTheUploadIsSniffedAndRead:
    def test_the_registry_names_it(self, acme: Any) -> None:
        assert sniff_format(_payload()) == "acmebox"
        assert "acmebox" in readers.sandbox_format_ids()
        assert "acmebox" in readers.choosable_reader_ids()

    def test_the_upload_provider_reads_it(self, acme: Any) -> None:
        provider = _upload_provider()
        assert provider.capabilities.report_format == "acmebox"
        run = provider.fetch("uploaded")
        assert run.report.source_format == "acmebox"
        assert run.task_id == "77"
        assert run.sample_sha256 == "c" * 64
        assert provider.signature_scale(run) == ACME_SCALE

    def test_without_the_reader_the_upload_is_refused(self) -> None:
        from maljan.providers.errors import ProviderError

        assert report_reader("acmebox") is None
        with pytest.raises(ProviderError):
            _upload_provider().fetch("uploaded")


class TestItReachesEveryConsumer:
    def test_the_app_hands_over_its_document_and_records_its_scale(
        self, acme: Any, tmp_path: Path
    ) -> None:
        app, document = _submitted(tmp_path, _upload_provider())
        assert document is not None
        assert app.container.sandbox_normalised == ("upload", "acmebox", "")
        # What the run summary records, which the console's Dynamic tab reads.
        assert recorded_signature_scale(app.container) == {
            "sandbox_signature_scale": ACME_SCALE.record()
        }
        # Nothing the reader read is lost: its extra fields and its own block.
        assert document["behavior"]["processes"][1]["extra"] == {"integrity": "medium"}
        assert document["acmebox_notes"] == ["guest rebooted once"]
        assert document["extracted"] == [{"config": {"family": "invented", "port": 8443}}]

    def test_the_dynamic_analyst_reads_it(self, acme: Any, tmp_path: Path) -> None:
        app, document = _submitted(tmp_path, _upload_provider())
        assert document is not None
        chunks = app.container._sandbox_slice("dynamic", "sandbox.behavior", document)
        text = " ".join(chunk.content for chunk in chunks)
        assert "relay.acme-test.example" in text
        assert "192.0.2.44:8443" in text

    def test_the_pack_indexes_and_records_its_sections(self, acme: Any, tmp_path: Path) -> None:
        from maljan.agents.evidence_recorder import EvidenceRecorder
        from maljan.pipeline.triage_pack import PIPELINE, run_pack
        from maljan.reporting.ledger_projection import dynamic_from_ledger
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
        from maljan.reporting.renderers.markdown import MarkdownRenderer
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_triage_pack import _inputs, _write
        from tests.unit.tools.test_binary import _pe

        app, document = _submitted(tmp_path, _upload_provider())
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        result = run_pack(
            recorder,
            _inputs(
                path,
                "pe",
                sandbox_report=document,
                sandbox_normalised_by=app.container.sandbox_normalised,
            ),
        )
        by_tool = {entry.tool: entry for entry in result.entries}
        index = by_tool["sandbox_sections"].structured["sections"]
        assert index["processes"]["items"] == 2
        assert index["signatures"]["items"] == 2
        assert index["network"]["items"] == 2
        assert index["extracted"]["items"] == 1
        assert index["api_calls"] == {
            "no": "no: the report lists `api_calls` as unavailable from its sandbox"
        }
        assert {"sandbox_processes", "sandbox_network", "sandbox_signatures"} <= set(by_tool)

        # The report's dynamic section, as the console's Dynamic tab shows it.
        dynamic = dynamic_from_ledger(result.entries)
        assert dynamic is not None
        assert sorted(s.name for s in dynamic.sandbox_signatures) == [
            "acme_beacon",
            "acme_persistence_task",
        ]
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)), dynamic=dynamic
        )
        assert "acme_beacon" in MarkdownRenderer().render(report)


def test_the_rest_provider_reads_a_body_through_it(acme: Any) -> None:
    from maljan.providers.sandbox.rest import RestSandboxProvider

    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.base_url = "https://xyz.example/api"
    cfg.sandbox.rest.report.format = "acmebox"
    provider = RestSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url="https://xyz.example/api",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=_payload())),
    )
    run = provider.fetch("T-1")
    assert run.report.source_format == "acmebox"
    assert run.report.provider == "rest"
    assert provider.signature_scale(run) == ACME_SCALE


def test_a_reader_an_installed_package_names_is_registered(monkeypatch: Any) -> None:
    class _Entry:
        name = "epbox"

        def load(self) -> Any:
            class EntryPointReader(AcmeBoxReader):
                id = "epbox"

            return EntryPointReader

    def _entry_points(group: str) -> list[Any]:
        return [_Entry()] if group == readers.ENTRY_POINT_GROUP else []

    monkeypatch.setattr("importlib.metadata.entry_points", _entry_points)
    monkeypatch.setattr(readers, "_ENTRY_POINTS_READ", [])
    try:
        found = report_reader("epbox")
        assert found is not None
        assert found.read(_payload(), provider="upload").source_format == "epbox"
    finally:
        unregister_report_reader("epbox")


def test_a_broken_entry_point_never_stops_the_built_ins(monkeypatch: Any) -> None:
    class _Broken:
        name = "broken"

        def load(self) -> Any:
            raise ImportError("not installed")

    monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [_Broken()])
    monkeypatch.setattr(readers, "_ENTRY_POINTS_READ", [])
    assert report_reader("cape2") is not None
