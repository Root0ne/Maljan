"""Each sandbox provider declares its signature scale, and the run records it.

The scale comes from the report format the provider read (a built-in format's
declaration, an uploaded report's declared format) or from the REST settings
for a report read through the mapping, never from a provider's name. The run
summary records it under one key only when a sandbox report was read, so a
summary without the key is a run recorded before scales were, read by the
console's legacy table.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from maljan.app import MaljanApp
from maljan.core.config import Settings
from maljan.core.report_formats import SIGNATURE_SCALE_KEY, SignatureScale, recorded_signature_scale
from maljan.providers.base import SandboxProvider
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider
from maljan.providers.sandbox.mock import MockSandboxProvider
from maljan.providers.sandbox.rest import RestSandboxProvider
from maljan.providers.sandbox.triage import TriageSandboxProvider
from maljan.providers.sandbox.upload import UploadSandboxProvider
from maljan.schemas.sandbox_report import SandboxReport, SandboxRun
from tests.unit.providers._cape_fixture import first_cape_report_path

CAPE_SCALE = {"name": "CAPE 1–3", "max": 3, "rungs": ["Low", "Medium", "High"]}


def _run(provider: str, source_format: str) -> SandboxRun:
    return SandboxRun(
        task_id="1",
        raw={},
        report=SandboxReport(provider=provider, source_format=source_format),  # type: ignore[arg-type]
    )


def _record(scale: SignatureScale | None) -> dict[str, Any] | None:
    return scale.record() if scale is not None else None


def _settings(**sandbox: Any) -> Settings:
    return Settings.model_validate({"sandbox": sandbox})


def test_a_provider_reading_a_built_in_format_declares_that_formats_scale() -> None:
    settings = _settings(provider="cape2")
    cape = CAPE2SandboxProvider.from_settings(settings)
    assert _record(cape.signature_scale(_run("cape2", "cape2"))) == CAPE_SCALE
    triage = TriageSandboxProvider.from_settings(_settings(provider="triage"))
    scale = triage.signature_scale(_run("triage", "triage"))
    assert scale is not None and scale.name == "Triage 1–10" and scale.max == 10


def test_a_report_of_no_declared_format_has_no_scale() -> None:
    mock = MockSandboxProvider.from_settings(_settings(provider="mock"))
    assert mock.signature_scale(_run("mock", "mock")) is None


def test_an_uploaded_report_takes_the_scale_of_the_format_it_sniffed_as() -> None:
    upload = UploadSandboxProvider.from_settings(_settings(provider="upload"))
    upload.set_pending_blob(first_cape_report_path().read_bytes())
    run = upload.fetch("uploaded")
    assert _record(upload.signature_scale(run)) == CAPE_SCALE


def test_an_uploaded_report_of_no_known_format_has_no_scale() -> None:
    upload = UploadSandboxProvider.from_settings(_settings(provider="upload"))
    upload.set_pending_blob(json.dumps({"hello": "world"}).encode())
    assert upload.signature_scale(_run("upload", "cape2")) is None


def _rest(**report: Any) -> RestSandboxProvider:
    settings = _settings(
        provider="rest", rest={"base_url": "https://xyz.example/api", "report": report}
    )
    return RestSandboxProvider.from_settings(settings)


def test_a_mapped_rest_report_takes_the_scale_its_settings_declare() -> None:
    provider = _rest(
        signature_scale_name="Vendor 1–5",
        signature_scale_rungs=["Informational", "Low", "Medium", "High", "Critical"],
    )
    scale = provider.signature_scale(_run("rest", "generic"))
    assert scale is not None and scale.record() == {
        "name": "Vendor 1–5",
        "max": 5,
        "rungs": ["Informational", "Low", "Medium", "High", "Critical"],
    }


def test_a_rest_scale_without_a_name_is_named_by_its_size() -> None:
    scale = _rest(signature_scale_rungs=["Low", "High"]).signature_scale(_run("rest", "generic"))
    assert scale is not None and scale.name == "1–2"


def test_a_mapped_rest_report_without_a_declared_scale_has_none() -> None:
    assert _rest().signature_scale(_run("rest", "generic")) is None


def test_a_rest_report_of_a_built_in_format_takes_that_formats_scale() -> None:
    provider = _rest(format="cape2", signature_scale_rungs=["Low"])
    assert _record(provider.signature_scale(_run("rest", "cape2"))) == CAPE_SCALE


def test_the_run_summary_records_the_scale_only_once_a_report_was_read() -> None:
    assert recorded_signature_scale(None) == {}
    assert recorded_signature_scale(SimpleNamespace(sandbox_normalised=None)) == {}
    read = SimpleNamespace(
        sandbox_normalised=("cape2", "cape2", "raw"), sandbox_signature_scale=CAPE_SCALE
    )
    assert recorded_signature_scale(read) == {SIGNATURE_SCALE_KEY: CAPE_SCALE}
    unrated = SimpleNamespace(
        sandbox_normalised=("mock", "mock", "raw"), sandbox_signature_scale=None
    )
    assert recorded_signature_scale(unrated) == {SIGNATURE_SCALE_KEY: None}


class _Provider(SandboxProvider):
    """A provider whose scale is fixed, or whose scale lookup raises."""

    def __init__(self, scale: SignatureScale | None, *, fails: bool = False) -> None:
        self._scale, self._fails = scale, fails

    @classmethod
    def from_settings(cls, cfg: Settings) -> _Provider:
        return cls(None)

    @property
    def capabilities(self) -> Any:
        return None

    def signature_scale(self, run: SandboxRun, formats: Any = None) -> SignatureScale | None:
        if self._fails:
            raise RuntimeError("no scale")
        return self._scale


def _app(settings: Settings | None = None) -> Any:
    app = object.__new__(MaljanApp)
    app.config = settings or Settings.model_validate({})
    app.container = SimpleNamespace(sandbox_normalised=None, sandbox_signature_scale=None)
    return app


def test_the_app_notes_the_reader_and_the_scale_its_provider_declares() -> None:
    app = _app()
    app._note_the_reader(
        _Provider(SignatureScale(name="CAPE 1–3", rungs=["Low", "Medium", "High"])),
        _run("cape2", "cape2"),
    )
    assert app.container.sandbox_normalised[:2] == ("cape2", "cape2")
    assert app.container.sandbox_signature_scale == CAPE_SCALE


def test_a_scale_lookup_that_raises_leaves_the_run_unrated() -> None:
    app = _app()
    app._note_the_reader(_Provider(None, fails=True), _run("cape2", "cape2"))
    assert app.container.sandbox_normalised is not None
    assert app.container.sandbox_signature_scale is None


FORK = {
    "name": "cape2",
    "signature_scale": {"name": "Fork 1–5", "rungs": ["Low", "Low", "Medium", "High", "Critical"]},
}


def test_a_live_run_records_the_scale_of_a_redeclared_built_in() -> None:
    settings = _settings(provider="cape2", report_formats=[FORK])
    app = _app(settings)
    app._note_the_reader(CAPE2SandboxProvider.from_settings(settings), _run("cape2", "cape2"))
    assert app.container.sandbox_signature_scale["name"] == "Fork 1–5"
    assert app.container.sandbox_signature_scale["max"] == 5


def test_a_rest_report_of_a_redeclared_built_in_takes_the_declared_scale() -> None:
    settings = _settings(
        provider="rest",
        rest={"base_url": "https://xyz.example/api", "report": {"format": "cape2"}},
        report_formats=[FORK],
    )
    app = _app(settings)
    app._note_the_reader(RestSandboxProvider.from_settings(settings), _run("rest", "cape2"))
    assert app.container.sandbox_signature_scale["name"] == "Fork 1–5"


def test_an_uploaded_report_of_a_redeclared_built_in_takes_the_same_scale() -> None:
    settings = _settings(provider="upload", report_formats=[FORK])
    upload = UploadSandboxProvider.from_settings(settings)
    upload.set_pending_blob(first_cape_report_path().read_bytes(), report_format="cape2")
    app = _app(settings)
    app._note_the_reader(upload, upload.fetch("uploaded"))
    assert app.container.sandbox_signature_scale["name"] == "Fork 1–5"
