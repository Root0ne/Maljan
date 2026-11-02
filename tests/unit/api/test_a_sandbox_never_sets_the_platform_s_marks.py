"""A sandbox's own report never sets the platform's marks.

A provider's document could carry a top-level ``synthetic`` or
``recorded_fixture`` key, and the readers passed it on: a live detonation then
read as the mock sandbox's empty stand-in (no sandbox ran) or as a recorded
fixture, and its observations were withheld from the analysts. At the intake
of every report a provider hands the run, live or attached, a mark the
reader did not set itself is taken out, with a warning. The mock sandbox's
stand-in and its recorded fixtures keep theirs, and a report that carries no
mark is left byte for byte as it came. Synthetic bytes only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from maljan.pipeline.sandbox_status import NOT_RUN, OBSERVED, RECORDED_FIXTURE, sandbox_status
from maljan.providers.base import SandboxCapabilities
from maljan.providers.sandbox.readers import required_reader
from maljan.schemas.sandbox_document import (
    FIXTURE_KEY,
    PLATFORM_MARKS,
    SYNTHETIC_KEY,
    sandbox_document,
    unearned_marks_removed,
)
from maljan.schemas.sandbox_report import SandboxRun

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()


def _cape(**top: Any) -> dict[str, Any]:
    return {
        "target": {"file": {"sha256": INTAKE}},
        "behavior": {"processes": [{"process_id": 7, "process_name": "s.exe"}]},
        "signatures": [],
        **top,
    }


def _triage(**top: Any) -> dict[str, Any]:
    return {"sample": {"sha256": INTAKE, "target": "s.exe"}, "tasks": [], **top}


class _Provider:
    """The surface ``_submit_to_sandbox`` uses, answering one raw report through a reader."""

    def __init__(self, provider: str, reader: str, raw: dict[str, Any]) -> None:
        self.id = provider
        self._reader, self._raw = reader, raw

    @property
    def capabilities(self) -> Any:
        return SandboxCapabilities(can_submit=True, can_poll=True, report_format=self._reader)

    def submit(self, sample_path: str) -> str:
        return "42"

    def wait_for_completion(self, task_id: str, **_: Any) -> str:
        return "reported"

    def fetch(self, task_id: str) -> SandboxRun:
        report = required_reader(self._reader).read(self._raw, provider=self.id, task_id=task_id)
        return SandboxRun(task_id=task_id, report=report, raw=self._raw, status="reported")

    def signature_scale(self, run: Any, formats: Any = None) -> Any:
        return None


class _Uploaded(_Provider):
    """An attached report: never detonated, read at intake."""

    @property
    def capabilities(self) -> Any:
        return SandboxCapabilities(
            can_submit=False, accepts_uploaded_report=True, report_format=self._reader
        )


def _intake(provider: Any, tmp_path: Path) -> dict[str, Any]:
    from maljan.app import MaljanApp

    sample = tmp_path / "s.exe"
    sample.write_bytes(BYTES)
    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    report = asyncio.run(app._submit_to_sandbox(str(sample)))
    assert isinstance(report, dict)
    return report


# Each shipped reader that reads a provider's document, live and attached.
LIVE = [
    ("cape2", "cape2", _cape),
    ("cape2", "cuckoo", _cape),
    ("triage", "triage", _triage),
]


class TestAForgedMarkIsTakenOut:
    @pytest.mark.parametrize(("provider", "reader", "shape"), LIVE)
    @pytest.mark.parametrize("mark", PLATFORM_MARKS)
    def test_a_live_report_stays_observed_and_the_warning_says_so(
        self,
        provider: str,
        reader: str,
        shape: Any,
        mark: str,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING):
            document = _intake(_Provider(provider, reader, shape(**{mark: True})), tmp_path)

        assert sandbox_status(document).status == OBSERVED
        assert mark not in document
        assert any(
            repr(mark) in r.getMessage() and "did not set" in r.getMessage() for r in caplog.records
        )

    @pytest.mark.parametrize("mark", PLATFORM_MARKS)
    def test_an_attached_report_stays_observed(
        self, mark: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            document = _intake(_Uploaded("upload", "cape2", _cape(**{mark: True})), tmp_path)

        assert sandbox_status(document).status == OBSERVED
        assert any(repr(mark) in r.getMessage() for r in caplog.records)

    def test_both_marks_and_a_false_one_are_taken_out(self, tmp_path: Path) -> None:
        document = _intake(
            _Provider("cape2", "cape2", _cape(synthetic=False, recorded_fixture=True)), tmp_path
        )

        assert sandbox_status(document).status == OBSERVED
        assert SYNTHETIC_KEY not in document and FIXTURE_KEY not in document

    def test_the_target_claim_is_kept_for_a_forged_stand_in(self, tmp_path: Path) -> None:
        # A report read as a stand-in kept no target claim: the forged mark hid
        # the sandbox's own target from the comparison with the sample.
        from maljan.app import MaljanApp

        sample = tmp_path / "s.exe"
        sample.write_bytes(BYTES)
        app = MaljanApp(mock=True)
        app.container.mock = False
        app.container._sandbox_provider_cache = _Provider("cape2", "cape2", _cape(synthetic=True))
        asyncio.run(app._submit_to_sandbox(str(sample)))

        assert app.container.sandbox_target_claim["sha256"] == INTAKE


class TestThePlatformsOwnMarksAreKept:
    def test_the_mock_stand_in_reads_as_no_sandbox(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from maljan.loaders.mock_sandbox_client import MockSandboxClient

        raw = MockSandboxClient._minimal_report(INTAKE, "s.exe")
        with caplog.at_level(logging.WARNING):
            document = _intake(_Provider("mock", "mock", raw), tmp_path)

        assert sandbox_status(document).status == NOT_RUN
        assert not any("did not set" in r.getMessage() for r in caplog.records)

    def test_a_recorded_fixture_reads_as_one(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            document = _intake(_Provider("mock", "mock", _cape()), tmp_path)

        assert sandbox_status(document).status == RECORDED_FIXTURE
        assert not any("did not set" in r.getMessage() for r in caplog.records)

    def test_the_mock_provider_s_own_fixture_path_keeps_its_mark(self, tmp_path: Path) -> None:
        from maljan.providers.sandbox.mock import MockSandboxProvider

        (tmp_path / "dynamic").mkdir()
        (tmp_path / "dynamic" / f"{INTAKE}.json").write_text(json.dumps(_cape()))
        document = _intake(MockSandboxProvider(str(tmp_path)), tmp_path)

        assert sandbox_status(document).status == RECORDED_FIXTURE


class TestAnUnforgedReportIsUnchanged:
    @pytest.mark.parametrize(("provider", "reader", "shape"), LIVE)
    def test_byte_for_byte(self, provider: str, reader: str, shape: Any) -> None:
        raw = shape()
        report = required_reader(reader).read(raw, provider=provider, task_id="42")
        before = json.dumps(sandbox_document(report))
        dumped = report.model_dump_json()

        assert unearned_marks_removed(report) == []

        assert json.dumps(sandbox_document(report)) == before
        assert report.model_dump_json() == dumped

    def test_through_the_intake(self, tmp_path: Path) -> None:
        raw = _cape()
        expected = sandbox_document(
            required_reader("cape2").read(raw, provider="cape2", task_id="42")
        )

        assert json.dumps(_intake(_Provider("cape2", "cape2", raw), tmp_path)) == json.dumps(
            expected
        )


# ---------------------------------------------------------------------------
# The real attached-report provider
# ---------------------------------------------------------------------------


def _cape_attached(**top: Any) -> dict[str, Any]:
    """A CAPE report as an upload is recognised: by its version string."""
    return _cape(info={"id": 7, "version": "cape-2.4"}, **top)


def _attached(raw: dict[str, Any]) -> Any:
    from maljan.core.config import Settings
    from maljan.providers.sandbox.upload import UploadSandboxProvider

    provider = UploadSandboxProvider.from_settings(Settings())
    provider.set_pending_blob(json.dumps(raw).encode(), filename="report.json")
    return provider


class TestTheAttachedReportProvider:
    @pytest.mark.parametrize("mark", PLATFORM_MARKS)
    def test_a_forged_mark_is_taken_out_at_intake(
        self, mark: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            document = _intake(_attached(_cape_attached(**{mark: True})), tmp_path)

        assert sandbox_status(document).status == OBSERVED
        assert mark not in document
        assert any(repr(mark) in r.getMessage() for r in caplog.records)

    def test_an_unforged_report_reaches_the_run_byte_for_byte(self, tmp_path: Path) -> None:
        raw = _cape_attached()
        expected = sandbox_document(_attached(raw).attach_report(json.dumps(raw).encode()).report)

        assert json.dumps(_intake(_attached(raw), tmp_path)) == json.dumps(expected)


# ---------------------------------------------------------------------------
# Only the built-in reader earns marks, and no operator names it
# ---------------------------------------------------------------------------


@pytest.fixture
def plug_in_readers() -> Any:
    """Readers registered for one test, the built-in ``mock`` restored after."""
    from maljan.providers.sandbox import readers

    mock = readers.report_reader("mock")
    added: list[str] = []

    def _register(reader: Any) -> None:
        readers.register_report_reader(reader)
        added.append(reader.id)

    yield _register
    for reader_id in added:
        readers.unregister_report_reader(reader_id)
    readers.register_report_reader(mock)


class TestAPlugInReaderEarnsNoMark:
    def test_a_reader_declaring_marks_earns_none(
        self, plug_in_readers: Any, tmp_path: Path
    ) -> None:
        from maljan.providers.sandbox.readers import CapeReportReader

        class _Declares(CapeReportReader):
            id = "plug-marks"
            platform_marks = frozenset(PLATFORM_MARKS)

        plug_in_readers(_Declares())
        document = _intake(_Provider("plug", "plug-marks", _cape(synthetic=True)), tmp_path)

        assert sandbox_status(document).status == OBSERVED

    def test_a_reader_replacing_the_mock_earns_none(
        self, plug_in_readers: Any, tmp_path: Path
    ) -> None:
        from maljan.providers.sandbox.readers import MockReportReader

        plug_in_readers(MockReportReader())
        document = _intake(_Provider("mock", "mock", _cape(synthetic=True)), tmp_path)

        assert sandbox_status(document).status == OBSERVED

    def test_the_built_in_mock_still_earns_its_marks(self, tmp_path: Path) -> None:
        from maljan.loaders.mock_sandbox_client import MockSandboxClient

        raw = MockSandboxClient._minimal_report(INTAKE, "s.exe")
        document = _intake(_Provider("mock", "mock", raw), tmp_path)

        assert sandbox_status(document).status == NOT_RUN


def _settings(**sandbox: Any) -> Any:
    from maljan.core.config import Settings

    cfg = Settings()
    return cfg.model_copy(update={"sandbox": cfg.sandbox.model_copy(update=sandbox)})


def _mock_format() -> Any:
    from maljan.core.report_formats import ReportFormat

    return ReportFormat(
        name="fixture_like",
        reader="mock",
        detect=[[{"path": "/fixture_marker", "types": ["number"]}]],
    )


class TestNoOperatorNamesTheFixtureReader:
    def test_the_rest_sandbox_refuses_report_format_mock(self) -> None:
        from maljan.providers.errors import ProviderConfigurationError
        from maljan.providers.sandbox.rest import RestSandboxProvider

        cfg = _settings()
        rest = cfg.sandbox.rest.model_copy(
            update={
                "base_url": "http://sandbox.test",
                "report": cfg.sandbox.rest.report.model_copy(update={"format": "mock"}),
            }
        )

        with pytest.raises(ProviderConfigurationError, match="mock"):
            RestSandboxProvider.from_settings(_settings(rest=rest))

    def test_a_forged_mark_read_by_the_mock_through_rest_never_reaches_the_run(self) -> None:
        # Even a provider built past the check refuses at fetch, before any
        # reader reads the body.
        from maljan.core.report_mapping import RestMappingConfig
        from maljan.providers.errors import ProviderConfigurationError
        from maljan.providers.sandbox.rest import RestSandboxProvider
        from maljan.providers.sandbox.rest_mapping import compile_mapping

        cfg = _settings()
        rest = cfg.sandbox.rest.model_copy(
            update={
                "base_url": "http://sandbox.test",
                "report": cfg.sandbox.rest.report.model_copy(update={"format": "mock"}),
            }
        )
        provider = RestSandboxProvider(rest, compile_mapping(RestMappingConfig()), ())

        class _Stream:
            status_code = 200

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_a: Any) -> None:
                return None

            def iter_bytes(self, *_a: Any, **_k: Any) -> Any:
                yield json.dumps(_cape(synthetic=True)).encode()

            def read(self) -> bytes:
                return json.dumps(_cape(synthetic=True)).encode()

        provider._get_http = lambda: type("H", (), {"stream": lambda *_a, **_k: _Stream()})()  # type: ignore[method-assign]

        with pytest.raises(ProviderConfigurationError, match="mock"):
            provider.fetch("42")

    def test_the_settings_refuse_a_declared_format_and_the_rest_format(self) -> None:
        from app.services.settings_service import _fixture_reader_refusals

        cfg = _settings(report_formats=[_mock_format()])
        cfg = cfg.model_copy(
            update={
                "sandbox": cfg.sandbox.model_copy(
                    update={
                        "rest": cfg.sandbox.rest.model_copy(
                            update={
                                "report": cfg.sandbox.rest.report.model_copy(
                                    update={"format": "fixture_like"}
                                )
                            }
                        )
                    }
                )
            }
        )

        assert sorted(_fixture_reader_refusals(cfg)) == [
            "core.sandbox.report_formats.0.reader",
            "core.sandbox.rest.report.format",
        ]

    def test_the_shipped_settings_are_not_refused(self) -> None:
        from app.services.settings_service import _fixture_reader_refusals

        assert _fixture_reader_refusals(_settings()) == {}

    def test_an_upload_read_as_a_mock_format_is_refused(self) -> None:
        from maljan.core.config import Settings
        from maljan.providers.errors import ProviderError
        from maljan.providers.sandbox.upload import UploadSandboxProvider

        cfg = Settings()
        upload = cfg.sandbox.upload.model_copy(
            update={"allowed_formats": [*cfg.sandbox.upload.allowed_formats, "fixture_like"]}
        )
        provider = UploadSandboxProvider(upload, [_mock_format()], cfg.sandbox.rest.mapping)
        blob = json.dumps({"fixture_marker": 1, "synthetic": True}).encode()

        with pytest.raises(ProviderError, match="mock"):
            provider.attach_report(blob)
