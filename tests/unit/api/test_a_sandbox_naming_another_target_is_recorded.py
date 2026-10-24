"""A live sandbox whose report names another target than the sample is recorded, not failed.

Only an attached report's claimed hash was compared with the sample, once, at
its upload. A sandbox that detonated the sample during the run names the
target it ran in its own report, and nothing read that against the sample.
The worker now does, from the neutral report whichever provider's reader
filled it: a target hash that is not the sample's is a run fact and a line in
the isolation part of the report, and the run is neither failed nor degraded
for it. A report that names the sample's hash, or none, adds nothing, so a run
stored before the check reads as before. Synthetic bytes only.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
import unicodedata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.worker import analysis_worker
from app.worker.analysis_worker import _report_inputs, keep_the_stopped_run
from app.worker.sample_integrity import sandbox_target_of
from maljan.analysis.disclosure import disclosure_record
from maljan.analysis.sample_integrity import (
    SANDBOX_KEY,
    sandbox_target_lines,
    sandbox_target_record,
)
from maljan.app import SANDBOX_FAILURE_CHARS
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.providers.base import SandboxCapabilities
from maljan.providers.sandbox.readers import required_reader
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer
from maljan.schemas.sandbox_report import SandboxRun
from maljan.utils.marked_cut import CUT_MARK

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()
OTHER = hashlib.sha256(b"some other bytes").hexdigest()


def _code(text: str) -> str:
    return f"`{text}`"


class TestTheRecord:
    def test_the_samples_hash_in_any_case_is_no_record(self) -> None:
        assert sandbox_target_record(INTAKE, INTAKE) is None
        assert sandbox_target_record(INTAKE, INTAKE.upper(), provider="cape2") is None

    def test_no_target_hash_is_no_record(self) -> None:
        for claimed in ("", None, "   "):
            assert sandbox_target_record(INTAKE, claimed, provider="cape2") is None

    def test_another_hash_is_recorded_with_its_sandbox_and_task(self) -> None:
        assert sandbox_target_record(INTAKE, OTHER, provider="cape2", task_id="7") == {
            "expected_sha256": INTAKE,
            "sandbox_sha256": OTHER,
            "provider": "cape2",
            "task_id": "7",
        }

    def test_the_record_is_said_in_one_line(self) -> None:
        record = sandbox_target_record(INTAKE, OTHER, provider="cape2", task_id="7")
        assert sandbox_target_lines(record, _code) == [
            f"The report of the sandbox `cape2` (task `7`) names its target SHA-256 as "
            f"`{OTHER}`, not the sample's intake SHA-256 `{INTAKE}`: what it observed may be "
            "of other bytes. The run was not failed for it; which findings it touches is the "
            "analyst's call."
        ]

    @pytest.mark.parametrize(
        "claimed",
        [
            "a" * 2_000_000,
            "\x1b[31m" + OTHER[:-5] + "\x00\x07",
            OTHER[:32] + "\n" + OTHER[32:],
            hashlib.md5(b"some other bytes").hexdigest(),
        ],
        ids=["over-long", "control-characters", "newline", "md5-length"],
    )
    def test_a_value_that_is_not_a_sha256_is_kept_bounded_on_one_line(self, claimed: str) -> None:
        record = sandbox_target_record(INTAKE, claimed, provider="cape2", task_id="7")
        assert record is not None
        assert record["sandbox_sha256_valid"] is False
        shown = record["sandbox_sha256"]
        assert len(shown) <= SANDBOX_FAILURE_CHARS
        assert not any(unicodedata.category(ch) == "Cc" for ch in shown)
        if len(claimed) > SANDBOX_FAILURE_CHARS:
            assert shown.endswith(CUT_MARK)
        [line] = sandbox_target_lines(record, _code)
        assert "names its target with a value that is not a SHA-256" in line
        assert f"intake SHA-256 `{INTAKE}`" in line
        assert "\n" not in line
        json.dumps(record)

    def test_an_upper_case_sha256_is_kept_lower_case(self) -> None:
        record = sandbox_target_record(INTAKE, f"  {OTHER.upper()} ")
        assert record is not None
        assert record["sandbox_sha256"] == OTHER
        assert "sandbox_sha256_valid" not in record

    def test_a_part_stored_without_the_record_says_nothing(self) -> None:
        assert sandbox_target_lines(None, _code) == []
        assert sandbox_target_lines({}, _code) == []


# ---------------------------------------------------------------------------
# Each provider's report shape, through the app and the worker
# ---------------------------------------------------------------------------


def _cape(sha256: str) -> dict[str, Any]:
    return {"target": {"file": {"sha256": sha256}}, "behavior": {}, "signatures": []}


def _flat(sha256: str) -> dict[str, Any]:
    return {"target": {"sha256": sha256}, "behavior": {}, "signatures": []}


def _triage(sha256: str) -> dict[str, Any]:
    return {"sample": {"sha256": sha256, "target": "s.exe"}, "tasks": []}


# (provider id, reader id, the raw report naming ``sha256``), one per shape a
# shipped reader fills the neutral report's target from. The mock sandbox's
# fixture is a recorded report, not a detonation during the run.
SHAPES = [
    ("cape2", "cape2", _cape),
    ("cape2", "cuckoo", _flat),
    ("triage", "triage", _triage),
    ("rest", "generic", _flat),
]


class _Provider:
    """The surface ``_submit_to_sandbox`` uses, answering one raw report through a reader."""

    def __init__(
        self, provider: str, reader: str, raw: dict[str, Any], status: str = "reported"
    ) -> None:
        self.id = provider
        self._reader, self._raw, self._status = reader, raw, status

    @property
    def capabilities(self) -> Any:
        return SandboxCapabilities(can_submit=True, can_poll=True, report_format=self._reader)

    def submit(self, sample_path: str) -> str:
        return "42"

    def wait_for_completion(self, task_id: str, **_: Any) -> str:
        return "reported"

    def fetch(self, task_id: str) -> SandboxRun:
        report = required_reader(self._reader).read(self._raw, provider=self.id, task_id=task_id)
        return SandboxRun(task_id=task_id, report=report, raw=self._raw, status=self._status)

    def signature_scale(self, run: Any, formats: Any = None) -> Any:
        return None


class _Uploaded(_Provider):
    """An attached report: checked at its upload, never detonated."""

    @property
    def capabilities(self) -> Any:
        return SandboxCapabilities(
            can_submit=False, accepts_uploaded_report=True, report_format=self._reader
        )


def _container_after(provider: Any, tmp_path: Path, *, used: bool = True) -> Any:
    from maljan.app import MaljanApp

    sample = tmp_path / "s.exe"
    sample.write_bytes(BYTES)
    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    report = asyncio.run(app._submit_to_sandbox(str(sample)))
    assert (report is not None) is used
    # Set by ``arun`` from the hash the job ran the sample under.
    app.container.sample_sha256 = INTAKE
    return app.container


class TestEachProviderShape:
    @pytest.mark.parametrize(("provider", "reader", "shape"), SHAPES)
    def test_another_target_is_recorded(
        self, provider: str, reader: str, shape: Any, tmp_path: Path
    ) -> None:
        container = _container_after(_Provider(provider, reader, shape(OTHER)), tmp_path)
        record = sandbox_target_of(container)
        assert record is not None
        assert record["sandbox_sha256"] == OTHER
        assert record["expected_sha256"] == INTAKE
        assert record["provider"] == provider
        assert record["task_id"] == "42"

    @pytest.mark.parametrize(("provider", "reader", "shape"), SHAPES)
    def test_the_samples_hash_is_no_record(
        self, provider: str, reader: str, shape: Any, tmp_path: Path
    ) -> None:
        container = _container_after(_Provider(provider, reader, shape(INTAKE)), tmp_path)
        assert container.sandbox_target_claim["sha256"] == INTAKE
        assert sandbox_target_of(container) is None

    @pytest.mark.parametrize(("provider", "reader", "shape"), SHAPES)
    def test_no_target_hash_is_no_record(
        self, provider: str, reader: str, shape: Any, tmp_path: Path
    ) -> None:
        container = _container_after(_Provider(provider, reader, shape("")), tmp_path)
        assert sandbox_target_of(container) is None

    def test_a_stand_in_report_keeps_no_claim(self, tmp_path: Path) -> None:
        raw = {"synthetic": True, **_flat(OTHER)}
        container = _container_after(_Provider("mock", "mock", raw), tmp_path)
        assert container.sandbox_target_claim is None
        assert sandbox_target_of(container) is None

    def test_a_recorded_fixture_keeps_no_claim(self, tmp_path: Path) -> None:
        container = _container_after(_Provider("mock", "mock", _cape(OTHER)), tmp_path)
        assert container.sandbox_target_claim is None
        assert sandbox_target_of(container) is None

    def test_a_failed_task_keeps_no_claim(self, tmp_path: Path) -> None:
        provider = _Provider("cape2", "cape2", _cape(OTHER), status="failed")
        container = _container_after(provider, tmp_path, used=False)
        assert container.sandbox_failure
        assert container.sandbox_target_claim is None
        assert sandbox_target_of(container) is None

    def test_an_attached_report_keeps_no_claim(self, tmp_path: Path) -> None:
        container = _container_after(_Uploaded("upload", "cape2", _cape(OTHER)), tmp_path)
        assert container.sandbox_target_claim is None
        assert sandbox_target_of(container) is None

    def test_a_job_without_a_sandbox_keeps_no_claim(self) -> None:
        assert sandbox_target_of(None) is None
        assert sandbox_target_of(SimpleNamespace(sample_sha256=INTAKE)) is None


# ---------------------------------------------------------------------------
# The stored run
# ---------------------------------------------------------------------------


def _isolation_part() -> dict[str, Any]:
    return {
        "worker": {"uid": 1000, "platform_names_in_env": []},
        "rows": [],
        "unsourced_reads": 0,
        "isolated": False,
        "isolated_by": "",
    }


def _state() -> dict[str, Any]:
    disclosure = disclosure_record(
        {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"},
        tokens={"llm_calls": 0, "per_agent": {}},
        agents=[],
    )
    disclosure["isolation"] = _isolation_part()
    summary = {"final_decision": "Malware", "disclosure": disclosure}
    payload = MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": INTAKE}},
            "verdict": "Malware",
            "run_summary": summary,
            "generated_at": "2026-10-01T00:00:00Z",
        }
    ).model_dump(mode="json")
    return {"run_summary": summary, "malware_report": payload}


def _claimed(sha256: str) -> Any:
    return SimpleNamespace(
        sample_sha256=INTAKE,
        sandbox_target_claim={"provider": "cape2", "task_id": "7", "sha256": sha256},
    )


def _inputs(state: dict[str, Any], **given: Any) -> dict[str, Any]:
    _, summary = _report_inputs(
        state,
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
        **given,
    )
    summary.pop("settings_snapshot")
    return summary


def _markdown(state: dict[str, Any]) -> str:
    return MarkdownRenderer().render(MalwareReport.model_validate(state["malware_report"]))


class TestTheStoredRun:
    def test_another_target_is_a_run_fact_and_an_isolation_line(self) -> None:
        record = sandbox_target_of(_claimed(OTHER))
        state = _state()
        summary = _inputs(state, sandbox_target=record)
        assert summary[SANDBOX_KEY] == record
        assert summary["disclosure"]["isolation"][SANDBOX_KEY] == record
        held = state["malware_report"]["run_summary"]
        assert held[SANDBOX_KEY] == record
        assert held["disclosure"]["isolation"][SANDBOX_KEY] == record
        # Not a degradation: the run is not failed or downgraded for it.
        assert not summary.get("degradation_reasons")
        assert not state["malware_report"].get("degradation_reasons")
        json.dumps(summary)
        markdown = _markdown(state)
        assert f"names its target SHA-256 as `{OTHER}`, not the sample's intake" in markdown
        assert "The report of the sandbox `cape2` (task `7`)" in markdown

    @pytest.mark.parametrize("claimed", [INTAKE, INTAKE.upper(), ""])
    def test_the_samples_hash_or_none_stores_and_renders_as_before(self, claimed: str) -> None:
        bare, given = _state(), _state()
        before = _inputs(bare)
        after = _inputs(given, sandbox_target=sandbox_target_of(_claimed(claimed)))
        assert before == after
        assert SANDBOX_KEY not in after
        assert bare["malware_report"] == given["malware_report"]
        assert _markdown(bare) == _markdown(given)


@pytest.mark.asyncio
async def test_a_stopped_run_is_stored_with_the_record() -> None:
    from app.models.report import AnalysisReport

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    container.sample_sha256 = INTAKE
    container.sandbox_target_claim = {"provider": "triage", "task_id": "9", "sha256": OTHER}
    state = {
        "file_hash": INTAKE,
        "file_name": "sample.exe",
        "run_started_at": time.time() - 5,
        "reports": {},
        "isr_reports": {},
        "evidence_ledger": [],
        "discussion_history": [],
        "degradation_reasons": [],
        "stage_results": {},
        "run_summary": {"degraded_mode": False, "degradation_reasons": []},
    }
    app = SimpleNamespace(container=container, built_report=None, latest_state=state)
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))

    kept = await keep_the_stopped_run(
        factory,
        job_uuid=job.id,
        job_id=str(job.id),
        app=app,
        note="Stopped by the operator.",
        transcript=[],
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
    )

    assert kept is True
    added = [obj for session in factory.sessions for obj in session.added]
    [report] = [obj for obj in added if isinstance(obj, AnalysisReport)]
    stored = report.run_summary[SANDBOX_KEY]
    assert stored == {
        "expected_sha256": INTAKE,
        "sandbox_sha256": OTHER,
        "provider": "triage",
        "task_id": "9",
    }
    assert report.malware_report["run_summary"][SANDBOX_KEY] == stored


def test_every_store_reads_the_sandbox_target() -> None:
    source = inspect.getsource(analysis_worker)
    # The completed run, the stopped run and the report kept after a failure.
    assert source.count("sandbox_target=sandbox_target_of(") == 3
    completed = inspect.getsource(analysis_worker.run_analysis)
    assert 'sandbox_target=sandbox_target_of(getattr(app, "container", None))' in completed
