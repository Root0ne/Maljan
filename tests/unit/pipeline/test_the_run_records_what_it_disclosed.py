"""A run records what it sent beyond this machine where its summary and its report are closed.

The report node builds the disclosure record once the run's last model call
and tool call are made, from the closing token counts and stage rollup, the
whole ledger and the job's settings, and writes the same record onto the
stored summary and the report's own; a run in mock mode, whose judge wrote no
summary, gets none. A stopped run's summary and partial report carry the
record as of the stop, which never says that nothing left. The sandbox
submission is recorded before it is made and marked once it answered.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.analysis import disclosure
from maljan.analysis.disclosure import STOPPED_PART_WAY, disclosure_record, run_disclosure
from maljan.core.config import Settings
from maljan.core.token_ledger import TokenLedger
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer
from tests.stages import paper_profile
from tests.unit.pipeline.test_what_is_served_is_the_final_report import _run, _state

LABEL = "openai/m @ https://llm.example.org"


@pytest.fixture
def container() -> Any:
    """The report node's container as the served-report harness builds it."""
    from unittest.mock import MagicMock

    fake = MagicMock()
    fake.agent_registry.list_agents.return_value = ["static"]
    fake.analyst_keys.return_value = ["static"]
    fake.agent_role.side_effect = lambda n: n
    fake.is_mock = False
    fake.config.reporting.enabled = True
    fake.config.llm.parallel_analysts = False
    fake.config.negotiation.max_iterations = 3
    fake.active_profile.return_value = paper_profile(["static"], parallel=False)
    fake.get_narrative_agent.return_value = None
    fake.get_report_composer.return_value = None
    fake.get_static_provider.return_value.capabilities.provides_evidence = False
    return fake


def _local_record() -> dict[str, Any]:
    return disclosure_record(
        {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:1"}
    )


@pytest.mark.asyncio
async def test_the_report_node_writes_one_record_onto_both_surfaces(
    container: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = TokenLedger()
    ledger.add({"input_tokens": 10, "output_tokens": 1}, agent="judge", model=LABEL)
    container.get_token_ledger.return_value = ledger
    seen: dict[str, Any] = {}
    record = _local_record()

    def _spy(held: Any, **kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs, container=held)
        return record

    monkeypatch.setattr(disclosure, "run_disclosure", _spy)

    result, column = await _run(container)
    stored = (result["malware_report"] or {}).get("run_summary") or {}

    assert seen["container"] is container
    assert seen["tokens"] == column["tokens"], "the closing counts, the report stage's included"
    assert seen["stages"] == column["stages"]
    assert list(seen["entries"]) == [], "the run's whole ledger"
    assert column["disclosure"] == stored["disclosure"] == record
    served = MarkdownRenderer().render(MalwareReport.model_validate(result["malware_report"]))
    assert disclosure.NOTHING_LEFT_SENTENCE in served
    assert result["malware_report_markdown"] == served


@pytest.mark.asyncio
async def test_a_run_whose_judge_wrote_no_summary_records_none(
    container: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[Any] = []
    monkeypatch.setattr(disclosure, "run_disclosure", lambda *a, **k: called.append(a))
    from tests.unit.pipeline import test_what_is_served_is_the_final_report as harness

    blank = _state()
    blank["run_summary"] = None
    monkeypatch.setattr(harness, "_state", lambda: blank)

    result, column = await _run(container)

    assert called == []
    assert "disclosure" not in column


def test_a_container_without_job_settings_records_none() -> None:
    assert run_disclosure(SimpleNamespace(config=object()), entries=[], tokens=None) is None


def test_the_record_reads_the_job_settings_and_the_submissions() -> None:
    settings = Settings.model_validate(
        {
            "llm": {"provider": "openai", "openai": {"base_url": "https://llm.example.org/v1"}},
            "sandbox": {"provider": "triage", "triage": {"base_url": "https://tria.example/api"}},
        }
    )
    held = SimpleNamespace(
        config=settings,
        sample_uploads=[disclosure.upload_record("triage", submitted=True)],
    )

    record = run_disclosure(
        held,
        entries=[],
        tokens={"llm_calls": 1, "per_agent": {"judge": {"llm_calls": 1, "models": {LABEL: 1}}}},
        stages=[{"key": "verdict", "ran": True, "agents": ["judge"]}],
    )

    assert record is not None
    assert [row["host"] for row in record["models"]] == ["llm.example.org"]
    assert [(row["source"], row["host"]) for row in record["uploads"]] == [
        ("triage", "tria.example")
    ]
    assert record["nothing_left"] is False


def _stopped_container(settings: Settings) -> SimpleNamespace:
    ledger = TokenLedger()
    ledger.add(
        {"input_tokens": 1, "output_tokens": 1},
        agent="static",
        model="openai/q @ http://127.0.0.1:1",
    )
    return SimpleNamespace(config=settings, sample_uploads=[], get_token_ledger=lambda: ledger)


def test_a_stopped_run_s_summary_and_partial_report_carry_the_record_as_of_the_stop() -> None:
    from maljan.pipeline.stopped_run import partial_report, stopped_run_summary

    settings = Settings.model_validate(
        {"llm": {"provider": "openai", "openai": {"base_url": "http://127.0.0.1:1/v1"}}}
    )
    held = _stopped_container(settings)
    state = {
        "run_summary": {"final_decision": "Malware", "stages": []},
        "malware_report": {"run_summary": {"final_decision": "Malware"}},
        "evidence_ledger": [],
    }

    summary = stopped_run_summary(state, held, note="stopped")
    report = partial_report(state, held, note="stopped")

    for record in (summary["disclosure"], report["run_summary"]["disclosure"]):
        assert record["partial_reason"] == STOPPED_PART_WAY
        assert record["nothing_left"] is False
        assert [row["host"] for row in record["models"]] == ["127.0.0.1"]


def test_a_stopped_run_keeps_the_record_its_report_node_closed() -> None:
    from maljan.pipeline.stopped_run import partial_report, stopped_run_summary

    held = _stopped_container(Settings(_env_file=None))
    closed = _local_record()
    state = {
        "run_summary": {"final_decision": "Malware", "disclosure": closed},
        "malware_report": {"run_summary": {"final_decision": "Malware", "disclosure": closed}},
        "evidence_ledger": [],
    }

    assert stopped_run_summary(state, held, note="stopped")["disclosure"] == closed
    assert partial_report(state, held, note="stopped")["run_summary"]["disclosure"] == closed


class _Provider:
    """The surface the submission uses, answering or raising on submit."""

    id = "stub"

    def __init__(self, *, raises: bool = False, address: str | None = None) -> None:
        from maljan.providers.base import SandboxCapabilities

        self.capabilities = SandboxCapabilities(
            can_submit=True, can_poll=True, report_format="mock"
        )
        self.raises = raises
        self.submission_address = address

    def submit(self, sample_path: str) -> str:
        if self.raises:
            raise RuntimeError("the sandbox closed the connection")
        return "42"

    def wait_for_completion(
        self, task_id: str, timeout_seconds: int, poll_interval_seconds: int
    ) -> str:
        return "failed"


@pytest.mark.parametrize(("raises", "submitted"), [(False, True), (True, False)])
def test_the_submission_is_recorded_before_it_is_made(
    tmp_path: Path, raises: bool, submitted: bool
) -> None:
    from maljan.app import MaljanApp

    sample = tmp_path / "s.exe"
    sample.write_bytes(b"payload")
    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = _Provider(raises=raises)

    asyncio.run(app._submit_to_sandbox(str(sample)))

    assert app.container.sample_uploads == [
        {"provider": "stub", "submitted": submitted, "address": "sandbox.stub.base_url"}
    ]


@pytest.mark.parametrize(
    ("address", "recorded"),
    [
        ("", []),
        (
            "sandbox.rest.base_url",
            [{"provider": "stub", "submitted": True, "address": "sandbox.rest.base_url"}],
        ),
    ],
)
def test_a_provider_says_where_its_submission_goes(
    tmp_path: Path, address: str, recorded: list[dict[str, Any]]
) -> None:
    from maljan.app import MaljanApp

    sample = tmp_path / "s.exe"
    sample.write_bytes(b"payload")
    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = _Provider(address=address)

    asyncio.run(app._submit_to_sandbox(str(sample)))

    assert app.container.sample_uploads == recorded


def test_the_built_in_providers_declare_where_their_submissions_go() -> None:
    from maljan.providers.registry import sandbox_provider_class, sandbox_provider_ids

    where = {
        provider: disclosure.submission_address(sandbox_provider_class(provider))
        for provider in sandbox_provider_ids()
    }

    # The recorded fixtures are read in place; every other one names its block's address.
    assert where.pop("mock") is None
    assert where == {provider: f"sandbox.{provider}.base_url" for provider in where}


def test_a_run_with_no_sample_submits_nothing(tmp_path: Path) -> None:
    from maljan.app import MaljanApp

    app = MaljanApp(mock=True)
    app.container.sample_uploads = [{"provider": "left over", "submitted": True}]

    asyncio.run(app._submit_to_sandbox(None))

    assert app.container.sample_uploads == []
