"""A run records what it sent beyond this machine where its summary and its report are closed.

The report node builds the disclosure record once the run's last model call
and tool call are made, from the closing token counts and stage rollup, the
whole ledger (and a count of the rows it could not read) and the job's
settings, and writes the same record onto the stored summary and the report's
own; a run in mock mode, whose judge wrote no summary, gets none. A stopped
run's summary and partial report carry the record as of the stop, which never
says that nothing left. The sandbox submission is recorded before it is made,
with the host the provider resolves its submission URL to, and marked once it
answered. The endpoints whose window probe answered as a model runtime are
kept where the probe ran, with no request of their own.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from maljan.analysis import disclosure
from maljan.analysis.disclosure import (
    INTRO_SENTENCE,
    STOPPED_PART_WAY,
    disclosure_record,
    run_disclosure,
    staging_record,
)
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


@pytest.fixture(autouse=True)
def _no_tracing_in_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LANGSMITH_TRACING", "LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING", raising=False)


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
    assert seen["unreadable"] == 0
    assert column["disclosure"] == stored["disclosure"] == record
    served = MarkdownRenderer().render(MalwareReport.model_validate(result["malware_report"]))
    assert INTRO_SENTENCE in served
    assert disclosure.disclosure_lines(record)[0] in served
    assert result["malware_report_markdown"] == served


@pytest.mark.asyncio
async def test_a_ledger_row_the_report_node_could_not_read_is_counted(
    container: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        disclosure, "run_disclosure", lambda held, **kwargs: seen.update(kwargs) or None
    )
    from tests.unit.pipeline import test_what_is_served_is_the_final_report as harness

    broken = _state()
    broken["evidence_ledger"] = [{"not": "a ledger row"}, {"id": 7}]
    monkeypatch.setattr(harness, "_state", lambda: broken)

    await _run(container)

    assert seen["unreadable"] == 2


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


def _held(settings: Settings, **over: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "config": settings,
        "sample_uploads": [],
        "sample_stagings": [],
        "runtime_answers": {},
    }
    values.update(over)
    return SimpleNamespace(**values)


def test_the_record_reads_the_job_settings_submissions_stagings_and_runtime_answers() -> None:
    settings = Settings.model_validate(
        {
            "llm": {"provider": "openai", "openai": {"base_url": "http://127.0.0.1:8080/v1"}},
            "sandbox": {"provider": "triage", "triage": {"base_url": "https://tria.example/api"}},
        }
    )
    held = _held(
        settings,
        sample_uploads=[disclosure.upload_record("triage", submitted=True, host="tria.example")],
        sample_stagings=[
            staging_record(
                "analysis", transport="http", url="https://re.example.org/mcp", state="done"
            )
        ],
        runtime_answers={"http://127.0.0.1:8080": "llama.cpp /props"},
    )
    tokens = {
        "llm_calls": 1,
        "per_agent": {"judge": {"llm_calls": 1, "models": {"openai/q @ http://127.0.0.1:8080": 1}}},
    }

    record = run_disclosure(
        held,
        entries=[],
        tokens=tokens,
        stages=[{"key": "verdict", "ran": True, "agents": ["judge"]}],
    )

    assert record is not None
    assert [(row["host"], row["runtime"]) for row in record["models"]] == [
        ("127.0.0.1", "llama.cpp /props")
    ]
    # Ordered as every part is: what went outside first, then by host.
    assert [(row["by"], row["source"], row["host"]) for row in record["uploads"]] == [
        ("staging", "mcp:analysis", "re.example.org"),
        ("sandbox", "triage", "tria.example"),
    ]
    assert record["nothing_left"] is False


def test_tracing_the_process_environment_turns_on_is_read_when_the_record_is_built(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    held = _held(Settings.model_validate({"langchain_tracing_v2": False}))

    quiet = run_disclosure(held, entries=[], tokens=None)
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    traced = run_disclosure(held, entries=[], tokens=None)

    assert quiet is not None and quiet["tracing"] is False
    assert traced is not None and traced["tracing"] is True
    assert traced["nothing_left"] is False


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


# ---------------------------------------------------------------------------
# The sandbox submission
# ---------------------------------------------------------------------------


class _Provider:
    """The surface the submission uses, answering or raising on submit."""

    id = "stub"

    def __init__(self, *, raises: bool = False, host: str | None = "sandbox.example") -> None:
        from maljan.providers.base import SandboxCapabilities

        self.capabilities = SandboxCapabilities(
            can_submit=True, can_poll=True, report_format="mock"
        )
        self.raises = raises
        self.host = host

    def submission_address(self) -> str | None:
        return self.host

    def submit(self, sample_path: str) -> str:
        if self.raises:
            raise RuntimeError("the sandbox closed the connection")
        return "42"

    def wait_for_completion(
        self, task_id: str, timeout_seconds: int, poll_interval_seconds: int
    ) -> str:
        return "failed"


def _submitted(tmp_path: Path, provider: Any) -> list[dict[str, Any]]:
    from maljan.app import MaljanApp

    sample = tmp_path / "s.exe"
    sample.write_bytes(b"payload")
    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    asyncio.run(app._submit_to_sandbox(str(sample)))
    return list(app.container.sample_uploads)


@pytest.mark.parametrize(("raises", "submitted"), [(False, True), (True, False)])
def test_the_submission_is_recorded_before_it_is_made(
    tmp_path: Path, raises: bool, submitted: bool
) -> None:
    assert _submitted(tmp_path, _Provider(raises=raises)) == [
        {"provider": "stub", "submitted": submitted, "host": "sandbox.example"}
    ]


@pytest.mark.parametrize(
    ("host", "recorded"),
    [
        (None, []),
        ("", [{"provider": "stub", "submitted": True, "host": ""}]),
    ],
)
def test_a_provider_says_where_its_submission_goes(
    tmp_path: Path, host: str | None, recorded: list[dict[str, Any]]
) -> None:
    assert _submitted(tmp_path, _Provider(host=host)) == recorded


def test_a_run_with_no_sample_submits_nothing() -> None:
    from maljan.app import MaljanApp

    app = MaljanApp(mock=True)
    app.container.sample_uploads = [{"provider": "left over", "submitted": True}]

    asyncio.run(app._submit_to_sandbox(None))

    assert app.container.sample_uploads == []


@pytest.mark.parametrize(
    ("provider", "values", "host"),
    [
        ("mock", {}, None),
        ("upload", {}, None),
        ("cape2", {"cape2": {"base_url": "http://10.65.0.40:8000"}}, "10.65.0.40"),
        ("triage", {"triage": {"base_url": "https://tria.example/api/v0"}}, "tria.example"),
        (
            "rest",
            {"rest": {"base_url": "https://detonate.example.org/api"}},
            "detonate.example.org",
        ),
        (
            "rest",
            {
                "rest": {
                    "base_url": "https://detonate.example.org/api",
                    "submit": {"path": "https://intake.example.net/upload"},
                }
            },
            "intake.example.net",
        ),
    ],
)
def test_each_built_in_provider_names_the_host_its_submission_reaches(
    provider: str, values: dict[str, Any], host: str | None
) -> None:
    from maljan.providers.registry import sandbox_provider_class

    settings = Settings.model_validate({"sandbox": values})
    made = sandbox_provider_class(provider).from_settings(settings)

    assert made.submission_address() == host


@pytest.mark.parametrize(
    "path", ["/samples", "samples/new", "https://intake.example.net/upload", "//cdn.example/x"]
)
def test_the_rest_submission_host_is_the_one_the_request_reaches(tmp_path: Path, path: str) -> None:
    """Merged as the client merges them: the recorded host is the request's own."""
    from maljan.providers.registry import sandbox_provider_class

    settings = Settings.model_validate(
        {
            "sandbox": {
                "rest": {"base_url": "https://detonate.example.org/api", "submit": {"path": path}}
            }
        }
    )
    made = sandbox_provider_class("rest").from_settings(settings)
    reached: list[str] = []

    def _answer(request: httpx.Request) -> httpx.Response:
        reached.append(request.url.host)
        return httpx.Response(200, json={"id": "1"})

    made._http = httpx.Client(
        base_url="https://detonate.example.org/api", transport=httpx.MockTransport(_answer)
    )
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"payload")
    made.submit(sample)

    assert reached == [made.submission_address()]


# ---------------------------------------------------------------------------
# The window probe's runtime answers
# ---------------------------------------------------------------------------


@pytest.fixture
def learned() -> Any:
    from maljan.llm import context_window

    context_window.forget_learned_windows()
    yield context_window
    context_window.forget_learned_windows()


def _model(endpoint: str, model: str = "q") -> SimpleNamespace:
    return SimpleNamespace(provider="openai", endpoint=endpoint, model=model)


def test_an_endpoint_that_answered_as_a_runtime_is_read_from_the_learned_windows(
    learned: Any,
) -> None:
    fact = learned.WindowFact(65536, learned.PROBED, "llama.cpp /props n_ctx")
    learned._remembered(("openai", "http://127.0.0.1:8080/v1", "q"), fact)
    hosted = learned.WindowFact(131072, learned.PROBED, "the API's model description")
    learned._remembered(("openai", "http://127.0.0.1:4000/v1", "q"), hosted)

    answers = learned.runtime_answers(
        [
            _model("http://127.0.0.1:8080/v1"),
            _model("http://127.0.0.1:4000/v1"),
            _model("http://127.0.0.1:9000/v1"),
        ]
    )

    assert answers == {"http://127.0.0.1:8080": "llama.cpp /props"}


def test_the_container_keeps_the_answers_where_the_windows_are_learned(learned: Any) -> None:
    from maljan.core.container import ServiceContainer

    fact = learned.WindowFact(65536, learned.PROBED, "the Ollama model description")
    learned._remembered(("openai", "http://10.0.0.5:11434", "q"), fact)
    held = SimpleNamespace(mock=False, _lock=threading.Lock(), runtime_answers={})
    ServiceContainer._note_runtime_answers(held, [_model("http://10.0.0.5:11434")])  # type: ignore[arg-type]
    assert held.runtime_answers == {"http://10.0.0.5:11434": "the Ollama model description"}

    mocked = SimpleNamespace(mock=True, _lock=threading.Lock(), runtime_answers={})
    ServiceContainer._note_runtime_answers(mocked, [_model("http://10.0.0.5:11434")])  # type: ignore[arg-type]
    assert mocked.runtime_answers == {}
