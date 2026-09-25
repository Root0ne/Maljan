"""The operator sets how long the Triage VM runs the sample, and the run says how long it ran.

A paid run's Triage capture lasted 148 s while the sample's first beacon comes
at 180 s: nothing was sent as the run time, so Triage's own default applied.
``sandbox.triage.analysis_seconds`` is sent as the submission's
``defaults.timeout`` when set, and nothing is sent when it is not; the polling
deadline must outlast it; a refusal is surfaced in Triage's words; and the run
summary states the run-time limit Triage set for the task.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import SandboxTriageConfig, Settings
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.triage import TriageSandboxProvider
from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

FIX = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox"


def _provider(handler, **over) -> TriageSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
    for key, value in over.items():
        setattr(cfg.sandbox.triage, key, value)
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
    )
    return provider


def _json_part(body: bytes) -> dict:
    start = body.index(b'{"kind"')
    end = body.index(b"\r\n", start)
    return json.loads(body[start:end])


class TestTheSubmission:
    def test_carries_the_run_time_when_it_is_set(self) -> None:
        seen: dict[str, bytes] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["body"] = request.content
            return httpx.Response(200, json={"id": "s1"})

        _provider(handler, analysis_seconds=300).submit(FIX / "triage_overview.json")
        assert _json_part(seen["body"])["defaults"] == {"timeout": 300}

    def test_carries_nothing_when_it_is_not(self) -> None:
        seen: dict[str, bytes] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["body"] = request.content
            return httpx.Response(200, json={"id": "s1"})

        _provider(handler).submit(FIX / "triage_overview.json")
        assert "defaults" not in _json_part(seen["body"])

    def test_a_refusal_is_said_in_triage_s_words(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                400,
                json={
                    "error": "INVALID_OPTIONS",
                    "message": "timeout exceeds the maximum for your account",
                },
            )

        with pytest.raises(ProviderError) as refused:
            _provider(handler, analysis_seconds=1800).submit(FIX / "triage_overview.json")
        said = str(refused.value)
        assert "INVALID_OPTIONS: timeout exceeds the maximum for your account" in said
        assert "defaults.timeout=1800 from sandbox.triage.analysis_seconds" in said


class TestTheSetting:
    def test_is_unset_by_default(self) -> None:
        assert Settings(_env_file=None).sandbox.triage.analysis_seconds is None

    def test_the_poll_must_outlast_the_run(self) -> None:
        with pytest.raises(ValidationError, match="must be longer than"):
            SandboxTriageConfig(analysis_seconds=900, timeout_seconds=900)
        assert (
            SandboxTriageConfig(analysis_seconds=300, timeout_seconds=900).analysis_seconds == 300
        )


class TestTheRunTimeTriageReports:
    def _overview(self) -> dict:
        return json.loads((FIX / "triage_overview_dict_tasks.json").read_text())

    def test_is_read_from_the_behavioural_tasks(self) -> None:
        report = triage_overview_to_sandbox_report(self._overview())
        assert report.run_limit_seconds == 150

    def test_two_tasks_that_disagree_state_none(self) -> None:
        overview = self._overview()
        first = next(iter(overview["tasks"].values()))
        first["timeout"] = 300
        assert triage_overview_to_sandbox_report(overview).run_limit_seconds is None

    def test_the_run_summary_states_it(self) -> None:
        view = to_cape_shaped_dict(triage_overview_to_sandbox_report(self._overview()))
        summary = RunSummaryBuilder(start_time=0.0).set_sandbox(view).build()
        assert summary.to_dict()["sandbox_run_limit"] == {"seconds": 150, "set_by": "Triage"}
        assert (
            "**Sandbox run-time limit**: 150 s, the run-time limit Triage set for the task"
            in summary.to_markdown()
        )
