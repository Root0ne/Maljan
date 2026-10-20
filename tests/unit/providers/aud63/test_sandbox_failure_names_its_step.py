"""PS-L8: a sandbox failure says which step failed, not only that one did."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from maljan.core.exceptions import SandboxError
from tests.unit.pipeline.test_a_sandbox_failure_states_its_reason import _app, _sample
from tests.unit.test_sandbox_container import _StubProvider


class _SubmitRefused(_StubProvider):
    def submit(self, *args: Any, **kwargs: Any) -> Any:
        raise SandboxError("connection refused")


class _FetchRefused(_StubProvider):
    def fetch(self, task_id: str) -> Any:
        raise SandboxError("connection refused")


def _failure(provider: Any, tmp_path: Path) -> str:
    app = _app(provider)
    assert asyncio.run(app._submit_to_sandbox(str(_sample(tmp_path)))) is None
    return app.container.sandbox_failure or ""


def test_the_same_error_reads_differently_by_step(tmp_path: Path) -> None:
    at_submit = _failure(_SubmitRefused(), tmp_path)
    at_fetch = _failure(_FetchRefused(), tmp_path)
    assert "submitting the sample" in at_submit and "connection refused" in at_submit
    assert "fetching the report" in at_fetch and "connection refused" in at_fetch


def test_a_secret_query_parameter_is_masked():
    from maljan.core.settings_overrides import redact_url

    out = redact_url("failed: https://h/x?a=1&api_key=SECRET&b=2 and https://h/y?token=T")
    assert "SECRET" not in out and "=T" not in out.replace("token=***", "")
    assert "a=1" in out and "b=2" in out


def test_a_failure_before_the_submission_is_not_called_reading_a_report(
    tmp_path: Path, monkeypatch
) -> None:
    import maljan.analysis.disclosure as disclosure

    def broken(provider: Any) -> Any:
        raise RuntimeError("no host")

    monkeypatch.setattr(disclosure, "submission_host", broken)
    failure = _failure(_StubProvider(), tmp_path)
    assert failure.startswith("preparing the submission:")


def test_only_secret_named_parameters_in_a_url_are_masked():
    from maljan.core.settings_overrides import redact_url

    kept = "https://h/x?design=1&keyword=2&monkey=3&author=4"
    assert redact_url(kept) == kept
    out = redact_url("https://h/x?api_key=A&access_token=B&x-sig=C&n=1")
    assert "=A" not in out and "=B" not in out and "=C" not in out and "n=1" in out
    outside = "retry ;key=value and &token=1 outside a url"
    assert redact_url(outside) == outside
