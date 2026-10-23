"""PS-M3: one transient poll failure never discards a running detonation.

A status poll that times out, loses its connection, answers a 5xx or a body
that does not parse says nothing about the task: it is the sandbox busy or
briefly unreachable. Triage and the REST provider wait it out with their
backoff until the poll's own deadline, as CAPE's client does, and a deadline
reached that way names the last error. A 4xx stays a verdict.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from maljan.core.config import Settings
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.rest import RestSandboxProvider
from maljan.providers.sandbox.triage import TriageSandboxProvider


def _triage(handler: Callable[[httpx.Request], httpx.Response]) -> Any:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
    )
    return provider


def _rest(handler: Callable[[httpx.Request], httpx.Response]) -> Any:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.base_url = "https://xyz.example/api"
    provider = RestSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url="https://xyz.example/api", transport=httpx.MockTransport(handler)
    )
    return provider


PROVIDERS = [pytest.param(_triage, id="triage"), pytest.param(_rest, id="rest")]

REPORTED = {"id": "s1", "status": "reported"}


def _answers(*steps: Any) -> Callable[[httpx.Request], httpx.Response]:
    """A handler answering each step in turn: a response, or an exception raised."""
    queue: Iterator[Any] = iter(steps)

    def handler(request: httpx.Request) -> httpx.Response:
        step = next(queue)
        if isinstance(step, Exception):
            raise step
        return step

    return handler


class _Clock:
    def __init__(self, step: float) -> None:
        self.t = 0.0
        self.step = step

    def __call__(self) -> float:
        self.t += self.step
        return self.t


@pytest.mark.parametrize("build", PROVIDERS)
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.ReadTimeout("timed out"), id="timeout"),
        pytest.param(httpx.ConnectError("connection refused"), id="connect"),
        pytest.param(httpx.Response(502, text="bad gateway"), id="502"),
        pytest.param(httpx.Response(500, text="boom"), id="500"),
        pytest.param(httpx.Response(200, text="<html>not json"), id="unparsable"),
    ],
)
def test_one_transient_failure_is_waited_out(build: Any, failure: Any) -> None:
    provider = build(_answers(failure, httpx.Response(200, json=REPORTED)))
    slept: list[float] = []
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert len(slept) == 1


@pytest.mark.parametrize("build", PROVIDERS)
def test_a_sandbox_that_never_comes_back_fails_at_the_deadline_naming_why(build: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    provider = build(handler)
    provider._sleep = lambda _s: None
    provider._now = _Clock(step=50.0)
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("s1", timeout_seconds=600)
    assert "did not complete" in str(exc.value)
    assert "ConnectError" in str(exc.value)


@pytest.mark.parametrize("build", PROVIDERS)
@pytest.mark.parametrize("status", [501, 505])
def test_a_request_the_server_can_never_serve_fails_at_once(build: Any, status: int) -> None:
    provider = build(_answers(httpx.Response(status, text="never")))
    provider._sleep = lambda _s: pytest.fail("a permanent error is not waited on")
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("s1", timeout_seconds=600)
    assert str(status) in str(exc.value)


@pytest.mark.parametrize("status", [501, 505])
def test_cape_fails_at_once_on_a_request_it_can_never_serve(status: int) -> None:
    from unittest.mock import patch

    from maljan.loaders.cape2_client import CAPEv2Client
    from maljan.loaders.sandbox_client import SandboxError

    with patch("httpx.Client"):
        client = CAPEv2Client(base_url="http://cape.invalid:8000")
    client._http = httpx.Client(
        base_url="http://cape.invalid:8000",
        transport=httpx.MockTransport(_answers(httpx.Response(status, text="never"))),
    )
    with (
        patch("time.sleep", side_effect=AssertionError("waited")),
        pytest.raises(SandboxError, match=str(status)),
    ):
        client.wait_for_completion("7", timeout_seconds=600, poll_interval_seconds=1)


@pytest.mark.parametrize("build", PROVIDERS)
def test_a_4xx_is_still_a_verdict(build: Any) -> None:
    provider = build(_answers(httpx.Response(404, text="no such task")))
    provider._sleep = lambda _s: pytest.fail("a verdict is not waited on")
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("s1", timeout_seconds=600)
    assert "404" in str(exc.value)
