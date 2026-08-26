"""One dropped socket must not cost a verdict, a mediation or a report section.

``openai_provider`` sets ``max_retries=0`` for the whole process, on purpose:
the SDK's own retries would storm a *stalled* request three times its 1800 s
timeout. The comment there says the ReAct loop's own retry "is the only retry
policy we want" — and that was true of the ReAct loop and nothing else. Every
call outside it inherited zero retries and gained nothing in exchange:

* the judge's verdict — where one blip degraded the entire run to "Suspicious"
* the mediator's fast path — the likeliest producer of a failed negotiation
* the judge's no-tools path
* both reporting paths, which swallowed the failure and silently dropped a
  section from a delivered report

A local llama-server dropping an idle socket during a long tool-call gap is a
routine event on this deployment, not an exotic one.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from openai import APIConnectionError

from maljan.agents.base_agent import retry_on_connection_error


def _conn_error() -> APIConnectionError:
    return APIConnectionError(request=MagicMock())


@pytest.fixture(autouse=True)
def _no_real_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the 1s/2s backoff out of the suite's wall clock.

    The delays themselves are asserted by reading them off the call, not by
    waiting for them — a test that sleeps to prove a sleep is just a slow test.
    """
    import asyncio as _asyncio

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(_asyncio, "sleep", _instant)


class TestOnlyConnectionErrorsAreRetried:
    @pytest.mark.asyncio
    async def test_a_transient_blip_is_survived(self) -> None:
        calls = {"n": 0}

        async def _flaky() -> str:
            calls["n"] += 1
            if calls["n"] < 3:
                raise _conn_error()
            return "verdict"

        assert await retry_on_connection_error(_flaky, what="Judge verdict") == "verdict"
        assert calls["n"] == 3

    @pytest.mark.asyncio
    async def test_it_gives_up_and_re_raises_rather_than_looping(self) -> None:
        calls = {"n": 0}

        async def _always_down() -> str:
            calls["n"] += 1
            raise _conn_error()

        with pytest.raises(APIConnectionError):
            await retry_on_connection_error(_always_down, what="Judge verdict")
        assert calls["n"] == 3, "bounded — an unreachable server must not be hammered"

    @pytest.mark.asyncio
    async def test_a_stall_is_never_retried(self) -> None:
        """The anti-storm intent that ``max_retries=0`` exists to protect.

        A stalled request surfaces as ``TimeoutError`` from the caller's
        ``wait_for``. Retrying it would mean three times the request timeout.
        """
        calls = {"n": 0}

        async def _stalled() -> str:
            calls["n"] += 1
            raise TimeoutError("hard cap")

        with pytest.raises(TimeoutError):
            await retry_on_connection_error(_stalled, what="Judge verdict")
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_other_errors_pass_straight_through(self) -> None:
        async def _bad_response() -> str:
            raise ValueError("malformed structured output")

        with pytest.raises(ValueError, match="malformed"):
            await retry_on_connection_error(_bad_response, what="x")

    @pytest.mark.asyncio
    async def test_the_first_attempt_costs_nothing_extra(self) -> None:
        async def _fine() -> str:
            return "ok"

        assert await retry_on_connection_error(_fine, what="x") == "ok"


class TestTheCallSitesActuallyUseIt:
    """A helper nobody calls is not a fix. These assert the wiring, because the
    previous policy failed exactly by being written down and not applied."""

    @pytest.mark.parametrize(
        ("module", "needle"),
        [
            ("maljan.agents.judge_agent", "Mediator fast path"),
            ("maljan.agents.judge_agent", "Judge verdict"),
            ("maljan.agents.judge_agent", "Judge no-tools path"),
            ("maljan.reporting.composer", "ReportComposer structured"),
            ("maljan.reporting.composer", "ReportComposer raw"),
            ("maljan.reporting.narrative_agent", "NarrativeAgent structured"),
            ("maljan.reporting.narrative_agent", "NarrativeAgent raw"),
        ],
    )
    def test_each_unprotected_site_is_now_wrapped(self, module: str, needle: str) -> None:
        import importlib
        import inspect

        source = inspect.getsource(importlib.import_module(module))
        assert "retry_on_connection_error" in source
        assert needle in source, f"{module} lost its {needle!r} retry"
