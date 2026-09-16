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
from openai import APIConnectionError, APIStatusError

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


def _status_error(status: int, headers: dict[str, str] | None = None) -> APIStatusError:
    """An ``APIStatusError`` shaped the way the openai SDK raises one."""
    response = MagicMock()
    response.status_code = status
    response.headers = headers or {}
    return APIStatusError(f"Error code: {status}", response=response, body=None)


class TestATransientProviderAnswerIsRetried:
    """A hosted endpoint saying "not now" is not the same as saying "no".

    Measured on a live run: the provider answered 500 "Internal server error"
    and 503 "Service temporarily overloaded" for a second at a time, and the
    static analyst, the negotiation, the verdict and every composer section
    were lost inside twelve seconds because each was a single attempt.
    """

    @pytest.mark.asyncio
    async def test_two_503s_then_an_answer(self) -> None:
        calls = {"n": 0}

        async def _overloaded() -> str:
            calls["n"] += 1
            if calls["n"] < 3:
                raise _status_error(503)
            return "verdict"

        assert await retry_on_connection_error(_overloaded, what="Judge verdict") == "verdict"
        assert calls["n"] == 3

    @pytest.mark.asyncio
    async def test_a_refusal_is_answered_once(self) -> None:
        """402 is about the account, and asking again cannot change it."""
        calls = {"n": 0}

        async def _payment_required() -> str:
            calls["n"] += 1
            raise _status_error(402)

        with pytest.raises(APIStatusError):
            await retry_on_connection_error(_payment_required, what="Judge verdict")
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_every_refusal_status_is_single_attempt(self) -> None:
        for status in (400, 401, 402, 403, 404, 422):

            async def _refused(_status: int, _calls: list[int]) -> str:
                _calls.append(_status)
                raise _status_error(_status)

            attempts: list[int] = []
            with pytest.raises(APIStatusError):
                await retry_on_connection_error(
                    lambda _s=status, _a=attempts: _refused(_s, _a), what="x"
                )
            assert len(attempts) == 1, status

    @pytest.mark.asyncio
    async def test_every_transient_status_is_retried(self) -> None:
        for status in (408, 409, 429, 500, 502, 503, 504):

            async def _transient(_status: int, _calls: list[int]) -> str:
                _calls.append(_status)
                if len(_calls) < 2:
                    raise _status_error(_status)
                return "ok"

            attempts: list[int] = []
            answer = await retry_on_connection_error(
                lambda _s=status, _a=attempts: _transient(_s, _a), what="x"
            )
            assert answer == "ok"
            assert len(attempts) == 2, status

    @pytest.mark.asyncio
    async def test_an_exhausted_budget_re_raises_the_last_error(self) -> None:
        calls = {"n": 0}

        async def _always_overloaded() -> str:
            calls["n"] += 1
            raise _status_error(503)

        with pytest.raises(APIStatusError) as exc:
            await retry_on_connection_error(_always_overloaded, what="Judge verdict")
        assert exc.value.status_code == 503
        assert calls["n"] == 3, "bounded — an overloaded provider must not be hammered"

    @pytest.mark.asyncio
    async def test_the_providers_retry_after_is_honoured_within_the_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio as _asyncio

        waits: list[float] = []

        async def _record(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(_asyncio, "sleep", _record)
        calls = {"n": 0}

        async def _rate_limited() -> str:
            calls["n"] += 1
            if calls["n"] < 2:
                raise _status_error(429, {"retry-after": "5"})
            return "ok"

        assert await retry_on_connection_error(_rate_limited, what="x") == "ok"
        assert waits == [5]

    @pytest.mark.asyncio
    async def test_an_unreasonable_retry_after_falls_back_to_the_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A provider asking for an hour is asking for longer than the caller has."""
        import asyncio as _asyncio

        waits: list[float] = []

        async def _record(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(_asyncio, "sleep", _record)
        calls = {"n": 0}

        async def _rate_limited() -> str:
            calls["n"] += 1
            if calls["n"] < 2:
                raise _status_error(429, {"retry-after": "3600"})
            return "ok"

        assert await retry_on_connection_error(_rate_limited, what="x") == "ok"
        assert waits == [1], "the helper's own backoff, not the provider's hour"

    @pytest.mark.asyncio
    async def test_a_retry_after_date_is_honoured_as_a_delay(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RFC 9110 allows a date, and hosted providers send one."""
        import asyncio as _asyncio
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        waits: list[float] = []

        async def _record(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(_asyncio, "sleep", _record)
        when = format_datetime(datetime.now(UTC) + timedelta(seconds=6))
        calls = {"n": 0}

        async def _rate_limited() -> str:
            calls["n"] += 1
            if calls["n"] < 2:
                raise _status_error(429, {"retry-after": when})
            return "ok"

        assert await retry_on_connection_error(_rate_limited, what="x") == "ok"
        assert waits and 4 <= waits[0] <= 6, waits

    @pytest.mark.asyncio
    async def test_a_date_in_the_past_falls_back_to_the_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio as _asyncio
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        waits: list[float] = []

        async def _record(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(_asyncio, "sleep", _record)
        when = format_datetime(datetime.now(UTC) - timedelta(hours=1))
        calls = {"n": 0}

        async def _rate_limited() -> str:
            calls["n"] += 1
            if calls["n"] < 2:
                raise _status_error(429, {"retry-after": when})
            return "ok"

        assert await retry_on_connection_error(_rate_limited, what="x") == "ok"
        assert waits == [1]

    def test_the_log_line_carries_no_provider_body(self) -> None:
        """A provider that quotes the request back has quoted the key back."""
        from maljan.agents.base_agent import _provider_fault

        error = _status_error(401)
        error.body = {"error": {"message": "invalid api key sk-live-abcdef"}}

        assert _provider_fault(error) == "APIStatusError 401"

    @pytest.mark.asyncio
    async def test_the_status_branch_logs_no_cause_chain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The chain ``repr()``s the exceptions behind this one, and behind a
        status error that is the provider's own answer."""
        from maljan.agents import base_agent

        def _explode(_exc: BaseException) -> str:  # pragma: no cover - must not run
            raise AssertionError("the status branch must not read the cause chain")

        monkeypatch.setattr(base_agent, "cause_chain", _explode)

        async def _overloaded() -> str:
            raise _status_error(503)

        with pytest.raises(APIStatusError):
            await retry_on_connection_error(_overloaded, what="x")

    @pytest.mark.asyncio
    async def test_the_status_line_does_not_report_an_absence_of_causes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A status error's line says the status and stops.

        The clause is dropped rather than filled with a sentence: "(caused by
        no cause recorded)" reads as though something had named itself.
        """
        lines: list[str] = []

        class _Log:
            def warning(self, template: str, *args: object) -> None:
                lines.append(template % args)

            def error(self, template: str, *args: object) -> None:
                lines.append(template % args)

        calls = {"n": 0}

        async def _overloaded() -> str:
            calls["n"] += 1
            if calls["n"] < 2:
                raise _status_error(503)
            return "ok"

        assert await retry_on_connection_error(_overloaded, what="x", log=_Log()) == "ok"
        assert lines and "caused by" not in lines[0]
        assert "HTTP 503" in lines[0]


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
