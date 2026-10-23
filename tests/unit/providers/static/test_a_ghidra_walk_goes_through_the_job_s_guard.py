"""Ghidra's own walks are held by the job's guard for Ghidra, the one the agents' calls go through.

The triage pass and the function-hash read count toward the server's breaker
and take one of its call slots; a breaker that is open stops either walk, and
the walk says so rather than reading as nothing found.

No Ghidra runs here: each request is answered in-process.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from maljan.core.config import Settings
from maljan.providers.base import StaticJobContext
from maljan.providers.server_guard import ServerGuard, ServerResting, guarded_http
from maljan.providers.static.ghidra import function_hashes as hashes
from maljan.providers.static.ghidra import provider as ghidra_provider
from maljan.providers.static.ghidra.passes import GhidraPasses, GhidraPassFailed
from maljan.providers.static.ghidra.provider import GhidraStaticProvider

URL = "http://ghidra.invalid"
HELD = "/data/samples/.work/s.exe"
LOADED = json.dumps({"success": True, "program": "s.exe"})


def _mock(monkeypatch: Any, handler: Any) -> None:
    real = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        return real(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)


def _fetch(guard: ServerGuard) -> Any:
    return hashes.fetch_bulk_function_hashes(
        base_url=URL,
        auth_token="",
        file_path=HELD,
        min_instructions=1,
        note_key="remote http://ghidra.invalid:80",
        shared=False,
        guard=guard,
    )


def _passes(handler: Any, guard: ServerGuard) -> GhidraPasses:
    return GhidraPasses(
        base_url=URL,
        sample_path=HELD,
        transport=httpx.MockTransport(handler),
        note_key="remote http://ghidra.invalid:80",
        guard=guard,
    )


def _resting(guard: ServerGuard) -> None:
    """The breaker opened by the agents' own calls."""
    for _ in range(guard.failures_to_open):
        guard.failed("the server could not be reached")
    assert guard.refusal("list_functions") is not None


class TestTheFunctionHashWalk:
    def test_its_unanswered_requests_count_toward_the_shared_breaker(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        _mock(monkeypatch, handler)
        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        got = _fetch(guard)
        assert not got and got.unavailable
        # The agents' next call is refused by the rest the walk earned.
        assert "resting" in str(guard.refusal("decompile_function"))

    def test_an_open_breaker_stops_it_with_a_stated_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(request.url.path)
            return httpx.Response(200, text=LOADED)

        _mock(monkeypatch, handler)
        guard = ServerGuard("ghidra", failures_to_open=2, cooldown_seconds=600.0)
        _resting(guard)
        got = _fetch(guard)
        assert sent == []
        assert not got
        assert "tool server 'ghidra' is resting" in got.unavailable
        assert "no hashes were read" in got.unavailable

    def test_each_page_takes_one_of_the_server_s_call_slots(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        guard = ServerGuard("ghidra", max_concurrent_calls=1)
        free: list[bool] = []

        def handler(request: httpx.Request) -> httpx.Response:
            slots = guard._thread_slots
            assert slots is not None
            took = slots.acquire(blocking=False)
            if took:
                slots.release()
            free.append(took)
            path = request.url.path
            if path == "/load_program":
                return httpx.Response(200, text=LOADED)
            if path == "/get_bulk_function_hashes":
                offset = int(request.url.params.get("offset", "0"))
                items = [] if offset else [{"name": "f", "hash": "h1", "instruction_count": 9}]
                return httpx.Response(200, text=json.dumps({"functions": items}))
            return httpx.Response(200, text=json.dumps({"success": True}))

        _mock(monkeypatch, handler)
        got = _fetch(guard)
        assert list(got) == [("f", "h1")]
        # Every request found the only slot taken: its own.
        assert free and not any(free)


class TestTheShippedDeclaration:
    """The walks as a job makes them: the shipped ``sample_open``, on a shared Ghidra."""

    def test_the_hash_walk_on_a_shared_ghidra_sends_nothing_to_a_resting_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.providers.sample_open import SampleNotes

        sent: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(request.url.path)
            return httpx.Response(200, text=LOADED)

        _mock(monkeypatch, handler)
        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        _resting(guard)
        got = hashes.fetch_bulk_function_hashes(
            base_url=URL,
            auth_token="",
            file_path=HELD,
            min_instructions=1,
            note_key="remote http://ghidra.invalid:80",
            sample_open=Settings(_env_file=None).static.ghidra.sample_open,  # type: ignore[call-arg]
            sample_notes=SampleNotes(),
            shared=True,
            guard=guard,
        )
        assert sent == []
        assert not got and "tool server 'ghidra' is resting" in got.unavailable

    def test_the_pass_sends_nothing_to_a_resting_ghidra(self) -> None:
        from maljan.providers.sample_open import SampleNotes

        sent: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(request.url.path)
            return httpx.Response(200, text=LOADED)

        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        _resting(guard)
        passes = GhidraPasses(
            base_url=URL,
            sample_path=HELD,
            transport=httpx.MockTransport(handler),
            sample_open=Settings(_env_file=None).static.ghidra.sample_open,  # type: ignore[call-arg]
            sample_notes=SampleNotes(),
            note_key="remote http://ghidra.invalid:80",
            guard=guard,
        )
        with pytest.raises(GhidraPassFailed, match="tool server 'ghidra' is resting"):
            passes.anti_analysis()
        assert sent == []


class _Stopped(BaseException):
    """A call its caller ended."""


class TestTheTrial:
    """``held`` decides a rest as the async path does, on a clock the test moves."""

    def _rested(self) -> tuple[ServerGuard, list[float]]:
        now = [0.0]
        guard = ServerGuard(
            "ghidra", failures_to_open=1, cooldown_seconds=10.0, clock=lambda: now[0]
        )
        with pytest.raises(httpx.ConnectError), guard.held("t"):
            raise httpx.ConnectError("refused")
        assert guard.refusal("t") is not None
        now[0] = 11.0
        return guard, now

    def test_an_answer_after_the_cooldown_ends_the_rest(self) -> None:
        guard, _ = self._rested()
        with guard.held("t"):
            pass
        assert guard.refusal("t") is None

    def test_a_trial_the_server_did_not_answer_starts_a_new_rest(self) -> None:
        guard, _ = self._rested()
        with pytest.raises(httpx.ConnectError), guard.held("t"):
            raise httpx.ConnectError("refused")
        assert "tried again in 10 s" in str(guard.refusal("t"))

    def test_a_trial_its_caller_ended_lets_the_next_call_try(self) -> None:
        guard, _ = self._rested()
        with pytest.raises(_Stopped), guard.held("t"):
            raise _Stopped
        assert guard._trial_in_flight is False
        with guard.held("t"):
            pass
        assert guard.refusal("t") is None

    def test_a_second_caller_is_refused_while_the_trial_is_out(self) -> None:
        guard, _ = self._rested()
        with guard.held("t"):
            with pytest.raises(ServerResting, match="one call has been let through"):
                with guard.held("t"):
                    pass

    def test_an_error_of_the_caller_s_own_counts_nothing(self) -> None:
        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        with pytest.raises(ValueError), guard.held("t"):
            raise ValueError("not the server's")
        assert guard.refusal("t") is None

    def test_an_http_error_that_is_not_the_transport_is_an_answer(self) -> None:
        guard = ServerGuard("ghidra", failures_to_open=2, cooldown_seconds=600.0)
        guard.failed("the server could not be reached")
        request = httpx.Request("GET", URL)
        with pytest.raises(httpx.HTTPStatusError), guard.held("t"):
            raise httpx.HTTPStatusError(
                "500", request=request, response=httpx.Response(500, request=request)
            )
        # The count was reset: one more failure does not open the breaker.
        guard.failed("the server could not be reached")
        assert guard.refusal("t") is None


class TestTheThreadCap:
    def test_threads_never_hold_more_calls_than_the_cap(self) -> None:
        import threading
        import time

        guard = ServerGuard("ghidra", max_concurrent_calls=2)
        lock = threading.Lock()
        inside = [0]
        peak = [0]

        def call() -> None:
            with guard.held("t"):
                with lock:
                    inside[0] += 1
                    peak[0] = max(peak[0], inside[0])
                time.sleep(0.02)
                with lock:
                    inside[0] -= 1

        threads = [threading.Thread(target=call) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert inside[0] == 0
        assert 1 <= peak[0] <= guard.max_concurrent_calls


class TestTheTriagePass:
    def test_an_open_breaker_fails_the_pass_with_the_guard_s_sentence(self) -> None:
        sent: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(request.url.path)
            return httpx.Response(200, text=LOADED)

        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        _resting(guard)
        passes = _passes(handler, guard)
        with pytest.raises(GhidraPassFailed, match="tool server 'ghidra' is resting"):
            passes.anti_analysis()
        assert sent == []

    def test_its_unanswered_requests_count_toward_the_shared_breaker(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        with pytest.raises(GhidraPassFailed, match="did not answer"):
            _passes(handler, guard).anti_analysis()
        assert guard.refusal("decompile_function") is not None

    def test_an_error_status_is_an_answer(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        with pytest.raises(GhidraPassFailed, match="HTTP 500"):
            _passes(handler, guard).anti_analysis()
        assert guard.refusal("decompile_function") is None


class TestOneGuardPerJob:
    def test_the_agents_and_the_walks_share_the_provider_s_guard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.providers.static.ghidra import http_client as ghidra_http_client

        built: list[Any] = []

        class _Fake:
            def __init__(self, **kwargs: Any) -> None:
                built.append(kwargs["guard"])

            async def initialize(self) -> None:
                return None

            def get_tools(self) -> list[Any]:
                return []

        monkeypatch.setattr(ghidra_http_client, "GhidraHTTPClient", _Fake)
        cfg = Settings(_env_file=None)  # type: ignore[call-arg]
        cfg.static.ghidra.enabled = True
        cfg.static.ghidra.transport = "http"
        monkeypatch.setattr(ghidra_provider, "get_settings_or_none", lambda: cfg)
        seen: dict[str, Any] = {}

        def fetch(**kw: Any) -> list[Any]:
            seen.update(kw)
            return []

        monkeypatch.setattr(hashes, "fetch_bulk_function_hashes", fetch)
        provider = GhidraStaticProvider.from_settings(cfg)
        job = StaticJobContext(mirror_sample_path=HELD)
        # The pass and the hash read may run before any agent attaches.
        scan = provider.anti_analysis_scan(job)
        provider.function_hashes(job)
        rests: list[dict[str, Any]] = []
        provider.open(StaticJobContext(on_server_rest=rests.append))
        guard = provider.server_guard()
        assert isinstance(guard, ServerGuard)
        assert scan.guard is guard and seen["guard"] is guard and built[0] is guard
        _resting(guard)
        # The rest reaches the job's hook the attach named.
        assert len(rests) == 1 and provider.rests == []

    def test_a_rest_before_any_attach_is_kept_for_the_run_summary(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = Settings(_env_file=None)  # type: ignore[call-arg]
        cfg.static.ghidra.transport = "http"
        monkeypatch.setattr(ghidra_provider, "get_settings_or_none", lambda: cfg)
        provider = GhidraStaticProvider.from_settings(cfg)
        _resting(provider.server_guard())
        assert [row["server"] for row in provider.rests] == [provider.id]

    def test_no_settings_no_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = Settings(_env_file=None)  # type: ignore[call-arg]
        monkeypatch.setattr(ghidra_provider, "get_settings_or_none", lambda: None)
        assert GhidraStaticProvider.from_settings(cfg).server_guard() is None


class TestGuardedHTTP:
    def test_no_guard_is_the_client_itself(self) -> None:
        client = object()
        assert guarded_http(client, None) is client

    def test_a_request_is_named_by_its_path_past_the_base(self) -> None:
        guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
        _resting(guard)
        http = guarded_http(object(), guard, "http://ghidra.invalid/api")
        with pytest.raises(ServerResting) as raised:
            http.get("http://ghidra.invalid/api/get_bulk_function_hashes?offset=0")
        assert raised.value.tool == "get_bulk_function_hashes"
        assert "server_resting" in raised.value.answer
