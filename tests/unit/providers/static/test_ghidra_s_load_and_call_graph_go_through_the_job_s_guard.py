"""Ghidra's load before the loop and its call-graph read are held by the job's guard.

The open of the job's sample (``open_sample``) and the sink pre-pass's call
graph (``call_graph``) count toward the server's breaker and take one of its
call slots, as the triage pass and the hash read do. A load a resting Ghidra
is not sent waits for the guard to admit calls again and is made then; only a
trial that fails stops it, with the guard's sentence. The pre-pass is skipped
with that sentence. The teardown close is not held: a close a resting guard
did not send would leave the job's programs open on a Ghidra other jobs share.

No Ghidra runs here: each request is answered in-process.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

import httpx
import pytest

from maljan.core.config import Settings
from maljan.core.exceptions import SampleNotOpened
from maljan.pipeline.events import describe_exception
from maljan.providers.base import prepare_sample
from maljan.providers.sample_open import SampleNotes
from maljan.providers.server_guard import ServerGuard
from maljan.providers.static.ghidra import provider as ghidra_provider
from maljan.providers.static.ghidra.provider import GhidraStaticProvider

URL = "http://ghidra.invalid"
HELD = "/data/samples/.work/s.exe"
LOADED = json.dumps({"success": True, "program": "s.exe"})


class _Ghidra:
    """A Ghidra that answers every request, and keeps the paths it was sent."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.fail = False
        self.status = 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(request.url.path)
        if self.fail:
            raise httpx.ConnectError("refused", request=request)
        if self.status != 200:
            return httpx.Response(self.status, text="boom")
        path = request.url.path
        if path == "/load_program":
            return httpx.Response(200, text=LOADED)
        if path == "/get_full_call_graph":
            return httpx.Response(200, text="entry -> CreateProcessA\n")
        return httpx.Response(200, text=json.dumps({"success": True, "program": "s.exe"}))


def _provider(
    monkeypatch: pytest.MonkeyPatch,
    ghidra: _Ghidra,
    *,
    failures_to_open: int = 1,
    max_concurrent_calls: int = 4,
    cooldown_seconds: float = 600.0,
) -> GhidraStaticProvider:
    real = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        return real(transport=httpx.MockTransport(ghidra.handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    cfg = Settings(_env_file=None)  # type: ignore[call-arg]
    cfg.static.ghidra.enabled = True
    cfg.static.ghidra.transport = "http"
    cfg.static.ghidra.url = URL
    cfg.mcp.breaker.failures_to_open = failures_to_open
    cfg.mcp.breaker.cooldown_seconds = cooldown_seconds
    cfg.mcp.breaker.max_concurrent_calls = max_concurrent_calls
    cfg.preprocessing.use_sink_reachability = True
    monkeypatch.setattr(ghidra_provider, "get_settings_or_none", lambda: cfg)
    provider = GhidraStaticProvider.from_settings(cfg)
    provider.sample_notes = SampleNotes()
    return provider


def _resting(guard: ServerGuard) -> None:
    """The breaker opened by the agents' own calls."""
    for _ in range(guard.failures_to_open):
        guard.failed("the server could not be reached")
    assert guard.refusal("list_functions") is not None


def _opens(provider: GhidraStaticProvider, paths: list[str]) -> dict[str, Any]:
    """Each path opened on its own thread, as analysts starting together do."""
    got: dict[str, Any] = {}

    def run(path: str) -> None:
        try:
            got[path] = provider.open_sample(path)
        except SampleNotOpened as exc:
            got[path] = exc

    threads = [threading.Thread(target=run, args=(path,)) for path in paths]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    # Nobody is left waiting on the guard.
    assert not any(thread.is_alive() for thread in threads)
    return got


class TestTheLoadBeforeTheLoop:
    def test_a_load_a_resting_ghidra_was_not_sent_is_made_after_the_cooldown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        provider = _provider(monkeypatch, ghidra, cooldown_seconds=0.2)
        _resting(provider.server_guard())
        assert provider.open_sample(HELD) is True
        # Sent once the rest's cooldown passed, as its trial; the trial ended the rest.
        assert ghidra.sent[0] == "/load_program"
        assert provider.server_guard().refusal("decompile_function") is None

    def test_opens_made_together_after_a_rest_all_open(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        answer = ghidra.handler

        def slow(request: httpx.Request) -> httpx.Response:
            time.sleep(0.2)
            return answer(request)

        ghidra.handler = slow  # type: ignore[method-assign]
        provider = _provider(monkeypatch, ghidra, cooldown_seconds=0.1)
        _resting(provider.server_guard())
        time.sleep(0.15)
        paths = [f"/data/samples/.work/s{i}.exe" for i in range(3)]
        # One is the trial; the others wait for its answer instead of stopping.
        assert _opens(provider, paths) == dict.fromkeys(paths, True)

    def test_a_failed_trial_stops_every_waiting_open_with_a_stated_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        ghidra.fail = True
        answer = ghidra.handler

        def slow(request: httpx.Request) -> httpx.Response:
            time.sleep(0.2)
            return answer(request)

        ghidra.handler = slow  # type: ignore[method-assign]
        provider = _provider(monkeypatch, ghidra, cooldown_seconds=0.1)
        _resting(provider.server_guard())
        time.sleep(0.15)
        paths = [f"/data/samples/.work/s{i}.exe" for i in range(3)]
        got = _opens(provider, paths)
        # Only the trial was sent, and it was not answered.
        assert ghidra.sent == ["/load_program"]
        for path in paths:
            failure = got[path]
            assert isinstance(failure, SampleNotOpened)
            said = describe_exception(failure)
            assert "did not answer the load of the job's sample" in said
            assert "tool server 'ghidra' is resting" in said
            # Nothing about the file: a loop after the rest loads it again.
            assert provider.sample_failure(path) is None

    def test_the_pre_pass_hands_a_failed_trial_to_the_stage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        ghidra.fail = True
        provider = _provider(monkeypatch, ghidra, cooldown_seconds=0.1)
        _resting(provider.server_guard())
        # Not swallowed as "did not open early": the stage records the agent stopped.
        with pytest.raises(SampleNotOpened, match="is resting"):
            prepare_sample(provider, HELD)
        assert ghidra.sent == ["/load_program"]

    def test_a_rest_another_call_began_just_before_the_load_is_waited_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        provider = _provider(monkeypatch, ghidra, cooldown_seconds=0.1)
        guard = provider.server_guard()
        real = provider._rest_client
        rested: list[bool] = []

        def client() -> Any:
            # The agents' calls rest Ghidra after this open began, before its load.
            if not rested:
                rested.append(True)
                _resting(guard)
            return real()

        monkeypatch.setattr(provider, "_rest_client", client)
        # Not a failed trial: this open sent nothing, so it waits the rest out.
        assert provider.open_sample(HELD) is True
        assert ghidra.sent[0] == "/load_program"

    def test_a_job_cancelled_while_its_open_waits_sends_no_load(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.cancellation import Cancellation, JobCancelled, bound

        ghidra = _Ghidra()
        provider = _provider(monkeypatch, ghidra)
        _resting(provider.server_guard())
        job = Cancellation()
        got: list[BaseException] = []

        def run() -> None:
            with bound(job):
                try:
                    provider.open_sample(HELD)
                except BaseException as exc:  # noqa: BLE001 - the test reads what stopped it
                    got.append(exc)

        thread = threading.Thread(target=run)
        thread.start()
        time.sleep(0.1)
        job.cancel("the operator cancelled the job")
        # Woken by the cancel, not by the rest's 600 s cooldown.
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert ghidra.sent == []
        assert len(got) == 1 and isinstance(got[0], JobCancelled)
        assert "the operator cancelled the job" in str(got[0])
        assert "before Ghidra's load of the job's sample" in str(got[0])

    def test_its_unanswered_loads_count_toward_the_shared_breaker(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        ghidra.fail = True
        provider = _provider(monkeypatch, ghidra, failures_to_open=2)
        with pytest.raises(SampleNotOpened, match="did not answer the load"):
            provider.open_sample(HELD)
        # The load and its one retry: two calls, two failures, the rest earned.
        assert ghidra.sent == ["/load_program", "/load_program"]
        assert "resting" in str(provider.server_guard().refusal("decompile_function"))

    def test_a_retry_the_first_failure_rested_is_not_sent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        ghidra.fail = True
        provider = _provider(monkeypatch, ghidra, failures_to_open=1)
        with pytest.raises(SampleNotOpened, match="is resting") as raised:
            provider.open_sample(HELD)
        assert ghidra.sent == ["/load_program"]
        assert "did not answer the load" in describe_exception(raised.value)

    def test_an_error_status_is_an_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ghidra = _Ghidra()
        ghidra.status = 500
        provider = _provider(monkeypatch, ghidra, failures_to_open=1)
        with pytest.raises(SampleNotOpened, match="HTTP 500"):
            provider.open_sample(HELD)
        assert provider.server_guard().refusal("decompile_function") is None

    def test_each_request_takes_one_of_the_server_s_call_slots(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghidra = _Ghidra()
        provider = _provider(monkeypatch, ghidra, max_concurrent_calls=1)
        guard = provider.server_guard()
        free: list[bool] = []
        answer = ghidra.handler

        def handler(request: httpx.Request) -> httpx.Response:
            slots = guard._thread_slots
            assert slots is not None
            took = slots.acquire(blocking=False)
            if took:
                slots.release()
            free.append(took)
            return answer(request)

        ghidra.handler = handler  # type: ignore[method-assign]
        assert provider.open_sample(HELD) is True
        # The load, the select and the analysis each found the only slot taken: its own.
        assert len(free) == 3 and not any(free)


class TestAStepAfterTheLoad:
    """Ghidra answered the load, then rests before the select is sent."""

    def _rests_after_the_load(self, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, _Ghidra]:
        ghidra = _Ghidra()
        provider = _provider(monkeypatch, ghidra)
        real = ghidra_provider._load

        def load(*args: Any) -> Any:
            loaded = real(*args)
            _resting(provider.server_guard())
            return loaded

        monkeypatch.setattr(ghidra_provider, "_load", load)
        return provider, ghidra

    def test_the_program_is_noted_for_the_teardown_and_the_sentence_says_so(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider, ghidra = self._rests_after_the_load(monkeypatch)
        with pytest.raises(SampleNotOpened) as raised:
            provider.open_sample(HELD)
        assert ghidra.sent == ["/load_program"]
        said = describe_exception(raised.value)
        assert "tool server 'ghidra' is resting" in said
        assert "Ghidra opened the job's sample as s.exe" in said
        assert "noted for the job's teardown to close" in said
        assert "was not sent" not in said.split(";")[0]
        assert provider.sample_failure(HELD) is None
        ghidra.sent.clear()
        provider.close()
        assert ghidra.sent == ["/close_program"]

    def test_with_no_note_to_keep_it_in_the_sentence_says_it_is_not_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider, _ = self._rests_after_the_load(monkeypatch)
        provider.sample_notes = None
        with pytest.raises(SampleNotOpened) as raised:
            provider.open_sample(HELD)
        assert "the job's teardown does not close it" in describe_exception(raised.value)


class TestTheCallGraph:
    def _opened(self, monkeypatch: pytest.MonkeyPatch, **kw: Any) -> tuple[Any, _Ghidra]:
        ghidra = _Ghidra()
        provider = _provider(monkeypatch, ghidra, **kw)
        assert provider.open_sample(HELD) is True
        ghidra.sent.clear()
        return provider, ghidra

    def test_it_is_read_through_the_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider, ghidra = self._opened(monkeypatch)
        graph = provider.call_graph(HELD)
        assert graph is not None
        assert ghidra.sent == ["/get_full_call_graph"]

    def test_a_resting_ghidra_skips_the_pre_pass_and_says_why(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        provider, ghidra = self._opened(monkeypatch)
        _resting(provider.server_guard())
        with caplog.at_level(logging.WARNING):
            assert provider.call_graph(HELD) is None
            assert provider.priority_functions(HELD) is None
        assert ghidra.sent == []
        said = [r.getMessage() for r in caplog.records if "call graph" in r.getMessage()]
        assert said and all("tool server 'ghidra' is resting" in line for line in said)
        assert all("sink-reachability pre-pass is skipped" in line for line in said)

    def test_its_unanswered_request_counts_toward_the_shared_breaker(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider, ghidra = self._opened(monkeypatch, failures_to_open=1)
        ghidra.fail = True
        # Fail-safe for the pre-pass, and the rest is earned for the agents.
        assert provider.priority_functions(HELD) is None
        assert ghidra.sent == ["/get_full_call_graph"]
        assert provider.server_guard().refusal("decompile_function") is not None


class TestTheTeardownClose:
    def test_the_close_is_sent_to_a_resting_ghidra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ghidra = _Ghidra()
        provider = _provider(monkeypatch, ghidra)
        assert provider.open_sample(HELD) is True
        ghidra.sent.clear()
        _resting(provider.server_guard())
        provider.close()
        # A refused close would leave the job's program open on a shared Ghidra.
        assert ghidra.sent == ["/close_program"]


class TestGuardedVerbs:
    def test_get_and_post_are_the_wrapped_client_s_own_held(self) -> None:
        from maljan.providers.server_guard import guarded_http

        made: list[str] = []

        class _OnlyVerbs:
            """A client with ``get`` and ``post`` and no ``request``."""

            def get(self, url: str, **_kw: Any) -> str:
                made.append(f"GET {url}")
                return "got"

            def post(self, url: str, **_kw: Any) -> str:
                made.append(f"POST {url}")
                return "posted"

        guard = ServerGuard("ghidra", max_concurrent_calls=1)
        http = guarded_http(_OnlyVerbs(), guard, URL)
        assert http.get(f"{URL}/get_full_call_graph") == "got"
        assert http.post(f"{URL}/load_program") == "posted"
        assert made == [f"GET {URL}/get_full_call_graph", f"POST {URL}/load_program"]
        _resting(guard)
        with pytest.raises(Exception, match="is resting"):
            http.get(f"{URL}/get_full_call_graph")
        assert len(made) == 2


class TestALookAtTheGuard:
    def test_refusal_never_claims_the_trial_a_waiter_waits_for(self) -> None:
        now = [0.0]
        guard = ServerGuard(
            "ghidra", failures_to_open=1, cooldown_seconds=10.0, clock=lambda: now[0]
        )
        guard.failed("the server could not be reached")
        rests = guard.rests_begun
        assert guard.refusal("t") is not None
        now[0] = 11.0
        # After the cooldown a look says the call would go, and claims nothing.
        assert guard.refusal("t") is None
        assert guard.refusal("t") is None
        assert guard._trial_in_flight is False
        done: list[bool] = []
        waiter = threading.Thread(target=lambda: done.append(guard.wait_admissible(rests)))
        waiter.start()
        waiter.join(timeout=5)
        assert not waiter.is_alive() and done == [True]
        # The trial is still the next call actually sent.
        with guard.held("t"):
            assert guard._trial_in_flight is True
        assert guard.refusal("t") is None and guard._reopen_at is None
