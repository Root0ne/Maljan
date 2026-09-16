"""A chat model belongs to one event loop, so the container caches one per loop.

An httpx connection pool is bound to the loop that first awaited it. This
process makes LLM calls on two: the shared agent loop every analyst and the
judge run on, and the worker's own, where the report node awaits the narrative
and composer rounds. One cached model handed to both fails inside httpx with
"bound to a different event loop", which the openai SDK reports as a bare
``APIConnectionError("Connection error.")`` — the fault the judge's first
verdict request hit on every run, and then the narrative round after it.

Two things make the partition real. The container keys every model cache by the
caller's loop, and the provider gives each model a pool of its own, because
``langchain_openai`` otherwise hands every model for one endpoint the same
``lru_cache``d client and the partition would be a partition of nothing.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


class _Registry:
    """Counts what was built, and hands back a distinguishable object."""

    def __init__(self) -> None:
        self.built: list[str] = []

    def _make(self, label: str) -> Any:
        self.built.append(label)
        return object()

    def build_model(self, role: str = "", **kwargs: Any) -> Any:
        return self._make(f"role:{role}")

    def build_model_for_agent(self, agent: str, **kwargs: Any) -> Any:
        return self._make(f"agent:{agent}")


def _container() -> tuple[ServiceContainer, _Registry]:
    container = ServiceContainer(Settings(_env_file=None), mock=True)
    registry = _Registry()
    container._llm_registry = registry  # type: ignore[assignment]
    return container, registry


def _on_new_loop(call: Any) -> Any:
    """Run ``call`` inside a loop of its own, on a thread of its own."""
    result: list[Any] = []

    def _run() -> None:
        loop = asyncio.new_event_loop()
        try:

            async def _go() -> Any:
                return call()

            result.append(loop.run_until_complete(_go()))
        finally:
            loop.close()

    thread = threading.Thread(target=_run)
    thread.start()
    thread.join(10)
    return result[0]


ACCESSORS = ["get_expert_llm", "get_judge_llm", "get_reporter_llm", "get_summarizer_llm"]


class TestOneModelPerLoop:
    @pytest.mark.parametrize("accessor", ACCESSORS)
    def test_two_loops_get_two_clients(self, accessor: str) -> None:
        container, registry = _container()
        call = getattr(container, accessor)

        first = _on_new_loop(call)
        second = _on_new_loop(call)

        assert first is not second
        assert len(registry.built) == 2

    @pytest.mark.parametrize("accessor", ACCESSORS)
    def test_one_loop_gets_the_cached_one(self, accessor: str) -> None:
        container, registry = _container()
        call = getattr(container, accessor)

        both = _on_new_loop(lambda: (call(), call()))

        assert both[0] is both[1]
        assert len(registry.built) == 1

    @pytest.mark.parametrize("accessor", ACCESSORS)
    def test_a_synchronous_caller_has_a_partition_of_its_own(self, accessor: str) -> None:
        """No running loop is its own key: the analyst path builds its model on
        a worker thread and uses it on the shared agent loop."""
        container, registry = _container()
        call = getattr(container, accessor)

        outside = call()

        assert call() is outside
        assert _on_new_loop(call) is not outside
        assert len(registry.built) == 2

    def test_a_per_agent_model_is_keyed_by_loop_and_name(self) -> None:
        container, registry = _container()

        static_one = container.get_agent_llm("static")
        network_one = container.get_agent_llm("network")

        assert static_one is not network_one
        assert container.get_agent_llm("static") is static_one
        assert _on_new_loop(lambda: container.get_agent_llm("static")) is not static_one
        assert registry.built == ["agent:static", "agent:network", "agent:static"]


class _FakeLoop:
    """A stand-in for an event loop: identity, and weak-referenceable."""


class TestWhatRetirementDrops:
    def test_every_model_cache_and_the_shared_pool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.core import container as module

        container, registry = _container()
        container.get_expert_llm()
        container.get_judge_llm()
        container.get_reporter_llm()
        container.get_summarizer_llm()
        container.get_agent_llm("static")
        container._narrative_agent_cache = object()
        container._report_composer_cache = object()

        cleared: list[bool] = []
        monkeypatch.setattr(
            module, "_LIVE_CONTAINERS", module.weakref.WeakSet([container]), raising=False
        )
        monkeypatch.setattr(
            "maljan.llm.openai_provider.clear_shared_httpx_clients",
            lambda: cleared.append(True),
        )

        module._drop_llm_caches_on_retirement(object())

        assert len(container._expert_llm_cache) == 0
        assert len(container._judge_llm_cache) == 0
        assert len(container._reporter_llm_cache) == 0
        assert len(container._summarizer_llm_cache) == 0
        assert len(container._agent_llm_cache) == 0
        assert container._narrative_agent_cache is None
        assert container._report_composer_cache is None
        assert cleared == [True], "the shared httpx pool is what the rebuild was inheriting"

    def test_a_loop_that_is_still_running_keeps_its_own_models(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Retiring one loop must not throw away another loop's valid models.

        The retired loop's pools are unusable and the ``None`` partition is
        the analyst tool loop's, which is the loop being retired. Everything
        else is bound to a loop that is still running.
        """
        from maljan.core import container as module

        container, _registry = _container()
        # Weakly keyed, so the stand-in loops must be objects a weak
        # reference can be taken to.
        retired, other = _FakeLoop(), _FakeLoop()
        container._judge_llm_cache.put(retired, "judge", object())
        container._judge_llm_cache.put(None, "judge", object())
        survivor = object()
        container._judge_llm_cache.put(other, "judge", survivor)

        monkeypatch.setattr(
            module, "_LIVE_CONTAINERS", module.weakref.WeakSet([container]), raising=False
        )
        monkeypatch.setattr("maljan.llm.openai_provider.clear_shared_httpx_clients", lambda: None)

        module._drop_llm_caches_on_retirement(retired)

        assert container._judge_llm_cache.lookup(retired, "judge") is None
        assert container._judge_llm_cache.lookup(None, "judge") is None
        assert container._judge_llm_cache.lookup(other, "judge") is survivor

    def test_the_next_call_rebuilds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.core import container as module

        container, registry = _container()
        before = container.get_judge_llm()

        monkeypatch.setattr(
            module, "_LIVE_CONTAINERS", module.weakref.WeakSet([container]), raising=False
        )
        module._drop_llm_caches_on_retirement(object())

        assert container.get_judge_llm() is not before


class TestTheProviderOwnsItsPool:
    def test_two_models_for_one_endpoint_do_not_share_connections(self) -> None:
        from maljan.llm.openai_provider import OpenAIProvider

        settings = Settings(
            _env_file=None,
            llm={"openai": {"api_key": "sk-test", "base_url": "http://127.0.0.1:8080/v1"}},
        )
        provider = OpenAIProvider(settings)

        first = provider.build_model("m", 0.0)
        second = provider.build_model("m", 0.0)

        assert first.http_async_client is not None
        assert first.http_async_client is not second.http_async_client

    def test_clearing_the_shared_cache_never_raises(self) -> None:
        from maljan.llm.openai_provider import clear_shared_httpx_clients

        clear_shared_httpx_clients()
        clear_shared_httpx_clients()
