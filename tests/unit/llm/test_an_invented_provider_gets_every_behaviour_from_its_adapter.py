"""A provider registered at runtime gets every behaviour by answering the interface.

The adapter below is invented: no shared module knows its name. Each fact the
platform asks of an LLM provider (window probe and declared window, effort,
structured output, error classification, reasoning against the cap, the
hour-long cache write, concurrency, per-agent endpoint, the per-call cap
field, the reasoning passback, the probe's one turn and its answer) is read
from it the way it is read from a shipped adapter.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from maljan.core.model_assignments import ModelAssignment, endpoint_for
from maljan.core.settings_overrides import build_settings
from maljan.llm import registry
from maljan.llm.provider_base import (
    _FACTS,
    LLMProvider,
    ModelListing,
    OneTurnRequest,
    facts_of,
    provider_error_packages,
    provider_names,
    provider_of_model,
    transient_error_packages,
)

ACME = "acme"
ACME_ROOT = "http://acme.local:9000"


class AcmeProvider(LLMProvider):
    name = ACME
    label = "Acme runtime"
    hosted = False
    credential_leaf = ""
    sdk_packages = frozenset({"acme_sdk"})
    llm_types = ("acme-chat",)
    per_call_cap_field = "max_new_tokens"
    supports_agent_base_url = True
    default_endpoint = ACME_ROOT
    effort_setting = "llm.acme.effort"
    concurrency = "serial"
    caches_once_answered = True
    reasoning_passback_keys = ("thoughts",)

    def __init__(self, config: Any) -> None:
        self._config = config

    @classmethod
    def effort_levels(cls, model: str) -> tuple[list[str] | None, list[str], str]:
        return ["gentle", "fierce"], [], "settings"

    @classmethod
    def effort_refusal(cls, effort: str) -> str | None:
        return None if effort in ("gentle", "fierce") else f"acme takes no {effort!r}"

    @classmethod
    def supports_structured_output(cls, settings: Any) -> bool:
        return True

    @classmethod
    def window_probes(cls, endpoint: object, model: str) -> tuple[Any, ...]:
        from maljan.llm import context_window as cw

        return (cw.Ask("GET", f"{endpoint}/window", None, cw.window_from_tgi_info, "acme"),)

    @classmethod
    def declared_window(cls, settings: Any) -> tuple[int, bool]:
        return 12_345, False

    @classmethod
    def reasoning_counts_against_cap(cls, settings: Any) -> bool:
        return True

    @classmethod
    def writes_hour_caches(cls, settings: Any) -> bool:
        return True

    @classmethod
    def model_listing(cls, settings: Any) -> ModelListing:
        return ModelListing(
            url=f"{ACME_ROOT}/catalogue",
            headers={},
            names=lambda payload: list(payload.get("names", [])),
            where=ACME_ROOT,
        )

    @classmethod
    def probed_model(cls, settings: Any, listed: list[str]) -> str:
        return listed[0] if listed else ""

    @classmethod
    def one_turn_request(
        cls, settings: Any, endpoint: str, model: str, effort: str | None = None
    ) -> OneTurnRequest:
        return OneTurnRequest(f"{endpoint}/speak", {}, {"who": model, "effort": effort or ""})

    @classmethod
    def said_something(cls, payload: Any) -> bool:
        return bool(str(payload.get("said") or "").strip())


@pytest.fixture(autouse=True)
def _acme_registered() -> Iterator[None]:
    registry.discover_providers()
    registry.register_provider(ACME)(AcmeProvider)
    try:
        yield
    finally:
        registry._PROVIDER_REGISTRY.pop(ACME, None)
        _FACTS.pop(ACME, None)


def _settings(**core: Any) -> Any:
    return build_settings({"llm.provider": ACME, **core})


class TestSettingsReadTheAdapter:
    def test_it_is_a_choice_and_can_be_selected(self) -> None:
        assert ACME in provider_names()
        assert _settings().llm.provider == ACME

    def test_a_stored_name_registered_only_elsewhere_still_loads(self) -> None:
        """Refused where it is saved, not where settings are read, as a memory backend is."""
        assert build_settings({"llm.provider": "registered-elsewhere"}).llm.provider == (
            "registered-elsewhere"
        )

    def test_an_entry_may_name_its_own_endpoint_and_one_of_its_efforts(self) -> None:
        from maljan.core.config import ModelChoice

        choice = ModelChoice(
            provider=ACME, model="m", base_url="http://elsewhere:1", effort="fierce"
        )
        assert choice.base_url == "http://elsewhere:1"
        with pytest.raises(ValueError, match="acme takes no 'loud'"):
            ModelChoice(provider=ACME, model="m", effort="loud")

    def test_its_endpoint_and_effort_options_are_its_own(self) -> None:
        from maljan.llm.effort import effort_options

        settings = _settings()
        assert endpoint_for(settings, ACME) == ACME_ROOT
        assert endpoint_for(settings, ACME, "http://own:2") == "http://own:2"
        options = effort_options(settings, ACME, "m")
        assert options["takes_effort"] and options["levels"] == ["gentle", "fierce"]


class TestTheModelLayerReadsTheAdapter:
    def test_window(self) -> None:
        from maljan.llm import context_window as cw

        (ask,) = cw.probe_plan(ACME, ACME_ROOT, "m")
        assert ask.url == f"{ACME_ROOT}/window"
        assert cw.declared_window(_settings(), ACME) == (12_345, False)

    def test_errors_are_classified_by_its_sdk(self) -> None:
        from maljan.llm.transient import transient_failure

        assert "acme_sdk" in provider_error_packages()
        assert "acme_sdk" in transient_error_packages()
        error = type("ServiceUnavailable", (Exception,), {"__module__": "acme_sdk.errors"})("busy")
        error.status_code = 503  # type: ignore[attr-defined]
        assert transient_failure(error) == "HTTP 503"

    def test_a_model_it_built_is_recognised(self) -> None:
        from maljan.llm.context_window import output_bound_kwargs
        from maljan.llm.registry import structured_output_supported
        from maljan.reporting.composer import _caches_once_answered

        class _Model:
            _llm_type = "acme-chat"

        model = _Model()
        assert provider_of_model(model) is AcmeProvider
        assert output_bound_kwargs(model, 64) == {"max_new_tokens": 64}
        assert _caches_once_answered(model) is True
        assert structured_output_supported(None, model) is True
        assert structured_output_supported(_settings(), None) is True

    def test_reasoning_cap_cache_and_passback(self) -> None:
        from maljan.agents.base_agent import _passback_keys
        from maljan.core.container import _reporter_reasons
        from maljan.core.spend import hour_cache_models

        settings = _settings(**{"llm.agents": {"judge": {"provider": ACME, "model": "big"}}})
        assert _reporter_reasons(settings, ACME) is True
        assert "big" in hour_cache_models(settings)
        assert "thoughts" in _passback_keys()

    def test_it_is_taken_to_serve_one_request_at_a_time(self) -> None:
        from maljan.pipeline.analyst_mode import _serves_concurrently

        assignment = ModelAssignment("static", ACME, ACME_ROOT, "m")
        concurrent, why = _serves_concurrently(_settings(), assignment, probe=False)
        assert concurrent is False and "Acme runtime" in why


class TestTheProbeAsksTheAdapter:
    @pytest.mark.asyncio
    async def test_the_listing_and_the_turn_are_its_own(self, monkeypatch) -> None:
        from app.services import settings_probes as probes

        spoken: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/catalogue":
                return httpx.Response(200, json={"names": ["tiny"]})
            spoken.append(__import__("json").loads(request.content))
            return httpx.Response(200, json={"said": "hello"})

        real = httpx.AsyncClient

        class _Routed(real):  # type: ignore[misc, valid-type]
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _Routed)
        result = await probes.probe_llm(_settings())
        assert result.ok, result.detail
        assert result.models == ["tiny"]
        assert spoken == [{"who": "tiny", "effort": ""}]
        assert facts_of(ACME) is AcmeProvider
