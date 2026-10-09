"""``llm.anthropic.base_url`` sends every Anthropic request to the address it names.

Unset — the default — nothing changes: a job's calls, the Models API question
and the settings probe all go to the Anthropic API, and a probe row is filed
under the vendor's name as before. Set, the same three go to the address it
names (a proxy, or the loopback stub a rehearsal runs against), and a probe row
is filed under that address, so the gate looks up the row the probe wrote.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from maljan.core.model_assignments import endpoint_for, endpoint_where
from maljan.core.settings_overrides import build_settings
from maljan.llm import context_window as cw
from maljan.llm import model_capabilities, model_output_limits
from maljan.llm.anthropic_provider import AnthropicProvider

MODEL = "claude-haiku-5-5"
STUB = "http://127.0.0.1:8765"


@pytest.fixture(autouse=True)
def _fresh() -> Any:
    cw.forget_learned_windows()
    model_output_limits.forget_learned()
    model_capabilities.forget_capabilities()
    yield
    cw.forget_learned_windows()
    model_output_limits.forget_learned()
    model_capabilities.forget_capabilities()


def _settings(**anthropic: Any) -> Any:
    return build_settings(
        {
            "llm.provider": "anthropic",
            "llm.anthropic.api_key": "test-anthropic-key",
            "llm.anthropic.expert_model": MODEL,
            "llm.anthropic.judge_model": MODEL,
            **{f"llm.anthropic.{key}": value for key, value in anthropic.items()},
        }
    )


class TestUnset:
    def test_is_the_default(self) -> None:
        assert _settings().llm.anthropic.base_url is None

    def test_files_a_probe_under_the_vendor_s_name(self) -> None:
        assert endpoint_for(_settings(), "anthropic") == "the Anthropic API"
        assert endpoint_where("anthropic") == "the Anthropic API"

    def test_asks_the_models_api_at_the_vendor(self) -> None:
        (ask,) = cw.probe_plan("anthropic", "the Anthropic API", MODEL)
        assert ask.url == f"https://api.anthropic.com/v1/models/{MODEL}"

    def test_builds_a_model_with_no_address_of_its_own(self) -> None:
        built = AnthropicProvider(_settings()).build_model(MODEL, 0.1)
        assert built.anthropic_api_url != STUB


class TestSet:
    def test_files_a_probe_under_the_address(self) -> None:
        settings = _settings(base_url=STUB + "/")
        assert endpoint_for(settings, "anthropic") == STUB
        assert endpoint_where("anthropic", anthropic_base_url=STUB) == STUB

    def test_asks_the_models_api_at_the_address(self) -> None:
        (ask,) = cw.probe_plan("anthropic", STUB, MODEL)
        assert ask.url == f"{STUB}/v1/models/{MODEL}"

    def test_the_window_probe_reaches_the_address(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []
        real = httpx.Client

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json={"type": "model", "max_input_tokens": 200_000})

        monkeypatch.setattr(
            httpx, "Client", lambda **_kw: real(transport=httpx.MockTransport(handler))
        )
        fact = cw.window_for_settings(_settings(base_url=STUB), ["static"])
        assert fact.tokens == 200_000
        assert seen == [f"{STUB}/v1/models/{MODEL}"]

    def test_builds_a_model_that_sends_to_the_address(self) -> None:
        built = AnthropicProvider(_settings(base_url=STUB)).build_model(MODEL, 0.1)
        assert built.anthropic_api_url == STUB

    def test_a_blank_address_is_none(self) -> None:
        assert _settings(base_url="  ").llm.anthropic.base_url is None

    def test_the_address_is_stored_as_the_client_will_use_it(self) -> None:
        assert _settings(base_url="HTTP://127.0.0.1:8765/").llm.anthropic.base_url == STUB
        built = AnthropicProvider(_settings(base_url=STUB + "/")).build_model(MODEL, 0.1)
        assert built.anthropic_api_url == STUB


class TestARefusedAddress:
    @pytest.mark.parametrize(
        ("value", "said"),
        [
            ("proxy.local:8080", "http:// or https://"),
            ("ftp://proxy.local", "http:// or https://"),
            ("https://", "host"),
            ("http://proxy.example.org", "https"),
            ("http://192.168.1.5:8765", "https"),
            ("http://172.32.0.1:8765", "https"),
            ("http://172.16.0.1:8765", "https"),
            ("https://user:pw@proxy.example.org", "user name"),
            ("https://proxy.example.org?x=1", "query"),
            ("https://proxy.example.org#x", "fragment"),
            ("https://proxy.example.org/v1", "/v1"),
            ("http://127.0.0.1:8765/v1/", "/v1"),
        ],
    )
    def test_is_refused_with_the_reason(self, value: str, said: str) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match=said.replace("?", r"\?")):
            _settings(base_url=value)

    @pytest.mark.parametrize(
        "value",
        [
            "https://proxy.example.org",
            "https://proxy.example.org/anthropic",
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://[::1]:8765",
            "http://host.docker.internal:8765",
            "http://172.17.0.1:8765",
            "http://172.31.255.1:8765",
        ],
    )
    def test_https_or_a_loopback_address_is_taken(self, value: str) -> None:
        assert _settings(base_url=value).llm.anthropic.base_url == value

    def test_the_probe_asks_the_address_the_client_uses(self) -> None:
        from app.services.settings_probes import _completion_request

        settings = _settings(base_url="https://proxy.example.org/anthropic/")
        where = endpoint_for(settings, "anthropic")
        url, _headers, _body = _completion_request("anthropic", where, MODEL, "k")
        built = AnthropicProvider(settings).build_model(MODEL, 0.1)
        assert url == f"{built.anthropic_api_url}/v1/messages"


class TestTheSettingsProbe:
    def test_asks_the_vendor_when_unset(self) -> None:
        from app.services.settings_probes import _completion_request

        url, _headers, _body = _completion_request(
            "anthropic", "the Anthropic API", MODEL, "test-anthropic-key"
        )
        assert url == "https://api.anthropic.com/v1/messages"

    def test_asks_the_address_when_set(self) -> None:
        from app.services.settings_probes import _completion_request

        url, _headers, _body = _completion_request("anthropic", STUB, MODEL, "test-anthropic-key")
        assert url == f"{STUB}/v1/messages"

    def test_reads_the_setting(self) -> None:
        from app.services.settings_probes import _INPUTS

        assert _INPUTS["llm"]["core.llm.anthropic.base_url"] == "anthropic_base_url"
