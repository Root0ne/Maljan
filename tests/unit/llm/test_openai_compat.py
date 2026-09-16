"""A custom base URL is not the same fact as a llama.cpp server.

The provider added ``repeat_penalty``, an ``n_predict`` echo of the output cap
and ``chat_template_kwargs`` to every request whenever ``base_url`` was set.
Those are llama.cpp's fields, not OpenAI's, and the first hosted run — against
``https://integrate.api.nvidia.com/v1`` — died on
``400 Validation: Unsupported parameter(s): n_predict`` before a single analyst
ran.

Which dialect the endpoint speaks is asked (``llm.openai.compat``) rather than
inferred from the presence of a URL, ``auto`` reads the host, and an endpoint
that rejects one of our extras anyway is retried once without them and
remembered.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from openai import BadRequestError

from maljan.core.config import Settings
from maljan.llm.openai_provider import (
    OpenAIProvider,
    forget_standard_only,
    is_local_endpoint,
    unsupported_parameter,
)


@pytest.fixture(autouse=True)
def _forget() -> Any:
    """The self-heal's memory is process-wide; no test may leak into another."""
    forget_standard_only()
    yield
    forget_standard_only()


def _settings(base_url: str | None, compat: str = "auto") -> Settings:
    return Settings(
        _env_file=None,
        llm={
            "openai": {
                "api_key": "sk-test",
                "base_url": base_url,
                "compat": compat,
                "repetition_penalty": 1.15,
                "disable_thinking": True,
            }
        },
    )


def _extras(base_url: str | None, compat: str = "auto") -> dict[str, Any] | None:
    model = OpenAIProvider(_settings(base_url, compat)).build_model("m", 0.0, max_tokens=512)
    return getattr(model, "extra_body", None)


class TestWhichHostsAreLocal:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8080/v1",
            "http://[::1]:8080/v1",
            "http://localhost:8080/v1",
            "http://box.localhost:8080/v1",
            "http://192.168.1.5:8080/v1",
            "http://10.0.0.4:1234/v1",
            "http://172.16.3.9/v1",
            "http://169.254.7.7/v1",
            "http://workstation.local:8080/v1",
        ],
    )
    def test_a_server_on_this_machine_or_network(self, url: str) -> None:
        assert is_local_endpoint(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://integrate.api.nvidia.com/v1",
            "https://api.deepseek.com",
            "https://api.moonshot.cn/v1",
            "https://my-azure.openai.azure.com/",
            "http://8.8.8.8/v1",
        ],
    )
    def test_a_hosted_api(self, url: str) -> None:
        assert is_local_endpoint(url) is False

    def test_no_url_at_all_is_openai_itself(self) -> None:
        assert is_local_endpoint(None) is False
        assert is_local_endpoint("") is False


class TestWhatEachModeSends:
    def test_auto_sends_the_extras_to_a_local_server(self) -> None:
        extras = _extras("http://127.0.0.1:8080/v1")
        assert extras == {
            "repeat_penalty": 1.15,
            "repetition_penalty": 1.15,
            "max_tokens": 512,
            "n_predict": 512,
            "chat_template_kwargs": {"enable_thinking": False},
        }

    def test_auto_sends_none_of_them_to_a_hosted_api(self) -> None:
        assert not _extras("https://integrate.api.nvidia.com/v1")

    def test_llama_cpp_sends_them_to_a_hosted_url_too(self) -> None:
        """An operator tunnelling a local server through a public name."""
        extras = _extras("https://llama.example.com/v1", compat="llama_cpp")
        assert extras is not None
        assert extras["n_predict"] == 512

    def test_standard_withholds_them_from_a_local_server(self) -> None:
        """A local vLLM or an OpenAI-shaped proxy that validates its body."""
        assert not _extras("http://127.0.0.1:8000/v1", compat="standard")

    def test_openai_itself_is_untouched_in_every_mode(self) -> None:
        for compat in ("auto", "llama_cpp", "standard"):
            assert not _extras(None, compat)

    def test_the_output_cap_still_reaches_the_standard_field(self) -> None:
        model = OpenAIProvider(_settings("https://api.deepseek.com")).build_model(
            "m", 0.0, max_tokens=512
        )
        assert model.max_tokens == 512


class TestWhichRejectionIsOurs:
    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("Validation: Unsupported parameter(s): n_predict", "n_predict"),
            ('unknown field "repeat_penalty"', "repeat_penalty"),
            ("extra fields not permitted: chat_template_kwargs", "chat_template_kwargs"),
            ("Unsupported value: 'temperature' does not support 0.0", None),
            ("Invalid request: messages must be a list", None),
            ("", None),
        ],
    )
    def test_only_a_field_we_added(self, message: str, expected: str | None) -> None:
        assert unsupported_parameter(message) == expected


class TestTheSelfHeal:
    @staticmethod
    def _bad_request(message: str) -> BadRequestError:
        response = MagicMock()
        response.status_code = 400
        return BadRequestError(message, response=response, body=None)

    def test_a_400_about_our_extras_retries_without_them(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built: list[dict[str, Any] | None] = []
        answers = [
            self._bad_request("Validation: Unsupported parameter(s): n_predict"),
            "the answer",
        ]

        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")
                self.max_tokens = kwargs.get("max_tokens")
                built.append(self.extra_body)

            def invoke(self, *args: Any, **kwargs: Any) -> Any:
                answer = answers.pop(0)
                if isinstance(answer, Exception):
                    raise answer
                return answer

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                return self.invoke(*args, **kwargs)

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        provider = OpenAIProvider(_settings("https://integrate.api.nvidia.com/v1", "llama_cpp"))
        model = provider.build_model("m", 0.0, max_tokens=512)

        assert model.invoke("hello") == "the answer"
        assert len(built) == 2
        assert built[0] is not None, "the first attempt carried the extras"
        assert not built[1], "the retry carried none of them"

    def test_the_endpoint_is_remembered_so_it_heals_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built: list[dict[str, Any] | None] = []

        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")
                built.append(self.extra_body)

            def invoke(self, *args: Any, **kwargs: Any) -> Any:
                if self.extra_body:
                    raise TestTheSelfHeal._bad_request("Unsupported parameter(s): n_predict")
                return "ok"

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                return self.invoke(*args, **kwargs)

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        provider = OpenAIProvider(_settings("https://hosted.example.com/v1", "llama_cpp"))
        assert provider.build_model("m", 0.0, max_tokens=512).invoke("hi") == "ok"

        built.clear()
        assert provider.build_model("m", 0.0, max_tokens=512).invoke("hi") == "ok"
        assert built == [None] or not built[0], "the second model was built standard from the start"

    def test_a_400_about_something_else_is_raised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")

            def invoke(self, *args: Any, **kwargs: Any) -> Any:
                raise TestTheSelfHeal._bad_request("Unsupported value: 'temperature'")

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                return self.invoke(*args, **kwargs)

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        provider = OpenAIProvider(_settings("http://127.0.0.1:8080/v1"))
        with pytest.raises(BadRequestError):
            provider.build_model("m", 0.0, max_tokens=512).invoke("hi")

    @pytest.mark.asyncio
    async def test_the_async_path_heals_the_same_way(self, monkeypatch: pytest.MonkeyPatch) -> None:
        built: list[dict[str, Any] | None] = []

        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")
                built.append(self.extra_body)

            def invoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                raise AssertionError("the async path must not call invoke")

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:
                if self.extra_body:
                    raise TestTheSelfHeal._bad_request("Unsupported parameter(s): n_predict")
                return "async answer"

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        provider = OpenAIProvider(_settings("https://hosted2.example.com/v1", "llama_cpp"))
        model = provider.build_model("m", 0.0, max_tokens=512)

        assert await model.ainvoke("hello") == "async answer"
        assert not built[1]

    def test_one_cached_model_pays_one_400_and_builds_one_replacement(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Five calls on the model a job caches, not five models.

        The endpoint memory only helps models built afterwards, and the
        container hands out one model per loop for the life of a job. Without a
        memo on the wrapper itself, every call raised the same 400 again and
        built another client that was used once and never closed.
        """
        built: list[dict[str, Any] | None] = []
        rejected: list[str] = []

        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")
                self.http_async_client = kwargs.get("http_async_client")
                built.append(self.extra_body)

            def invoke(self, *args: Any, **kwargs: Any) -> Any:
                if self.extra_body:
                    rejected.append("400")
                    raise TestTheSelfHeal._bad_request("Unsupported parameter(s): n_predict")
                return "ok"

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                return self.invoke(*args, **kwargs)

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        provider = OpenAIProvider(_settings("https://hosted3.example.com/v1", "llama_cpp"))
        model = provider.build_model("m", 0.0, max_tokens=512)

        assert [model.invoke("hi") for _ in range(5)] == ["ok"] * 5
        assert len(rejected) == 1, "the endpoint is asked with the extras exactly once"
        assert len(built) == 2, "one model with the extras, one replacement without"

    def test_the_replacement_inherits_the_pool_rather_than_opening_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pool per heal is the leak the memo exists to stop.

        The endpoint objected to a request field, not to the connection, so
        the rebuilt model is handed the client the original already owns.
        """
        pools: list[Any] = []
        closed: list[str] = []

        class _SyncClient:
            def close(self) -> None:
                closed.append("sync")

        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")
                self.http_async_client = kwargs.get("http_async_client") or object()
                self.root_client = _SyncClient()
                pools.append(self.http_async_client)

            def invoke(self, *args: Any, **kwargs: Any) -> Any:
                if self.extra_body:
                    raise TestTheSelfHeal._bad_request("Unsupported parameter(s): n_predict")
                return "ok"

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                return self.invoke(*args, **kwargs)

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        provider = OpenAIProvider(_settings("https://hosted4.example.com/v1", "llama_cpp"))
        assert provider.build_model("m", 0.0, max_tokens=512).invoke("hi") == "ok"

        assert pools[0] is pools[1], "the replacement was handed the original's pool"
        assert closed == ["sync"], "the client the replacement does not inherit is closed"

    def test_the_container_caches_the_replacement_rather_than_the_model_that_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A heal swaps the cached model, so no later caller starts from it."""
        from maljan.core.container import PerLoopModels, _swap_healed_llm

        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")

            def invoke(self, *args: Any, **kwargs: Any) -> Any:
                if self.extra_body:
                    raise TestTheSelfHeal._bad_request("Unsupported parameter(s): n_predict")
                return "ok"

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                return self.invoke(*args, **kwargs)

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        from maljan.core import container as container_module

        provider = OpenAIProvider(_settings("https://hosted5.example.com/v1", "llama_cpp"))
        model = provider.build_model("m", 0.0, max_tokens=512)

        cache = PerLoopModels()
        cache.put(None, "judge", model)

        class _Holder:
            def __init__(self) -> None:
                import threading

                self._lock = threading.RLock()
                self._expert_llm_cache = cache
                self._judge_llm_cache = cache
                self._reporter_llm_cache = PerLoopModels()
                self._summarizer_llm_cache = PerLoopModels()
                self._agent_llm_cache = PerLoopModels()

        holder = _Holder()
        monkeypatch.setattr(container_module, "_LIVE_CONTAINERS", [holder])
        monkeypatch.setattr(
            "maljan.llm.openai_provider._HEAL_LISTENERS", [_swap_healed_llm], raising=False
        )

        assert model.invoke("hi") == "ok"

        assert cache.lookup(None, "judge") is not model
        assert cache.lookup(None, "judge").invoke("hi") == "ok"

    def test_a_local_server_that_never_complains_keeps_its_extras(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Chat:
            def __init__(self, **kwargs: Any) -> None:
                self.extra_body = kwargs.get("extra_body")

            def invoke(self, *args: Any, **kwargs: Any) -> Any:
                return self.extra_body

            async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
                return self.invoke(*args, **kwargs)

        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Chat)

        provider = OpenAIProvider(_settings("http://127.0.0.1:8080/v1"))
        assert provider.build_model("m", 0.0, max_tokens=512).invoke("hi")["n_predict"] == 512


class TestTheSettingIsOfferedToAnOperator:
    def test_it_is_in_the_catalog_with_its_choices(self) -> None:
        from maljan.core.settings_catalog import core_catalog

        entry = next(f for f in core_catalog() if f.path == "llm.openai.compat")
        assert entry.choices == ["auto", "llama_cpp", "standard"]
        assert entry.default == "auto"
        assert "400" in (entry.description or "")


class TestStructuredOutputIsUnchanged:
    def test_any_custom_base_url_still_has_none(self) -> None:
        from maljan.llm.registry import structured_output_supported

        assert structured_output_supported(_settings("https://integrate.api.nvidia.com/v1")) is (
            False
        )
        assert structured_output_supported(_settings(None)) is True
