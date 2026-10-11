"""The settings probes: every provider answers through its own test.

The model probe lists models, builds the one-turn request and reads its answer
through the selected LLM provider's adapter; a static or sandbox provider is
built from the candidate settings and its own ``probe()`` is asked; a memory
backend's ``readiness()``; a reputation source's ``probe()``.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.services import settings_probes as probes
from maljan.llm.ollama_provider import THINKING_SETTING
from maljan.llm.openai_provider import OpenAIProvider
from maljan.llm.provider_base import facts_of


def _dsn(scheme: str, userinfo: str, rest: str) -> str:
    """Assemble a credentialed URL at runtime so no literal DSN sits in the source
    (secret scanners flag ``scheme://user:pass@host`` even in a masking test)."""
    return f"{scheme}://{userinfo}@{rest}"


def _route(monkeypatch, handler) -> None:
    """Every ``httpx.AsyncClient`` built from here on answers through ``handler``."""
    real = httpx.AsyncClient

    class _Routed(real):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Routed)


def _settings(**core: Any) -> Any:
    """Candidate settings from dotted keys, as a probe of staged values reads them."""
    return probes.candidate_settings({f"core.{k}": v for k, v in core.items()}, {})


def _staged(**core: Any) -> dict[str, Any]:
    return {f"core.{k}": v for k, v in core.items()}


# ── The model probe ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_llm_probe_lists_models_and_completes(monkeypatch):
    def handler(req: httpx.Request):
        if req.url.path.endswith("/models"):
            assert req.headers["authorization"] == "Bearer k"
            return httpx.Response(200, json={"data": [{"id": "qwen"}, {"id": "other"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    _route(monkeypatch, handler)
    r = await probes.probe_llm(
        _settings(
            **{
                "llm.openai.base_url": "http://llm/v1",
                "llm.openai.api_key": "k",
                "llm.openai.expert_model": "qwen",
            }
        )
    )
    assert r.ok and r.models == ["qwen", "other"] and "qwen" in r.detail


@pytest.mark.asyncio
async def test_llm_probe_anthropic_ok(monkeypatch):
    from maljan.llm.context_window import ANTHROPIC_VERSION

    def handler(req: httpx.Request):
        assert req.headers["x-api-key"] == "sk-ant-secret"
        assert req.headers["anthropic-version"] == ANTHROPIC_VERSION
        if req.url.path.endswith("/messages"):
            return httpx.Response(200, json={"content": [{"type": "text", "text": "OK"}]})
        return httpx.Response(
            200, json={"data": [{"id": "claude-sonnet-4-20250514"}, {"id": "claude-haiku"}]}
        )

    _route(monkeypatch, handler)
    r = await probes.probe_llm(
        _settings(
            **{
                "llm.provider": "anthropic",
                "llm.anthropic.api_key": "sk-ant-secret",
                "llm.anthropic.expert_model": "claude-sonnet-4-20250514",
            }
        )
    )
    assert r.ok and r.models == ["claude-sonnet-4-20250514", "claude-haiku"]


@pytest.mark.asyncio
async def test_llm_probe_anthropic_asks_with_the_effort_and_takes_a_thinking_answer(monkeypatch):
    """The turn a job asks: its effort sent, and a model that only thought has answered."""
    sent: list[dict] = []

    def handler(req: httpx.Request):
        if req.url.path.endswith("/messages"):
            sent.append(json.loads(req.content))
            return httpx.Response(
                200,
                json={
                    "content": [{"type": "thinking", "thinking": "", "signature": "EoB" * 20}],
                    "stop_reason": "max_tokens",
                },
            )
        return httpx.Response(200, json={"data": [{"id": "claude-haiku-5-5"}]})

    _route(monkeypatch, handler)
    r = await probes.probe_llm(
        _settings(
            **{
                "llm.provider": "anthropic",
                "llm.anthropic.api_key": "test-anthropic-key",
                "llm.anthropic.expert_model": "claude-haiku-5-5",
                "llm.anthropic.effort": "max",
            }
        )
    )
    assert r.ok
    assert sent and all(body["output_config"] == {"effort": "max"} for body in sent)
    assert all("temperature" not in body for body in sent)


@pytest.mark.asyncio
async def test_llm_probe_ollama_ok(monkeypatch):
    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            return httpx.Response(200, json={"response": "OK"})
        assert req.url.path.endswith("/api/tags")
        return httpx.Response(200, json={"models": [{"name": "qwen3.5:9b"}, {"name": "llama3:8b"}]})

    _route(monkeypatch, handler)
    r = await probes.probe_llm(
        _settings(
            **{
                "llm.provider": "ollama",
                "llm.ollama.base_url": "http://ollama:11434",
                "llm.ollama.expert_model": "qwen3.5:9b",
                "llm.ollama.judge_model": "qwen3.5:9b",
            }
        )
    )
    assert r.ok and "qwen3.5:9b" in r.models


@pytest.mark.asyncio
async def test_llm_probe_ollama_names_a_missing_global_model(monkeypatch):
    _route(monkeypatch, lambda req: httpx.Response(200, json={"models": [{"name": "llama3:8b"}]}))
    r = await probes.probe_llm(
        _settings(
            **{
                "llm.provider": "ollama",
                "llm.ollama.expert_model": "qwen3:8b",
                "llm.ollama.judge_model": "qwen3:8b",
            }
        )
    )
    assert r.ok is False and "missing ['qwen3:8b']" in r.detail


@pytest.mark.asyncio
async def test_llm_probe_gemini_ok(monkeypatch):
    def handler(req: httpx.Request):
        assert req.headers["x-goog-api-key"] == "goog-secret"
        assert "key=" not in str(req.url)
        if req.url.path.endswith(":generateContent"):
            return httpx.Response(
                200, json={"candidates": [{"content": {"parts": [{"text": "OK"}]}}]}
            )
        return httpx.Response(200, json={"models": [{"name": "models/gemini-2.5-pro"}]})

    _route(monkeypatch, handler)
    r = await probes.probe_llm(
        _settings(
            **{
                "llm.provider": "gemini",
                "llm.gemini.api_key": "goog-secret",
                "llm.gemini.expert_model": "gemini-2.5-pro",
            }
        )
    )
    assert r.ok and r.models == ["models/gemini-2.5-pro"]


@pytest.mark.asyncio
async def test_an_unregistered_provider_is_refused_without_raising():
    r = await probes.run_probe("llm", _staged(**{"llm.provider": "bedrock"}), {})
    assert r.ok is False and "llm.provider" in r.detail and "bedrock" not in r.detail


@pytest.mark.asyncio
async def test_llm_probe_anthropic_and_gemini_keys_never_leak_on_failure(monkeypatch):
    _route(monkeypatch, lambda r: httpx.Response(403))
    r1 = await probes.probe_llm(
        _settings(**{"llm.provider": "anthropic", "llm.anthropic.api_key": "sk-ant-super-secret"})
    )
    assert r1.ok is False and "sk-ant-super-secret" not in r1.detail
    r2 = await probes.probe_llm(
        _settings(**{"llm.provider": "gemini", "llm.gemini.api_key": "goog-super-secret"})
    )
    assert r2.ok is False and "goog-super-secret" not in r2.detail


@pytest.mark.asyncio
async def test_run_probe_merges_form_over_stored_over_defaults(monkeypatch):
    seen: dict[str, Any] = {}

    async def fake(settings):
        seen["settings"] = settings
        return probes.ProbeResult(True, 1, "x")

    monkeypatch.setattr(probes, "probe_llm", fake)
    # build_settings is store-only, so an env sibling must not leak into the
    # resolved value; it is set here to prove that.
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    await probes.run_probe(
        "llm",
        {"core.llm.openai.base_url": "http://form/v1", "core.llm.openai.api_key": None},
        {"core.llm.openai.expert_model": "stored-model"},
    )
    settings = seen["settings"]
    assert settings.llm.openai.base_url == "http://form/v1"
    assert settings.llm.openai.api_key is None
    assert settings.llm.openai.expert_model == "stored-model"
    assert settings.llm.provider == "openai"


@pytest.mark.asyncio
async def test_unknown_probe_is_answered_not_raised():
    r = await probes.run_probe("nope", {}, {})
    assert r.ok is False and "unknown probe" in r.detail


def test_the_per_agent_map_is_annotated_with_the_llm_probe():
    from maljan.core.settings_annotations import ANNOTATIONS

    assert ANNOTATIONS["llm.agents"].get("probe") == "llm"


# A per-agent model that does not exist on the server was accepted by the
# probe and only surfaced when the job reached the agent that used it.


def _tags_transport(monkeypatch, names):
    """An Ollama server that lists ``names`` and generates with those only."""

    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            asked = json.loads(req.content or b"{}").get("model", "")
            if asked not in names:
                return httpx.Response(404, json={"error": f"model {asked!r} not found"})
            return httpx.Response(200, json={"response": "OK"})
        assert req.url.path.endswith("/api/tags")
        return httpx.Response(200, json={"models": [{"name": n} for n in names]})

    _route(monkeypatch, handler)


def _ollama(agents: dict[str, Any] | None = None, **more: Any) -> Any:
    core: dict[str, Any] = {
        "llm.provider": "ollama",
        "llm.ollama.base_url": "http://ollama:11434",
        "llm.ollama.expert_model": "qwen3:8b",
        "llm.ollama.judge_model": "qwen3:8b",
        **more,
    }
    if agents is not None:
        core["llm.agents"] = agents
    return _settings(**core)


@pytest.mark.asyncio
async def test_llm_probe_names_a_per_agent_model_the_server_does_not_have(monkeypatch):
    _tags_transport(monkeypatch, ["qwen3:8b"])
    r = await probes.probe_llm(_ollama({"judge": {"provider": "ollama", "model": "qwen3:nope"}}))
    assert r.ok is False
    assert "judge=qwen3:nope" in r.detail


@pytest.mark.asyncio
async def test_llm_probe_asks_every_model_an_agent_falls_back_to(monkeypatch):
    _tags_transport(monkeypatch, ["qwen3:8b", "qwen3:4b"])
    r = await probes.probe_llm(
        _ollama(
            {
                "static": {
                    "provider": "ollama",
                    "model": "qwen3:4b",
                    "fallbacks": [{"provider": "ollama", "model": "gemma3:nope"}],
                }
            }
        )
    )
    assert r.ok is False
    assert "static fallback 1=gemma3:nope" in r.detail


@pytest.mark.asyncio
async def test_llm_probe_accepts_per_agent_models_the_server_has(monkeypatch):
    _tags_transport(monkeypatch, ["qwen3:8b", "qwen3:4b"])
    r = await probes.probe_llm(_ollama({"judge": {"provider": "ollama", "model": "qwen3:4b"}}))
    assert r.ok is True


@pytest.mark.asyncio
async def test_llm_probe_asks_a_per_agent_endpoint_for_its_own_catalogue(monkeypatch):
    """An agent on its own Ollama host is checked there, not against the global one."""
    catalogues = {"ollama": ["qwen3:8b"], "gpu-box": ["qwen3:4b"]}

    def handler(req: httpx.Request):
        names = catalogues[req.url.host]
        if req.url.path.endswith("/api/generate"):
            asked = json.loads(req.content or b"{}").get("model", "")
            if asked not in names:
                return httpx.Response(404, json={"error": f"model {asked!r} not found"})
            return httpx.Response(200, json={"response": "OK"})
        return httpx.Response(200, json={"models": [{"name": n} for n in names]})

    _route(monkeypatch, handler)
    judge = {"provider": "ollama", "model": "qwen3:4b", "base_url": "http://gpu-box:11434"}
    assert (await probes.probe_llm(_ollama({"judge": judge}))).ok is True
    missing = await probes.probe_llm(_ollama({"judge": {**judge, "model": "qwen3:8b"}}))
    assert missing.ok is False
    assert "judge=qwen3:8b @ http://gpu-box:11434" in missing.detail


@pytest.mark.asyncio
async def test_llm_probe_ignores_a_per_agent_entry_on_another_provider(monkeypatch):
    _tags_transport(monkeypatch, ["qwen3:8b"])
    r = await probes.probe_llm(_ollama({"static": {"provider": "openai", "model": "gpt-4o"}}))
    assert r.ok is True


@pytest.mark.asyncio
async def test_the_llm_probe_asks_one_pair_once(monkeypatch):
    """Agents that all name the global model at the global endpoint are one call."""
    asked = []

    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            asked.append(json.loads(req.content or b"{}").get("model", ""))
            return httpx.Response(200, json={"response": "OK"})
        return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

    _route(monkeypatch, handler)
    r = await probes.probe_llm(
        _ollama(
            {
                name: {"provider": "ollama", "model": "qwen3:8b"}
                for name in ("static", "network", "dynamic", "reverser", "triage")
            }
        )
    )
    assert asked == ["qwen3:8b"], "one pair, one call"
    assert r.ok is True
    assert (r.details or {})["completions"] == [
        {
            "endpoint": "http://ollama:11434",
            "model": "qwen3:8b",
            "provider": "ollama",
            "ok": True,
            "detail": "'qwen3:8b' answered",
        }
    ]


class _Clock:
    """Time that only moves when the handler moves it."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def perf_counter(self) -> float:
        return self.now


@pytest.mark.asyncio
async def test_the_llm_probe_stops_at_its_own_budget_and_says_what_it_did_not_try(monkeypatch):
    """The whole probe is bounded, and an unasked pair files nothing."""
    clock = _Clock()

    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            clock.now += probes.COMPLETION_TIMEOUT
            return httpx.Response(200, json={"response": "OK"})
        return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

    _route(monkeypatch, handler)
    settings = _ollama(
        {f"a{n}": {"provider": "ollama", "model": f"qwen3:{n}b"} for n in (1, 2, 3, 4)}
    )
    monkeypatch.setattr(probes, "time", clock)
    r = await probes.probe_llm(settings)
    filed = [pair["model"] for pair in (r.details or {})["completions"]]
    fits = int(probes.LLM_PROBE_BUDGET_SECONDS // probes.COMPLETION_TIMEOUT)
    assert filed == ["qwen3:8b", "qwen3:1b", "qwen3:2b"][:fits]
    assert r.ok is False, "a pair nobody asked is not a pass"
    assert f"not tried within {int(probes.LLM_PROBE_BUDGET_SECONDS)} s" in r.detail
    assert "a3=qwen3:3b" in r.detail and "a4=qwen3:4b" in r.detail
    assert "press Test again" in r.detail


@pytest.mark.asyncio
async def test_the_budget_covers_the_catalogue_listing_in_front_of_the_completions(monkeypatch):
    """The wall an operator waits at starts when the probe does."""
    clock = _Clock()
    listing = 100.0

    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            clock.now += probes.COMPLETION_TIMEOUT
            return httpx.Response(200, json={"response": "OK"})
        clock.now += listing
        return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

    _route(monkeypatch, handler)
    settings = _ollama({f"a{n}": {"provider": "ollama", "model": f"qwen3:{n}b"} for n in (1, 2, 3)})
    monkeypatch.setattr(probes, "time", clock)
    r = await probes.probe_llm(settings)
    fits = int((probes.LLM_PROBE_BUDGET_SECONDS - listing) // probes.COMPLETION_TIMEOUT)
    filed = [pair["model"] for pair in (r.details or {})["completions"]]
    assert filed == ["qwen3:8b", "qwen3:1b", "qwen3:2b"][:fits]
    assert clock.now <= probes.LLM_PROBE_BUDGET_SECONDS, "the probe ran past its documented wall"
    assert "a3=qwen3:3b" in r.detail


@pytest.mark.asyncio
async def test_a_failing_pair_names_its_server_and_nothing_else(monkeypatch):
    """A base URL may carry credentials in front of the host and a path behind it."""
    base = _dsn("http", "opuser:opsecret", "box:8080/v1")

    def handler(req: httpx.Request):
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "qwen"}]})
        return httpx.Response(404, json={"error": "no such model"})

    _route(monkeypatch, handler)
    r = await probes.probe_llm(
        _settings(
            **{
                "llm.openai.base_url": "http://box:8080/v1",
                "llm.openai.api_key": "k",
                "llm.openai.expert_model": "qwen",
                "llm.agents": {"judge": {"provider": "openai", "model": "ghost", "base_url": base}},
            }
        )
    )
    assert r.ok is False
    assert "judge=ghost @ http://box:8080" in r.detail
    assert "opuser" not in r.detail and "opsecret" not in r.detail
    assert "/v1" not in r.detail, "a path says nothing about which server answered"
    filed = {(pair["endpoint"], pair["model"]) for pair in (r.details or {})["completions"]}
    assert (base, "ghost") in filed, "the row is still filed under the address it called"


# The probe asks a local OpenAI-compatible server the same question the agents
# ask it: a reasoning model left thinking spends the probe's eight tokens in
# its own chain of thought and answers with an empty ``content``.

LOCAL_ENDPOINT = "http://127.0.0.1:8080/v1"


def _openai_body(endpoint: str, **openai: Any) -> dict[str, Any]:
    settings = _settings(**{f"llm.openai.{k}": v for k, v in openai.items()})
    return OpenAIProvider.one_turn_request(settings, endpoint, "qwen").body


def test_the_probe_sends_the_thinking_switch_the_agents_send():
    body = _openai_body(LOCAL_ENDPOINT, disable_thinking=True)
    assert body["chat_template_kwargs"]["enable_thinking"] is False


def test_the_thinking_switch_is_absent_unless_it_is_turned_on():
    assert "chat_template_kwargs" not in _openai_body(LOCAL_ENDPOINT, disable_thinking=False)


def test_the_thinking_switch_goes_where_the_agents_would_send_it():
    """The endpoints the agents' provider leaves alone are left alone here too."""
    hosted = _openai_body("https://api.openai.com/v1", disable_thinking=True)
    standard = _openai_body(LOCAL_ENDPOINT, disable_thinking=True, compat="standard")
    forced = _openai_body("https://box.example.com/v1", disable_thinking=True, compat="llama_cpp")
    assert "chat_template_kwargs" not in hosted
    assert "chat_template_kwargs" not in standard
    assert forced["chat_template_kwargs"]["enable_thinking"] is False


@pytest.mark.asyncio
async def test_every_openai_endpoint_the_probe_asks_gets_the_thinking_switch(monkeypatch):
    """A per-agent override is asked at its own endpoint, with the same switch."""
    bodies: dict[str, dict] = {}

    def handler(req: httpx.Request):
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "qwen"}]})
        bodies[str(req.url.host)] = json.loads(req.content or b"{}")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    _route(monkeypatch, handler)
    core = {
        "llm.openai.base_url": LOCAL_ENDPOINT,
        "llm.openai.api_key": "k",
        "llm.openai.expert_model": "qwen",
        "llm.openai.disable_thinking": True,
        "llm.agents": {
            "judge": {
                "provider": "openai",
                "model": "qwen",
                "base_url": "http://192.168.1.9:8080/v1",
            }
        },
    }
    r = await probes.probe_llm(_settings(**core))
    assert r.ok is True
    assert set(bodies) == {"127.0.0.1", "192.168.1.9"}
    for host, body in bodies.items():
        assert body["chat_template_kwargs"] == {"enable_thinking": False}, host

    bodies.clear()
    core["llm.openai.disable_thinking"] = False
    assert (await probes.probe_llm(_settings(**core))).ok is True
    for host, body in bodies.items():
        assert "chat_template_kwargs" not in body, host


def _answer(payload):
    return httpx.Response(200, request=httpx.Request("POST", "http://x"), json=payload)


def test_an_endpoint_that_reasoned_did_answer():
    """An empty ``content`` beside a filled ``reasoning_content`` is an answer."""
    openai = facts_of("openai")
    reasoned = _answer(
        {"choices": [{"message": {"content": "", "reasoning_content": "Thinking Process: ok"}}]}
    )
    older_spelling = _answer({"choices": [{"message": {"content": "", "reasoning": "ok"}}]})
    assert probes._said_something(openai, reasoned) is True
    assert probes._said_something(openai, older_spelling) is True


def test_an_answer_with_nothing_in_it_at_all_is_still_nothing():
    openai = facts_of("openai")
    empty = _answer({"choices": [{"message": {"content": "", "reasoning_content": "  "}}]})
    no_message = _answer({"choices": [{"message": {}}]})
    assert probes._said_something(openai, empty) is False
    assert probes._said_something(openai, no_message) is False


def test_a_reasoning_field_that_is_not_text_said_nothing():
    """A structured ``reasoning`` is not an answer."""
    openai = facts_of("openai")
    structured = _answer(
        {"choices": [{"message": {"content": "", "reasoning": {"content": "", "steps": []}}}]}
    )
    listed = _answer({"choices": [{"message": {"content": "", "reasoning_content": [{}]}}]})
    assert probes._said_something(openai, structured) is False
    assert probes._said_something(openai, listed) is False


def test_a_reasoning_object_beside_real_text_is_still_an_answer():
    spoke = _answer({"choices": [{"message": {"content": "ok", "reasoning": {"steps": ["a"]}}}]})
    assert probes._said_something(facts_of("openai"), spoke) is True


def test_a_body_that_is_not_json_still_said_something():
    raw = httpx.Response(200, request=httpx.Request("POST", "http://x"), content=b"OK")
    assert probes._said_something(facts_of("openai"), raw) is True


# A reasoning model on Ollama fails the gate at the shipped default, and the
# failure names the setting that turns it around.


@pytest.mark.asyncio
async def test_an_ollama_model_that_answered_nothing_names_the_setting(monkeypatch):
    _route(monkeypatch, lambda r: httpx.Response(200, json={"response": ""}))
    ok, said = await probes.complete_one_turn(
        "ollama", endpoint="http://127.0.0.1:11434", model="gemma4:12b"
    )
    assert ok is False
    assert THINKING_SETTING in said
    assert "answered nothing. A reasoning model" in said


@pytest.mark.asyncio
async def test_the_sentence_is_gone_once_the_setting_is_on(monkeypatch):
    _route(monkeypatch, lambda r: httpx.Response(200, json={"response": ""}))
    _ok, said = await probes.complete_one_turn(
        "ollama",
        endpoint="http://127.0.0.1:11434",
        model="gemma4:12b",
        settings=_settings(**{"llm.ollama.disable_thinking": True}),
    )
    assert THINKING_SETTING not in said


@pytest.mark.asyncio
async def test_a_timeout_names_it_too(monkeypatch):
    class _Timeout:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        async def post(self, *_a, **_k):
            raise httpx.TimeoutException("too slow")

    monkeypatch.setattr(probes, "_client", lambda *_a, **_k: _Timeout())
    ok, said = await probes.complete_one_turn(
        "ollama", endpoint="http://127.0.0.1:11434", model="gemma4:12b"
    )
    assert ok is None
    assert THINKING_SETTING in said


@pytest.mark.asyncio
async def test_another_provider_is_not_told_about_an_ollama_setting(monkeypatch):
    _route(
        monkeypatch,
        lambda r: httpx.Response(200, json={"choices": [{"message": {"content": ""}}]}),
    )
    _ok, said = await probes.complete_one_turn(
        "openai", endpoint="http://127.0.0.1:8080/v1", model="qwen"
    )
    assert THINKING_SETTING not in said


@pytest.mark.asyncio
async def test_a_provider_with_no_test_request_is_named():
    ok, said = await probes.complete_one_turn("not-registered", endpoint="x", model="m")
    assert ok is False and "not-registered" in said


# Ollama loads a model at the context size the first request names; a probe
# that asked at the server's default left the model loaded at another size.


def _ollama_generate_bodies(monkeypatch) -> list[dict]:
    bodies: list[dict] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/api/generate"):
            bodies.append(json.loads(req.content))
            return httpx.Response(200, json={"response": "OK"})
        return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

    _route(monkeypatch, handler)
    return bodies


@pytest.mark.asyncio
async def test_the_ollama_probe_loads_the_model_at_the_window_the_job_uses(monkeypatch):
    from maljan.core.config import OllamaConfig

    bodies = _ollama_generate_bodies(monkeypatch)
    result = await probes.run_probe(
        "llm",
        _staged(
            **{
                "llm.provider": "ollama",
                "llm.ollama.expert_model": "qwen3:8b",
                "llm.ollama.judge_model": "qwen3:8b",
            }
        ),
        {},
    )
    assert result.ok, result.detail
    assert bodies, "the probe asked nothing"
    default = OllamaConfig()
    for body in bodies:
        assert body["options"]["num_ctx"] == default.num_ctx
        assert body["keep_alive"] == default.keep_alive


@pytest.mark.asyncio
async def test_the_ollama_probe_follows_a_staged_window_and_keep_alive(monkeypatch):
    bodies = _ollama_generate_bodies(monkeypatch)
    await probes.run_probe(
        "llm",
        _staged(
            **{
                "llm.provider": "ollama",
                "llm.ollama.expert_model": "qwen3:8b",
                "llm.ollama.judge_model": "qwen3:8b",
                "llm.ollama.num_ctx": 16384,
                "llm.ollama.keep_alive": "45m",
            }
        ),
        {"core.llm.ollama.num_ctx": 8192},
    )
    assert bodies
    assert all(body["options"]["num_ctx"] == 16384 for body in bodies)
    assert all(body["keep_alive"] == "45m" for body in bodies)


def test_the_window_is_only_sent_to_ollama():
    """The other providers take no such field; a hosted API refuses unknown ones."""
    settings = _settings(**{"llm.ollama.num_ctx": 16384, "llm.ollama.keep_alive": "45m"})
    for provider, endpoint in (("openai", LOCAL_ENDPOINT), ("anthropic", ""), ("gemini", "")):
        request = facts_of(provider).one_turn_request(settings, endpoint, "m")
        assert request is not None
        assert "num_ctx" not in json.dumps(request.body)
        assert "keep_alive" not in request.body


# ── Providers' own probes ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ghidra_probe_reports_http_error(monkeypatch):
    _route(monkeypatch, lambda r: httpx.Response(401))
    r = await probes.run_probe(
        "ghidra",
        _staged(**{"static.ghidra.url": "http://ghidra:8089", "static.ghidra.auth_token": "t"}),
        {},
    )
    assert r.ok is False and "401" in r.detail


@pytest.mark.asyncio
async def test_ghidra_probe_reads_the_authenticated_schema_and_lists_tools(monkeypatch):
    """A token the server rejects must fail the probe, so the probe reads the
    endpoint that enforces it, and returns the names a job will expose."""
    seen: dict[str, str] = {}

    def handler(r: httpx.Request) -> httpx.Response:
        seen["path"] = r.url.path
        seen["auth"] = r.headers.get("Authorization", "")
        return httpx.Response(
            200, json={"tools": [{"path": "/load_program"}, {"path": "/analyze/function"}]}
        )

    _route(monkeypatch, handler)
    r = await probes.run_probe(
        "ghidra",
        _staged(**{"static.ghidra.url": "http://ghidra:8089/", "static.ghidra.auth_token": "t"}),
        {},
    )
    assert seen == {"path": "/mcp/schema", "auth": "Bearer t"}
    assert r.ok and r.tools == ["load_program", "analyze_function"] and r.detail == "2 tools"


@pytest.mark.asyncio
async def test_a_stored_value_reaches_a_provider_probe(monkeypatch):
    seen: dict[str, str] = {}

    def handler(r: httpx.Request) -> httpx.Response:
        seen["host"] = r.url.host
        return httpx.Response(200)

    _route(monkeypatch, handler)
    r = await probes.run_probe(
        "cape2", {}, {"core.sandbox.cape2.base_url": "http://cape.example:8000"}
    )
    assert r.ok is True and seen["host"] == "cape.example"


@pytest.mark.asyncio
async def test_cape_probe_resolves_from_the_default_settings_with_nothing_staged(monkeypatch):
    from maljan.core.settings_overrides import build_settings

    seen: dict[str, str] = {}

    def handler(r: httpx.Request) -> httpx.Response:
        seen["url"] = str(r.url)
        return httpx.Response(200)

    _route(monkeypatch, handler)
    result = await probes.run_probe("cape2", {}, {})
    assert result.ok is True
    assert seen["url"].startswith(build_settings({}).sandbox.cape2.base_url.rstrip("/"))


@pytest.mark.asyncio
async def test_triage_probe_reports_ok(monkeypatch):
    def handler(req: httpx.Request):
        assert req.url.path.endswith("/resources")
        assert req.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json={})

    _route(monkeypatch, handler)
    r = await probes.run_probe(
        "triage",
        _staged(
            **{
                "sandbox.triage.base_url": "https://tria.ge/api/v0",
                "sandbox.triage.api_token": "tok",
            }
        ),
        {},
    )
    assert r.ok is True


@pytest.mark.asyncio
async def test_triage_probe_reports_401_without_the_token_value(monkeypatch):
    _route(monkeypatch, lambda r: httpx.Response(401))
    r = await probes.run_probe(
        "triage", _staged(**{"sandbox.triage.api_token": "super-secret-triage-token"}), {}
    )
    assert r.ok is False
    assert "401" in r.detail
    assert "super-secret-triage-token" not in r.detail


@pytest.mark.asyncio
async def test_triage_probe_with_a_missing_token_makes_no_request(monkeypatch):
    def must_not_be_called(*_a, **_k):
        raise AssertionError("no HTTP client should be built without a token")

    monkeypatch.setattr(httpx, "AsyncClient", must_not_be_called)
    r = await probes.run_probe("triage", _staged(**{"sandbox.triage.api_token": ""}), {})
    assert r.ok is False
    assert "api_token" in r.detail


@pytest.mark.asyncio
async def test_a_reputation_source_reads_its_own_key_and_never_echoes_it(monkeypatch):
    seen: dict[str, str] = {}

    def handler(req: httpx.Request):
        seen["key"] = req.headers.get("x-apikey", "")
        return httpx.Response(500)

    _route(monkeypatch, handler)
    r = await probes.run_probe("virustotal", {"api.virustotal_api_key": "super-secret-value"}, {})
    assert seen["key"] == "super-secret-value"
    assert r.ok is False and "super-secret-value" not in r.detail


@pytest.mark.asyncio
async def test_a_reputation_probe_timeout_is_reported_not_raised(monkeypatch):
    def handler(_r):
        raise httpx.ReadTimeout("slow")

    _route(monkeypatch, handler)
    r = await probes.run_probe("abuseipdb", {"api.abuseipdb_api_key": "k"}, {})
    assert r.ok is False and "timeout" in r.detail.lower()


@pytest.mark.asyncio
async def test_a_memory_backend_probe_asks_the_store_it_builds_and_closes_it(monkeypatch):
    import maljan.memory.store_factory as factory

    built: list[Any] = []

    class _Store:
        closed = False

        def readiness(self) -> str:
            return "ready; collection 'c' exists"

        def close(self) -> None:
            self.closed = True

    def build(memory):
        assert memory.backend == "qdrant"
        built.append(_Store())
        return built[-1]

    monkeypatch.setattr(factory, "build_memory_store", build)
    r = await probes.run_probe("qdrant", _staged(**{"memory.qdrant.collection": "c"}), {})
    assert r.ok and r.detail == "ready; collection 'c' exists"
    assert built and built[0].closed


@pytest.mark.asyncio
async def test_a_memory_backend_that_cannot_answer_is_reported_redacted(monkeypatch):
    import maljan.memory.store_factory as factory
    from maljan.core.exceptions import MemoryStoreError

    class _Store:
        def readiness(self) -> str:
            raise MemoryStoreError(f"did not answer at {_dsn('http', 'u:hunter2', 'q:6333')}")

        def close(self) -> None:
            return None

    monkeypatch.setattr(factory, "build_memory_store", lambda memory: _Store())
    r = await probes.run_probe("qdrant", {}, {})
    assert r.ok is False and "hunter2" not in r.detail


@pytest.mark.asyncio
async def test_redis_probe_pings(monkeypatch):
    class FakeRedis:
        async def ping(self):
            return True

        async def aclose(self):
            return None

    class FakeRedisFactory:
        @staticmethod
        def from_url(*args, **kwargs):
            return FakeRedis()

    monkeypatch.setattr(probes, "Redis", FakeRedisFactory)
    r = await probes.probe_redis({"url": "redis://fake:6379/0"})
    assert r.ok is True and "PONG" in r.detail


@pytest.mark.asyncio
async def test_redis_probe_masks_credentials_in_url_on_failure(monkeypatch):
    class FailingRedis:
        @staticmethod
        def from_url(url, **kwargs):
            raise ConnectionError(
                f"could not connect to {_dsn('redis', 'user:hunter2', 'bad-host:6379/0')}"
            )

    monkeypatch.setattr(probes, "Redis", FailingRedis)
    r = await probes.probe_redis({"url": _dsn("redis", "user:hunter2", "bad-host:6379/0")})
    assert r.ok is False
    assert "hunter2" not in r.detail
    assert "user:hunter2@" not in r.detail
    assert "***@bad-host" in r.detail


@pytest.mark.parametrize(
    "raw, leaked",
    [
        (_dsn("redis", ":onlypass", "bad-host:6379/0"), "onlypass"),
        (_dsn("redis", "user:p@ss", "bad-host:6379/0"), "ss@"),
        (_dsn("redis", "user:pa:ss", "bad-host:6379/0"), "pa:ss"),
    ],
)
def test_redact_url_handles_empty_user_and_at_in_password(raw, leaked):
    out = probes.redact_url(f"could not connect to {raw}")
    assert leaked not in out
    assert "***@bad-host:6379/0" in out


def test_redact_url_leaves_credential_free_urls_alone():
    text = "could not connect to redis://bad-host:6379/0 (mail x@y.z)"
    assert probes.redact_url(text) == text


# r2: the provider finds its binary as a job does, then holds a handshake.


def _r2mcp_is_found_where_configured(monkeypatch) -> None:
    from maljan.providers.static import r2

    monkeypatch.setattr(
        r2, "resolve_r2_binary", lambda configured, env=None: r2.R2Binary(configured, ())
    )


@pytest.mark.asyncio
async def test_r2_probe_reports_a_missing_binary_by_name():
    r = await probes.run_probe(
        "r2", _staged(**{"static.r2.binary_path": "definitely-not-a-real-r2mcp-binary-xyz"}), {}
    )
    assert r.ok is False
    assert "definitely-not-a-real-r2mcp-binary-xyz" in r.detail
    assert "looked in: PATH" in r.detail, "the test says where it looked, as a job does"


@pytest.mark.asyncio
async def test_r2_probe_reports_a_timeout_and_kills_the_handshake(monkeypatch):
    import asyncio

    from maljan.providers import server_probe, servers

    closed: list[bool] = []

    class _HangingHandle:
        def __init__(self, name, config):
            self.name = name
            self.config = config

        async def aopen(self, job_id, **kw):
            await asyncio.sleep(100)

        async def aclose(self):
            closed.append(True)

    from maljan.core.settings_overrides import build_settings
    from maljan.providers.static.r2 import R2StaticProvider

    provider = R2StaticProvider.from_settings(build_settings({}))
    monkeypatch.setattr(servers, "ServerHandle", _HangingHandle)
    monkeypatch.setattr(server_probe, "PROBE_BUDGET_SECONDS", 0.05)
    _r2mcp_is_found_where_configured(monkeypatch)
    r = await provider.probe()
    assert r.ok is False
    assert "no MCP handshake" in r.detail
    assert closed == [True], "the hung handshake must be closed, not left running"


@pytest.mark.asyncio
async def test_r2_probe_reports_the_tool_count_on_success(monkeypatch):
    from maljan.providers import servers

    class _Handle:
        def __init__(self, name, config):
            self.name = name
            self.config = config

        async def aopen(self, job_id, **kw):
            return None

        async def aclose(self):
            return None

        def all_tool_names(self):
            return ["open_file", "analyze"]

    from maljan.providers.static.r2 import R2StaticProvider

    provider = R2StaticProvider.from_settings(_settings(**{"static.r2.binary_path": "r2mcp"}))
    monkeypatch.setattr(servers, "ServerHandle", _Handle)
    _r2mcp_is_found_where_configured(monkeypatch)
    r = probes._from_provider(await provider.probe(), 0.0)
    assert r.ok is True
    assert "2 tools offered by 'r2mcp'" in r.detail
    assert r.tools == ["open_file", "analyze"]


@pytest.mark.asyncio
async def test_probe_mcp_closes_a_real_handle_that_hangs_mid_handshake(monkeypatch):
    """End-to-end through the real ``ServerHandle``: a toolkit whose
    ``initialize`` never returns is torn down when the probe's budget expires."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    cleaned: list[MagicMock] = []

    def hanging_factory(*args, **kwargs):
        instance = MagicMock()

        async def hang() -> None:
            await asyncio.sleep(100)

        instance.initialize = hang
        instance.get_tools = MagicMock(return_value=[])
        instance.cleanup = AsyncMock(return_value=None)
        cleaned.append(instance)
        return instance

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", hanging_factory)
    monkeypatch.setattr(probes, "PROBE_BUDGET_SECONDS", 0.05)
    result = await probes.probe_mcp({"name": "x", "entry": {"enabled": True, "command": "mcp"}})
    assert result.ok is False
    assert "no MCP handshake" in result.detail
    cleaned[0].cleanup.assert_called_once()


# The generic REST sandbox: the provider is built from the candidate settings,
# so a staged auth header or mapping edit is what "Test" exercises.


def _rest(**rest: Any) -> dict[str, Any]:
    return _staged(**{f"sandbox.rest.{k}": v for k, v in rest.items()})


@pytest.mark.asyncio
async def test_rest_probe_reports_ok_on_200_and_carries_the_staged_auth(monkeypatch):
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("x-api-key")
        return httpx.Response(200, json={})

    _route(monkeypatch, handler)
    r = await probes.run_probe(
        "rest",
        _rest(
            **{
                "base_url": "https://xyz.example/api",
                "auth.header": "X-API-Key",
                "auth.scheme": "",
                "auth.token": "s3cr3t",
            }
        ),
        {},
    )
    assert r.ok is True
    assert seen["path"] == "/api/samples/probe"
    assert seen["auth"] == "s3cr3t"  # empty scheme: the raw token, unprefixed


@pytest.mark.asyncio
async def test_rest_probe_reports_ok_on_a_404_for_the_fake_task(monkeypatch):
    _route(monkeypatch, lambda r: httpx.Response(404))
    r = await probes.run_probe("rest", _rest(base_url="https://xyz.example/api"), {})
    assert r.ok is True
    assert r.detail == "reachable, status endpoint answered 404 for a fake task"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_rest_probe_reports_the_credential_was_refused(monkeypatch, status):
    _route(monkeypatch, lambda r: httpx.Response(status))
    r = await probes.run_probe(
        "rest", _rest(**{"base_url": "https://xyz.example/api", "auth.token": "s3cr3t-token"}), {}
    )
    assert r.ok is False
    assert str(status) in r.detail
    assert "s3cr3t-token" not in r.detail


@pytest.mark.asyncio
async def test_rest_probe_reports_a_connection_error_legibly(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    _route(monkeypatch, handler)
    r = await probes.run_probe("rest", _rest(base_url="https://xyz.example/api"), {})
    assert r.ok is False
    assert "ConnectError" in r.detail


@pytest.mark.asyncio
async def test_rest_probe_reports_a_bad_mapping_path_naming_the_channel():
    r = await probes.run_probe(
        "rest", _rest(**{"base_url": "https://xyz.example/api", "mapping.dns": "$[["}), {}
    )
    assert r.ok is False
    assert "dns" in r.detail


@pytest.mark.asyncio
async def test_rest_probe_notes_tls_verification_is_off(monkeypatch):
    _route(monkeypatch, lambda r: httpx.Response(200))
    r = await probes.run_probe(
        "rest", _rest(base_url="https://xyz.example/api", verify_tls=False), {}
    )
    assert r.ok is True
    assert "TLS verification is off" in r.detail


@pytest.mark.asyncio
async def test_rest_probe_never_puts_the_token_in_the_url_or_detail(monkeypatch):
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200)

    _route(monkeypatch, handler)
    r = await probes.run_probe(
        "rest",
        _rest(**{"base_url": "https://xyz.example/api", "auth.token": "super-secret-rest-token"}),
        {},
    )
    assert "super-secret-rest-token" not in r.detail
    assert "super-secret-rest-token" not in str(seen["url"])


@pytest.mark.asyncio
async def test_a_provider_that_fails_while_it_is_built_is_reported_without_its_credentials(
    monkeypatch,
):
    """A failure no probe expected still reaches the operator with any URL's credentials cut."""
    from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

    secret_url = _dsn("http", "user:hunter2", "cape.example:8000")

    def broken(cls, cfg):
        raise RuntimeError(f"could not prepare {secret_url}")

    monkeypatch.setattr(CAPE2SandboxProvider, "from_settings", classmethod(broken))
    r = await probes.run_probe("cape2", {}, {})
    assert r.ok is False
    assert "hunter2" not in r.detail and "RuntimeError" in r.detail
