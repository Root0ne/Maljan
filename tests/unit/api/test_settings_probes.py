from __future__ import annotations

import json

import httpx
import pytest

from app.services import settings_probes as probes


def _dsn(scheme: str, userinfo: str, rest: str) -> str:
    """Assemble a credentialed URL at runtime so no literal DSN sits in the source
    (secret scanners flag ``scheme://user:pass@host`` even in a masking test)."""
    return f"{scheme}://{userinfo}@{rest}"


def transport(handler):
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_llm_probe_lists_models_and_completes(monkeypatch):
    def handler(req: httpx.Request):
        if req.url.path.endswith("/models"):
            assert req.headers["authorization"] == "Bearer k"
            return httpx.Response(200, json={"data": [{"id": "qwen"}, {"id": "other"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_llm(
        {"base_url": "http://llm/v1", "api_key": "k", "expert_model": "qwen"}
    )
    assert r.ok and r.models == ["qwen", "other"] and "qwen" in r.detail


@pytest.mark.asyncio
async def test_ghidra_probe_reports_http_error(monkeypatch):
    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(
            transport=transport(lambda r: httpx.Response(401)), timeout=10
        ),
    )
    r = await probes.probe_ghidra({"url": "http://ghidra:8089", "auth_token": "t"})
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
            200,
            json={"tools": [{"path": "/load_program"}, {"path": "/analyze/function"}]},
        )

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_ghidra({"url": "http://ghidra:8089/", "auth_token": "t"})
    assert seen == {"path": "/mcp/schema", "auth": "Bearer t"}
    assert r.ok and r.tools == ["load_program", "analyze_function"] and r.detail == "2 tools"


@pytest.mark.asyncio
async def test_timeout_is_reported_not_raised(monkeypatch):
    def handler(_r):
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_qdrant({"url": "http://q:6333", "collection": "c"})
    assert r.ok is False and "timeout" in r.detail.lower()


@pytest.mark.asyncio
async def test_run_probe_merges_form_over_stored_over_defaults(monkeypatch):
    seen = {}

    async def fake(values):
        seen.update(values)
        return probes.ProbeResult(True, 1, "x")

    monkeypatch.setitem(probes.PROBES, "llm", fake)
    # Task 3: build_settings is store-only, so an env sibling must not leak
    # into the resolved value -- it is set here specifically to prove that.
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    await probes.run_probe(
        "llm",
        {"core.llm.openai.base_url": "http://form/v1", "core.llm.openai.api_key": None},
        {"core.llm.openai.expert_model": "stored-model"},
    )
    # form beats stored beats the model default, per field, for the OpenAI slot...
    assert seen["base_url"] == "http://form/v1"
    assert seen["api_key"] is None
    assert seen["expert_model"] == "stored-model"
    assert seen["provider"] == "openai"
    # ...and every other provider's fields are still resolved (candidate > stored > default),
    # so _INPUTS["llm"] covers all four providers regardless of which one is active.
    assert {
        "judge_model",
        "anthropic_api_key",
        "anthropic_expert_model",
        "anthropic_judge_model",
        "ollama_base_url",
        "ollama_expert_model",
        "ollama_judge_model",
        "gemini_api_key",
        "gemini_expert_model",
        "gemini_judge_model",
    } <= seen.keys()


@pytest.mark.asyncio
async def test_unknown_probe():
    with pytest.raises(KeyError):
        await probes.run_probe("nope", {}, {})


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
async def test_probe_results_never_leak_secret_values(monkeypatch):
    def handler(req: httpx.Request):
        return httpx.Response(500)

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_virustotal({"api_key": "super-secret-value"})
    assert "super-secret-value" not in r.detail


@pytest.mark.asyncio
async def test_llm_probe_anthropic_ok(monkeypatch):
    def handler(req: httpx.Request):
        assert req.headers["x-api-key"] == "sk-ant-secret"
        assert req.headers["anthropic-version"] == probes.ANTHROPIC_VERSION
        if req.url.path.endswith("/messages"):
            return httpx.Response(200, json={"content": [{"type": "text", "text": "OK"}]})
        return httpx.Response(
            200, json={"data": [{"id": "claude-sonnet-4-20250514"}, {"id": "claude-haiku"}]}
        )

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_llm(
        {
            "provider": "anthropic",
            "anthropic_api_key": "sk-ant-secret",
            "anthropic_expert_model": "claude-sonnet-4-20250514",
        }
    )
    assert r.ok and r.models == ["claude-sonnet-4-20250514", "claude-haiku"]


@pytest.mark.asyncio
async def test_llm_probe_ollama_ok(monkeypatch):
    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            return httpx.Response(200, json={"response": "OK"})
        assert req.url.path.endswith("/api/tags")
        return httpx.Response(200, json={"models": [{"name": "qwen3.5:9b"}, {"name": "llama3:8b"}]})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_llm(
        {
            "provider": "ollama",
            "ollama_base_url": "http://ollama:11434",
            "ollama_expert_model": "qwen3.5:9b",
            "ollama_judge_model": "qwen3.5:9b",
        }
    )
    assert r.ok and "qwen3.5:9b" in r.models


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

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_llm(
        {
            "provider": "gemini",
            "gemini_api_key": "goog-secret",
            "gemini_expert_model": "gemini-2.5-pro",
        }
    )
    assert r.ok and r.models == ["models/gemini-2.5-pro"]


@pytest.mark.asyncio
async def test_llm_probe_unknown_provider_fails_without_raising():
    r = await probes.probe_llm({"provider": "bedrock"})
    assert r.ok is False and "bedrock" in r.detail


@pytest.mark.asyncio
async def test_llm_probe_anthropic_and_gemini_keys_never_leak_on_failure(monkeypatch):
    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(
            transport=transport(lambda r: httpx.Response(403)), timeout=10
        ),
    )
    r1 = await probes.probe_llm(
        {"provider": "anthropic", "anthropic_api_key": "sk-ant-super-secret"}
    )
    assert r1.ok is False and "sk-ant-super-secret" not in r1.detail

    r2 = await probes.probe_llm({"provider": "gemini", "gemini_api_key": "goog-super-secret"})
    assert r2.ok is False and "goog-super-secret" not in r2.detail


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


@pytest.mark.asyncio
async def test_qdrant_probe_sends_the_api_key_header_when_set(monkeypatch):
    def handler(req: httpx.Request):
        assert req.headers.get("api-key") == "k"
        return httpx.Response(200, json={})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_qdrant({"url": "http://q:6333", "collection": "c", "api_key": "k"})
    assert r.ok


@pytest.mark.asyncio
async def test_qdrant_probe_omits_the_header_when_no_api_key(monkeypatch):
    def handler(req: httpx.Request):
        assert "api-key" not in req.headers
        return httpx.Response(200, json={})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_qdrant({"url": "http://q:6333", "collection": "c"})
    assert r.ok


def test_the_cape_probe_is_registered_under_both_names():
    assert probes.PROBES["cape2"] is probes.probe_cape2
    assert probes.PROBES["cape"] is probes.probe_cape2


@pytest.mark.asyncio
async def test_triage_probe_reports_ok(monkeypatch):
    def handler(req: httpx.Request):
        assert req.url.path.endswith("/resources")
        assert req.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json={})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_triage({"base_url": "https://tria.ge/api/v0", "api_token": "tok"})
    assert r.ok is True


@pytest.mark.asyncio
async def test_triage_probe_reports_401_without_the_token_value(monkeypatch):
    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(
            transport=transport(lambda r: httpx.Response(401)), timeout=10
        ),
    )
    r = await probes.probe_triage(
        {"base_url": "https://tria.ge/api/v0", "api_token": "super-secret-triage-token"}
    )
    assert r.ok is False
    assert "401" in r.detail
    assert "super-secret-triage-token" not in r.detail


@pytest.mark.asyncio
async def test_triage_probe_with_a_missing_token_makes_no_request(monkeypatch):
    def must_not_be_called():
        raise AssertionError("no HTTP client should be built without a token")

    monkeypatch.setattr(probes, "_client", must_not_be_called)
    r = await probes.probe_triage({"base_url": "https://tria.ge/api/v0", "api_token": ""})
    assert r.ok is False
    assert "no API token configured" in r.detail


def test_probe_inputs_name_only_existing_settings_keys():
    from app.services.settings_catalog_api import catalog_index

    index = catalog_index()
    for name, inputs in probes._INPUTS.items():
        for key in inputs:
            assert key in index, f"probe {name!r} reads unknown setting {key}"


@pytest.mark.asyncio
async def test_ghidra_probe_reads_the_static_block(monkeypatch):
    seen: dict[str, object] = {}

    async def fake(v):
        seen.update(v)
        return probes.ProbeResult(True, 1, "HTTP 200")

    monkeypatch.setitem(probes.PROBES, "ghidra", fake)
    await probes.run_probe("ghidra", {"core.static.ghidra.url": "http://ghidra.example:8089"}, {})
    assert seen["url"] == "http://ghidra.example:8089"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["cape2", "cape"])
async def test_cape_probe_resolves_from_the_live_settings_object_with_nothing_staged(
    monkeypatch, name
):
    """Regression: with no candidate value and no stored override, every
    ``_INPUTS[name]`` key is resolved by walking attributes off the
    default-only ``Settings`` object ``run_probe`` builds via
    ``build_settings`` (its fallback branch, exercised by neither of the two
    tests above). A flat ``cape2_base_url``/``cape2_api_token`` here raised
    ``AttributeError`` against the nested ``SandboxConfig.cape2`` block the
    provider rename introduced -- the actual failure mode behind the
    settings UI's "Test CAPE connection" button returning a 500.

    Compared against ``build_settings({})`` rather than bare ``Settings()``
    (Task 3: ``run_probe`` is store-only and never reads the environment;
    comparing against the environment-reading constructor here would drift
    on any box with a real ``.env``).
    """
    from maljan.core.settings_overrides import build_settings

    seen: dict[str, object] = {}

    async def fake(v):
        seen.update(v)
        return probes.ProbeResult(True, 1, "HTTP 200")

    monkeypatch.setitem(probes.PROBES, name, fake)
    result = await probes.run_probe(name, {}, {})

    assert result.ok is True
    defaults = build_settings({})
    assert seen["base_url"] == defaults.sandbox.cape2.base_url
    assert isinstance(seen["api_token"], str)


@pytest.mark.asyncio
async def test_r2_probe_reports_a_missing_binary_by_name():
    r = await probes.probe_r2({"binary_path": "definitely-not-a-real-r2mcp-binary-xyz"})
    assert r.ok is False
    assert "definitely-not-a-real-r2mcp-binary-xyz" in r.detail


@pytest.mark.asyncio
async def test_r2_probe_reports_a_timeout_and_kills_the_handshake(monkeypatch):
    import asyncio

    closed: list[bool] = []

    class _HangingHandle:
        def __init__(self, name, config):
            self.name = name
            self.config = config

        async def aopen(self, job_id, **kw):
            await asyncio.sleep(100)

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(probes, "ServerHandle", _HangingHandle)
    monkeypatch.setattr(probes, "PROBE_BUDGET_SECONDS", 0.05)
    r = await probes.probe_r2({"binary_path": "r2mcp"})
    assert r.ok is False
    assert "no MCP handshake" in r.detail
    assert closed == [True], "the hung handshake must be closed, not left running"


@pytest.mark.asyncio
async def test_r2_probe_reports_the_tool_count_on_success(monkeypatch):
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

    monkeypatch.setattr(probes, "ServerHandle", _Handle)
    r = await probes.probe_r2({"binary_path": "r2mcp"})
    assert r.ok is True
    assert "2 tools offered by 'r2mcp'" in r.detail
    assert r.tools == ["open_file", "analyze"]


def test_the_r2_probe_is_registered():
    assert probes.PROBES["r2"] is probes.probe_r2
    assert probes._INPUTS["r2"] == {"core.static.r2.binary_path": "binary_path"}


@pytest.mark.asyncio
async def test_r2_probe_reads_the_static_block(monkeypatch):
    seen: dict[str, object] = {}

    async def fake(v):
        seen.update(v)
        return probes.ProbeResult(True, 1, "32 tools")

    monkeypatch.setitem(probes.PROBES, "r2", fake)
    await probes.run_probe("r2", {"core.static.r2.binary_path": "/opt/r2/bin/r2mcp"}, {})
    assert seen["binary_path"] == "/opt/r2/bin/r2mcp"


@pytest.mark.asyncio
async def test_probe_mcp_closes_a_real_handle_that_hangs_mid_handshake(monkeypatch):
    """End-to-end through the real ``ServerHandle`` — not the fake used by
    ``test_mcp_probe.py`` — a toolkit whose ``initialize`` never returns must
    still be torn down when the probe's budget expires, and the probe must
    report the timeout rather than hanging itself."""
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


def _fake_rest_async_client(handler):
    """A drop-in ``httpx.AsyncClient`` factory whose requests never leave the
    process, patched onto the ``rest`` module the same way Task 11/12's own
    ``TriageSandboxProvider`` probe test patches ``triage.httpx.AsyncClient``."""
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        return real_async_client(transport=httpx.MockTransport(handler), timeout=10)

    return factory


@pytest.mark.asyncio
async def test_rest_probe_reports_ok_on_200_and_carries_the_staged_auth(monkeypatch):
    import maljan.providers.sandbox.rest as rest_module

    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("x-api-key")
        return httpx.Response(200, json={})

    monkeypatch.setattr(rest_module.httpx, "AsyncClient", _fake_rest_async_client(handler))
    r = await probes.probe_rest(
        {
            "base_url": "https://xyz.example/api",
            "auth_header": "X-API-Key",
            "auth_scheme": "",
            "token": "s3cr3t",
        }
    )
    assert r.ok is True
    assert seen["path"] == "/api/samples/probe"
    assert seen["auth"] == "s3cr3t"  # empty scheme: the raw token, unprefixed


@pytest.mark.asyncio
async def test_rest_probe_reports_ok_on_a_404_for_the_fake_task(monkeypatch):
    import maljan.providers.sandbox.rest as rest_module

    monkeypatch.setattr(
        rest_module.httpx,
        "AsyncClient",
        _fake_rest_async_client(lambda r: httpx.Response(404)),
    )
    r = await probes.probe_rest({"base_url": "https://xyz.example/api"})
    assert r.ok is True
    assert r.detail == "reachable, status endpoint answered 404 for a fake task"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_rest_probe_reports_the_credential_was_refused(monkeypatch, status):
    import maljan.providers.sandbox.rest as rest_module

    monkeypatch.setattr(
        rest_module.httpx,
        "AsyncClient",
        _fake_rest_async_client(lambda r: httpx.Response(status)),
    )
    r = await probes.probe_rest({"base_url": "https://xyz.example/api", "token": "s3cr3t-token"})
    assert r.ok is False
    assert str(status) in r.detail
    assert "s3cr3t-token" not in r.detail


@pytest.mark.asyncio
async def test_rest_probe_reports_a_connection_error_legibly(monkeypatch):
    import maljan.providers.sandbox.rest as rest_module

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    monkeypatch.setattr(rest_module.httpx, "AsyncClient", _fake_rest_async_client(handler))
    r = await probes.probe_rest({"base_url": "https://xyz.example/api"})
    assert r.ok is False
    assert "ConnectError" in r.detail


@pytest.mark.asyncio
async def test_rest_probe_reports_a_bad_mapping_path_naming_the_channel():
    r = await probes.probe_rest({"base_url": "https://xyz.example/api", "mapping_dns": "$[["})
    assert r.ok is False
    assert "dns" in r.detail


@pytest.mark.asyncio
async def test_rest_probe_notes_tls_verification_is_off(monkeypatch):
    import maljan.providers.sandbox.rest as rest_module

    monkeypatch.setattr(
        rest_module.httpx,
        "AsyncClient",
        _fake_rest_async_client(lambda r: httpx.Response(200)),
    )
    r = await probes.probe_rest({"base_url": "https://xyz.example/api", "verify_tls": False})
    assert r.ok is True
    assert "TLS verification is off" in r.detail


@pytest.mark.asyncio
async def test_rest_probe_never_puts_the_token_in_the_url_or_detail(monkeypatch):
    import maljan.providers.sandbox.rest as rest_module

    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200)

    monkeypatch.setattr(rest_module.httpx, "AsyncClient", _fake_rest_async_client(handler))
    r = await probes.probe_rest(
        {"base_url": "https://xyz.example/api", "token": "super-secret-rest-token"}
    )
    assert "super-secret-rest-token" not in r.detail
    assert "super-secret-rest-token" not in str(seen["url"])


# ---------------------------------------------------------------------------
# BUG 8 (live run S9): a per-agent model that does not exist on the Ollama
# server was accepted by both probes and only surfaced when the job reached
# the agent that used it.
# ---------------------------------------------------------------------------


def _tags_transport(monkeypatch, names):
    """An Ollama server that lists ``names`` and generates with those only.

    The probe asks for both: the tag list says the endpoint is up and the name
    is in its catalogue, and the one-turn completion says the server will
    actually load it. A tag it does not have is refused with a 404, the way
    Ollama refuses it.
    """

    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            asked = json.loads(req.content or b"{}").get("model", "")
            if asked not in names:
                return httpx.Response(404, json={"error": f"model {asked!r} not found"})
            return httpx.Response(200, json={"response": "OK"})
        assert req.url.path.endswith("/api/tags")
        return httpx.Response(200, json={"models": [{"name": n} for n in names]})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )


@pytest.mark.asyncio
async def test_llm_probe_names_a_per_agent_model_the_server_does_not_have(monkeypatch):
    _tags_transport(monkeypatch, ["qwen3:8b"])
    r = await probes.probe_llm(
        {
            "provider": "ollama",
            "ollama_base_url": "http://ollama:11434",
            "ollama_expert_model": "qwen3:8b",
            "ollama_judge_model": "qwen3:8b",
            "agents": {"judge": {"provider": "ollama", "model": "qwen3:nope"}},
        }
    )
    assert r.ok is False
    assert "judge=qwen3:nope" in r.detail


@pytest.mark.asyncio
async def test_llm_probe_accepts_per_agent_models_the_server_has(monkeypatch):
    _tags_transport(monkeypatch, ["qwen3:8b", "qwen3:4b"])
    r = await probes.probe_llm(
        {
            "provider": "ollama",
            "ollama_base_url": "http://ollama:11434",
            "ollama_expert_model": "qwen3:8b",
            "ollama_judge_model": "qwen3:8b",
            "agents": {"judge": {"provider": "ollama", "model": "qwen3:4b"}},
        }
    )
    assert r.ok is True


@pytest.mark.asyncio
async def test_llm_probe_asks_a_per_agent_endpoint_for_its_own_catalogue(monkeypatch):
    """An agent on its own Ollama host is checked there, not against the global one."""
    catalogues = {
        "ollama": ["qwen3:8b"],
        "gpu-box": ["qwen3:4b"],
    }

    def handler(req: httpx.Request):
        names = catalogues[req.url.host]
        if req.url.path.endswith("/api/generate"):
            asked = json.loads(req.content or b"{}").get("model", "")
            if asked not in names:
                return httpx.Response(404, json={"error": f"model {asked!r} not found"})
            return httpx.Response(200, json={"response": "OK"})
        assert req.url.path.endswith("/api/tags")
        return httpx.Response(200, json={"models": [{"name": n} for n in names]})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    values = {
        "provider": "ollama",
        "ollama_base_url": "http://ollama:11434",
        "ollama_expert_model": "qwen3:8b",
        "ollama_judge_model": "qwen3:8b",
        "agents": {
            "judge": {
                "provider": "ollama",
                "model": "qwen3:4b",
                "base_url": "http://gpu-box:11434",
            }
        },
    }
    assert (await probes.probe_llm(values)).ok is True

    values["agents"]["judge"]["model"] = "qwen3:8b"
    missing = await probes.probe_llm(values)
    assert missing.ok is False
    assert "judge=qwen3:8b @ http://gpu-box:11434" in missing.detail


@pytest.mark.asyncio
async def test_llm_probe_ignores_a_per_agent_entry_on_another_provider(monkeypatch):
    _tags_transport(monkeypatch, ["qwen3:8b"])
    r = await probes.probe_llm(
        {
            "provider": "ollama",
            "ollama_base_url": "http://ollama:11434",
            "ollama_expert_model": "qwen3:8b",
            "ollama_judge_model": "qwen3:8b",
            "agents": {"static": {"provider": "openai", "model": "gpt-4o"}},
        }
    )
    assert r.ok is True


@pytest.mark.asyncio
async def test_run_probe_resolves_the_per_agent_map_for_the_llm_probe(monkeypatch):
    seen = {}

    async def fake(values):
        seen.update(values)
        return probes.ProbeResult(True, 1, "x")

    monkeypatch.setitem(probes.PROBES, "llm", fake)
    await probes.run_probe(
        "llm",
        {"core.llm.agents": {"judge": {"provider": "ollama", "model": "qwen3:4b"}}},
        {},
    )
    assert seen["agents"] == {"judge": {"provider": "ollama", "model": "qwen3:4b"}}


def test_the_per_agent_map_is_annotated_with_the_llm_probe():
    from maljan.core.settings_annotations import ANNOTATIONS

    assert ANNOTATIONS["llm.agents"].get("probe") == "llm"


@pytest.mark.asyncio
async def test_the_llm_probe_asks_one_pair_once(monkeypatch):
    """Agents that all name the global model at the global endpoint are one call.

    On a local server every completion is a model load, so six ways of asking
    the same question would be six loads for one answer.
    """
    asked = []

    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            asked.append(json.loads(req.content or b"{}").get("model", ""))
            return httpx.Response(200, json={"response": "OK"})
        return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_llm(
        {
            "provider": "ollama",
            "ollama_base_url": "http://ollama:11434",
            "ollama_expert_model": "qwen3:8b",
            "ollama_judge_model": "qwen3:8b",
            "agents": {
                name: {"provider": "ollama", "model": "qwen3:8b"}
                for name in ("static", "network", "dynamic", "reverser", "triage")
            },
        }
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


@pytest.mark.asyncio
async def test_the_llm_probe_stops_at_its_own_budget_and_says_what_it_did_not_try(monkeypatch):
    """The whole probe is bounded, and an unasked pair files nothing.

    A person is at the button. Pairs are asked one after another, so their
    budgets add up; the ones there was no room left for are named, and pressing
    Test again asks them.
    """

    class _Clock:
        """Time that only moves when a completion is made, a whole budget at a time."""

        def __init__(self) -> None:
            self.now = 0.0

        def monotonic(self) -> float:
            return self.now

        def perf_counter(self) -> float:
            return self.now

    clock = _Clock()

    def handler(req: httpx.Request):
        if req.url.path.endswith("/api/generate"):
            clock.now += probes.COMPLETION_TIMEOUT
            return httpx.Response(200, json={"response": "OK"})
        return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

    monkeypatch.setattr(probes, "time", clock)
    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_llm(
        {
            "provider": "ollama",
            "ollama_base_url": "http://ollama:11434",
            "ollama_expert_model": "qwen3:8b",
            "ollama_judge_model": "qwen3:8b",
            "agents": {
                "a1": {"provider": "ollama", "model": "qwen3:1b"},
                "a2": {"provider": "ollama", "model": "qwen3:2b"},
                "a3": {"provider": "ollama", "model": "qwen3:3b"},
                "a4": {"provider": "ollama", "model": "qwen3:4b"},
            },
        }
    )

    filed = [pair["model"] for pair in (r.details or {})["completions"]]
    fits = int(probes.LLM_PROBE_BUDGET_SECONDS // probes.COMPLETION_TIMEOUT)
    assert filed == ["qwen3:8b", "qwen3:1b", "qwen3:2b"][:fits]
    assert r.ok is False, "a pair nobody asked is not a pass"
    assert f"not tried within {int(probes.LLM_PROBE_BUDGET_SECONDS)} s" in r.detail
    assert "a3=qwen3:3b" in r.detail and "a4=qwen3:4b" in r.detail
    assert "press Test again" in r.detail


@pytest.mark.asyncio
async def test_a_failing_pair_names_its_server_and_nothing_else(monkeypatch):
    """The sentence reaches the operator's screen and the stored row.

    A base URL may carry credentials in front of the host and a path behind it;
    neither says which server answered.
    """
    base = _dsn("http", "opuser:opsecret", "box:8080/v1")

    def handler(req: httpx.Request):
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "qwen"}]})
        return httpx.Response(404, json={"error": "no such model"})

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    r = await probes.probe_llm(
        {
            "provider": "openai",
            "base_url": "http://box:8080/v1",
            "api_key": "k",
            "expert_model": "qwen",
            "agents": {"judge": {"provider": "openai", "model": "ghost", "base_url": base}},
        }
    )

    assert r.ok is False
    assert "judge=ghost @ http://box:8080" in r.detail
    assert "opuser" not in r.detail and "opsecret" not in r.detail
    assert "/v1" not in r.detail, "a path says nothing about which server answered"
    filed = {(pair["endpoint"], pair["model"]) for pair in (r.details or {})["completions"]}
    assert (base, "ghost") in filed, "the row is still filed under the address it called"


# ---------------------------------------------------------------------------
# The probe asks a local OpenAI-compatible server the same question the agents
# ask it. A reasoning model left thinking spends the probe's eight tokens
# inside its own chain of thought and comes back HTTP 200 with an empty
# ``content`` and a filled ``reasoning_content``; the probe read that as
# "answered nothing" and the submit gate then refused every job.
# ---------------------------------------------------------------------------

LOCAL_ENDPOINT = "http://127.0.0.1:8080/v1"


def _answer(payload):
    return httpx.Response(200, request=httpx.Request("POST", "http://x"), json=payload)


def test_the_probe_sends_the_thinking_switch_the_agents_send():
    _url, _headers, body = probes._completion_request(
        "openai", LOCAL_ENDPOINT, "qwen3.6-35b-a3b", "k", disable_thinking=True
    )

    assert body["chat_template_kwargs"]["enable_thinking"] is False


def test_the_thinking_switch_is_absent_unless_it_is_turned_on():
    _url, _headers, body = probes._completion_request(
        "openai", LOCAL_ENDPOINT, "qwen3.6-35b-a3b", "k", disable_thinking=False
    )

    assert "chat_template_kwargs" not in body


def test_the_thinking_switch_goes_where_the_agents_would_send_it():
    """The endpoints the agents' provider leaves alone are left alone here too.

    ``sends_llama_cpp_extras`` is the provider's own predicate: a hosted
    OpenAI-compatible API answers an unknown body field with 400, so neither
    the run nor the probe that gates it may put one there.
    """
    _url, _headers, hosted = probes._completion_request(
        "openai", "https://api.openai.com/v1", "gpt-4o-mini", "k", disable_thinking=True
    )
    _url2, _headers2, standard = probes._completion_request(
        "openai", LOCAL_ENDPOINT, "qwen", "k", disable_thinking=True, compat="standard"
    )
    _url3, _headers3, forced = probes._completion_request(
        "openai",
        "https://box.example.com/v1",
        "qwen",
        "k",
        disable_thinking=True,
        compat="llama_cpp",
    )

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

    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(transport=transport(handler), timeout=10),
    )
    values = {
        "provider": "openai",
        "base_url": LOCAL_ENDPOINT,
        "api_key": "k",
        "expert_model": "qwen",
        "disable_thinking": True,
        "agents": {
            "judge": {
                "provider": "openai",
                "model": "qwen",
                "base_url": "http://192.168.1.9:8080/v1",
            }
        },
    }

    r = await probes.probe_llm(values)

    assert r.ok is True
    assert set(bodies) == {"127.0.0.1", "192.168.1.9"}
    for host, body in bodies.items():
        assert body["chat_template_kwargs"] == {"enable_thinking": False}, host

    bodies.clear()
    values["disable_thinking"] = False
    assert (await probes.probe_llm(values)).ok is True
    for host, body in bodies.items():
        assert "chat_template_kwargs" not in body, host


@pytest.mark.asyncio
async def test_run_probe_carries_the_thinking_switch_into_the_llm_probe(monkeypatch):
    """A staged switch is what the probe tests, not the stored one."""
    seen: dict = {}

    async def fake(values):
        seen.update(values)
        return probes.ProbeResult(True, 1, "x")

    monkeypatch.setitem(probes.PROBES, "llm", fake)
    await probes.run_probe(
        "llm",
        {"core.llm.openai.disable_thinking": True, "core.llm.openai.compat": "llama_cpp"},
        {},
    )

    assert seen["disable_thinking"] is True
    assert seen["compat"] == "llama_cpp"


def test_an_endpoint_that_reasoned_did_answer():
    """An empty ``content`` beside a filled ``reasoning_content`` is an answer.

    The server answered on the model the run will use; it spent the eight
    tokens on reasoning, which proves the model loaded and the key was
    accepted. Calling that "answered nothing" refused every job.
    """
    reasoned = _answer(
        {"choices": [{"message": {"content": "", "reasoning_content": "Thinking Process: ok"}}]}
    )
    older_spelling = _answer({"choices": [{"message": {"content": "", "reasoning": "ok"}}]})

    assert probes._said_something("openai", reasoned) is True
    assert probes._said_something("openai", older_spelling) is True


def test_an_answer_with_nothing_in_it_at_all_is_still_nothing():
    """The failure the check exists for is unchanged: an empty body is empty."""
    empty = _answer({"choices": [{"message": {"content": "", "reasoning_content": "  "}}]})
    no_message = _answer({"choices": [{"message": {}}]})

    assert probes._said_something("openai", empty) is False
    assert probes._said_something("openai", no_message) is False


def test_a_reasoning_field_that_is_not_text_said_nothing():
    """A structured ``reasoning`` is not an answer.

    Some builds send an object there rather than a string. ``str(value or "")``
    read a non-empty dict as text — it stringifies to something truthy — so a
    server that returned an empty ``content`` beside a structured but contentless
    ``reasoning`` passed a probe it should have failed.
    """
    structured = _answer(
        {"choices": [{"message": {"content": "", "reasoning": {"content": "", "steps": []}}}]}
    )
    listed = _answer({"choices": [{"message": {"content": "", "reasoning_content": [{}]}}]})

    assert probes._said_something("openai", structured) is False
    assert probes._said_something("openai", listed) is False


def test_a_reasoning_object_beside_real_text_is_still_an_answer():
    """The guard drops the field, not the message: text elsewhere still counts."""
    spoke = _answer({"choices": [{"message": {"content": "ok", "reasoning": {"steps": ["a"]}}}]})
    assert probes._said_something("openai", spoke) is True


# ---------------------------------------------------------------------------
# A reasoning model added on Ollama fails the gate at the shipped default, and
# the operator has no way to know which setting turns it around. Measured: a
# 12B reasoning model answered nothing in 55 s at the default and answered in
# 243 ms with ``core.llm.ollama.disable_thinking`` on, and with
# ``core.llm.require_probe`` the API refuses every job in between. The default
# stays the operator's decision; the failure names its door.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_ollama_model_that_answered_nothing_names_the_setting(monkeypatch):
    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(
            transport=transport(lambda r: httpx.Response(200, json={"response": ""})), timeout=10
        ),
    )

    ok, said = await probes.complete_one_turn(
        "ollama", endpoint="http://127.0.0.1:11434", model="gemma4:12b"
    )

    assert ok is False
    assert probes.THINKING_SETTING in said
    assert "answered nothing" in said


@pytest.mark.asyncio
async def test_the_sentence_is_gone_once_the_setting_is_on(monkeypatch):
    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(
            transport=transport(lambda r: httpx.Response(200, json={"response": ""})), timeout=10
        ),
    )

    _ok, said = await probes.complete_one_turn(
        "ollama",
        endpoint="http://127.0.0.1:11434",
        model="gemma4:12b",
        disable_thinking=True,
    )

    assert probes.THINKING_SETTING not in said


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
    assert probes.THINKING_SETTING in said


@pytest.mark.asyncio
async def test_another_provider_is_not_told_about_an_ollama_setting(monkeypatch):
    monkeypatch.setattr(
        probes,
        "_client",
        lambda *_a, **_k: httpx.AsyncClient(
            transport=transport(
                lambda r: httpx.Response(200, json={"choices": [{"message": {"content": ""}}]})
            ),
            timeout=10,
        ),
    )

    _ok, said = await probes.complete_one_turn(
        "openai", endpoint="http://127.0.0.1:8080/v1", model="qwen"
    )

    assert probes.THINKING_SETTING not in said
