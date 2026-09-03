from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services import settings_probes as probes  # noqa: E402


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
        probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10)
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
        lambda: httpx.AsyncClient(transport=transport(lambda r: httpx.Response(401)), timeout=10),
    )
    r = await probes.probe_ghidra({"url": "http://ghidra:8089", "auth_token": "t"})
    assert r.ok is False and "401" in r.detail


@pytest.mark.asyncio
async def test_timeout_is_reported_not_raised(monkeypatch):
    def handler(_r):
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(
        probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10)
    )
    r = await probes.probe_qdrant({"url": "http://q:6333", "collection": "c"})
    assert r.ok is False and "timeout" in r.detail.lower()


@pytest.mark.asyncio
async def test_run_probe_merges_form_over_stored_and_env(monkeypatch):
    seen = {}

    async def fake(values):
        seen.update(values)
        return probes.ProbeResult(True, 1, "x")

    monkeypatch.setitem(probes.PROBES, "llm", fake)
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    await probes.run_probe(
        "llm",
        {"core.llm.openai.base_url": "http://form/v1", "core.llm.openai.api_key": None},
        {"core.llm.openai.expert_model": "stored-model"},
    )
    # form beats stored beats env, per field, for the OpenAI slot...
    assert seen["base_url"] == "http://form/v1"
    assert seen["api_key"] == "env-key"
    assert seen["expert_model"] == "stored-model"
    assert seen["provider"] == "openai"
    # ...and every other provider's fields are still resolved (candidate > stored > env),
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
        probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10)
    )
    r = await probes.probe_virustotal({"api_key": "super-secret-value"})
    assert "super-secret-value" not in r.detail


@pytest.mark.asyncio
async def test_llm_probe_anthropic_ok(monkeypatch):
    def handler(req: httpx.Request):
        assert req.headers["x-api-key"] == "sk-ant-secret"
        assert req.headers["anthropic-version"] == probes.ANTHROPIC_VERSION
        return httpx.Response(
            200, json={"data": [{"id": "claude-sonnet-4-20250514"}, {"id": "claude-haiku"}]}
        )

    monkeypatch.setattr(
        probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10)
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
        assert req.url.path.endswith("/api/tags")
        return httpx.Response(200, json={"models": [{"name": "qwen3.5:9b"}, {"name": "llama3:8b"}]})

    monkeypatch.setattr(
        probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10)
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
        return httpx.Response(200, json={"models": [{"name": "models/gemini-2.5-pro"}]})

    monkeypatch.setattr(
        probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10)
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
        lambda: httpx.AsyncClient(transport=transport(lambda r: httpx.Response(403)), timeout=10),
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
