from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services import settings_probes as probes  # noqa: E402


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
    assert seen == {
        "base_url": "http://form/v1",
        "api_key": "env-key",
        "expert_model": "stored-model",
        "judge_model": seen["judge_model"],
        "provider": seen["provider"],
    }


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
