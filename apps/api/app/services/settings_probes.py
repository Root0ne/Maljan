"""Connection tests for settings the UI is about to save. Nothing is persisted."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from maljan.core.settings_overrides import build_settings, redact_url, split_key
from pydantic import ValidationError
from redis.asyncio import Redis

from app.config import settings as api_settings

TIMEOUT = 10.0


@dataclass
class ProbeResult:
    ok: bool
    latency_ms: int
    detail: str
    models: list[str] | None = None


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT)


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


async def _get(
    url: str, headers: dict[str, str] | None = None
) -> tuple[bool, str, httpx.Response | None]:
    try:
        async with _client() as c:
            r = await c.get(url, headers=headers)
        return r.status_code < 400, f"HTTP {r.status_code}", r
    except httpx.TimeoutException:
        return False, f"timeout after {int(TIMEOUT)} s", None
    except httpx.HTTPError as exc:
        # httpx embeds the request URL in several transport errors; the URL
        # came from an operator setting and may carry credentials.
        return False, redact_url(f"{type(exc).__name__}: {exc}"), None


ANTHROPIC_VERSION = "2023-06-01"


async def _probe_llm_openai(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    base = str(v.get("base_url") or "https://api.openai.com/v1").rstrip("/")
    headers = {"Authorization": f"Bearer {v.get('api_key') or 'none'}"}
    ok, detail, r = await _get(f"{base}/models", headers)
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), f"model list: {detail}")
    models = [m.get("id", "") for m in r.json().get("data", [])]
    model = v.get("expert_model") or (models[0] if models else "")
    try:
        async with _client() as c:
            cr = await c.post(
                f"{base}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "max_tokens": 8,
                    "messages": [{"role": "user", "content": "Reply with OK."}],
                },
            )
    except httpx.TimeoutException:
        return ProbeResult(
            False, _ms(t0), f"{len(models)} models listed; completion timed out", models
        )
    except httpx.HTTPError as exc:
        return ProbeResult(
            False, _ms(t0), f"{len(models)} models listed; completion failed: {exc}", models
        )
    if cr.status_code >= 400:
        return ProbeResult(
            False,
            _ms(t0),
            f"{len(models)} models listed; completion with {model!r}: HTTP {cr.status_code}",
            models,
        )
    return ProbeResult(
        True, _ms(t0), f"{len(models)} models listed; completion with {model!r} succeeded", models
    )


async def _probe_llm_anthropic(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    headers = {
        "x-api-key": str(v.get("anthropic_api_key") or ""),
        "anthropic-version": ANTHROPIC_VERSION,
    }
    ok, detail, r = await _get("https://api.anthropic.com/v1/models", headers)
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), f"model list: {detail}")
    models = [m.get("id", "") for m in r.json().get("data", [])]
    model = v.get("anthropic_expert_model") or (models[0] if models else "")
    return ProbeResult(True, _ms(t0), f"{len(models)} models listed; {model!r} configured", models)


async def _probe_llm_ollama(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    base = str(v.get("ollama_base_url") or "http://localhost:11434").rstrip("/")
    ok, detail, r = await _get(f"{base}/api/tags")
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), f"model list: {detail}")
    models = [m.get("name", "") for m in r.json().get("models", [])]
    expert = v.get("ollama_expert_model") or ""
    judge = v.get("ollama_judge_model") or ""
    missing = [m for m in {expert, judge} if m and m not in models]
    if missing:
        return ProbeResult(
            False, _ms(t0), f"{len(models)} models available; missing {missing}", models
        )
    return ProbeResult(
        True, _ms(t0), f"{len(models)} models available; expert/judge present", models
    )


async def _probe_llm_gemini(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    headers = {"x-goog-api-key": str(v.get("gemini_api_key") or "")}
    ok, detail, r = await _get("https://generativelanguage.googleapis.com/v1beta/models", headers)
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), f"model list: {detail}")
    models = [m.get("name", "") for m in r.json().get("models", [])]
    model = v.get("gemini_expert_model") or (models[0] if models else "")
    return ProbeResult(True, _ms(t0), f"{len(models)} models listed; {model!r} configured", models)


_LLM_PROBES: dict[str, Callable[[dict[str, Any]], Awaitable[ProbeResult]]] = {
    "openai": _probe_llm_openai,
    "anthropic": _probe_llm_anthropic,
    "ollama": _probe_llm_ollama,
    "gemini": _probe_llm_gemini,
}


async def probe_llm(v: dict[str, Any]) -> ProbeResult:
    provider = str(v.get("provider") or "openai")
    probe = _LLM_PROBES.get(provider)
    if probe is None:
        return ProbeResult(False, 0, f"unknown provider: {provider!r}")
    return await probe(v)


async def probe_ghidra(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    headers = {"Authorization": f"Bearer {v['auth_token']}"} if v.get("auth_token") else None
    ok, detail, _ = await _get(f"{str(v.get('url') or '').rstrip('/')}/check_connection", headers)
    return ProbeResult(ok, _ms(t0), detail)


async def probe_cape2(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    headers = {"Authorization": f"Token {v['api_token']}"} if v.get("api_token") else None
    ok, detail, _ = await _get(
        f"{str(v.get('base_url') or '').rstrip('/')}/apiv2/tasks/view/1/", headers
    )
    return ProbeResult(ok, _ms(t0), detail)


async def probe_qdrant(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    base = str(v.get("url") or "").rstrip("/")
    key = v.get("api_key")
    headers = {"api-key": str(key)} if key else None
    ok, detail, _ = await _get(f"{base}/readyz", headers)
    if not ok:
        return ProbeResult(False, _ms(t0), f"readyz: {detail}")
    ok2, detail2, _ = await _get(f"{base}/collections/{v.get('collection')}", headers)
    return ProbeResult(
        True,
        _ms(t0),
        f"ready; collection {v.get('collection')!r} "
        f"{'exists' if ok2 else 'missing (' + detail2 + '), created on first write'}",
    )


async def probe_redis(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    url = str(api_settings.redis_url)  # read-only setting; no candidate value can arrive
    try:
        r = Redis.from_url(url, socket_timeout=TIMEOUT)
        pong = await r.ping()
        await r.aclose()
        return ProbeResult(bool(pong), _ms(t0), "PONG" if pong else "no PONG")
    except Exception as exc:  # noqa: BLE001 - reported to the operator, never raised to the route
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {redact_url(str(exc))}")


async def probe_virustotal(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    # /ip_addresses/<public ip> validates any key; /users/current needs a user-scoped one.
    ok, detail, _ = await _get(
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        {"x-apikey": str(v.get("api_key") or "")},
    )
    return ProbeResult(ok, _ms(t0), detail)


async def probe_abuseipdb(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    ok, detail, _ = await _get(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
        {"Key": str(v.get("api_key") or ""), "Accept": "application/json"},
    )
    return ProbeResult(ok, _ms(t0), detail)


PROBES: dict[str, Callable[[dict[str, Any]], Awaitable[ProbeResult]]] = {
    "llm": probe_llm,
    "ghidra": probe_ghidra,
    "cape2": probe_cape2,
    # "cape" is kept for one release: a stored annotation may still name it.
    "cape": probe_cape2,
    "qdrant": probe_qdrant,
    "redis": probe_redis,
    "virustotal": probe_virustotal,
    "abuseipdb": probe_abuseipdb,
}

# Which settings each probe reads, and the short name it gets them under.
_INPUTS: dict[str, dict[str, str]] = {
    "llm": {
        "core.llm.provider": "provider",
        "core.llm.openai.base_url": "base_url",
        "core.llm.openai.api_key": "api_key",
        "core.llm.openai.expert_model": "expert_model",
        "core.llm.openai.judge_model": "judge_model",
        "core.llm.anthropic.api_key": "anthropic_api_key",
        "core.llm.anthropic.expert_model": "anthropic_expert_model",
        "core.llm.anthropic.judge_model": "anthropic_judge_model",
        "core.llm.ollama.base_url": "ollama_base_url",
        "core.llm.ollama.expert_model": "ollama_expert_model",
        "core.llm.ollama.judge_model": "ollama_judge_model",
        "core.llm.gemini.api_key": "gemini_api_key",
        "core.llm.gemini.expert_model": "gemini_expert_model",
        "core.llm.gemini.judge_model": "gemini_judge_model",
    },
    "ghidra": {
        "core.static.ghidra.url": "url",
        "core.static.ghidra.auth_token": "auth_token",
    },
    "cape2": {
        "core.sandbox.cape2.base_url": "base_url",
        "core.sandbox.cape2.api_token": "api_token",
    },
    "cape": {
        "core.sandbox.cape2.base_url": "base_url",
        "core.sandbox.cape2.api_token": "api_token",
    },
    "qdrant": {
        "core.memory.qdrant_url": "url",
        "core.memory.qdrant_collection": "collection",
        "core.memory.qdrant_api_key": "api_key",
    },
    "redis": {},
    "virustotal": {"api.virustotal_api_key": "api_key"},
    "abuseipdb": {"api.abuseipdb_api_key": "api_key"},
}


def _unwrap(value: Any) -> Any:
    return value.get_secret_value() if hasattr(value, "get_secret_value") else value


async def run_probe(name: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult:
    probe = PROBES[name]
    try:
        core_layer = {split_key(k)[1]: v for k, v in stored.items() if k.startswith("core.")}
        core_layer.update(
            {
                split_key(k)[1]: v
                for k, v in values.items()
                if k.startswith("core.") and v is not None
            }
        )
        core = build_settings(core_layer)
    except (ValueError, ValidationError) as exc:
        # A malformed key or a staged value the model rejects is an operator
        # error, not a route error. Name the fields, never echo the values.
        fields = (
            "; ".join(".".join(str(x) for x in e["loc"]) for e in exc.errors())
            if isinstance(exc, ValidationError)
            else type(exc).__name__
        )
        return ProbeResult(False, 0, f"invalid candidate values: {fields}")
    resolved: dict[str, Any] = {}
    for key, short in _INPUTS[name].items():
        ns, path = split_key(key)
        if key in values and values[key] is not None:
            resolved[short] = values[key]
        elif key in stored:
            resolved[short] = stored[key]
        elif ns == "core":
            cursor: Any = core
            for part in path.split("."):
                cursor = getattr(cursor, part)
            resolved[short] = _unwrap(cursor)
        else:
            resolved[short] = _unwrap(getattr(api_settings, path))
    return await probe(resolved)
