"""Connection tests for settings the UI is about to save. Nothing is persisted."""

from __future__ import annotations

import asyncio
import importlib.util
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from maljan.core.config import MCPServerConfig
from maljan.core.logger import logger
from maljan.core.paths import resolve_data
from maljan.core.settings_overrides import build_settings, redact_url, split_key
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.sandbox.rest_mapping import compile_mapping
from maljan.providers.servers import ServerHandle
from pydantic import SecretStr, ValidationError
from redis.asyncio import Redis

from app.config import settings as api_settings
from app.services.server_map import TOKEN_MASK as _TOKEN_MASK

TIMEOUT = 10.0

# A connection test is a person waiting at a button. Five seconds is long
# enough for a local stdio server to answer tools/list and short enough that a
# wedged one is reported rather than endured.
PROBE_BUDGET_SECONDS = 5.0


@dataclass
class ProbeResult:
    ok: bool
    latency_ms: int
    detail: str
    models: list[str] | None = None
    tools: list[str] | None = None


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


_PROBE_CLEANUP_TASKS: set[asyncio.Task[Any]] = set()


def _detach_cleanup(coro: Any, label: str) -> None:
    """Run ``coro`` to completion without making the caller wait for it.

    ``handle.aclose()`` is already internally bounded (``_acleanup``'s own
    20 s timeout); awaiting it here on top of a failed/timed-out ``aopen``
    re-adds that whole budget to a probe the operator's own click is
    documented at 5 s (F9). A strong reference is kept in
    ``_PROBE_CLEANUP_TASKS`` until it finishes so the task is not garbage
    collected mid-flight.
    """
    task = asyncio.ensure_future(coro)
    _PROBE_CLEANUP_TASKS.add(task)

    def _done(t: asyncio.Task[Any]) -> None:
        _PROBE_CLEANUP_TASKS.discard(t)
        if not t.cancelled() and (exc := t.exception()) is not None:
            logger.warning("probe cleanup for '%s' failed (non-fatal): %s", label, exc)

    task.add_done_callback(_done)


async def handshake_tools(config: MCPServerConfig, name: str) -> list[str]:
    """Attach ``config`` long enough to read its manifest, then let go.

    The only stdio handshake in the project besides a job's own: it is
    ``ServerHandle``, so a server that answers here answers the same way in a
    run. Whatever happens, the handle is eventually closed — a probe that
    leaves a child process behind turns a mis-typed command into a slow leak
    of subprocesses, which is exactly what a person clicking "Test" twice
    would produce.

    Regression (F9): a plain ``asyncio.wait_for(handle.aopen(...), 5.0)``
    does not give up after 5 s when ``aopen`` is wedged. ``wait_for`` cancels
    the inner coroutine and then *waits for the cancellation to finish* before
    raising ``TimeoutError`` — and ``aopen``'s own cancellation handler awaits
    ``_acleanup``, itself bounded at 20 s, so the operator's "Test" click can
    take ~25 s instead of the documented 5. ``asyncio.wait`` never cancels the
    handshake: past the budget this simply stops waiting on it and lets it
    (and its own cleanup) finish in the background, closing the handle once
    it does.
    """
    handle = ServerHandle(name, config)

    async def _run() -> list[str]:
        await handle.aopen(f"probe-{name}")
        return handle.all_tool_names()

    task: asyncio.Task[list[str]] = asyncio.ensure_future(_run())
    done, _pending = await asyncio.wait({task}, timeout=PROBE_BUDGET_SECONDS)
    if task not in done:
        # Ask it to stop, but do not wait for that to finish here — that wait
        # is exactly the ~20 s ``_acleanup`` budget this fix avoids blocking
        # on. A short, fixed grace period still lets the common case (a
        # cancellation that responds immediately) close the handle before
        # this returns; a genuinely wedged server closes later, from the
        # callback, once its own cancellation finally unwinds.
        task.cancel()
        done2, _pending2 = await asyncio.wait({task}, timeout=0.1)
        if task in done2:
            await handle.aclose()
        else:
            task.add_done_callback(lambda _t: _detach_cleanup(handle.aclose(), f"probe-{name}"))
        raise TimeoutError(f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s")
    try:
        return task.result()
    finally:
        await handle.aclose()


def _probe_config(entry: dict[str, Any]) -> MCPServerConfig:
    """The entry as configured, forced on and un-narrowed.

    A probe answers "what does this server offer"; a disabled entry or an
    empty allow-list are answers to a different question ("what may the model
    call"), and applying them here would make the manifest unreadable exactly
    when the operator needs it to pick from.
    """
    config = MCPServerConfig.model_validate(entry)
    return config.model_copy(update={"enabled": True, "tools": None})


async def probe_mcp(v: dict[str, Any]) -> ProbeResult:
    """Launch one configured MCP server and list the tools it offers."""
    t0 = time.perf_counter()
    name = str(v.get("name") or "server")
    try:
        config = _probe_config(dict(v.get("entry") or {}))
    except ValidationError as exc:
        fields = "; ".join(".".join(str(x) for x in e["loc"]) for e in exc.errors())
        return ProbeResult(False, _ms(t0), f"invalid server settings: {fields}")
    try:
        names = await handshake_tools(config, name)
    except TimeoutError:
        return ProbeResult(False, _ms(t0), f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s")
    except FileNotFoundError as exc:
        return ProbeResult(False, _ms(t0), f"{exc} not found on PATH")
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    listed = ", ".join(names[:8]) + ("…" if len(names) > 8 else "")
    return ProbeResult(True, _ms(t0), f"{len(names)} tools: {listed}", None, names)


# settings_service.py's mask for a stored secret the editor never receives in
# the clear (pydantic's own ``SecretStr`` JSON dump: ten literal asterisks,
# regardless of the real value's length). Defined once, in ``server_map``
# (the per-server registry needed a name for it too); kept under this old
# name here so the one place that needs to recognise it, rather than echo it
# back as a real token, does not change.
_MASKED_SECRET = _TOKEN_MASK


def _merge_server_entry(
    stored_entry: dict[str, Any], staged_entry: dict[str, Any]
) -> dict[str, Any]:
    """Layer a staged edit over the stored entry, field by field.

    A staged edit carries only the fields the editor's form touched; replacing
    the whole entry (rather than merging into it) would drop every field the
    operator left alone — most commonly ``args``/``env`` when only ``command``
    was edited. ``auth_token`` gets one more rule: the editor never receives a
    stored secret in the clear, so a staged value that is the settings
    service's mask — or empty, the value an untouched password field posts —
    means "left alone," not "cleared." Either way the stored token, already in
    ``merged`` from the copy below, is what reaches the handshake.
    """
    merged = dict(stored_entry)
    for key, value in staged_entry.items():
        if key == "auth_token" and value in (_MASKED_SECRET, ""):
            continue
        merged[key] = value
    return merged


async def run_mcp_probe(server: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult:
    """Probe one entry of the server map, staged fields winning over stored ones.

    Separate from ``run_probe`` because this probe is addressed to a *key*
    inside one setting rather than to a set of settings: ``_INPUTS`` maps
    catalog keys to short names, and there is no catalog key for "the r2custom
    entry".
    """
    stored_candidate = stored.get("core.mcp.servers")
    staged_candidate = values.get("core.mcp.servers")
    stored_map = stored_candidate if isinstance(stored_candidate, dict) else {}
    staged_map = staged_candidate if isinstance(staged_candidate, dict) else {}
    if server not in stored_map and server not in staged_map:
        # Fall back to the effective settings: a built-in the operator has
        # never edited has no stored row at all.
        from maljan.core.config import Settings

        effective = Settings().mcp.servers
        if server not in effective:
            available = (
                ", ".join(sorted(set(stored_map) | set(staged_map) | set(effective))) or "(none)"
            )
            return ProbeResult(False, 0, f"unknown server: {server!r}. Available: {available}")
        entry = effective[server].model_dump(mode="json")
    else:
        entry = _merge_server_entry(stored_map.get(server) or {}, staged_map.get(server) or {})
    return await probe_mcp({"name": server, "entry": entry})


async def probe_r2(v: dict[str, Any]) -> ProbeResult:
    """Launch the configured r2mcp and count the tools it offers, in 5 seconds.

    A stdio handshake is the only honest test of a subprocess-backed server: a
    binary that exists but cannot serve MCP is exactly the failure an operator
    needs named before a job fails on it.
    """
    t0 = time.perf_counter()
    command = str(v.get("binary_path") or "r2mcp")
    config = MCPServerConfig(enabled=True, transport="stdio", command=command)
    try:
        names = await handshake_tools(config, "r2")
    except TimeoutError:
        return ProbeResult(False, _ms(t0), f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s")
    except FileNotFoundError:
        return ProbeResult(False, _ms(t0), f"{command!r} not found on PATH")
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    return ProbeResult(True, _ms(t0), f"{len(names)} tools offered by {command!r}", None, names)


async def probe_capa(v: dict[str, Any]) -> ProbeResult:
    """Count capa + YARA rule files without touching a sample.

    No live handshake exists for either — both are local libraries reading
    local rule directories — so the connection test is the same check the
    provider itself makes before a run: is the library importable, and does
    each configured directory hold rule files. Naming which of the two is
    missing here is exactly what stops an operator from discovering an empty
    ``provides_evidence=False`` run only after a job finishes.
    """
    t0 = time.perf_counter()
    parts: list[str] = []
    capa_ok = False
    if importlib.util.find_spec("capa") is None:
        parts.append("capa library is not installed (uv sync --extra capa)")
    else:
        capa_dir = Path(resolve_data(str(v.get("capa_rules_dir") or "")))
        capa_rules = list(capa_dir.rglob("*.yml")) if capa_dir.is_dir() else []
        if not capa_dir.is_dir():
            parts.append(f"capa rules directory {capa_dir} does not exist")
        elif not capa_rules:
            parts.append(f"capa rules directory {capa_dir} has no *.yml rules")
        else:
            capa_ok = True
            parts.append(f"{len(capa_rules)} rules under {capa_dir}")

    yara_dir = Path(resolve_data(str(v.get("yara_rules_dir") or "")))
    yara_files = [*yara_dir.glob("*.yml"), *yara_dir.glob("*.yaml")] if yara_dir.is_dir() else []
    if not yara_dir.is_dir():
        parts.append(f"YARA rules directory {yara_dir} does not exist")
    elif not yara_files:
        parts.append(f"YARA rules directory {yara_dir} has no rule file")
    else:
        parts.append(f"{len(yara_files)} YARA rule file(s) under {yara_dir}")

    return ProbeResult(capa_ok, _ms(t0), "; ".join(parts))


async def probe_cape2(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    headers = {"Authorization": f"Token {v['api_token']}"} if v.get("api_token") else None
    ok, detail, _ = await _get(
        f"{str(v.get('base_url') or '').rstrip('/')}/apiv2/tasks/view/1/", headers
    )
    return ProbeResult(ok, _ms(t0), detail)


async def probe_triage(v: dict[str, Any]) -> ProbeResult:
    token = v.get("api_token")
    if not token:
        # No point building a client for a call the token would refuse: a
        # missing key is reported for what it is, without touching the network.
        return ProbeResult(False, 0, "no API token configured")
    t0 = time.perf_counter()
    headers = {"Authorization": f"Bearer {token}"}
    ok, detail, _ = await _get(f"{str(v.get('base_url') or '').rstrip('/')}/resources", headers)
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


def _str(v: dict[str, Any], key: str, default: str) -> str:
    """``v[key]`` as a string, or ``default`` when the key is absent.

    Not ``v.get(key) or default``: an operator-set empty string is a real
    value for several of these fields (an empty auth scheme sends the token
    raw; an empty mapping path means "this channel is not published"), and
    coercing it to the default would silently discard that choice.
    """
    value = v.get(key)
    return str(value) if value is not None else default


async def probe_rest(v: dict[str, Any]) -> ProbeResult:
    """Ask the configured sandbox's status endpoint about a task that does not exist.

    Every leaf ``_INPUTS["rest"]`` reads is folded into the ``SandboxRestConfig``
    handed to the provider — not just the four the HTTP call itself touches —
    so a staged auth header/scheme or mapping edit is what "Test" actually
    exercises, the same as saving and running a job would use.
    """
    t0 = time.perf_counter()
    from maljan.core.config import (
        RestAuthConfig,
        RestMappingConfig,
        RestReportConfig,
        RestStatusConfig,
        SandboxRestConfig,
    )
    from maljan.providers.sandbox.rest import RestSandboxProvider

    field_names = v.get("mapping_field_names")
    try:
        rest = SandboxRestConfig(
            base_url=_str(v, "base_url", ""),
            auth=RestAuthConfig(
                header=_str(v, "auth_header", "Authorization"),
                scheme=_str(v, "auth_scheme", "Bearer"),
                token=SecretStr(_str(v, "token", "")),
            ),
            status=RestStatusConfig(
                path=_str(v, "status_path", "/samples/{task_id}"),
                state_path=_str(v, "status_state_path", "$.status"),
            ),
            report=RestReportConfig(
                path=_str(v, "report_path", "/samples/{task_id}/report"),
                format=_str(v, "report_format", "generic"),  # type: ignore[arg-type]
            ),
            mapping=RestMappingConfig(
                target_sha256=_str(v, "mapping_target_sha256", "$.target.sha256"),
                processes=_str(v, "mapping_processes", ""),
                calls=_str(v, "mapping_calls", ""),
                signatures=_str(v, "mapping_signatures", ""),
                dns=_str(v, "mapping_dns", ""),
                http=_str(v, "mapping_http", ""),
                tcp=_str(v, "mapping_tcp", ""),
                udp=_str(v, "mapping_udp", ""),
                hosts=_str(v, "mapping_hosts", ""),
                domains=_str(v, "mapping_domains", ""),
                dropped_files=_str(v, "mapping_dropped_files", ""),
                registry=_str(v, "mapping_registry", ""),
                field_names=field_names if isinstance(field_names, dict) else {},
            ),
            timeout_seconds=int(v.get("timeout_seconds") or 900),
            poll_interval_seconds=int(v.get("poll_interval_seconds") or 15),
            verify_tls=bool(v.get("verify_tls", True)),
        )
        provider = RestSandboxProvider(rest, compile_mapping(rest.mapping))
    except (ProviderConfigurationError, ValidationError) as exc:
        fields = (
            "; ".join(".".join(str(x) for x in e["loc"]) for e in exc.errors())
            if isinstance(exc, ValidationError)
            else str(exc)
        )
        return ProbeResult(False, _ms(t0), fields)
    result = await provider.probe()
    return ProbeResult(result.ok, result.latency_ms or _ms(t0), result.detail)


PROBES: dict[str, Callable[[dict[str, Any]], Awaitable[ProbeResult]]] = {
    "llm": probe_llm,
    "ghidra": probe_ghidra,
    "r2": probe_r2,
    "mcp": probe_mcp,
    "capa_yara": probe_capa,
    # "capa" aliases "capa_yara" the way "cape" aliases "cape2": an older
    # stored annotation may still name the tool rather than the provider id.
    "capa": probe_capa,
    "cape2": probe_cape2,
    # "cape" is kept for one release: a stored annotation may still name it.
    "cape": probe_cape2,
    "triage": probe_triage,
    "qdrant": probe_qdrant,
    "redis": probe_redis,
    "virustotal": probe_virustotal,
    "abuseipdb": probe_abuseipdb,
    "rest": probe_rest,
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
    "r2": {
        "core.static.r2.binary_path": "binary_path",
    },
    "mcp": {},
    "capa_yara": {
        "core.static.capa.rules_dir": "capa_rules_dir",
        "core.static.yara.rules_dir": "yara_rules_dir",
    },
    "capa": {
        "core.static.capa.rules_dir": "capa_rules_dir",
        "core.static.yara.rules_dir": "yara_rules_dir",
    },
    "cape2": {
        "core.sandbox.cape2.base_url": "base_url",
        "core.sandbox.cape2.api_token": "api_token",
    },
    "cape": {
        "core.sandbox.cape2.base_url": "base_url",
        "core.sandbox.cape2.api_token": "api_token",
    },
    "triage": {
        "core.sandbox.triage.base_url": "base_url",
        "core.sandbox.triage.api_token": "api_token",
    },
    "qdrant": {
        "core.memory.qdrant_url": "url",
        "core.memory.qdrant_collection": "collection",
        "core.memory.qdrant_api_key": "api_key",
    },
    "redis": {},
    "virustotal": {"api.virustotal_api_key": "api_key"},
    "abuseipdb": {"api.abuseipdb_api_key": "api_key"},
    "rest": {
        "core.sandbox.rest.base_url": "base_url",
        "core.sandbox.rest.auth.header": "auth_header",
        "core.sandbox.rest.auth.scheme": "auth_scheme",
        "core.sandbox.rest.auth.token": "token",
        "core.sandbox.rest.status.path": "status_path",
        "core.sandbox.rest.status.state_path": "status_state_path",
        "core.sandbox.rest.report.path": "report_path",
        "core.sandbox.rest.report.format": "report_format",
        "core.sandbox.rest.verify_tls": "verify_tls",
        "core.sandbox.rest.timeout_seconds": "timeout_seconds",
        "core.sandbox.rest.poll_interval_seconds": "poll_interval_seconds",
        "core.sandbox.rest.mapping.target_sha256": "mapping_target_sha256",
        "core.sandbox.rest.mapping.processes": "mapping_processes",
        "core.sandbox.rest.mapping.calls": "mapping_calls",
        "core.sandbox.rest.mapping.signatures": "mapping_signatures",
        "core.sandbox.rest.mapping.dns": "mapping_dns",
        "core.sandbox.rest.mapping.http": "mapping_http",
        "core.sandbox.rest.mapping.tcp": "mapping_tcp",
        "core.sandbox.rest.mapping.udp": "mapping_udp",
        "core.sandbox.rest.mapping.hosts": "mapping_hosts",
        "core.sandbox.rest.mapping.domains": "mapping_domains",
        "core.sandbox.rest.mapping.dropped_files": "mapping_dropped_files",
        "core.sandbox.rest.mapping.registry": "mapping_registry",
        "core.sandbox.rest.mapping.field_names": "mapping_field_names",
    },
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
