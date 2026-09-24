"""Connection tests for settings the UI is about to save. Nothing is persisted."""

from __future__ import annotations

import asyncio
import importlib.util
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from maljan.core import virustotal
from maljan.core.config import BUILTIN_SERVER_KEYS, MCPServerConfig, builtin_env_allow
from maljan.core.logger import logger
from maljan.core.model_assignments import endpoint_for, endpoint_label, endpoint_where
from maljan.core.paths import resolve_data
from maljan.core.settings_overrides import build_settings, redact_url, split_key
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.sandbox.rest_mapping import compile_mapping
from maljan.providers.servers import ServerHandle
from pydantic import SecretStr, ValidationError
from redis.asyncio import Redis

from app.config import settings as api_settings
from app.services.server_map import TOKEN_MASK as _TOKEN_MASK
from app.services.settings_catalog_api import API_DEFAULTS

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
    # Structured, probe-specific facts the generic renderer ignores and a
    # dedicated editor reads. The agent probe is the first user: a prompt hash
    # and a per-server status do not fit in a sentence.
    details: dict[str, Any] | None = None


def _client(timeout: float = TIMEOUT) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout)


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


def _validation_detail(exc: ValidationError) -> str:
    """Render a pydantic ValidationError as ``field: reason`` per error.

    Naming only the field ("agents") tells the operator nothing about what is
    wrong with it; the message ("'x': a generic agent needs a prompt") is the
    whole diagnosis. Pydantic's "Value error, " prefix on a custom validator's
    message adds nothing, so it is dropped.
    """
    parts = []
    for e in exc.errors():
        loc = ".".join(str(x) for x in e["loc"])
        msg = str(e.get("msg") or "").removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}" if msg else loc)
    return "; ".join(parts)


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

# What every completion probe asks for and how much of an answer it will take.
# One turn, eight tokens: enough to prove the endpoint serves this model and
# short enough that a person at a button is not left waiting for prose.
COMPLETION_PROMPT = "Reply with OK."
COMPLETION_MAX_TOKENS = 8

# What a completion gets, apart from the ten seconds a catalogue listing gets.
# A gate refuses jobs on this answer, and a local server that unloaded its
# model after its keep-alive reloads it on the next call: a 35B on commodity
# hardware is not a ten-second load, and refusing every job because the model
# was cold would be the probe deciding the run rather than reporting on it.
COMPLETION_TIMEOUT = 90.0

# What the whole ``llm`` probe gets, however many pairs it has to ask. The
# pairs are asked one after another on purpose — a single local server told to
# load three models at once is the re-prefill this project has already
# diagnosed — so their budgets add up, and five minutes is as long as a person
# at a button is asked to wait. A pair there was no room left to ask is named
# in the answer and files no row: it was not tried, which is neither a pass nor
# a failure, and pressing Test again asks it.
#
# The clock starts where the probe starts, not where the completions start:
# the catalogue listing in front of them is part of the wait an operator is
# counting, and a budget measured from after it is a wall the answer does not
# keep.
LLM_PROBE_BUDGET_SECONDS = 300.0


def probe_deadline() -> float:
    """The monotonic moment by which an ``llm`` probe entering now is done."""
    return time.monotonic() + LLM_PROBE_BUDGET_SECONDS


async def complete_one_turn(
    provider: str,
    *,
    endpoint: str,
    model: str,
    api_key: str = "",
    disable_thinking: bool = False,
    compat: str = "auto",
    reasoning_effort: str = "",
    num_ctx: int | None = None,
    keep_alive: str | None = None,
) -> tuple[bool | None, str]:
    """Ask ``model`` at ``endpoint`` for one short answer.

    The only check that proves anything. Listing a provider's models says the
    endpoint is up and that a name appears in a catalogue; it does not say the
    server will load that model, that the key may use it, or that the name has
    not been misspelled in a way the catalogue happens to contain. A gate that
    refuses a job on the strength of a probe has to rest on a probe that made
    the call the job will make.

    Three answers, not two. ``True`` is a model that answered with something;
    ``False`` is one that refused, failed or answered with nothing; ``None``
    is a call that ran out of time, which teaches nothing either way and must
    leave no row behind — a cold model that took ninety-one seconds to load is
    not a model that is missing, and writing it down as one would lock the
    operator out of their own jobs until they noticed.

    ``disable_thinking``, ``compat`` and ``reasoning_effort`` are the
    OpenAI-compatible settings that decide the request body's shape, carried in
    so that the turn asked here is the turn an agent would ask. ``num_ctx`` and ``keep_alive`` are
    Ollama's: the server loads a model at the context size the request names
    and keeps it for the time the request names, so a probe asked without them
    leaves the model loaded at the server's own default and the job's first
    call pays a full reload. See ``_completion_request``.

    Never raises: a probe answers with what happened, including when what
    happened is that nothing did.
    """
    model = str(model or "").strip()
    if not model:
        return False, "no model named"
    url, headers, body = _completion_request(
        provider,
        endpoint,
        model,
        api_key,
        disable_thinking=disable_thinking,
        compat=compat,
        reasoning_effort=reasoning_effort,
        num_ctx=num_ctx,
        keep_alive=keep_alive,
    )
    if url is None:
        return False, f"unknown provider: {provider!r}"
    try:
        async with _client(COMPLETION_TIMEOUT) as client:
            answer = await client.post(url, headers=headers, json=body)
    except httpx.TimeoutException:
        return None, (
            f"{model!r} did not answer within {int(COMPLETION_TIMEOUT)} s; it may still be "
            "loading — try again once it is warm. Nothing was written down for it."
            + _thinking_remediation(provider, disable_thinking)
        )
    except httpx.HTTPError as exc:
        return False, redact_url(f"{model!r} could not be reached: {type(exc).__name__}: {exc}")
    if answer.status_code >= 400:
        return False, f"{model!r} answered HTTP {answer.status_code}"
    if not _said_something(provider, answer):
        # A 2xx with nothing in it is the failure this check exists for: a
        # proxy that answers politely for a model it cannot serve, a response
        # whose only candidate was filtered away.
        # The full stop belongs to this sentence, not to the remedy that may
        # follow it: without it the two ran together as
        # "…answered nothing A reasoning model answers…".
        return False, f"{model!r} answered nothing." + _thinking_remediation(
            provider, disable_thinking
        )
    return True, f"{model!r} answered"


# The setting whose default a reasoning model on Ollama fails the gate at, and
# the sentence that names it. A measured trial: a 12B reasoning model answered
# nothing in 55 s at the default and answered in 243 ms with the setting on,
# and with ``core.llm.require_probe`` on the API refuses every job until an
# operator finds the switch. The default stays — an operator who wants the
# model's reasoning gets it — but the wall names its door.
THINKING_SETTING = "core.llm.ollama.disable_thinking"


def _thinking_remediation(provider: str, disable_thinking: bool) -> str:
    """What to try when an Ollama model spends its budget thinking, or ``""``."""
    if provider != "ollama" or disable_thinking:
        return ""
    return (
        f" A reasoning model answers in its thinking channel and leaves the answer empty:"
        f" set {THINKING_SETTING} to true, which asks Ollama for the answer without the"
        f" reasoning, and test again."
    )


def _spoken(value: Any) -> str:
    """One message field as the text it holds, or nothing when it holds none.

    ``str(value or "")`` read a structured ``reasoning`` — an object rather
    than a string, which some builds send — as an answer, because a non-empty
    dict stringifies to something truthy. A field that is not text did not say
    anything this check can read.
    """
    return value.strip() if isinstance(value, str) else ""


def _said_something(provider: str, answer: httpx.Response) -> bool:
    """Whether the provider's answer carries text or a tool call.

    Read per provider because the four put it in four places. A body that is
    not JSON, or JSON of a shape this does not know, counts as an answer: the
    endpoint said something, and inventing a failure from a shape nobody
    anticipated would be worse than missing an empty one.
    """
    try:
        payload = answer.json()
    except ValueError:
        return bool(answer.content)
    if not isinstance(payload, dict):
        return bool(payload)
    if provider in ("openai",):
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            return False
        message = (choices[0] or {}).get("message") or {}
        # Reasoning text counts. A local server serving a reasoning model with
        # thinking left on puts the whole answer in ``reasoning_content``
        # (``reasoning`` on some builds) and hands back an empty ``content``:
        # the model loaded, the key was accepted and the endpoint spoke, which
        # is everything this check is asked to establish. An empty body with
        # no reasoning and no tool call is still nothing.
        return bool(
            _spoken(message.get("content"))
            or _spoken(message.get("reasoning_content"))
            or _spoken(message.get("reasoning"))
            or message.get("tool_calls")
        )
    if provider == "ollama":
        # Thinking counts, for the same reason ``reasoning_content`` counts
        # above: a reasoning model given eight tokens spends them in its
        # thinking channel and answers with an empty ``response``. The model
        # loaded and the endpoint spoke, which is everything this check is
        # asked to establish — and refusing it locked every reasoning model on
        # Ollama out of a deployment that gates jobs on the probe. ``/api/chat``
        # puts the same two fields under ``message``; a proxy may answer in
        # either shape, so both are read.
        message = payload.get("message")
        message = message if isinstance(message, dict) else {}
        return bool(
            _spoken(payload.get("response"))
            or _spoken(payload.get("thinking"))
            or _spoken(message.get("content"))
            or _spoken(message.get("thinking"))
            or message.get("tool_calls")
        )
    if provider == "anthropic":
        content = payload.get("content")
        if not isinstance(content, list) or not content:
            return False
        return any(str(part.get("text") or "").strip() or part.get("name") for part in content)
    if provider == "gemini":
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            return False
        parts = ((candidates[0] or {}).get("content") or {}).get("parts") or []
        return any(str(part.get("text") or "").strip() for part in parts)
    return bool(payload)


def _openai_extras(
    base: str, disable_thinking: bool, compat: str, reasoning_effort: str = ""
) -> dict[str, Any]:
    """The request fields beyond OpenAI's basic ones this endpoint would get in a run.

    Decided by the provider's own two functions rather than by a second copy of
    the rule here: ``sends_llama_cpp_extras`` says whether this endpoint takes
    them at all — a hosted OpenAI-compatible API answers an unknown body field
    with 400, so a probe that sent one would fail a model the run can reach —
    and ``add_thinking_switch`` writes the one field. A probe that asks a
    different question from the run it gates is the defect this removes: with
    thinking left on, a local reasoning model spent the probe's eight tokens
    inside its own chain of thought and answered with an empty string.

    Imported inside the function: this is the API process, and the agents'
    provider module pulls langchain in behind it.
    """
    from maljan.llm.openai_provider import (
        add_deepseek_thinking_switch,
        add_thinking_switch,
        sends_llama_cpp_extras,
    )

    extras: dict[str, Any] = {}
    if sends_llama_cpp_extras(base, str(compat or "auto")):
        add_thinking_switch(extras, bool(disable_thinking))
    elif compat == "deepseek":
        add_deepseek_thinking_switch(extras, bool(disable_thinking))
    # The operator's effort as the run sends it: a value the endpoint does not
    # know is refused here rather than on the job's first call.
    effort = str(reasoning_effort or "").strip()
    if effort:
        extras["reasoning_effort"] = effort
    return extras


def _completion_request(
    provider: str,
    endpoint: str,
    model: str,
    api_key: str,
    *,
    disable_thinking: bool = False,
    compat: str = "auto",
    reasoning_effort: str = "",
    num_ctx: int | None = None,
    keep_alive: str | None = None,
) -> tuple[str | None, dict[str, str], dict[str, Any]]:
    """The one-turn request each provider takes, as ``(url, headers, body)``.

    ``num_ctx`` and ``keep_alive`` travel to Ollama only, the two fields the
    agents' provider sends with every call that decide the instance Ollama
    keeps loaded. The other providers take no such field.
    """
    base = str(endpoint or "").rstrip("/")
    if provider == "openai":
        return (
            f"{base or 'https://api.openai.com/v1'}/chat/completions",
            {"Authorization": f"Bearer {api_key or 'none'}"},
            {
                "model": model,
                "max_tokens": COMPLETION_MAX_TOKENS,
                "messages": [{"role": "user", "content": COMPLETION_PROMPT}],
                **_openai_extras(base, disable_thinking, compat, reasoning_effort),
            },
        )
    if provider == "ollama":
        body: dict[str, Any] = {
            "model": model,
            "prompt": COMPLETION_PROMPT,
            "stream": False,
            "options": {"num_predict": COMPLETION_MAX_TOKENS},
        }
        # Only when the deployment asked for it. Ollama refuses ``think`` for a
        # model that has no thinking mode, so sending it always would fail the
        # models that never had the problem.
        if disable_thinking:
            body["think"] = False
        # The job's own window and keep-alive, so the model this loads is the
        # instance the job's first call finds rather than one it has to reload.
        if num_ctx:
            body["options"]["num_ctx"] = int(num_ctx)
        if keep_alive:
            body["keep_alive"] = str(keep_alive)
        return (
            f"{base or 'http://localhost:11434'}/api/generate",
            {},
            body,
        )
    if provider == "anthropic":
        return (
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION},
            {
                "model": model,
                "max_tokens": COMPLETION_MAX_TOKENS,
                "messages": [{"role": "user", "content": COMPLETION_PROMPT}],
            },
        )
    if provider == "gemini":
        return (
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            {"x-goog-api-key": api_key},
            {
                "contents": [{"parts": [{"text": COMPLETION_PROMPT}]}],
                "generationConfig": {"maxOutputTokens": COMPLETION_MAX_TOKENS},
            },
        )
    return None, {}, {}


def _listing_failed(endpoint: str, detail: str) -> str:
    """A catalogue read that failed, and where it was tried.

    "model list: connection refused" is the same sentence whichever endpoint
    was configured, and an operator with two servers staged cannot tell which
    one refused them. ``endpoint_label`` keeps the scheme and the host and
    drops the path, the query and any credential in front of it, which is
    exactly as much as a failure message may carry.
    """
    from maljan.core.model_assignments import endpoint_label

    label = endpoint_label(endpoint)
    return f"model list at {label}: {detail}" if label else f"model list: {detail}"


async def _probe_llm_openai(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    deadline = probe_deadline()
    base = endpoint_where("openai", openai_base_url=v.get("base_url"))
    headers = {"Authorization": f"Bearer {v.get('api_key') or 'none'}"}
    ok, detail, r = await _get(f"{base}/models", headers)
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), _listing_failed(base, detail))
    models = [m.get("id", "") for m in r.json().get("data", [])]
    model = v.get("expert_model") or (models[0] if models else "")
    pairs = _pairs_to_file(v, "openai", base, str(model))
    # Every OpenAI-compatible pair, the per-agent ones at their own endpoints
    # included, is asked with the request body its agent would send: the
    # thinking switch is a global setting and the dialect decides, per
    # endpoint, whether it goes on the wire at all.
    reached, broken, untried = await _complete_each_pair(
        "openai",
        pairs,
        str(v.get("api_key") or ""),
        deadline=deadline,
        disable_thinking=bool(v.get("disable_thinking")),
        compat=str(v.get("compat") or "auto"),
        reasoning_effort=str(v.get("reasoning_effort") or ""),
    )
    return _completed(t0, reached, broken, untried, f"{len(models)} models listed", models)


async def _probe_llm_anthropic(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    deadline = probe_deadline()
    headers = {
        "x-api-key": str(v.get("anthropic_api_key") or ""),
        "anthropic-version": ANTHROPIC_VERSION,
    }
    ok, detail, r = await _get("https://api.anthropic.com/v1/models", headers)
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), _listing_failed("https://api.anthropic.com", detail))
    models = [m.get("id", "") for m in r.json().get("data", [])]
    model = v.get("anthropic_expert_model") or (models[0] if models else "")
    # Anthropic has one endpoint, so a per-agent entry differs only in its
    # model; each is still asked, because the key may be refused for one model
    # and not another.
    pairs = _pairs_to_file(v, "anthropic", endpoint_where("anthropic"), str(model))
    reached, broken, untried = await _complete_each_pair(
        "anthropic", pairs, str(v.get("anthropic_api_key") or ""), deadline=deadline
    )
    return _completed(t0, reached, broken, untried, f"{len(models)} models listed", models)


def _agent_models(v: dict[str, Any], provider: str) -> dict[str, tuple[str, str | None]]:
    """Every ``llm.agents`` entry served by ``provider``, name to (model, base_url).

    An entry names its own provider; one that leaves it empty inherits the
    global ``llm.provider``. Entries are dicts when they arrive staged from
    the UI and ``AgentLLMConfig`` objects when they come from the effective
    settings, so both are read here.

    The base URL comes back beside the model because an entry may point at its
    own server: asking the global one about a model the agent will look for
    somewhere else answers a different question. ``None`` means the entry
    inherits the global endpoint.

    ``run_probe`` always resolves ``core.llm.provider`` into the inputs, so the
    fallback below is only reached by a direct call; it reads the field's own
    default rather than naming a provider here, so an inheriting entry cannot
    be skipped because two places disagree about what the default is.
    """
    from maljan.core.config import LLMConfig

    raw = v.get("agents")
    if not isinstance(raw, dict):
        return {}
    global_provider = str(v.get("provider") or LLMConfig.model_fields["provider"].default)
    out: dict[str, tuple[str, str | None]] = {}
    for name, entry in raw.items():
        if isinstance(entry, dict):
            data: dict[str, Any] = entry
        elif hasattr(entry, "model_dump"):
            data = entry.model_dump(mode="json")
        else:
            continue
        # The models an entry falls back to are asked exactly as its first one
        # is: a fallback is a model the run may call, and the gate refuses a
        # job whose fallback no probe has reached.
        rows = [data, *[row for row in (data.get("fallbacks") or []) if isinstance(row, dict)]]
        for position, row in enumerate(rows):
            entry_provider = str(row.get("provider") or "") or global_provider
            model = str(row.get("model") or "")
            base_url = str(row.get("base_url") or "").strip() or None
            if model and entry_provider == provider:
                label = str(name) if position == 0 else f"{name} fallback {position}"
                out[label] = (model, base_url)
    return out


def _pairs_to_file(
    v: dict[str, Any], provider: str, base: str, expert_model: str
) -> dict[tuple[str, str], str]:
    """Every ``(endpoint, model)`` pair this probe will file, each one once.

    The selected provider's expert model at its own endpoint, and every
    per-agent override at *its* own endpoint — a second llama.cpp on another
    port is the ordinary shape of this deployment, and it is never listed by
    the global one. A typo in one of those used to surface only when the job
    reached that agent, minutes in, and a row filed from somebody else's call
    would be the same silence wearing a green badge.

    Keyed on the pair and not on the label, so a deployment that pins five
    agents to the global model at the global endpoint is one call and one row
    rather than six of each: on a local server every one of those is a model
    load, and asking the same question six times answers it no better.

    The endpoint comes from ``endpoint_where`` — the function the submit gate
    resolves its own key with — so what is filed and what is looked up are one
    spelling of one address.
    """
    pairs: dict[tuple[str, str], str] = {
        (base, expert_model): f"expert={expert_model} @ {endpoint_label(base)}"
    }
    for name, (model, agent_base) in sorted(_agent_models(v, provider).items()):
        endpoint = endpoint_where(
            provider,
            agent_base,
            openai_base_url=v.get("base_url"),
            ollama_base_url=v.get("ollama_base_url"),
        )
        pairs.setdefault((endpoint, model), f"{name}={model} @ {endpoint_label(endpoint)}")
    return pairs


async def _complete_each_pair(
    provider: str,
    pairs: dict[tuple[str, str], str],
    api_key: str,
    *,
    deadline: float,
    disable_thinking: bool = False,
    compat: str = "auto",
    reasoning_effort: str = "",
    num_ctx: int | None = None,
    keep_alive: str | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """One completion per pair in turn; what was reached, what failed, what was not tried.

    Every pair the probe will file a row for is asked, at its own endpoint and
    on its own model, because a row filed from somebody else's call is the
    defect this whole gate exists to remove. A pair that timed out is left out
    of the first two lists: nothing was learned about it, so nothing is written
    down and the sentence the operator reads says to try again.

    One at a time, and the whole run inside ``LLM_PROBE_BUDGET_SECONDS``. A
    pair is only started when its own budget still fits in what is left of the
    probe's, so the request cannot run past that however many cold models are
    named; the rest are handed back as not tried, under the same rule as a
    timeout — no row, and a sentence saying to ask again.

    ``deadline`` is taken by the caller as the probe begins, so the seconds the
    catalogue listing spent are seconds this loop no longer has.
    """
    reached: list[dict[str, Any]] = []
    broken: list[str] = []
    untried: list[str] = []
    for (endpoint, model), label in pairs.items():
        if time.monotonic() + COMPLETION_TIMEOUT > deadline:
            untried.append(label)
            continue
        answered, said = await complete_one_turn(
            provider,
            endpoint=endpoint,
            model=model,
            api_key=api_key,
            disable_thinking=disable_thinking,
            compat=compat,
            reasoning_effort=reasoning_effort,
            num_ctx=num_ctx,
            keep_alive=keep_alive,
        )
        if answered is None:
            broken.append(f"{label}: {said}")
            continue
        reached.append(
            {
                "endpoint": endpoint,
                "model": model,
                "provider": provider,
                "ok": bool(answered),
                "detail": said,
            }
        )
        if not answered:
            broken.append(f"{label}: {said}")
    return reached, broken, untried


async def _probe_llm_ollama(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    deadline = probe_deadline()
    base = endpoint_where("ollama", ollama_base_url=v.get("ollama_base_url"))
    ok, detail, r = await _get(f"{base}/api/tags")
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), _listing_failed(base, detail))
    models = [m.get("name", "") for m in r.json().get("models", [])]
    expert = v.get("ollama_expert_model") or ""
    judge = v.get("ollama_judge_model") or ""
    missing = [m for m in {expert, judge} if m and m not in models]
    if missing:
        return ProbeResult(
            False, _ms(t0), f"{len(models)} models available; missing {missing}", models
        )
    pairs = _pairs_to_file(v, "ollama", base, str(expert))
    reached, broken, untried = await _complete_each_pair(
        "ollama",
        pairs,
        "",
        deadline=deadline,
        disable_thinking=bool(v.get("ollama_disable_thinking")),
        num_ctx=int(v.get("ollama_num_ctx") or 0) or None,
        keep_alive=str(v.get("ollama_keep_alive") or "") or None,
    )
    return _completed(t0, reached, broken, untried, f"{len(models)} models available", models)


def _completed(
    t0: float,
    reached: list[dict[str, Any]],
    broken: list[str],
    untried: list[str],
    listing: str,
    models: list[str] | None = None,
) -> ProbeResult:
    """One probe result from the completions it made, and the pairs it may file.

    ``details["completions"]`` is what the settings route writes down, so what
    is filed and what was called are the same list rather than two computations
    that have to agree. A pair that timed out or was never started is in
    neither: the sentence names it and says to ask again, and nothing is
    recorded for it. A probe with such a pair is not a pass — the models it did
    reach answered, but the question the operator asked has not been answered
    in full.
    """
    answered = [pair for pair in reached if pair["ok"]]
    ok = bool(reached) and not broken and not untried
    said = list(broken)
    if untried:
        said.append(
            f"not tried within {int(LLM_PROBE_BUDGET_SECONDS)} s: "
            + ", ".join(untried)
            + " — press Test again to ask them"
        )
    detail = f"{listing}; " + (
        "; ".join(said)
        if said
        else ", ".join(str(pair["detail"]) for pair in answered) or "nothing to call"
    )
    return ProbeResult(ok, _ms(t0), detail, models, None, {"completions": reached})


async def _probe_llm_gemini(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    deadline = probe_deadline()
    headers = {"x-goog-api-key": str(v.get("gemini_api_key") or "")}
    ok, detail, r = await _get("https://generativelanguage.googleapis.com/v1beta/models", headers)
    if not ok or r is None:
        return ProbeResult(
            False, _ms(t0), _listing_failed("https://generativelanguage.googleapis.com", detail)
        )
    models = [m.get("name", "") for m in r.json().get("models", [])]
    model = v.get("gemini_expert_model") or (models[0] if models else "")
    pairs = _pairs_to_file(v, "gemini", endpoint_where("gemini"), str(model))
    reached, broken, untried = await _complete_each_pair(
        "gemini", pairs, str(v.get("gemini_api_key") or ""), deadline=deadline
    )
    return _completed(t0, reached, broken, untried, f"{len(models)} models listed", models)


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


async def context_window_facts(settings: Any) -> dict[str, Any]:
    """The window these settings' models serve, and what it gives one answer.

    Free of charge and asked of the operator's own endpoints: the same metadata
    requests the worker makes (``maljan.llm.context_window``), never a
    generation call. An endpoint that says nothing falls to the vendored table
    and then to the stated fallback, so this always answers and never raises.

    ``cap`` is what one tool answer would be allowed on an empty conversation,
    which is the largest it can be; a conversation with something in it gets
    less, and the run summary reports the range that actually applied. Where
    the window is unknown nothing is derived from it and ``cap`` is the
    documented constant, with ``remedy`` naming what would change that.
    ``setting`` is what ``core.preprocessing.max_tool_output_chars`` holds, so
    the console can say whether the window decides at all.
    """
    from maljan.agents.composition import analyst_keys
    from maljan.llm.context_window import (
        ANSWER_SHARE,
        UNKNOWN_WINDOW_REMEDY,
        ContextBudget,
        awindow_for_settings,
        generation_reserve,
    )

    configured = int(getattr(settings.preprocessing, "max_tool_output_chars", 0) or 0)
    try:
        agents = [*analyst_keys(settings), "judge"]
        window = await awindow_for_settings(settings, agents, probe=configured <= 0)
    except Exception as exc:  # noqa: BLE001 — a window is never worth a failed page
        logger.warning("the context window could not be learned: %s", type(exc).__name__)
        from maljan.llm.context_window import unknown_window

        window = unknown_window(f"the probe could not be made ({type(exc).__name__})")
    budget = ContextBudget(window, reply_tokens=generation_reserve(settings))
    return {
        "tokens": window.tokens,
        "source": window.source,
        "detail": window.detail,
        "chars_per_token": budget.chars_per_token,
        "reply_tokens": budget.reply_tokens,
        "answer_share": ANSWER_SHARE,
        "cap": configured if configured > 0 else budget.cap_without_recording(),
        "derived": configured <= 0,
        "setting": configured,
        "remedy": "" if budget.derives or configured > 0 else UNKNOWN_WINDOW_REMEDY,
    }


def _ghidra_tool_names(schema: Any) -> list[str]:
    """The tool names ``GhidraHTTPClient`` derives from the server's schema.

    Same rule as ``_create_langchain_tool``: a tool is its ``path`` with the
    leading slash dropped and the remaining slashes joined by underscores, so
    the names the probe lists are the names the model will call.
    """
    entries = schema.get("tools", []) if isinstance(schema, dict) else []
    names: list[str] = []
    for entry in entries:
        path = str(entry.get("path", "")) if isinstance(entry, dict) else ""
        if path:
            names.append(path.lstrip("/").replace("/", "_"))
    return names


async def probe_ghidra(v: dict[str, Any]) -> ProbeResult:
    """Fetch the tool schema, which is the authenticated endpoint a job uses first.

    ``/check_connection`` answers 200 without a token, so a probe against it
    reported a server as reachable while every job then failed with 401 on
    ``/mcp/schema``. Probing the schema proves the token as well as the
    address, and hands the editor the manifest for its tick boxes.
    """
    t0 = time.perf_counter()
    headers = {"Authorization": f"Bearer {v['auth_token']}"} if v.get("auth_token") else None
    ok, detail, r = await _get(f"{str(v.get('url') or '').rstrip('/')}/mcp/schema", headers)
    if not ok or r is None:
        return ProbeResult(ok, _ms(t0), detail)
    try:
        names = _ghidra_tool_names(r.json())
    except ValueError:
        return ProbeResult(False, _ms(t0), f"{detail}; the schema was not JSON")
    return ProbeResult(True, _ms(t0), f"{len(names)} tools", None, names)


def _failure_detail(exc: BaseException) -> str:
    """One legible sentence for anything a probe can end with.

    An exception group is unwrapped to its leaves, because the group's own
    message ("unhandled errors in a TaskGroup") names nothing an operator can
    act on. A cancellation has no message at all, so it is worded here.
    """
    if isinstance(exc, BaseExceptionGroup):
        leaves = [_failure_detail(e) for e in exc.exceptions]
        return "; ".join(dict.fromkeys(leaves)) or "the probe was cancelled before it answered"
    if isinstance(exc, asyncio.CancelledError):
        return "the probe was cancelled before it answered"
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _probe_in_fresh_loop(factory: Callable[[], Awaitable[ProbeResult]]) -> ProbeResult:
    """Run one probe start to finish on an event loop of its own.

    A staged stdio entry whose command is not an MCP server used to answer
    HTTP 500. ``ServerHandle.aopen`` re-raises whatever
    ended the handshake unchanged, and a child that dies inside the transport's
    anyio task group ends it with a cancellation -- bare, or wrapped in the
    group's ``BaseExceptionGroup``. Neither is an ``Exception``, so the
    ``except Exception`` guards each probe already had let it through, and the
    request task inherited the cancellation: the handler produced no response
    at all and ``BaseHTTPMiddleware.call_next`` raised "No response returned."
    The browser saw a bare connection failure with no CORS headers on it.

    Running the probe on a loop of its own is what makes that structurally
    impossible: a cancel scope can only reach tasks of the loop it belongs to,
    and no task of the request's loop is on this one. The handle is opened and
    closed on this same loop, which is the rule ``ServerHandle`` is built
    around (a stack unwinds where it was wound). Whatever comes out --
    exception, group, or cancellation -- becomes a ``ProbeResult`` here, so the
    caller has nothing left to inherit.

    Budgets are unchanged: ``PROBE_BUDGET_SECONDS`` and the agent probe's
    per-server multiple are applied inside this loop exactly as before. So is
    the child reaping -- ``aopen``'s own teardown runs here, and a cleanup
    detached with ``_detach_cleanup`` is awaited by ``asyncio.run``'s shutdown
    rather than dropped.
    """

    async def _runner() -> ProbeResult:
        try:
            return await factory()
        except BaseException as exc:  # noqa: BLE001 - reported, never re-raised
            logger.warning("probe failed: %s", _failure_detail(exc))
            return ProbeResult(False, 0, _failure_detail(exc))

    try:
        return asyncio.run(_runner())
    except BaseException as exc:  # noqa: BLE001 - a loop that could not even start
        logger.warning("probe loop failed: %s", _failure_detail(exc))
        return ProbeResult(False, 0, _failure_detail(exc))


async def in_probe_loop(factory: Callable[[], Awaitable[ProbeResult]]) -> ProbeResult:
    """Await ``factory`` on a worker thread's own loop. Never raises."""
    return await asyncio.to_thread(_probe_in_fresh_loop, factory)


_PROBE_CLEANUP_TASKS: set[asyncio.Task[Any]] = set()


def _detach_cleanup(coro: Any, label: str) -> None:
    """Run ``coro`` to completion without making the caller wait for it.

    ``handle.aclose()`` is already internally bounded (``_acleanup``'s own
    20 s timeout); awaiting it here on top of a failed/timed-out ``aopen``
    re-adds that whole budget to a probe the operator's own click is
    documented at 5 s. A strong reference is kept in
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
    """Attach ``config`` long enough to read its tool names, then let go."""
    names, _capabilities = await handshake(config, name)
    return names


async def handshake(config: MCPServerConfig, name: str) -> tuple[list[str], dict[str, Any] | None]:
    """Attach ``config`` long enough to read its manifest, then let go.

    Returns the tool names and, when the server offers ``capabilities``, that
    manifest as a plain dict — which tools are available on the server's host
    and why the others are not — so the console can say so before a run.

    The only stdio handshake in the project besides a job's own: it is
    ``ServerHandle``, so a server that answers here answers the same way in a
    run. Whatever happens, the handle is eventually closed — a probe that
    leaves a child process behind turns a mis-typed command into a slow leak
    of subprocesses, which is exactly what a person clicking "Test" twice
    would produce.

    A plain ``asyncio.wait_for(handle.aopen(...), 5.0)``
    does not give up after 5 s when ``aopen`` is wedged. ``wait_for`` cancels
    the inner coroutine and then *waits for the cancellation to finish* before
    raising ``TimeoutError`` — and ``aopen``'s own cancellation handler awaits
    ``_acleanup``, itself bounded at 20 s, so the operator's "Test" click can
    take ~25 s instead of the documented 5. ``asyncio.wait`` never cancels the
    handshake: past the budget this simply stops waiting on it and lets it
    (and its own cleanup) finish in the background, closing the handle once
    it does.
    """
    from maljan.tools import staging

    handle = ServerHandle(name, config)
    # Per call, not per server. A probe is not a job, so the directory its
    # identity names is this call's to take away — and two operators pressing
    # Test on one server at the same time would otherwise share a leaf, so one
    # call's cleanup would remove the other call's directory while it was
    # still using it.
    probe_key = f"probe-{name}-{uuid.uuid4().hex[:8]}"

    async def _run() -> tuple[list[str], dict[str, Any] | None]:
        await handle.aopen(probe_key)
        capabilities = getattr(handle, "capabilities", None)
        to_dict = getattr(capabilities, "to_dict", None)
        return handle.all_tool_names(), (to_dict() if callable(to_dict) else None)

    # Every way out of this — the answer, a failure, and the timeout that
    # raises out of the branch below — leaves the directory removed. A probe
    # stages nothing, so there is normally nothing there; what makes this worth
    # the line is that the one path that used to skip it, the timeout, is the
    # path on which a server *was* started and may have written something.
    try:
        task: asyncio.Task[tuple[list[str], dict[str, Any] | None]] = asyncio.ensure_future(_run())
        done, _pending = await asyncio.wait({task}, timeout=PROBE_BUDGET_SECONDS)
        if task not in done:
            # Ask it to stop, but do not wait for that to finish here — that
            # wait is exactly the ~20 s ``_acleanup`` budget this fix avoids
            # blocking on. A short, fixed grace period still lets the common
            # case (a cancellation that responds immediately) close the handle
            # before this returns; a genuinely wedged server closes later, from
            # the callback, once its own cancellation finally unwinds.
            task.cancel()
            done2, _pending2 = await asyncio.wait({task}, timeout=0.1)
            if task in done2:
                await handle.aclose()
            else:
                task.add_done_callback(lambda _t: _detach_cleanup(handle.aclose(), probe_key))
            raise TimeoutError(f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s")
        try:
            return task.result()
        finally:
            await handle.aclose()
    finally:
        staging.remove_job_staging(probe_key)


def _probe_config(entry: dict[str, Any], name: str) -> MCPServerConfig:
    """The entry as configured, forced on and un-narrowed.

    A probe answers "what does this server offer"; a disabled entry or an
    empty allow-list are answers to a different question ("what may the model
    call"), and applying them here would make the manifest unreadable exactly
    when the operator needs it to pick from.

    ``name`` is the server's key, not a label: it decides whether this is a
    built-in, and a built-in is started with the environment names a job
    starts it with (``builtin_env_allow``) rather than with whatever a stored
    row holds — the probe exists so that the console tests the same server the
    run gets.
    """
    config = MCPServerConfig.model_validate(entry)
    update: dict[str, Any] = {"enabled": True, "tools": None}
    if name in BUILTIN_SERVER_KEYS:
        update["env_allow"] = builtin_env_allow(name, config.env_allow)
    return config.model_copy(update=update)


async def probe_mcp(v: dict[str, Any]) -> ProbeResult:
    """Launch one configured MCP server and list the tools it offers."""
    t0 = time.perf_counter()
    name = str(v.get("name") or "server")
    try:
        config = _probe_config(dict(v.get("entry") or {}), name)
    except ValidationError as exc:
        fields = _validation_detail(exc)
        return ProbeResult(False, _ms(t0), f"invalid server settings: {fields}")
    # VirusTotal's endpoint answers an unauthenticated handshake with a
    # transport error whose text says nothing about credentials, so the one
    # state an operator actually lands in -- the built-in is there, nobody has
    # registered yet -- is named here instead of being read out of a stack
    # trace. Only this server: every other token-less server may legitimately
    # be open.
    if name == virustotal.SERVER_KEY and not config.auth_token.get_secret_value():
        return ProbeResult(False, _ms(t0), virustotal.NO_TOKEN_DETAIL)
    try:
        names, capabilities = await handshake(config, name)
    except TimeoutError:
        return ProbeResult(False, _ms(t0), f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s")
    except FileNotFoundError as exc:
        return ProbeResult(False, _ms(t0), f"{exc} not found on PATH")
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    listed = ", ".join(names[:8]) + ("…" if len(names) > 8 else "")
    detail = f"{len(names)} tools: {listed}"
    details: dict[str, Any] | None = None
    if capabilities is not None:
        unavailable = [
            cell for cell in capabilities.get("tools", []) if not cell.get("available", True)
        ]
        if unavailable:
            detail += f"; {len(unavailable)} unavailable on this host"
        details = {"capabilities": capabilities}
    return ProbeResult(True, _ms(t0), detail, None, names, details)


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
        # Fall back to the default settings: a built-in the operator has
        # never edited has no stored row at all.
        effective = build_settings({}).mcp.servers
        if server not in effective:
            available = (
                ", ".join(sorted(set(stored_map) | set(staged_map) | set(effective))) or "(none)"
            )
            return ProbeResult(False, 0, f"unknown server: {server!r}. Available: {available}")
        entry = effective[server].model_dump(mode="json")
    else:
        entry = _merge_server_entry(stored_map.get(server) or {}, staged_map.get(server) or {})
    return await in_probe_loop(lambda: probe_mcp({"name": server, "entry": entry}))


async def probe_agent(v: dict[str, Any]) -> ProbeResult:
    """Resolve one agent definition against the given settings, without running it.

    The prompt is assembled, the tool servers are opened on the ordinary probe
    budget and their manifests read, and the model is asked for one short
    answer at the endpoint this agent would call. ``aresolve_agent`` is the
    same function a run calls, so what this reports is what that run receives;
    the completion is there because submitting a job is refused on the
    strength of this probe, and a gate has to rest on a call that was made.
    """
    import hashlib

    t0 = time.perf_counter()
    name = str(v.get("name") or "")
    try:
        core = dict(v.get("settings") or {})
        settings = build_settings(core)
    except ValidationError as exc:
        fields = _validation_detail(exc)
        return ProbeResult(False, _ms(t0), f"invalid agent settings: {fields}")
    if name not in settings.agents.definitions:
        available = ", ".join(sorted(settings.agents.definitions)) or "(none)"
        return ProbeResult(False, _ms(t0), f"unknown agent: {name!r}. Available: {available}")

    from maljan.agents.composition import aresolve_agent
    from maljan.core.config import ToolRef
    from maljan.core.container import ServiceContainer

    definition = settings.agents.definitions[name]
    bound = [
        key
        for key, server in settings.mcp.servers.items()
        if server.enabled and name in server.agents
    ]
    bound += [
        str(ref.server)
        for ref in definition.tools
        if ref.kind == "mcp" and str(ref.server) not in bound
    ]
    bound = list(dict.fromkeys(bound))

    # One server's own open, at B's budget; the whole resolution gets that
    # budget once per server bound to the agent, never a fixed multiple —
    # an agent with five servers legitimately needs five times as long as
    # one with one, and an agent with none should not wait for one either.
    budget = PROBE_BUDGET_SECONDS * max(1, len(bound))
    # Per call: see ``handshake_tools``. The container carries it, so every
    # handle this probe opens — its agent's servers and any static provider
    # the definition references — opens under one identity that is this call's.
    job_key = f"probe-{name}-{uuid.uuid4().hex[:8]}"

    # ``mock=True`` is what makes this cheap and safe: the container builds no
    # LLM registry at all, so ``get_agent_llm`` would raise rather than reach a
    # provider. The model is reported from the settings instead, below.
    container = ServiceContainer(settings, mock=True, job_id=job_key)

    # The same fix, reused rather than re-derived: ``asyncio.wait_for`` waits
    # for the cancelled coroutine's own cleanup before raising, and a wedged
    # server open's cleanup is exactly the wait a 5 s-per-server probe budget
    # cannot afford. ``asyncio.wait`` stops waiting at the budget and lets a
    # still-running attach (and the container's own teardown) finish in the
    # background instead — see ``handshake_tools`` for the same shape.
    task: asyncio.Task[Any] = asyncio.ensure_future(
        aresolve_agent(name, container, job_key=job_key)
    )
    done, _pending = await asyncio.wait({task}, timeout=budget)
    if task not in done:
        task.cancel()
        done2, _pending2 = await asyncio.wait({task}, timeout=0.1)
        if task in done2:
            await container.aclose()
        else:
            task.add_done_callback(lambda _t: _detach_cleanup(container.aclose(), job_key))
        return ProbeResult(
            False, _ms(t0), f"the agent's servers did not answer within {budget:.0f} s"
        )
    try:
        resolved = task.result()
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        await container.aclose()
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")

    # From here on, the container is open and must close on every exit —
    # a successful report, an unexpected failure while assembling one, or a
    # single server's listing blowing up. ``finally`` is what makes that true
    # regardless of which of those three happens; a bare ``await
    # container.aclose()`` after the loop, as before, skipped entirely on an
    # exception and leaked every server the resolve above had just opened.
    try:
        tools = [str(getattr(t, "name", "")) for t in resolved.tools]
        reasons = set(resolved.degradation_reasons)
        registry = container.get_server_registry()
        servers = []
        for key in bound:
            try:
                server_tools, _server_reasons = await registry.atools_for_ref(
                    ToolRef(kind="mcp", server=key), job_key
                )
            except Exception as exc:  # noqa: BLE001 — degrades this server, not the probe
                servers.append({"key": key, "tools": [], "status": f"{type(exc).__name__}: {exc}"})
                continue
            servers.append(
                {
                    "key": key,
                    "tools": [str(getattr(t, "name", "")) for t in server_tools],
                    "status": next((r for r in reasons if f"'{key}" in r), "ok"),
                }
            )
        agent_llm = settings.llm.agents.get(name)
        llm_provider = agent_llm.provider if agent_llm else settings.llm.provider
        # No per-agent override means the agent inherits the global expert
        # model; reporting "" left the operator to work out which provider
        # block that came from. ``expert_model`` already picks the leaf the
        # selected provider uses.
        llm_model = agent_llm.model if agent_llm else settings.llm.expert_model
        listed = ", ".join(tools[:8]) + ("…" if len(tools) > 8 else "")
        detail = f"{len(tools)} tools: {listed}" if tools else "resolved; no tools"
        # The model is the one thing resolution cannot answer for. Listing a
        # provider's catalogue is not enough either: a server can offer a name
        # it will not load, a key can be refused for one model and not
        # another, and a misspelling can land on a name the catalogue happens
        # to hold. Submitting a job refuses a team on the strength of this
        # probe, so the probe makes the call the job will make — one turn,
        # eight tokens, at the agent's own endpoint and on its own model.
        endpoint = endpoint_for(
            settings, llm_provider, getattr(agent_llm, "base_url", None) if agent_llm else None
        )

        async def _ask(provider: str, where: str, model: str) -> tuple[bool | None, str]:
            return await complete_one_turn(
                provider,
                endpoint=where,
                model=model,
                api_key=_provider_key(settings, provider),
                # An agent's own endpoint gets the body its own run would carry.
                # Each provider is asked about its own thinking switch — the two
                # are spelled differently and read by different code — and
                # ``compat`` belongs to the OpenAI block alone.
                disable_thinking=(
                    bool(settings.llm.ollama.disable_thinking)
                    if provider == "ollama"
                    else bool(settings.llm.openai.disable_thinking)
                ),
                compat=str(settings.llm.openai.compat or "auto"),
                reasoning_effort=(
                    str(settings.llm.openai.reasoning_effort or "") if provider == "openai" else ""
                ),
                # Ollama loads a model at the window and for the keep-alive the
                # request names; asked the way the job asks, the probe leaves
                # loaded the instance the job's first call will find.
                num_ctx=int(settings.llm.ollama.num_ctx) if provider == "ollama" else None,
                keep_alive=str(settings.llm.ollama.keep_alive) if provider == "ollama" else None,
            )

        answered, said = await _ask(llm_provider, endpoint, str(llm_model or ""))
        detail = f"{detail}; {said}"
        # A call that ran out of time proves nothing either way, so the probe
        # reports it as a failure the operator can act on and files no row —
        # a cold model is not a missing one.
        completions = (
            []
            if answered is None
            else [
                {
                    "endpoint": endpoint,
                    "model": str(llm_model or ""),
                    "provider": llm_provider,
                    "ok": bool(answered),
                    "detail": said,
                }
            ]
        )
        # Each model the agent falls back to is asked the same one turn, one
        # after another, and filed under its own pair: the gate refuses a job
        # whose fallback no probe has reached, and this is the probe that
        # reaches it. The agent passes only when every model on its list did.
        for position, choice in enumerate(getattr(agent_llm, "fallbacks", None) or [], 1):
            where = endpoint_for(settings, choice.provider, choice.base_url)
            reached, told = await _ask(choice.provider, where, str(choice.model))
            detail = f"{detail}; fallback {position} {choice.provider}/{choice.model}: {told}"
            if reached is not None:
                completions.append(
                    {
                        "endpoint": where,
                        "model": str(choice.model),
                        "provider": choice.provider,
                        "ok": bool(reached),
                        "detail": told,
                    }
                )
            answered = bool(answered) and bool(reached)
        return ProbeResult(
            bool(answered),
            _ms(t0),
            detail,
            None,
            tools,
            {
                "completions": completions,
                "prompt_chars": len(resolved.prompt),
                "prompt_sha256": hashlib.sha256(resolved.prompt.encode("utf-8")).hexdigest(),
                # Prompts are operator-authored text, not secrets (spec §11),
                # so the probe returns it in full: the settings UI shows a
                # built-in's resolved prompt read-only, and a clone seeds its
                # copy from this text rather than guessing it.
                "prompt": resolved.prompt,
                # The same text without the platform's sentence about the
                # agent's tools, which is what a clone copies: the clone gets a
                # sentence of its own, for its own tool list.
                "authored_prompt": resolved.authored_prompt or resolved.prompt,
                "llm": {
                    "provider": llm_provider,
                    "model": llm_model,
                    # Where the call went, so the probe's answer is filed
                    # under the pair it was taken against.
                    "endpoint": endpoint,
                },
                "static_provider": resolved.static_provider_id,
                "servers": servers,
            },
        )
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    finally:
        await container.aclose()


def _provider_key(settings: Any, provider: str) -> str:
    """The credential a provider authenticates with, as a plain string.

    A per-agent entry may point at its own endpoint, but never carries its own
    key: the credential stays global (``AgentLLMConfig``), so one lookup by
    provider answers for every agent.
    """
    block = getattr(settings.llm, provider, None)
    secret = getattr(block, "api_key", None)
    if secret is None:
        return ""
    reveal = getattr(secret, "get_secret_value", None)
    return str(reveal() if callable(reveal) else secret)


async def run_agent_probe(name: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult:
    """Probe one agent definition, staged values winning over stored ones.

    Separate from ``run_probe`` for the reason ``run_mcp_probe`` is: the probe
    is addressed to a *key* inside a setting, and ``_INPUTS`` maps catalog keys
    to short names with no entry for "the strings definition".
    """
    merged: dict[str, Any] = {}
    for layer in (stored, values):
        for key, value in layer.items():
            if key.startswith("core."):
                merged[key[len("core.") :]] = value
    return await in_probe_loop(lambda: probe_agent({"name": name, "settings": merged}))


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
    open_channels = v.get("mapping_channels")
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
                channels=open_channels if isinstance(open_channels, dict) else {},
            ),
            timeout_seconds=int(v.get("timeout_seconds") or 900),
            poll_interval_seconds=int(v.get("poll_interval_seconds") or 15),
            verify_tls=bool(v.get("verify_tls", True)),
        )
        provider = RestSandboxProvider(rest, compile_mapping(rest.mapping))
    except (ProviderConfigurationError, ValidationError) as exc:
        fields = _validation_detail(exc) if isinstance(exc, ValidationError) else str(exc)
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
    "agent": probe_agent,
}

# Which settings each probe reads, and the short name it gets them under.
_INPUTS: dict[str, dict[str, str]] = {
    "llm": {
        "core.llm.provider": "provider",
        "core.llm.openai.base_url": "base_url",
        "core.llm.openai.api_key": "api_key",
        "core.llm.openai.expert_model": "expert_model",
        "core.llm.openai.judge_model": "judge_model",
        # The two leaves that shape an OpenAI-compatible request body. A probe
        # that asked without them asked a question no agent asks.
        "core.llm.openai.compat": "compat",
        "core.llm.openai.disable_thinking": "disable_thinking",
        "core.llm.openai.reasoning_effort": "reasoning_effort",
        "core.llm.anthropic.api_key": "anthropic_api_key",
        "core.llm.anthropic.expert_model": "anthropic_expert_model",
        "core.llm.anthropic.judge_model": "anthropic_judge_model",
        "core.llm.ollama.base_url": "ollama_base_url",
        "core.llm.ollama.expert_model": "ollama_expert_model",
        "core.llm.ollama.judge_model": "ollama_judge_model",
        "core.llm.ollama.disable_thinking": "ollama_disable_thinking",
        # The two leaves that decide which instance Ollama keeps loaded.
        "core.llm.ollama.num_ctx": "ollama_num_ctx",
        "core.llm.ollama.keep_alive": "ollama_keep_alive",
        "core.llm.gemini.api_key": "gemini_api_key",
        "core.llm.gemini.expert_model": "gemini_expert_model",
        "core.llm.gemini.judge_model": "gemini_judge_model",
        "core.llm.agents": "agents",
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
        "core.sandbox.rest.mapping.channels": "mapping_channels",
    },
    "agent": {},
}


def _unwrap(value: Any) -> Any:
    return value.get_secret_value() if hasattr(value, "get_secret_value") else value


def candidate_settings(values: dict[str, Any], stored: dict[str, Any]) -> Any:
    """The core settings a probe of these staged values would run against.

    Staged over stored, the same layering every probe reads, exported because
    the caller that records what a probe reached needs the same answer: which
    endpoint, and which model, the values under test name.
    """
    core_layer = {split_key(k)[1]: v for k, v in stored.items() if k.startswith("core.")}
    core_layer.update(
        {split_key(k)[1]: v for k, v in values.items() if k.startswith("core.") and v is not None}
    )
    return build_settings(core_layer)


async def run_probe(name: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult:
    probe = PROBES[name]
    try:
        core = candidate_settings(values, stored)
    except (ValueError, ValidationError) as exc:
        # A malformed key or a staged value the model rejects is an operator
        # error, not a route error. Name the fields and why they were
        # rejected, never echo the values.
        fields = _validation_detail(exc) if isinstance(exc, ValidationError) else type(exc).__name__
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
        elif path in API_DEFAULTS:
            # Editable api.* leaves no longer live on APISettings;
            # their probe-time default comes from the catalog table instead.
            resolved[short] = _unwrap(API_DEFAULTS[path])
        else:
            resolved[short] = _unwrap(getattr(api_settings, path))
    # Deliberately no context-window block on the probe result. The window is
    # a fact about the endpoint rather than about whether a model answered, the
    # settings page reads it from its own route, and computing it here spent up
    # to three metadata requests per Test press on something no surface drew.
    return await in_probe_loop(lambda: probe(resolved))
