"""Connection tests for settings the UI is about to save. Nothing is persisted.

Every provider answers for itself: the model probe asks the selected LLM
provider's adapter (``maljan.llm.provider_base``) where its models are listed,
which request one short turn is and how its answer is read; a static or
sandbox provider is built from the candidate settings and its own ``probe()``
is asked; a memory backend's ``readiness()``; a reputation source's
``probe()``. Nothing here names a provider.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from maljan.core.config import BUILTIN_SERVER_KEYS, MCPServerConfig, builtin_env_allow
from maljan.core.logger import logger
from maljan.core.model_assignments import endpoint_for, endpoint_label
from maljan.core.plugins import ALLOW_LIST_KEY, PLUGIN_GROUPS
from maljan.core.settings_overrides import build_settings, redact_url, split_key
from maljan.core.tool_declarations import SANDBOX_ROLE
from maljan.llm.provider_base import COMPLETION_MAX_TOKENS as _COMPLETION_MAX_TOKENS
from maljan.llm.provider_base import COMPLETION_PROMPT as _COMPLETION_PROMPT
from maljan.llm.provider_base import facts_of
from maljan.providers import server_probe
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.servers import ServerHandle
from pydantic import ValidationError
from redis.asyncio import Redis

from app.config import settings as api_settings
from app.services.server_map import TOKEN_MASK as _TOKEN_MASK
from app.services.settings_catalog_api import API_DEFAULTS

TIMEOUT = 10.0

# What the MCP probe says about a server that declares how its credential is
# obtained (``credential_bootstrap``) and holds none yet.
NO_CREDENTIAL_DETAIL = (
    "no credential: obtain one with this server's step in the tool-server setup "
    "guide, or paste a token into this server's token field"
)

# A connection test is a person waiting at a button
# (``server_probe.PROBE_BUDGET_SECONDS``).
PROBE_BUDGET_SECONDS = server_probe.PROBE_BUDGET_SECONDS


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


# What every completion probe asks for and how much of an answer it takes: the
# adapters build the request (``LLMProvider.one_turn_request``) around these.
COMPLETION_PROMPT = _COMPLETION_PROMPT
COMPLETION_MAX_TOKENS = _COMPLETION_MAX_TOKENS

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
    settings: Any = None,
    effort: str | None = None,
) -> tuple[bool | None, str]:
    """Ask ``model`` at ``endpoint`` for one short answer, as ``provider``'s adapter builds it.

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

    ``settings`` are the settings the request is shaped from, as an agent's
    would be (the provider's own switches, its window, its keep-alive);
    ``None`` reads the shipped defaults. ``effort`` is the effort the run
    sends: the model's own, else the provider's global one.

    Never raises: a probe answers with what happened, including when what
    happened is that nothing did.
    """
    model = str(model or "").strip()
    if not model:
        return False, "no model named"
    if settings is None:
        settings = build_settings({})
    facts = facts_of(provider)
    request = facts.one_turn_request(settings, endpoint, model, effort)
    if request is None:
        return False, f"unknown provider: {provider!r}"
    remedy = facts.silence_remedy(settings)
    try:
        async with _client(COMPLETION_TIMEOUT) as client:
            answer = await client.post(request.url, headers=request.headers, json=request.body)
    except httpx.TimeoutException:
        return None, (
            f"{model!r} did not answer within {int(COMPLETION_TIMEOUT)} s; it may still be "
            "loading — try again once it is warm. Nothing was written down for it." + remedy
        )
    except httpx.HTTPError as exc:
        return False, redact_url(f"{model!r} could not be reached: {type(exc).__name__}: {exc}")
    if answer.status_code >= 400:
        return False, f"{model!r} answered HTTP {answer.status_code}"
    if not _said_something(facts, answer):
        # A 2xx with nothing in it is the failure this check exists for: a
        # proxy that answers politely for a model it cannot serve, a response
        # whose only candidate was filtered away. The full stop belongs to
        # this sentence, not to the remedy that may follow it.
        return False, f"{model!r} answered nothing." + remedy
    return True, f"{model!r} answered"


def _said_something(facts: Any, answer: httpx.Response) -> bool:
    """Whether the provider's answer carries text or a tool call.

    The adapter reads its own answer shape (``LLMProvider.said_something``). A
    body that is not JSON, or JSON that is not an object, counts as an answer:
    the endpoint said something, and inventing a failure from a shape nobody
    anticipated would be worse than missing an empty one.
    """
    try:
        payload = answer.json()
    except ValueError:
        return bool(answer.content)
    if not isinstance(payload, dict):
        return bool(payload)
    return bool(facts.said_something(payload))


def _listing_failed(endpoint: str, detail: str) -> str:
    """A catalogue read that failed, and where it was tried.

    "model list: connection refused" is the same sentence whichever endpoint
    was configured, and an operator with two servers staged cannot tell which
    one refused them. ``endpoint_label`` keeps the scheme and the host and
    drops the path, the query and any credential in front of it, which is
    exactly as much as a failure message may carry.
    """
    label = endpoint_label(endpoint)
    return f"model list at {label}: {detail}" if label else f"model list: {detail}"


async def probe_llm(settings: Any) -> ProbeResult:
    """List the selected provider's models, then ask each model a run would call one turn.

    Every step is the provider's own (``maljan.llm.provider_base``): where its
    models are listed and how a name is read, which model is asked first, the
    request and how its answer is read. A provider that lists nothing is asked
    without a listing.
    """
    t0 = time.perf_counter()
    deadline = probe_deadline()
    provider = str(settings.llm.provider)
    from maljan.llm.provider_base import provider_names

    if provider not in provider_names():
        # Named by its setting, never by what was typed into it.
        return ProbeResult(False, _ms(t0), "llm.provider names no registered LLM provider")
    facts = facts_of(provider)
    listing = facts.model_listing(settings)
    models: list[str] = []
    said_listing = "no model list"
    if listing is not None:
        ok, detail, r = await _get(listing.url, listing.headers)
        if not ok or r is None:
            return ProbeResult(False, _ms(t0), _listing_failed(listing.where, detail))
        try:
            models = [str(name) for name in listing.names(r.json())]
        except ValueError:
            return ProbeResult(
                False, _ms(t0), _listing_failed(listing.where, f"{detail}; not JSON")
            )
        if listing.check is not None:
            missing = listing.check(settings, models)
            if missing:
                return ProbeResult(False, _ms(t0), missing, models)
        said_listing = f"{len(models)} {listing.noun}"
    elif facts.one_turn_request(settings, "", "probe") is None:
        return ProbeResult(False, _ms(t0), f"the {provider!r} provider offers no connection test")
    model = facts.probed_model(settings, models)
    pairs = _pairs_to_file(settings, provider, endpoint_for(settings, provider), str(model))
    # Every pair, the per-agent ones at their own endpoints included, is asked
    # with the request body its agent would send.
    reached, broken, untried = await _complete_each_pair(
        settings, provider, pairs, deadline=deadline
    )
    return _completed(
        t0, reached, broken, untried, said_listing, models if listing is not None else None
    )


def _agent_models(settings: Any, provider: str) -> dict[str, tuple[str, str | None, str | None]]:
    """Every ``llm.agents`` entry served by ``provider``, name to (model, base_url, effort).

    An entry names its own provider; one that leaves it empty inherits the
    global ``llm.provider``. The base URL comes back beside the model because
    an entry may point at its own server: asking the global one about a model
    the agent will look for somewhere else answers a different question.
    ``None`` means the entry inherits the global endpoint. The effort is the
    model's own, ``None`` where it inherits the provider's global one. The
    models an entry falls back to are asked exactly as its first one is: a
    fallback is a model the run may call, and the gate refuses a job whose
    fallback no probe has reached.
    """
    global_provider = str(settings.llm.provider)
    out: dict[str, tuple[str, str | None, str | None]] = {}
    for name, entry in (settings.llm.agents or {}).items():
        chain = entry.chain() if hasattr(entry, "chain") else [entry]
        for position, row in enumerate(chain):
            entry_provider = str(getattr(row, "provider", "") or "") or global_provider
            model = str(getattr(row, "model", "") or "")
            base_url = str(getattr(row, "base_url", "") or "").strip() or None
            effort = str(getattr(row, "effort", "") or "").strip() or None
            if model and entry_provider == provider:
                label = str(name) if position == 0 else f"{name} fallback {position}"
                out[label] = (model, base_url, effort)
    return out


def _pairs_to_file(
    settings: Any, provider: str, base: str, expert_model: str
) -> dict[tuple[str, str, str | None], str]:
    """Every ``(endpoint, model, effort)`` this probe will file, each one once.

    The effort is an entry's own, ``None`` where it inherits the provider's
    global one: two entries on one model at different efforts are two
    questions, and each is asked at the effort its run sends.

    The selected provider's expert model at its own endpoint, and every
    per-agent override at *its* own endpoint — a second server on another
    port is the ordinary shape of a deployment, and it is never listed by the
    global one. Keyed on the pair and not on the label, so a deployment that
    pins five agents to the global model at the global endpoint is one call and
    one row rather than six of each.

    The endpoint comes from ``endpoint_for`` — the function the submit gate
    resolves its own key with — so what is filed and what is looked up are one
    spelling of one address.
    """
    pairs: dict[tuple[str, str, str | None], str] = {
        (base, expert_model, None): f"expert={expert_model} @ {endpoint_label(base)}"
    }
    for name, (model, agent_base, effort) in sorted(_agent_models(settings, provider).items()):
        endpoint = endpoint_for(settings, provider, agent_base)
        at = f" at effort {effort}" if effort else ""
        pairs.setdefault(
            (endpoint, model, effort), f"{name}={model}{at} @ {endpoint_label(endpoint)}"
        )
    return pairs


def _with_own_effort(completion: dict[str, Any], effort: str | None) -> dict[str, Any]:
    """``completion``, naming the model's own effort when one was asked at.

    The settings route files the row under the model and that effort
    (``filed_model``); a completion with none is filed as it always was.
    """
    if effort:
        completion["effort"] = effort
    return completion


async def _complete_each_pair(
    settings: Any,
    provider: str,
    pairs: dict[tuple[str, str, str | None], str],
    *,
    deadline: float,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """One completion per pair in turn; what was reached, what failed, what was not tried.

    Every pair the probe will file a row for is asked, at its own endpoint and
    on its own model, because a row filed from somebody else's call is the
    defect this whole gate exists to remove. A pair that timed out is left out
    of the first two lists: nothing was learned about it, so nothing is written
    down and the sentence the operator reads says to try again.

    One at a time, and the whole run inside ``LLM_PROBE_BUDGET_SECONDS``. A
    pair is only started when its own budget still fits in what is left of the
    probe's; the rest are handed back as not tried, under the same rule as a
    timeout — no row, and a sentence saying to ask again. ``deadline`` is taken
    by the caller as the probe begins.

    A pair is asked at its entry's own effort where it carries one, else at
    the provider's global effort, and its completion names its own so the row
    is filed under it.
    """
    from maljan.llm.effort import effort_in_force

    reached: list[dict[str, Any]] = []
    broken: list[str] = []
    untried: list[str] = []
    for (endpoint, model, own_effort), label in pairs.items():
        if time.monotonic() + COMPLETION_TIMEOUT > deadline:
            untried.append(label)
            continue
        effort, _ = effort_in_force(settings, provider, own_effort)
        answered, said = await complete_one_turn(
            provider, endpoint=endpoint, model=model, settings=settings, effort=effort
        )
        if answered is None:
            broken.append(f"{label}: {said}")
            continue
        reached.append(
            _with_own_effort(
                {
                    "endpoint": endpoint,
                    "model": model,
                    "provider": provider,
                    "ok": bool(answered),
                    "detail": said,
                },
                own_effort,
            )
        )
        if not answered:
            broken.append(f"{label}: {said}")
    return reached, broken, untried


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
    from maljan.agents.composition import window_assignments
    from maljan.llm.context_window import (
        ANSWER_SHARE,
        ContextBudget,
        awindow_for_settings,
        generation_reserve,
        unknown_window_remedy,
    )

    configured = int(getattr(settings.preprocessing, "max_tool_output_chars", 0) or 0)
    assignments = window_assignments(settings)
    try:
        window = await awindow_for_settings(settings, assignments, probe=configured <= 0)
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
        "remedy": (
            ""
            if budget.derives or configured > 0
            else unknown_window_remedy(str(a.provider) for a in assignments)
        ),
    }


def _failure_detail(exc: BaseException) -> str:
    """One legible sentence for anything a probe can end with.

    An exception group is unwrapped to its leaves, because the group's own
    message ("unhandled errors in a TaskGroup") names nothing an operator can
    act on. A cancellation has no message at all, so it is worded here. A URL
    in the text loses its credentials: the address came from an operator's
    setting, and a provider's own failure may carry it whole.
    """
    if isinstance(exc, BaseExceptionGroup):
        leaves = [_failure_detail(e) for e in exc.exceptions]
        return "; ".join(dict.fromkeys(leaves)) or "the probe was cancelled before it answered"
    if isinstance(exc, asyncio.CancelledError):
        return "the probe was cancelled before it answered"
    text = str(exc).strip()
    return redact_url(f"{type(exc).__name__}: {text}" if text else type(exc).__name__)


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


def _detach_cleanup(coro: Any, label: str) -> None:
    """Run ``coro`` to completion without making the caller wait for it (``server_probe``)."""
    server_probe.detach_cleanup(coro, label)


async def handshake_tools(config: MCPServerConfig, name: str) -> list[str]:
    """Attach ``config`` long enough to read its tool names, then let go."""
    names, _capabilities = await handshake(config, name)
    return names


async def handshake(config: MCPServerConfig, name: str) -> tuple[list[str], dict[str, Any] | None]:
    """Attach ``config`` long enough to read its manifest, then let go.

    Returns the tool names and, when the server offers ``capabilities``, that
    manifest as a plain dict, so the console can say which tools are available
    on the server's host before a run. ``server_probe.handshake`` does the
    work, on this module's budget and handle class.
    """
    return await server_probe.handshake(
        config, name, budget=PROBE_BUDGET_SECONDS, handle_factory=ServerHandle
    )


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
    run gets. Its tool declarations are read as every path reads a sent map
    (``tool_declarations.sent_in_force``): marked, as the entry's changes over
    what the server ships, as the console stages them; without the mark,
    whole, as an earlier release read it.
    """
    from maljan.core.settings_overrides import SERVER_MAP_PATH, shipped_tool_facts
    from maljan.core.tool_declarations import sent_in_force

    facts = entry.get("tool_facts")
    if isinstance(facts, dict):
        shipped = shipped_tool_facts(f"{SERVER_MAP_PATH}.{name}")
        entry = {**entry, "tool_facts": sent_in_force(shipped, facts)}
    config = MCPServerConfig.model_validate(entry)
    update: dict[str, Any] = {"enabled": True, "tools": None}
    if name in BUILTIN_SERVER_KEYS:
        update["env_allow"] = builtin_env_allow(name, config.env_allow)
    return config.model_copy(update=update)


def _declared_tools(config: MCPServerConfig, name: str) -> frozenset[str]:
    """The tools ``name`` declares as the entry probed has them in force.

    An entry that sets its tool declarations has them in force already (the
    shipped ones with its changes over them, so a shipped tool it removed is
    undeclared); one that sets none has what the server ships.
    """
    from maljan.core.settings_overrides import SERVER_MAP_PATH, shipped_tool_facts

    if "tool_facts" in config.model_fields_set:
        return frozenset(config.tool_facts)
    return frozenset(shipped_tool_facts(f"{SERVER_MAP_PATH}.{name}"))


async def _inspect(
    config: MCPServerConfig, name: str, plan: Callable[[list[Any]], list[Any]] | None
) -> server_probe.Inspection:
    """Attach ``config`` to read what it says of its tools (``server_probe.inspect``)."""
    return await server_probe.inspect(
        config, name, budget=PROBE_BUDGET_SECONDS, handle_factory=ServerHandle, plan=plan
    )


def _proposals(
    found: server_probe.Inspection,
    declared: frozenset[str],
    *,
    withheld: list[str] | None,
    sandbox_source: bool = False,
    remote: bool = False,
) -> dict[str, Any] | None:
    """The declaration proposals for the tools ``found`` lists and nothing declares.

    Data for an admin to accept field by field (``core.declaration_proposals``);
    nothing here is saved and no run reads it. ``None`` when there is no tool
    to propose for. A proposal that cannot be built is reported as none rather
    than failing the connection test. ``withheld`` is what a confirmed call
    is made without (:func:`_withheld`); ``None`` when the server's
    declaration needs its credential and it is sent. ``sandbox_source`` says
    the server's declaration names it a sandbox source (its ``roles``), the
    only server whose tools may be proposed sandbox kinds. ``remote`` says it is
    reached at an address other jobs share (:func:`maljan.core.declaration_proposals.propose`).
    """
    from maljan.core.declaration_proposals import propose
    from maljan.tools.capabilities import CAPABILITIES_TOOL

    if not found.definitions:
        return None
    try:
        proposals = propose(
            found.definitions,
            capabilities=found.capabilities,
            answers=found.answers,
            skip=declared | {CAPABILITIES_TOOL},
            sandbox_source=sandbox_source,
            remote=remote,
        )
    except Exception as exc:  # noqa: BLE001 — a proposal is never worth the probe
        logger.warning("declaration proposals could not be built (%s).", type(exc).__name__)
        return None
    if found.probed:
        proposals["probed"] = dict(found.probed)
    # What each confirmed call would be made with: this server as configured,
    # less what ``withheld`` names, or its credential when its declaration
    # needs one.
    for call in proposals.get("planned") or []:
        call["credential"] = withheld is None
        call["withheld"] = list(withheld or [])
    held = proposals["tools"] or proposals["server"] or proposals.get("failed")
    held = held or proposals.get("notes")
    return proposals if held else None


def _needs_credential(config: MCPServerConfig) -> bool:
    """Whether the server's declaration says it needs a credential to answer at all."""
    return config.credential_bootstrap is not None or bool(config.required_env_allow)


def _withheld(config: MCPServerConfig) -> list[str] | None:
    """What a confirmed harmless call is made without: ``None`` when nothing is withheld by rule.

    The server is used exactly as configured (its URL, arguments and files);
    only its auth token and the environment values it does not declare
    non-secret (``variable_names``) are withheld, each named here, the
    environment by its variable's name. A server whose declaration says it
    needs a credential is sent it (``None``).
    """
    if _needs_credential(config):
        return None
    plain = set(config.variable_names)
    out = ["auth token"] if config.auth_token.get_secret_value() else []
    out.extend(f"environment {name}" for name in config.env if name not in plain)
    out.extend(
        f"environment {name}"
        for name in config.env_allow
        if name not in plain and name not in config.env
    )
    return out


def _without_credentials(config: MCPServerConfig) -> MCPServerConfig:
    """``config`` as configured, less what :func:`_withheld` names.

    The URL, arguments, command and working directory are kept exactly; the
    auth token is dropped and the environment keeps only the names the server
    declares non-secret. A server whose declaration needs a credential is
    returned unchanged.
    """
    if _needs_credential(config):
        return config
    from pydantic import SecretStr

    plain = set(config.variable_names)
    return config.model_copy(
        update={
            "auth_token": SecretStr(""),
            "env": {k: v for k, v in config.env.items() if k in plain},
            "env_allow": [n for n in config.env_allow if n in plain],
        }
    )


# What a probe note says when a call was made without withheld values.
WITHHELD_NOTE = "made without {withheld}"


async def _confirmed_calls(
    config: MCPServerConfig,
    name: str,
    plan: Callable[[list[Any]], list[Any]],
    withheld: list[str] | None,
) -> server_probe.Inspection | dict[str, str]:
    """The confirmed calls, on an attach of their own; never fails the connection test.

    Made on ``config`` less what ``withheld`` names. A server that does not
    start or answer that way is reported per planned tool, saying what was
    withheld; a call that answered with an error says the same, plainly.

    A stdio child that dies while it starts can end the attach with a bare
    ``asyncio.CancelledError`` (its transport's task group cancels the
    scope), or a group of such: that is the server's failure and is reported
    like any other. The probe's own cancellation is not, and propagates:
    it is told apart by this task's pending cancellation requests.
    """
    from maljan.tools.errors import error_parts

    attached = _without_credentials(config)
    missing = ", ".join(withheld or [])

    def _not_called(exc: BaseException) -> dict[str, str]:
        reason = f"not called: the server did not answer ({type(exc).__name__})"
        if missing:
            reason += f" when started without {missing}"
        return {"": reason}

    def _the_probe_is_cancelled() -> bool:
        task = asyncio.current_task()
        return task is not None and task.cancelling() > 0

    try:
        found = await _inspect(attached, name, plan)
    except asyncio.CancelledError as exc:
        if _the_probe_is_cancelled():
            raise
        return _not_called(exc)
    except BaseExceptionGroup as group:
        if _the_probe_is_cancelled() or (
            group.subgroup((KeyboardInterrupt, SystemExit)) is not None
        ):
            raise
        return _not_called(group)
    except Exception as exc:  # noqa: BLE001 — the calls are reported, never the test's failure
        return _not_called(exc)
    if missing:
        for tool, said in list(found.probed.items()):
            note = WITHHELD_NOTE.format(withheld=missing)
            answered = found.answers.get(tool)
            if answered is not None and error_parts(answered[1]) is not None:
                found.probed[tool] = f"{said}; it answered with an error, and was {note}"
            else:
                found.probed[tool] = f"{said}; {note}"
    return found


async def probe_mcp(v: dict[str, Any]) -> ProbeResult:
    """Launch one configured MCP server, list the tools it offers and propose their declarations.

    Nothing is called unless the operator confirmed it: the proposals list
    the harmless calls a tool its server marks read-only allows
    (``proposals.planned``), each saying what it would be made without.
    Only the tools named in ``confirmed_calls`` that are still planned are
    called, once each, on an attach of their own made with this server as
    configured less its auth token and secret environment values (unless its
    declaration needs a credential), so their answers can propose what the
    schemas do not say (``core.declaration_proposals``). The connection
    test's verdict is the configured server's handshake alone.
    """
    t0 = time.perf_counter()
    name = str(v.get("name") or "server")
    try:
        config = _probe_config(dict(v.get("entry") or {}), name)
    except ValidationError as exc:
        fields = _validation_detail(exc)
        return ProbeResult(False, _ms(t0), f"invalid server settings: {fields}")
    # A server that declares how its credential is obtained needs one: its
    # endpoint may answer an unauthenticated handshake with a transport error
    # whose text says nothing about credentials, so the state an operator
    # actually lands in -- the server is there, nobody has obtained its
    # credential yet -- is named here instead of being read out of a stack
    # trace. A server that declares no bootstrap may legitimately be open.
    if config.credential_bootstrap is not None and not config.auth_token.get_secret_value():
        return ProbeResult(False, _ms(t0), NO_CREDENTIAL_DETAIL)
    declared = _declared_tools(config, name)
    raw_confirmed = v.get("confirmed_calls")
    confirmed = (
        {str(t) for t in raw_confirmed if isinstance(t, str)}
        if isinstance(raw_confirmed, list | tuple | set)
        else set()
    )
    try:
        found = await _inspect(config, name, None)
        names, capabilities = found.names, found.capabilities
    except TimeoutError:
        return ProbeResult(False, _ms(t0), f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s")
    except FileNotFoundError as exc:
        return ProbeResult(False, _ms(t0), f"{exc} not found on PATH")
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    withheld = _withheld(config)
    if confirmed:
        from maljan.core.declaration_proposals import plan_calls
        from maljan.tools.capabilities import CAPABILITIES_TOOL

        def plan(definitions: list[Any]) -> list[Any]:
            planned = plan_calls(definitions, skip=declared | {CAPABILITIES_TOOL})
            return [call for call in planned if call.tool in confirmed]

        called = await _confirmed_calls(config, name, plan, withheld)
        if isinstance(called, dict):
            reason = called[""]
            try:
                planned_now = {c.tool for c in plan(found.definitions)}
            except Exception:  # noqa: BLE001 — a plan never costs the connection test
                planned_now = set()
            found.probed = {tool: reason for tool in sorted(planned_now)}
        else:
            found.answers, found.probed = called.answers, called.probed
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
    from maljan.providers.sample_open import is_shared_address

    proposals = _proposals(
        found,
        declared,
        withheld=withheld,
        sandbox_source=SANDBOX_ROLE in config.roles,
        remote=is_shared_address(config),
    )
    if proposals is not None:
        details = {**(details or {}), "proposals": proposals}
        detail += f"; declarations proposed for {len(proposals['tools'])} undeclared tools"
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


async def run_mcp_probe(
    server: str,
    values: dict[str, Any],
    stored: dict[str, Any],
    *,
    confirmed_calls: list[str] | None = None,
) -> ProbeResult:
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
    return await in_probe_loop(
        lambda: probe_mcp(
            {"name": server, "entry": entry, "confirmed_calls": list(confirmed_calls or [])}
        )
    )


async def _ask_each_model(
    settings: Any, name: str
) -> tuple[bool, str, list[dict[str, Any]], dict[str, Any]]:
    """Ask every model ``llm.agents.<name>`` lists for one short answer, in order.

    ``(answered, detail, completions, llm)``: whether every model answered,
    what each said, the completions to file under the pair each was asked at,
    and the first model's provider, model and endpoint. With no entry the
    global expert model is the one asked, which is what the run calls. Shared
    by an agent definition's probe and a role's (``mediator``, ``summarizer``),
    whose entry is read the same way.
    """
    agent_llm = settings.llm.agents.get(name)
    llm_provider = agent_llm.provider if agent_llm else settings.llm.provider
    # No per-agent override means the agent inherits the global expert
    # model; reporting "" left the operator to work out which provider
    # block that came from. ``expert_model`` already picks the leaf the
    # selected provider uses.
    llm_model = agent_llm.model if agent_llm else settings.llm.expert_model
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

    async def _ask(
        provider: str, where: str, model: str, own_effort: str | None = None
    ) -> tuple[bool | None, str]:
        from maljan.llm.effort import effort_in_force

        # The model's own effort (``llm.agents.<key>.effort``), else the
        # provider's global one, as the run sends it; the request body is the
        # one the agent's own run would carry, shaped by its provider.
        effort, _ = effort_in_force(settings, provider, own_effort)
        return await complete_one_turn(
            provider, endpoint=where, model=model, settings=settings, effort=effort
        )

    own_effort = getattr(agent_llm, "effort", None) if agent_llm else None
    answered, said = await _ask(llm_provider, endpoint, str(llm_model or ""), own_effort)
    detail = said
    # A call that ran out of time proves nothing either way, so the probe
    # reports it as a failure the operator can act on and files no row —
    # a cold model is not a missing one.
    completions = (
        []
        if answered is None
        else [
            _with_own_effort(
                {
                    "endpoint": endpoint,
                    "model": str(llm_model or ""),
                    "provider": llm_provider,
                    "ok": bool(answered),
                    "detail": said,
                },
                own_effort,
            )
        ]
    )
    # Each model the agent falls back to is asked the same one turn, one
    # after another, and filed under its own pair: the gate refuses a job
    # whose fallback no probe has reached, and this is the probe that
    # reaches it. The agent passes only when every model on its list did.
    for position, choice in enumerate(getattr(agent_llm, "fallbacks", None) or [], 1):
        where = endpoint_for(settings, choice.provider, choice.base_url)
        reached, told = await _ask(
            choice.provider, where, str(choice.model), getattr(choice, "effort", None)
        )
        detail = f"{detail}; fallback {position} {choice.provider}/{choice.model}: {told}"
        if reached is not None:
            completions.append(
                _with_own_effort(
                    {
                        "endpoint": where,
                        "model": str(choice.model),
                        "provider": choice.provider,
                        "ok": bool(reached),
                        "detail": told,
                    },
                    getattr(choice, "effort", None),
                )
            )
        answered = bool(answered) and bool(reached)
    llm = {"provider": llm_provider, "model": llm_model, "endpoint": endpoint}
    return bool(answered), detail, completions, llm


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
    from maljan.core.config import ROLE_ENTRY_KEYS

    if name in ROLE_ENTRY_KEYS:
        # A role with no definition (the mediator, the function summariser)
        # has no prompt or tools to resolve; what a run needs of it is that
        # its models answer.
        try:
            answered, said, completions, llm = await _ask_each_model(settings, name)
        except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
            return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
        return ProbeResult(
            answered,
            _ms(t0),
            f"a role with no tools; {said}",
            None,
            [],
            {"completions": completions, "llm": llm},
        )
    if name not in settings.agents.definitions:
        available = ", ".join(sorted([*settings.agents.definitions, *ROLE_ENTRY_KEYS]))
        return ProbeResult(False, _ms(t0), f"unknown agent: {name!r}. Available: {available}")

    from maljan.agents.composition import aresolve_agent, mcp_refs_for
    from maljan.core.config import ToolRef
    from maljan.core.container import ServiceContainer

    bound = [
        key
        for key, server in settings.mcp.servers.items()
        if server.enabled and name in server.agents
    ]
    # The definition's server references as resolution reads them, a
    # capability reference as the servers it stands for.
    bound += [
        str(ref.server) for ref in mcp_refs_for(settings, name) if str(ref.server) not in bound
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
        listed = ", ".join(tools[:8]) + ("…" if len(tools) > 8 else "")
        resolved_detail = f"{len(tools)} tools: {listed}" if tools else "resolved; no tools"
        answered, said, completions, llm = await _ask_each_model(settings, name)
        detail = f"{resolved_detail}; {said}"
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
                # Where the call went, so the probe's answer is filed under the
                # pair it was taken against.
                "llm": llm,
                "static_provider": resolved.static_provider_id,
                "servers": servers,
            },
        )
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    finally:
        await container.aclose()


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


async def probe_redis(v: dict[str, Any] | None = None) -> ProbeResult:
    t0 = time.perf_counter()
    url = str(api_settings.redis_url)  # read-only setting; no candidate value can arrive
    try:
        r = Redis.from_url(url, socket_timeout=TIMEOUT)
        pong = await r.ping()
        await r.aclose()
        return ProbeResult(bool(pong), _ms(t0), "PONG" if pong else "no PONG")
    except Exception as exc:  # noqa: BLE001 - reported to the operator, never raised to the route
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {redact_url(str(exc))}")


# The probes that are not a provider's: the model probe (every LLM provider
# answers through its adapter), a tool server of the registry, an agent
# definition, and the API's own queue. Every other probe id is a registered
# provider's: static, sandbox, memory backend or reputation source.
OWN_PROBES = ("llm", "mcp", "agent", "redis")


def _probed_sources(stored: dict[str, Any] | None) -> dict[str, Any]:
    """The enrichment sources in force that declare a connection test, by key."""
    from maljan.enrichment.declared import effective_sources

    from app.services.enrichment_sources import ENRICHMENT_SOURCES_KEY, stored_map

    held = stored_map((stored or {}).get(ENRICHMENT_SOURCES_KEY))
    return {key: s for key, s in effective_sources(held).items() if s.probe is not None}


def _provider_probe_kinds(stored: dict[str, Any] | None = None) -> dict[str, str]:
    """Every registered provider's probe id, and which registry holds it.

    An enrichment source is tested under its key; ``stored`` adds the ones an
    operator declared to the ones the platform ships.
    """
    from maljan.core.plugins import accepted_names, loaded_names
    from maljan.memory.store_factory import memory_backends
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    kinds: dict[str, str] = {}
    for source in _probed_sources(stored):
        kinds.setdefault(source, "reputation")
    allowed = (stored or {}).get(ALLOW_LIST_KEY) or []
    for kind, ids in (
        ("memory", memory_backends()),
        ("sandbox", sandbox_provider_ids()),
        ("static", static_provider_ids()),
    ):
        # A plugin is tested under its id when the stored list allows it,
        # whether or not this process has loaded it yet.
        plugin_ids = loaded_names(kind)
        shipped = [i for i in ids if i not in plugin_ids]
        for provider_id in [*shipped, *sorted(accepted_names(kind, allowed))]:
            kinds.setdefault(provider_id, kind)
    return kinds


def probe_names() -> list[str]:
    """Every probe id the settings route answers."""
    return [*OWN_PROBES, *(k for k in _provider_probe_kinds() if k not in OWN_PROBES)]


def with_staged_sources(stored: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """``stored`` with its enrichment source map as the staged entries leave it."""
    from app.services.enrichment_sources import ENRICHMENT_SOURCES_KEY, staged_over_stored

    return {**stored, ENRICHMENT_SOURCES_KEY: staged_over_stored(stored, values)}


def known_probe(name: str, stored: dict[str, Any] | None = None) -> bool:
    """Whether ``name`` is a probe the settings route answers, with these stored settings."""
    return name in OWN_PROBES or name in _provider_probe_kinds(stored)


def _from_provider(result: Any, t0: float) -> ProbeResult:
    """A provider's ``ProviderProbe`` as the route's answer."""
    return ProbeResult(
        bool(result.ok),
        int(getattr(result, "latency_ms", 0) or 0) or _ms(t0),
        str(result.detail),
        None,
        getattr(result, "tools", None),
    )


async def _probe_registered_provider(kind: str, name: str, core: Any) -> ProbeResult:
    """Build provider ``name`` from the candidate settings and ask its own ``probe()``.

    The test and the job read one object built one way, so they cannot
    disagree about which address, credential or mapping is in force.
    """
    from maljan.providers.registry import _SANDBOX_REGISTRY, _STATIC_REGISTRY, discover_providers

    t0 = time.perf_counter()
    discover_providers()
    registry = _STATIC_REGISTRY if kind == "static" else _SANDBOX_REGISTRY
    if name not in registry:
        # An allowed plugin this process has not loaded: why, or that it is
        # still loading, never a bare failure.
        from maljan.core.plugins import unavailable_reason

        why = unavailable_reason(kind, name) or "it is an allowed plugin still loading in the API"
        return ProbeResult(False, _ms(t0), f"{kind} provider {name!r} is not loaded: {why}")
    try:
        cls: Any = registry[name]
        provider = cls.from_settings(core)
    except (ProviderConfigurationError, ValidationError, ValueError) as exc:
        fields = _validation_detail(exc) if isinstance(exc, ValidationError) else str(exc)
        return ProbeResult(False, _ms(t0), fields)
    return _from_provider(await provider.probe(), t0)


async def _probe_memory_backend(name: str, core: Any) -> ProbeResult:
    """Build memory backend ``name`` from the candidate settings and ask its ``readiness()``."""
    from maljan.core.exceptions import MemoryStoreError
    from maljan.memory.store_factory import build_memory_store

    t0 = time.perf_counter()
    memory = core.memory.model_copy(update={"backend": name})
    store: Any = None
    try:
        store = await asyncio.to_thread(build_memory_store, memory)
        said = await asyncio.wait_for(asyncio.to_thread(store.readiness), TIMEOUT)
        return ProbeResult(True, _ms(t0), str(said))
    except TimeoutError:
        return ProbeResult(False, _ms(t0), f"timeout after {int(TIMEOUT)} s")
    except (MemoryStoreError, Exception) as exc:  # noqa: BLE001 - reported, never raised
        return ProbeResult(False, _ms(t0), redact_url(f"{type(exc).__name__}: {exc}"))
    finally:
        if store is not None:
            close = getattr(store, "close", None)
            if callable(close):
                with contextlib.suppress(Exception):
                    close()


def _api_value(key: str, values: dict[str, Any], stored: dict[str, Any]) -> Any:
    """An ``api.*`` setting as a probe of these staged values reads it."""
    _ns, path = split_key(key)
    if key in values and values[key] is not None:
        return _unwrap(values[key])
    if key in stored:
        return _unwrap(stored[key])
    if path in API_DEFAULTS:
        # Editable api.* leaves no longer live on APISettings; their probe-time
        # default comes from the catalog table instead.
        return _unwrap(API_DEFAULTS[path])
    return _unwrap(getattr(api_settings, path, None))


async def _probe_reputation_source(
    name: str, values: dict[str, Any], stored: dict[str, Any]
) -> ProbeResult:
    """Ask enrichment source ``name``'s declared test, with the credential it reads.

    The declaration is the staged one where the map is staged, laid over the
    stored one; a staged own key that is the mask means the stored key.
    """
    from maljan.enrichment.declared import effective_sources, probe_source

    from app.services.enrichment_sources import credential_settings, staged_over_stored

    t0 = time.perf_counter()
    source = effective_sources(staged_over_stored(stored, values)).get(name)
    if source is None:
        return ProbeResult(False, _ms(t0), f"no enrichment source {name!r} is in force")
    if source.credential and source.credential not in credential_settings():
        # The test would send that secret to the declaration's own host.
        return ProbeResult(
            False, _ms(t0), f"credential {source.credential!r} is not an enrichment secret setting"
        )
    if source.credential.startswith("api."):
        credential = _api_value(source.credential, values, stored)
    elif source.credential:
        node: Any = candidate_settings(values, stored)
        for part in source.credential.split(".")[1:]:
            node = getattr(node, part, None)
        credential = node
    else:
        credential = source.api_key
    return _from_provider(await probe_source(source, str(_unwrap(credential) or "")), t0)


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
    """Run probe ``name`` against the staged values layered over the stored ones.

    A provider's probe is that provider's own (``probe()``, a memory backend's
    ``readiness()``, an enrichment source's declared test), built from the
    candidate settings; the model probe asks the selected LLM provider's
    adapter. Deliberately no context-window block on the result: the window
    is a fact about the endpoint rather than about whether a model answered,
    and the settings page reads it from its own route.
    """
    kinds = _provider_probe_kinds(with_staged_sources(stored, values))
    if name not in OWN_PROBES and name not in kinds:
        return ProbeResult(False, 0, f"unknown probe: {name!r}")
    if kinds.get(name) == "reputation":
        return await in_probe_loop(lambda: _probe_reputation_source(name, values, stored))
    if name == "redis":
        return await in_probe_loop(probe_redis)
    plugin_kind = "llm" if name == "llm" else kinds.get(name)
    if plugin_kind in PLUGIN_GROUPS:
        # A plugin's own test runs its own code: that plugin alone (the LLM
        # test's is the provider it would ask), when the stored list allows
        # it, loaded off the event loop and waited for at most this budget.
        from app.services.plugins import load_in_background

        tested = (
            str(values.get("core.llm.provider", stored.get("core.llm.provider")) or "")
            if name == "llm"
            else name
        )
        await load_in_background(stored.get(ALLOW_LIST_KEY), [f"{plugin_kind}:{tested}"], TIMEOUT)
    try:
        core = candidate_settings(values, stored)
    except (ValueError, ValidationError) as exc:
        # A malformed key or a staged value the model rejects is an operator
        # error, not a route error. Name the fields and why they were
        # rejected, never echo the values.
        fields = _validation_detail(exc) if isinstance(exc, ValidationError) else type(exc).__name__
        return ProbeResult(False, 0, f"invalid candidate values: {fields}")
    if name == "llm":
        return await in_probe_loop(lambda: probe_llm(core))
    if name == "mcp":
        return await in_probe_loop(lambda: probe_mcp({}))
    if name == "agent":
        return await in_probe_loop(lambda: probe_agent({}))
    kind = kinds[name]
    if kind == "memory":
        return await in_probe_loop(lambda: _probe_memory_backend(name, core))
    return await in_probe_loop(lambda: _probe_registered_provider(kind, name, core))
