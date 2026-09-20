"""The window the operator's own model was served with, and what it buys.

One number used to decide how much of a tool answer a model was allowed to
read: ``core.preprocessing.max_tool_output_chars``, six thousand characters.
It was chosen against one deployment — a local server started with a large
window and a forty-step static loop — and it is wrong in both directions
everywhere else. On a model served with 32,768 tokens it is generous enough
that forty observations do not fit; on a model with a million it throws away
information for nothing.

So the number is derived instead, from the window the served model actually
has. Learning that window costs nothing: every server this platform can be
pointed at either publishes the window on a metadata endpoint or belongs to a
vendor that publishes it in writing. **Nothing here asks a model to produce a
single token.** The requests this module can make are fixed and listed in
:data:`PROBE_PATHS`; a guard test drives every plan this module can build
through a transport that refuses anything else.

Where the window comes from, in order:

``declared``
    ``core.llm.openai.context_size`` for an OpenAI-compatible endpoint, and
    ``core.llm.ollama.num_ctx`` for Ollama. The Ollama one is not an opinion:
    the provider sends it with every call, so it *is* the served window.
``probed``
    ``GET /props`` on llama.cpp, whose ``default_generation_settings.n_ctx``
    is the window the server was started with (``n_ctx_per_seq`` on the builds
    that report the per-slot figure instead); ``GET /v1/models`` for vLLM and
    anything compatible, whose entry carries ``max_model_len`` — and for
    OpenRouter, whose entry carries ``context_length``; ``GET /info`` on Text
    Generation Inference, whose ``max_total_tokens`` is the same fact;
    ``POST /api/show`` on Ollama, whose ``model_info`` carries
    ``<arch>.context_length``.
``table``
    ``data/model_context_windows_v1.json``, keyed by model-id family. A
    fallback for the vendor APIs that publish a window without serving it and
    for an open-weight tag behind a proxy that says nothing. The file says how
    to correct a row it has wrong.
``fallback``
    :data:`FALLBACK_WINDOW_TOKENS`, when nothing above answered.

A probe never fails a run and never blocks a settings save. Everything it can
end with becomes a :class:`WindowFact` with the reason in words, so an operator
reading a run summary sees which of the four applied and why.

**What the window buys.** :func:`derive_tool_output_chars` is the whole
arithmetic and is tested on its own. It has one property worth stating: an
answer takes :data:`ANSWER_SHARE` of what is *left*, and what is left is
measured again before the next answer, so the answers of one conversation sum
to strictly less than the room that conversation started with. The share
decides how many answers fit before the floor, not whether the window holds
them.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from maljan.core.logger import logger
from maljan.core.paths import resolve_data

__all__ = [
    "ANSWER_SHARE",
    "CHARS_PER_TOKEN",
    "ContextBudget",
    "DECLARED",
    "DEFAULT_REPLY_TOKENS",
    "FALLBACK",
    "FALLBACK_WINDOW_TOKENS",
    "MIN_TOOL_OUTPUT_CHARS",
    "PROBED",
    "PROBE_PATHS",
    "PROBE_TIMEOUT_SECONDS",
    "TABLE",
    "TABLE_PATH",
    "WindowFact",
    "Ask",
    "alearn_window",
    "aprobe_window",
    "awindow_for_settings",
    "budget_for_settings",
    "budget_or_unknown",
    "declared_window",
    "derive_tool_output_chars",
    "forget_learned_windows",
    "generation_reserve",
    "learn_window",
    "model_family",
    "output_limit",
    "probe_plan",
    "probe_window",
    "reply_reserve_tokens",
    "table_window",
    "unknown_window",
    "window_for_settings",
    "window_from_llama_props",
    "window_from_model_list",
    "window_from_ollama_show",
    "window_from_tgi_info",
]


# ---------------------------------------------------------------------------
# The arithmetic
# ---------------------------------------------------------------------------

# How many characters of tool output one token of this deployment's window
# holds. Measured rather than assumed: the salvage failure this project already
# has on record re-sent nineteen tool observations capped at 6,000 characters —
# about 114,000 characters before the framing — and the server reported that
# conversation at 38,868 tokens, which is 2.93 characters per token. Three is
# that figure rounded to the nearest whole character; the 2% it is optimistic
# by is absorbed several times over by the reply reserve and the share below.
#
# Deliberately not the four characters per token the token ledger's estimate
# and the salvage budget use. Those measure English prose. What this bounds is
# JSON from a tool server and decompiled C, and both tokenise denser than prose
# — which is exactly what the measurement above says.
CHARS_PER_TOKEN = 3

# What one tool answer may take of the room that is left when it arrives.
#
# Safety is not what this decides. An answer is measured against what is free
# at the moment of the call and the next answer is measured again, so the
# answers of one conversation sum to less than the room it began with whatever
# this is. What the share decides is how big the first answer is and how fast
# they shrink after it.
#
# An eighth, argued at the smallest window this platform is run on — 32,768
# tokens, which leaves 24,576 free after the reply reserve, or 73,728
# characters. An eighth of that is 9,216 characters for the first answer, more
# than the 6,000-character constant it replaces on the very deployment that
# constant was tuned against, and the cap stays above the floor for about
# twelve answers. A sixteenth would start at 4,608 — below the old constant on
# that same model, which is a regression dressed up as a derivation — and a
# quarter would start at 18,432 and fall to the floor after nine, spending the
# window on the first few calls of a loop that has forty steps. Past the
# twelfth answer the floor holds and each one carries the shortener's notice,
# so a loop that has filled its window keeps working on smaller answers rather
# than stopping.
ANSWER_SHARE = 0.125

# The smallest cap a tool answer is ever given, however full the conversation.
#
# Below this an answer stops being one. The notice a shortened answer carries
# costs at most 477 characters (``output_shortening.MAX_SENTENCE_ROOM``), so
# two thousand leaves at least 1,523 for the document itself — three times the
# 512 characters below which that module treats a string as a label rather than
# a payload, which is what lets one long value survive beside the answer's own
# account of itself. When the floor binds, nothing new happens: the answer
# meets the structural shortener at this size, comes back as a document with
# its ``shortened`` map, and carries the notice naming the arguments that
# narrow it.
MIN_TOOL_OUTPUT_CHARS = 2000

# What is held back for the model's own reply when nothing configures it. The
# analyst and judge generation caps are both 8,192 tokens, and this is the
# figure used when both are left unbounded.
DEFAULT_REPLY_TOKENS = 8192

# The reply reserve is never more than this fraction of the window. Without it
# a small window reserves its whole self for a reply that will never be that
# long, and every answer lands on the floor.
REPLY_RESERVE_DIVISOR = 4

# The window assumed when nothing reported one and the table does not name the
# model. Small on purpose, and the direction matters: a window guessed too
# large overflows the server, which on llama.cpp is a silent context shift that
# drops the oldest tokens — the framing the whole loop depends on — while a
# window guessed too small only costs information. An operator who lands here
# is told so by name in the run summary and fixes it in one field
# (``core.llm.openai.context_size``).
FALLBACK_WINDOW_TOKENS = 8192

# Where a window was learned. Four words, each of which an operator can act on.
DECLARED = "declared"
PROBED = "probed"
TABLE = "table"
FALLBACK = "fallback"


@dataclass(frozen=True)
class WindowFact:
    """One model's served context window, and how it came to be known."""

    tokens: int
    source: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"tokens": self.tokens, "source": self.source, "detail": self.detail}


def unknown_window(reason: str = "") -> WindowFact:
    """The conservative window, for a model nothing could answer for."""
    said = reason or "no endpoint reported a window and the model is not in the table"
    return WindowFact(FALLBACK_WINDOW_TOKENS, FALLBACK, said)


def reply_reserve_tokens(window_tokens: int, configured: int = 0) -> int:
    """What is kept back for the model's own reply, in tokens.

    ``configured`` is the deployment's own generation cap — the larger of the
    analyst's and the judge's, because one cap serves calls made on behalf of
    both. Zero means neither is bounded, and :data:`DEFAULT_REPLY_TOKENS`
    stands in. Never more than a quarter of the window, so a small window is
    not spent entirely on room for an answer that cannot be that long.
    """
    wanted = int(configured) if int(configured) > 0 else DEFAULT_REPLY_TOKENS
    ceiling = max(1, int(window_tokens) // REPLY_RESERVE_DIVISOR)
    return max(1, min(wanted, ceiling))


def derive_tool_output_chars(
    *,
    window_tokens: int,
    held_chars: int = 0,
    reply_tokens: int = 0,
    chars_per_token: int = CHARS_PER_TOKEN,
    share: float = ANSWER_SHARE,
    floor: int = MIN_TOOL_OUTPUT_CHARS,
) -> int:
    """How many characters of one tool answer this model may be handed now.

    ``window_tokens`` is the served window. ``held_chars`` is what the
    conversation already holds, measured as the server will see it and
    converted at ``chars_per_token``. ``reply_tokens`` is what is kept back for
    the model's own reply; zero asks :func:`reply_reserve_tokens` for it.

    The result is never below ``floor`` and never above what the window could
    hold, and a window of zero — nothing known — is the floor.
    """
    window = max(0, int(window_tokens))
    if window <= 0:
        return floor
    per_token = max(1, int(chars_per_token))
    reserve = int(reply_tokens) if int(reply_tokens) > 0 else reply_reserve_tokens(window)
    held_tokens = max(0, int(held_chars)) // per_token
    free_tokens = window - reserve - held_tokens
    if free_tokens <= 0:
        return floor
    return max(floor, int(free_tokens * per_token * max(0.0, float(share))))


# ---------------------------------------------------------------------------
# The vendored table
# ---------------------------------------------------------------------------

TABLE_PATH = "data/model_context_windows_v1.json"

_table_lock = threading.Lock()
_table: dict[str, int] | None = None


def _load_table() -> dict[str, int]:
    """The vendored table, read once. An unreadable file is an empty table."""
    global _table
    with _table_lock:
        if _table is not None:
            return _table
        rows: dict[str, int] = {}
        try:
            raw = json.loads(Path(resolve_data(TABLE_PATH)).read_text(encoding="utf-8"))
            for key, value in (raw.get("windows") or {}).items():
                if isinstance(value, int) and value > 0:
                    rows[str(key).lower()] = value
        except Exception as exc:  # noqa: BLE001 — a fallback table never fails a run
            logger.warning("the vendored context-window table could not be read: %s", exc)
        _table = rows
        return _table


def model_family(model: object) -> str:
    """A model id reduced to what the table is keyed by.

    Lower-cased, with any vendor path segment in front of it removed
    (``openrouter`` and the Ollama registry both write one) and any tag after a
    colon removed (``qwen3:8b`` and ``qwen3:32b`` are one family as far as a
    published window goes).
    """
    name = str(model or "").strip().lower()
    if not name:
        return ""
    name = name.rpartition("/")[2] or name
    return name.partition(":")[0]


def table_window(model: object) -> WindowFact | None:
    """What the vendored table says about ``model``, or ``None``.

    The longest key the family starts with wins, so ``gpt-4o`` is not answered
    by the ``gpt-4`` row.
    """
    family = model_family(model)
    if not family:
        return None
    rows = _load_table()
    matches = [key for key in rows if family.startswith(key)]
    if not matches:
        return None
    key = max(matches, key=len)
    return WindowFact(
        rows[key],
        TABLE,
        f"the vendored table's {key!r} row; the endpoint reported no window",
    )


# ---------------------------------------------------------------------------
# What a probe may ask for
# ---------------------------------------------------------------------------

# The four metadata paths, and the whole of what this module may request. Every
# one of them describes a server or a model; none of them runs anything.
LLAMA_PROPS_PATH = "/props"
MODEL_LIST_PATH = "/v1/models"
OLLAMA_SHOW_PATH = "/api/show"
TGI_INFO_PATH = "/info"

PROBE_PATHS: tuple[str, ...] = (
    LLAMA_PROPS_PATH,
    MODEL_LIST_PATH,
    OLLAMA_SHOW_PATH,
    TGI_INFO_PATH,
)

# A probe is on the path of a settings save and of a job's first tool attach,
# so it is short. A metadata endpoint that has not answered in two seconds is
# one the fallback answers for.
PROBE_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class Ask:
    """One metadata request a probe may make, and how to read its answer."""

    method: str
    url: str
    body: dict[str, Any] | None
    read: Callable[[Any, str], int]
    what: str


def _root_of(endpoint: object) -> str:
    """The server's root, with an OpenAI-compatible ``/v1`` suffix removed.

    ``/props`` and ``/info`` sit at the root of the server, while the base URL
    an operator configures for an OpenAI-compatible endpoint conventionally
    ends at ``/v1``.
    """
    base = str(endpoint or "").rstrip("/")
    return base[: -len("/v1")] if base.endswith("/v1") else base


def window_from_llama_props(payload: Any, _model: str = "") -> int:
    """llama.cpp's ``/props``: the window the server was started with.

    ``default_generation_settings.n_ctx`` is the whole context the server
    holds. A build that serves several slots reports the per-slot figure as
    ``n_ctx_per_seq`` instead, and that is the window one conversation gets, so
    it is read when the first is absent. A top-level ``n_ctx`` is the same fact
    on the older builds.
    """
    if not isinstance(payload, dict):
        return 0
    settings = payload.get("default_generation_settings")
    settings = settings if isinstance(settings, dict) else {}
    for holder in (settings, payload):
        for key in ("n_ctx", "n_ctx_per_seq"):
            value = holder.get(key)
            if isinstance(value, int) and value > 0:
                return value
    return 0


def window_from_model_list(payload: Any, model: str = "") -> int:
    """An OpenAI-compatible model list: the entry for ``model``, if it says.

    vLLM writes ``max_model_len``; OpenRouter writes ``context_length``; some
    proxies write ``context_window``. A list with one entry answers for the
    model whatever it is called, because a server with one model loaded is the
    ordinary local shape and the id it advertises is often a file path.
    """
    if not isinstance(payload, dict):
        return 0
    entries = [row for row in (payload.get("data") or []) if isinstance(row, dict)]
    if not entries:
        return 0
    wanted = str(model or "").strip().lower()
    named = [row for row in entries if str(row.get("id") or "").strip().lower() == wanted]
    for row in named or (entries if len(entries) == 1 else []):
        for key in ("max_model_len", "context_length", "context_window"):
            value = row.get(key)
            if isinstance(value, int) and value > 0:
                return value
    return 0


def window_from_ollama_show(payload: Any, _model: str = "") -> int:
    """Ollama's ``/api/show``: the model's own window, unless a parameter wins.

    ``model_info`` is keyed by architecture (``qwen3.context_length``), so the
    key is found rather than named. ``parameters`` is the text of the
    Modelfile's own settings, and a ``num_ctx`` in it is what the server will
    serve — a smaller window than the model could hold, which is the number
    that binds.
    """
    if not isinstance(payload, dict):
        return 0
    declared = _num_ctx_in(payload.get("parameters"))
    info = payload.get("model_info")
    native = 0
    if isinstance(info, dict):
        for key, value in info.items():
            if str(key).endswith(".context_length") and isinstance(value, int) and value > 0:
                native = value
                break
    if declared > 0:
        return min(declared, native) if native > 0 else declared
    return native


def _num_ctx_in(parameters: Any) -> int:
    """``num_ctx`` out of Ollama's parameter text, or zero.

    The field is a block of ``name value`` lines rather than a mapping, and a
    deployment that has never set one has no line at all.
    """
    if not isinstance(parameters, str):
        return 0
    for line in parameters.splitlines():
        head, _, tail = line.strip().partition(" ")
        if head == "num_ctx":
            try:
                return int(tail.strip())
            except ValueError:
                return 0
    return 0


def window_from_tgi_info(payload: Any, _model: str = "") -> int:
    """Text Generation Inference's ``/info``: ``max_total_tokens``."""
    if not isinstance(payload, dict):
        return 0
    value = payload.get("max_total_tokens")
    return value if isinstance(value, int) and value > 0 else 0


def probe_plan(provider: str, endpoint: object, model: str = "") -> tuple[Ask, ...]:
    """Every metadata request this provider kind offers, best first.

    The whole surface of what this module can put on a network, so a guard
    test can enumerate it rather than trust a reading of the code. A vendor API
    with nothing to ask is an empty plan, and the table answers for it.
    """
    root = _root_of(endpoint)
    if provider == "ollama":
        base = root or "http://localhost:11434"
        return (
            Ask(
                "POST",
                f"{base}{OLLAMA_SHOW_PATH}",
                {"model": model},
                window_from_ollama_show,
                "the Ollama model description",
            ),
        )
    if provider != "openai" or not root:
        return ()
    return (
        Ask("GET", f"{root}{LLAMA_PROPS_PATH}", None, window_from_llama_props, "llama.cpp /props"),
        Ask(
            "GET",
            f"{root}{MODEL_LIST_PATH}",
            None,
            window_from_model_list,
            "the served model list",
        ),
        Ask("GET", f"{root}{TGI_INFO_PATH}", None, window_from_tgi_info, "the server description"),
    )


def _headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"} if api_key else {}


def _read_answer(ask: Ask, answer: httpx.Response, model: str) -> int:
    if answer.status_code >= 400:
        return 0
    try:
        payload = answer.json()
    except ValueError:
        return 0
    try:
        return max(0, int(ask.read(payload, model)))
    except Exception:  # noqa: BLE001 — a shape nobody anticipated is not a window
        return 0


def _probed(ask: Ask, tokens: int) -> WindowFact:
    return WindowFact(tokens, PROBED, f"{ask.what} reported {tokens:,} tokens")


def _nothing_answered(plan: Iterable[Ask]) -> str:
    asked = ", ".join(ask.what for ask in plan)
    return f"nothing was reported by {asked}" if asked else "this provider serves no window"


def probe_window(
    provider: str, *, endpoint: object, model: str = "", api_key: str = ""
) -> WindowFact | None:
    """Ask the endpoint what window it serves. ``None`` when it did not say.

    Synchronous, for the worker: a job resolves its window once, on a worker
    thread, before its first tool answer. Never raises.
    """
    plan = probe_plan(provider, endpoint, model)
    if not plan:
        return None
    try:
        with httpx.Client(timeout=PROBE_TIMEOUT_SECONDS) as client:
            for ask in plan:
                try:
                    answer = _send(client, ask, api_key)
                except httpx.HTTPError as exc:
                    logger.debug("context window: %s did not answer (%s)", ask.what, type(exc))
                    continue
                tokens = _read_answer(ask, answer, model)
                if tokens > 0:
                    return _probed(ask, tokens)
    except Exception as exc:  # noqa: BLE001 — a probe never fails a run
        logger.debug("the context-window probe could not be made: %s", exc)
        return None
    logger.debug("context window: %s", _nothing_answered(plan))
    return None


async def aprobe_window(
    provider: str, *, endpoint: object, model: str = "", api_key: str = ""
) -> WindowFact | None:
    """The same question on the caller's loop, for the settings probe."""
    plan = probe_plan(provider, endpoint, model)
    if not plan:
        return None
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
            for ask in plan:
                try:
                    answer = await _asend(client, ask, api_key)
                except httpx.HTTPError as exc:
                    logger.debug("context window: %s did not answer (%s)", ask.what, type(exc))
                    continue
                tokens = _read_answer(ask, answer, model)
                if tokens > 0:
                    return _probed(ask, tokens)
    except Exception as exc:  # noqa: BLE001 — a probe never blocks a settings save
        logger.debug("the context-window probe could not be made: %s", exc)
        return None
    logger.debug("context window: %s", _nothing_answered(plan))
    return None


def _send(client: httpx.Client, ask: Ask, api_key: str) -> httpx.Response:
    if ask.method == "POST":
        return client.post(ask.url, json=ask.body or {}, headers=_headers(api_key))
    return client.get(ask.url, headers=_headers(api_key))


async def _asend(client: httpx.AsyncClient, ask: Ask, api_key: str) -> httpx.Response:
    if ask.method == "POST":
        return await client.post(ask.url, json=ask.body or {}, headers=_headers(api_key))
    return await client.get(ask.url, headers=_headers(api_key))


# ---------------------------------------------------------------------------
# Learning it once, per provider, endpoint and model
# ---------------------------------------------------------------------------

_learned_lock = threading.Lock()
_learned: dict[tuple[str, str, str], WindowFact] = {}


def forget_learned_windows() -> None:
    """Drop every cached answer. For a test, and for a settings import."""
    with _learned_lock:
        _learned.clear()


def learn_window(
    provider: str,
    *,
    endpoint: object,
    model: str = "",
    api_key: str = "",
    declared: int = 0,
    probe: bool = True,
) -> WindowFact:
    """The served window for one ``(provider, endpoint, model)``, learned once.

    Cached on exactly those three, so a changed endpoint or a changed model is
    a different question and gets asked again. ``declared`` is the operator's
    own statement of the window and short-circuits everything: for Ollama it is
    what the provider sends with each call, and for an OpenAI-compatible
    endpoint it is the operator naming a window no metadata endpoint offered.

    ``probe=False`` answers from what is already known, the table and the
    fallback, without touching the network.
    """
    if int(declared) > 0:
        return _declared_fact(int(declared))
    key = (str(provider), str(endpoint or ""), str(model or ""))
    with _learned_lock:
        cached = _learned.get(key)
    if cached is not None:
        return cached
    fact: WindowFact | None = None
    if probe:
        fact = probe_window(provider, endpoint=endpoint, model=model, api_key=api_key)
    return _remembered(key, fact or table_window(model) or unknown_window())


async def alearn_window(
    provider: str,
    *,
    endpoint: object,
    model: str = "",
    api_key: str = "",
    declared: int = 0,
    probe: bool = True,
) -> WindowFact:
    """:func:`learn_window` on the caller's loop, for the settings probe.

    The same order, the same cache and the same rule about what is remembered;
    only the transport differs, because the API is async and the worker is not.
    """
    if int(declared) > 0:
        return _declared_fact(int(declared))
    key = (str(provider), str(endpoint or ""), str(model or ""))
    with _learned_lock:
        cached = _learned.get(key)
    if cached is not None:
        return cached
    fact: WindowFact | None = None
    if probe:
        fact = await aprobe_window(provider, endpoint=endpoint, model=model, api_key=api_key)
    return _remembered(key, fact or table_window(model) or unknown_window())


def _declared_fact(tokens: int) -> WindowFact:
    return WindowFact(
        tokens, DECLARED, "the window this deployment's settings name for the endpoint"
    )


def _remembered(key: tuple[str, str, str], fact: WindowFact) -> WindowFact:
    """Cache a probed answer and hand it back; anything else is not cached.

    A table or fallback answer costs nothing to reach, and remembering one
    would mean a server that happened to be down when the first job ran is
    never asked again for the life of the process.
    """
    if fact.source == PROBED:
        with _learned_lock:
            _learned[key] = fact
    return fact


def declared_window(settings: Any, provider: str) -> int:
    """The window this deployment's own settings name for ``provider``.

    Ollama's ``num_ctx`` is sent with every call, so it is the served window
    rather than a description of one. The OpenAI-compatible ``context_size``
    is the operator saying what their server was started with, and zero — its
    default — means they have not said.
    """
    try:
        if provider == "ollama":
            return int(settings.llm.ollama.num_ctx)
        if provider == "openai":
            return int(getattr(settings.llm.openai, "context_size", 0) or 0)
    except Exception as exc:  # noqa: BLE001 — an unreadable setting is not a window
        logger.debug("context window: the declared window could not be read (%s)", exc)
    return 0


def _provider_key(settings: Any, provider: str) -> str:
    """The credential ``provider`` authenticates with, as a plain string."""
    try:
        secret = getattr(getattr(settings.llm, provider, None), "api_key", None)
        reveal = getattr(secret, "get_secret_value", None)
        return str(reveal() if callable(reveal) else (secret or ""))
    except Exception:  # noqa: BLE001 — a probe without a key is still a probe
        return ""


def window_for_settings(settings: Any, agents: list[str], *, probe: bool = True) -> WindowFact:
    """The window one run may count on, across every model its agents call.

    The smallest of them, because one cap is handed to every tool server the
    job opens and a cap sized for the roomiest model would overflow the
    tightest. A run whose agents all sit on one endpoint — the ordinary shape —
    asks one question and gets one answer.
    """
    from maljan.core.model_assignments import assignments_for

    facts: list[WindowFact] = []
    for assignment in assignments_for(settings, agents):
        facts.append(
            learn_window(
                assignment.provider,
                endpoint=assignment.endpoint,
                model=assignment.model,
                api_key=_provider_key(settings, assignment.provider),
                declared=declared_window(settings, assignment.provider),
                probe=probe,
            )
        )
    if not facts:
        return unknown_window("this run names no model")
    return min(facts, key=lambda fact: fact.tokens)


async def awindow_for_settings(
    settings: Any, agents: list[str], *, probe: bool = True
) -> WindowFact:
    """:func:`window_for_settings` on the caller's loop."""
    from maljan.core.model_assignments import assignments_for

    facts = [
        await alearn_window(
            assignment.provider,
            endpoint=assignment.endpoint,
            model=assignment.model,
            api_key=_provider_key(settings, assignment.provider),
            declared=declared_window(settings, assignment.provider),
            probe=probe,
        )
        for assignment in assignments_for(settings, agents)
    ]
    if not facts:
        return unknown_window("this run names no model")
    return min(facts, key=lambda fact: fact.tokens)


def generation_reserve(settings: Any) -> int:
    """The largest generation cap this deployment configures, in tokens.

    One cap serves answers read by an analyst and by the judge, so the larger
    of the two reserves is the one that has to hold.
    """
    try:
        return max(
            int(getattr(settings.llm, "expert_max_tokens", 0) or 0),
            int(getattr(settings.llm, "judge_max_tokens", 0) or 0),
        )
    except Exception:  # noqa: BLE001 — an unreadable setting takes the default
        return 0


# ---------------------------------------------------------------------------
# What one run spends
# ---------------------------------------------------------------------------


class ContextBudget:
    """One run's window, and the cap it gives the tool answer arriving now.

    Built once per job and put on every toolkit the job opens, the way the
    truncation ledger is. It holds the window that was learned, the reply room
    that is kept back, and what each agent's conversation currently weighs.

    The conversation is recorded per agent by the run-state refresher, which
    already runs before every model turn and already has the messages in hand,
    measured with the same rule the salvage trim uses — the payload of a tool
    request counts, not just its text. Where analysts run in parallel the
    fullest live conversation decides, because one cap serves them all and the
    fullest is the one with least room to spare.

    Reading is lock-protected and never raises: a budget that cannot answer
    hands back the floor, which is a smaller answer rather than a failed call.
    """

    def __init__(
        self,
        window: WindowFact,
        *,
        reply_tokens: int = 0,
        chars_per_token: int = CHARS_PER_TOKEN,
        share: float = ANSWER_SHARE,
        floor: int = MIN_TOOL_OUTPUT_CHARS,
    ) -> None:
        self.window = window
        self.chars_per_token = max(1, int(chars_per_token))
        self.share = float(share)
        self.floor = max(1, int(floor))
        self.reply_tokens = reply_reserve_tokens(window.tokens, reply_tokens)
        self._lock = threading.Lock()
        self._held: dict[str, int] = {}
        self._smallest = 0
        self._largest = 0

    def note_conversation(self, agent: str, chars: int) -> None:
        """Record what one agent's conversation weighs as of this turn."""
        with self._lock:
            self._held[str(agent)] = max(0, int(chars))

    def forget_conversation(self, agent: str) -> None:
        """Forget a loop that has finished, so its size stops binding."""
        with self._lock:
            self._held.pop(str(agent), None)

    def held_chars(self) -> int:
        """The fullest live conversation, in characters."""
        with self._lock:
            return max(self._held.values(), default=0)

    def chars_for_one_answer(self) -> int:
        """The cap a tool answer arriving now is given."""
        cap = derive_tool_output_chars(
            window_tokens=self.window.tokens,
            held_chars=self.held_chars(),
            reply_tokens=self.reply_tokens,
            chars_per_token=self.chars_per_token,
            share=self.share,
            floor=self.floor,
        )
        with self._lock:
            self._smallest = cap if self._smallest == 0 else min(self._smallest, cap)
            self._largest = max(self._largest, cap)
        return cap

    def snapshot(self) -> dict[str, Any]:
        """What was in force, for the run summary."""
        with self._lock:
            smallest, largest = self._smallest, self._largest
        return {
            "tokens": self.window.tokens,
            "source": self.window.source,
            "detail": self.window.detail,
            "chars_per_token": self.chars_per_token,
            "reply_tokens": self.reply_tokens,
            "answer_share": self.share,
            "cap_floor": self.floor,
            "cap_smallest": smallest,
            "cap_largest": largest,
        }


def budget_for_settings(settings: Any, agents: list[str], *, probe: bool = True) -> ContextBudget:
    """This run's context budget, window learned and reply room reserved."""
    return ContextBudget(
        window_for_settings(settings, agents, probe=probe),
        reply_tokens=generation_reserve(settings),
    )


_UNKNOWN_BUDGET = ContextBudget(unknown_window("no run context budget was attached"))


def budget_or_unknown(budget: Any) -> ContextBudget:
    """``budget`` when there is one, and the conservative budget when not.

    A toolkit built outside a job — a test, a settings probe — still has to
    answer "how much of this may the model read", and the honest answer for a
    model nobody identified is the fallback window's share of itself.
    """
    return budget if isinstance(budget, ContextBudget) else _UNKNOWN_BUDGET


def output_limit(configured: int, budget: Any) -> int:
    """How many characters of one tool answer may reach the model right now.

    One function for both tool paths — the MCP toolkit's guardrail and the
    Ghidra HTTP client's — because they support one claim: what the model reads
    is inside the limit in force for this call. A positive ``configured`` is the
    operator having set ``core.preprocessing.max_tool_output_chars`` themselves
    and is used unchanged; zero asks the window.
    """
    if int(configured) > 0:
        return int(configured)
    return budget_or_unknown(budget).chars_for_one_answer()
