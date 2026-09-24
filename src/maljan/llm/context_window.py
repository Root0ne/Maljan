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
    the provider sends it with every call, so it is one half of the served
    window — the other half is what the weights hold, which is why a
    settings-named window short-circuits nothing and the two are combined by
    taking the smaller.
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
    Nothing answered, and **nothing is derived**. A cap computed from a window
    nobody measured is the platform stating what it does not know; the
    documented :data:`UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS` applies instead and
    every surface says the window is unknown and names
    :data:`UNKNOWN_WINDOW_REMEDY`.

A probe never fails a run and never blocks a settings save. Everything it can
end with becomes a :class:`WindowFact` with the reason in words, so an operator
reading a run summary sees which of the four applied and why. A number an
endpoint reports is untrusted input and is believed only up to
:data:`MAX_BELIEVABLE_WINDOW_TOKENS` — see :func:`believable`.

**What the window buys.** :func:`derive_tool_output_chars` is the whole
arithmetic and is tested on its own. Two properties hold, and both are
measured rather than asserted:

* a cap never exceeds the room that is really left, so the answers of one
  conversation sum to strictly less than the room it began with — the floor
  included, which is what the share and both memory ceilings rest on;
* room is charged as it is handed out rather than only at the next model turn,
  and per agent, so a turn that requests several tools at once spends one
  turn's room between them however wide its fan-out, and one analyst's turn
  cannot clear the total another is still spending against.

Everything this module hands a model is charged, refusals included, and both
are measured against the same budget: the window less the room kept back for
the model's reply. Past the point where there is no room for an answer the
agent is told once, its tool phase ends, and the reserve is still whole —
which matters because the forced synthesis that answers for a full
conversation is written in it.
"""

from __future__ import annotations

import contextlib
import json
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextvars import ContextVar
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
    "MAX_BELIEVABLE_WINDOW_TOKENS",
    "MAX_METADATA_BYTES",
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
    "NO_ROOM_BELOW_CHARS",
    "UNKNOWN_WINDOW_REMEDY",
    "UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS",
    "believable",
    "declared_window",
    "derive_tool_output_chars",
    "forget_learned_windows",
    "generation_reserve",
    "learn_window",
    "model_family",
    "no_room_sentence",
    "output_limit",
    "probe_plan",
    "probe_window",
    "reply_reserve_tokens",
    "derived_reply",
    "output_cap_for",
    "table_window",
    "tool_definition_chars",
    "window_full_error",
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

# The cap a tool answer is given once the share falls below it — while the
# room affords it, and no further.
#
# Below this an answer stops being worth shortening. The notice a shortened
# answer carries costs at most 477 characters
# (``output_shortening.MAX_SENTENCE_ROOM``), so two thousand leaves at least
# 1,523 for the document itself — three times the 512 characters below which
# that module treats a string as a label rather than a payload, which is what
# lets one long value survive beside the answer's own account of itself. When
# the floor binds, nothing new happens to the answer: it meets the structural
# shortener at this size, comes back as a document with its ``shortened`` map,
# and carries the notice naming the arguments that narrow it.
#
# This is a floor on the *share*, never on the room. An earlier cut of it
# overrode the room, and the consequence was not theoretical: a twenty-round
# loop on an 8,192-token window — a window the vendored table itself ships for
# two model families — finished 5,248 tokens past the window it was sizing
# itself against, and any window under about 24,000 overran once the
# conversation started with a chunk in it. Measured over the largest loop the
# settings configure, the static analyst's twenty tool rounds, every window in
# the shipped table now finishes inside its own free room; the tightest margin
# is 4,096 tokens, which finishes exactly at it.
#
# A run where this bound is visible: the smallest cap in force equals this
# number. A run where the room ran out entirely is visible too — see
# :data:`NO_ROOM_BELOW_CHARS` and ``tool_output_no_room`` on the ledger. The
# room that runs out is the tool budget, not the window: an agent's tool phase
# ends with the whole reply reserve unspent, which is what the salvage needs.
MIN_TOOL_OUTPUT_CHARS = 2000

# The documented fallback for a reply when no window was learned for the model:
# nothing is derived from an unknown window (``derived_reply``). A learned
# window derives a quarter of itself, with no fixed figure above it.
DEFAULT_REPLY_TOKENS = 8192

# The reply reserve is never more than this fraction of the window. Without it
# a small window reserves its whole self for a reply that will never be that
# long, and every answer lands on the floor.
REPLY_RESERVE_DIVISOR = 4

# Below this a cap stops being an answer and the model is handed a sentence
# instead. The widest notice a shortened answer can carry is 477 characters
# (``output_shortening.MAX_SENTENCE_ROOM``), and the shortener stops treating a
# string as a payload at all below 512, so 989 characters is the exact point
# under which nothing of the answer survives the notice. A thousand is that
# boundary rounded up, and the relationship is pinned by a test rather than
# restated here.
NO_ROOM_BELOW_CHARS = 1000

# The window recorded when nothing reported one. Nothing is derived from it —
# see :data:`UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS` — and it exists so that the
# surfaces have a number to show beside the word ``fallback`` rather than a
# blank. Small on purpose, and the direction matters: a window guessed too
# large overflows the server, which on llama.cpp is a silent context shift that
# drops the oldest tokens — the framing the whole loop depends on.
FALLBACK_WINDOW_TOKENS = 8192

# What a tool answer is capped at when the window is unknown.
#
# Not a derivation. Deriving a cap from a window nobody measured is the
# platform stating a thing it does not know, dressed as arithmetic — and the
# arithmetic makes it worse rather than better, because a guessed 8,192 put
# through the formula produces a loop that overruns the very window it guessed.
# So an unknown window uses the constant this platform shipped with for years
# and says, on every surface, that the window is unknown and which setting
# would fix it. Unrelated to ``schemas.tool_evidence``'s own six thousand,
# which bounds a stored record rather than a prompt.
UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS = 6000

# The one thing an operator does about it, named wherever the word ``fallback``
# is printed.
UNKNOWN_WINDOW_REMEDY = (
    "set core.llm.openai.context_size to the window the server was started with, "
    "or add the model to the vendored context-window table"
)

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


def reply_reserve_tokens(window_tokens: int, configured: int = 0, declared: int = 0) -> int:
    """What is kept back for the model's own reply, in tokens: the one rule.

    A quarter of the window, so a small window is not spent entirely on room
    for an answer that cannot be that long, and no fixed figure above it: a
    large window gives a long answer room. ``configured`` is an operator's own
    generation cap and ``declared`` the model's own maximum output where its
    provider states one (``model_output_limits.declared_output_limit``); either, when set, is
    kept if it is smaller.
    """
    tokens = max(1, int(window_tokens) // REPLY_RESERVE_DIVISOR)
    for bound in (int(configured or 0), int(declared or 0)):
        if bound > 0:
            tokens = min(tokens, bound)
    return max(1, tokens)


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

    **The cap never exceeds the room that is really left.** The floor applies
    while the room affords it and is reduced to the room when it does not, and
    when what is left cannot hold an answer at all the result is ``0`` — the
    caller then hands the model no answer and says so once
    (:func:`no_room_sentence`), after which that agent's tool phase ends. A
    floor that overrode the room was how a twenty-round loop on a shipped
    8,192-token window finished 5,248 tokens past the window it was sizing
    itself against.

    The platform's own refusals are not caps and are not free: they are
    charged through :meth:`ContextBudget.charge` and withheld entirely when
    they would not fit, and what they are measured against is the same tool
    budget a cap comes out of — the window less the reply reserve
    (:meth:`ContextBudget.room_for`). A marker or a notice a branch adds to an
    answer comes out of that answer's own cap rather than after it, and
    anything a branch does hand back beyond its cap is charged. So the whole of
    what this platform hands a model, answers and refusals together, stays
    inside the tool budget, and the reserve the forced synthesis writes its
    answer in is never spent on saying that the room ran out.

    Measured by driving this module's own guardrail over every window the
    vendored table ships, at 20, 40 and 60 rounds, empty and preloaded, and at
    fan-outs of 32 and 128: the tool budget is never exceeded — the worst case
    is zero characters over — and the whole reply reserve survives.

    What is outside the claim is the model's own output — its tool requests and
    its prose. The platform does not hand those over and cannot cap them, and
    on a very small window they exceed the window before the platform's text
    does.

    A window of zero — nothing known — is the floor, because nothing is being
    measured and the caller is not deriving anything from it.
    """
    window = max(0, int(window_tokens))
    if window <= 0:
        return floor
    per_token = max(1, int(chars_per_token))
    reserve = int(reply_tokens) if int(reply_tokens) > 0 else reply_reserve_tokens(window)
    # Subtracted in characters rather than converted to tokens and back: the
    # round trip through integer division loses up to two characters a call,
    # and those add up to a loop that finishes a character past the room it
    # was measuring itself against.
    free_chars = max(0, (window - reserve) * per_token - max(0, int(held_chars)))
    share_of_it = int(free_chars * max(0.0, float(share)))
    cap = share_of_it if share_of_it >= floor else min(floor, free_chars)
    return cap if cap >= NO_ROOM_BELOW_CHARS else 0


def no_room_sentence(chars_in: int) -> str:
    """What the model is told instead of an answer the conversation cannot hold.

    Said **once** per loop. A deterministic fact about this conversation, not a
    judgement about the tool: the call was made, it answered, and there is no
    room left to show any of it. Saying so is the only alternative to handing
    over a fragment too small to read or overflowing the window the whole
    derivation exists to fit inside. The tool's own arguments are not named —
    narrowing the answer would not help, because the room is gone rather than
    the answer too large.

    Its length is charged to the budget like any answer, because it is text
    that enters the conversation; and the loop's tool phase ends after it, so
    nothing pays for this sentence twice.
    """
    return (
        f"This tool answered with {chars_in:,} characters and none of them could be added: "
        "the conversation has no room left for a tool answer. Nothing was left out of the "
        "record — the evidence ledger holds the whole answer under this call's id. "
        "The tool phase of this stage ends here; answer from what has already been gathered."
    )


# What a tool call made after the room ran out is answered with. The tool is
# not run, so nothing of its answer enters the conversation; what enters is
# this line, and it is charged. Short on purpose: the sentence above is said
# once, the run-state block repeats the fact every turn at no cumulative cost,
# and this is what a model that asks anyway pays.
TOOL_PHASE_ENDED_NOTICE = "[no room] Not run: the tool phase ended. Answer now."

# The line the run-state block carries once the room is gone. Replaced with
# the rest of the block on every model turn, so it costs the same whether the
# loop reads it once or forty times.
NO_ROOM_RUN_STATE = "no room left for tool answers: answer from what has been gathered"


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
    return WindowFact(rows[key], TABLE, f"the vendored table's {key!r} row was used instead")


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
#
# A plain float bounds each *operation* — httpx applies it to connect, read,
# write and pool separately — so on its own a server that sends one byte every
# 1.9 s is never cut off. ``PROBE_BUDGET_SECONDS`` is the wall around the whole
# plan, and each request is given what is left of it rather than a fresh two
# seconds, so the plan cannot outlive its budget however slowly one endpoint
# drips.
PROBE_TIMEOUT_SECONDS = 2.0
PROBE_BUDGET_SECONDS = 4.0

# The largest metadata answer the probe will read. A server description is
# kilobytes; the largest legitimate one, a public model catalogue, is a couple
# of megabytes. Past this the answer is not read at all, because a probe that
# is free is not free if a broken endpoint can hand it a gigabyte.
MAX_METADATA_BYTES = 8_000_000

# The largest window this platform will believe an endpoint that reports one.
#
# Ten million tokens is more than an order of magnitude past the largest window
# any model is served with, so nothing real is refused; what is refused is an
# endpoint reporting its window in characters, in bytes, or with a units bug.
# That matters because the consequence is not an over-estimate: a cap derived
# from 10**18 is larger than any answer there will ever be, so the guardrail's
# ``chars_in <= limit`` is always true and the shortener, the summariser and
# the character cut all stop running for the whole run.
MAX_BELIEVABLE_WINDOW_TOKENS = 10_000_000


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


def _body_within_bounds(answer: httpx.Response, what: str) -> bytes | None:
    """The body, read a chunk at a time and abandoned past the bound.

    Read rather than materialised: a metadata answer is kilobytes, the largest
    legitimate one is a couple of megabytes, and a broken or hostile endpoint's
    is unbounded. Checking the length after ``.content`` would already have
    downloaded whatever was sent, on a machine that is also running a model.
    """
    held = bytearray()
    for chunk in answer.iter_bytes():
        held.extend(chunk)
        if len(held) > MAX_METADATA_BYTES:
            logger.debug("context window: %s answered with more than the probe reads", what)
            answer.close()
            return None
    return bytes(held)


def _read_answer(ask: Ask, answer: httpx.Response, model: str) -> tuple[int, str]:
    """The window this answer reports, or zero.

    The response is streamed, so a body nobody reads is closed rather than
    left to the client's own teardown: a 404 is the ordinary answer to
    ``/info`` on a llama.cpp server, and three of them a plan is three
    connections held for no reason.
    """
    if answer.status_code >= 400:
        answer.close()
        return 0, ""
    body = _body_within_bounds(answer, ask.what)
    if body is None:
        return 0, ""
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return 0, ""
    try:
        reported = ask.read(payload, model)
    except Exception:  # noqa: BLE001 — a shape nobody anticipated is not a window
        return 0, ""
    if ask.read is window_from_model_list:
        try:
            from maljan.llm.model_output_limits import note_from_model_list

            note_from_model_list(payload, model)
        except Exception:  # noqa: BLE001 — a limit nobody states is not one
            logger.debug("context window: no output limit read from %s", ask.what)
    believed = believable(reported)
    if believed > 0 or not isinstance(reported, int) or reported <= 0:
        return believed, ""
    return 0, (
        f"{ask.what} reported {int(reported):,} tokens, which is past the "
        f"{MAX_BELIEVABLE_WINDOW_TOKENS:,} this platform will believe; the figure was refused"
    )


def believable(tokens: object) -> int:
    """``tokens`` as a window this platform will act on, or zero.

    An endpoint's number is untrusted input. A proxy reporting a window in
    characters, in bytes, or with a units bug produces an integer that is
    perfectly well-formed and absurd, and the consequence is not a bad estimate
    — a cap of 375 million million characters makes ``chars_in <= limit`` true
    for every answer there will ever be, so the shortener, the summariser and
    the character cut all stop running and a two-hundred-megabyte tool answer
    goes straight into the conversation. One arithmetic accident switches the
    guardrail off for a whole run.

    So a window is believed only up to :data:`MAX_BELIEVABLE_WINDOW_TOKENS`,
    and anything past it is refused rather than clamped: a number that far out
    is not a large window reported badly, it is a different unit, and treating
    it as a window of any size would be inventing one. ``True`` is excluded
    explicitly, because it is an ``int`` and would read as a window of 1.
    """
    if isinstance(tokens, bool) or not isinstance(tokens, int):
        return 0
    if tokens <= 0 or tokens > MAX_BELIEVABLE_WINDOW_TOKENS:
        return 0
    return tokens


def _probed(ask: Ask, tokens: int) -> WindowFact:
    return WindowFact(tokens, PROBED, f"{ask.what} reported {tokens:,} tokens")


def _nothing_answered(plan: Iterable[Ask]) -> str:
    asked = ", ".join(ask.what for ask in plan)
    return f"nothing was reported by {asked}" if asked else "this provider serves no window"


def probe_window(
    provider: str, *, endpoint: object, model: str = "", api_key: str = ""
) -> WindowFact | None:
    """Ask the endpoint what window it serves.

    ``None`` when nothing was learned and nothing needs saying. A
    :data:`FALLBACK` fact when an endpoint answered with a number this platform
    refuses to believe, because that is a thing an operator has to be told and
    a silent fall to the table would not tell them.

    Synchronous, for the worker: a job resolves its window once, on a worker
    thread, before its first tool answer. Never raises.
    """
    plan = probe_plan(provider, endpoint, model)
    if not plan:
        return None
    refused = ""
    deadline = time.monotonic() + PROBE_BUDGET_SECONDS
    try:
        with httpx.Client(timeout=PROBE_TIMEOUT_SECONDS) as client:
            for ask in plan:
                if time.monotonic() >= deadline:
                    logger.debug("context window: the probe ran out of time before %s", ask.what)
                    break
                try:
                    answer = _send(client, ask, api_key, deadline)
                except httpx.HTTPError as exc:
                    logger.debug("context window: %s did not answer (%s)", ask.what, type(exc))
                    continue
                tokens, said = _read_answer(ask, answer, model)
                if tokens > 0:
                    return _probed(ask, tokens)
                refused = refused or said
    except Exception as exc:  # noqa: BLE001 — a probe never fails a run
        logger.debug("the context-window probe could not be made: %s", exc)
        return None
    return _nothing_believable(plan, refused)


async def aprobe_window(
    provider: str, *, endpoint: object, model: str = "", api_key: str = ""
) -> WindowFact | None:
    """The same question on the caller's loop, for the settings probe."""
    plan = probe_plan(provider, endpoint, model)
    if not plan:
        return None
    refused = ""
    deadline = time.monotonic() + PROBE_BUDGET_SECONDS
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
            for ask in plan:
                if time.monotonic() >= deadline:
                    logger.debug("context window: the probe ran out of time before %s", ask.what)
                    break
                try:
                    answer = await _asend(client, ask, api_key, deadline)
                except httpx.HTTPError as exc:
                    logger.debug("context window: %s did not answer (%s)", ask.what, type(exc))
                    continue
                tokens, said = _read_answer(ask, answer, model)
                if tokens > 0:
                    return _probed(ask, tokens)
                refused = refused or said
    except Exception as exc:  # noqa: BLE001 — a probe never blocks a settings save
        logger.debug("the context-window probe could not be made: %s", exc)
        return None
    return _nothing_believable(plan, refused)


def _nothing_believable(plan: Iterable[Ask], refused: str) -> WindowFact | None:
    """What a probe that learned no window has to say for itself.

    Nothing, when the endpoints simply did not report one — the table answers
    next and there is no news. A fallback fact carrying the reason when one of
    them reported a number that was refused: an operator whose proxy reports a
    window in bytes needs to read that sentence rather than wonder why their
    run is using the vendored figure.
    """
    if refused:
        logger.warning("context window: %s", refused)
        return unknown_window(refused)
    logger.debug("context window: %s", _nothing_answered(plan))
    return None


def _left(deadline: float) -> float:
    """What is left of the plan's budget, as a per-request timeout.

    httpx applies a plain float per *operation* — connect, read, write, pool —
    so a server that sends one chunk every 1.9 s never trips the two seconds.
    Handing each request what remains of the plan's own wall clock is what
    makes the budget bound the plan rather than the gaps between its asks.
    """
    return max(0.05, deadline - time.monotonic())


def _send(client: httpx.Client, ask: Ask, api_key: str, deadline: float) -> httpx.Response:
    request = client.build_request(
        ask.method,
        ask.url,
        headers=_headers(api_key),
        json=ask.body if ask.method == "POST" else None,
        timeout=_left(deadline),
    )
    return client.send(request, stream=True)


async def _asend(
    client: httpx.AsyncClient, ask: Ask, api_key: str, deadline: float
) -> httpx.Response:
    request = client.build_request(
        ask.method,
        ask.url,
        headers=_headers(api_key),
        json=ask.body if ask.method == "POST" else None,
        timeout=_left(deadline),
    )
    return await client.send(request, stream=True)


# ---------------------------------------------------------------------------
# Learning it once, per provider, endpoint and model
# ---------------------------------------------------------------------------

# How long an answer about one endpoint is believed. Long enough that the
# several agents of a job, and the several jobs of a shift, ask once; short
# enough that a server restarted with a different window, or one that was down
# when the first job ran, is asked again without anybody restarting the worker.
# Both outcomes are cached under it — a dead endpoint asked once per agent was
# four plans and twenty-four seconds of a run.
WINDOW_CACHE_SECONDS = 900.0

_learned_lock = threading.Lock()
_learned: dict[tuple[str, str, str], tuple[float, WindowFact | None]] = {}


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
    declared_is_default: bool = False,
    probe: bool = True,
) -> WindowFact:
    """The served window for one ``(provider, endpoint, model)``, learned once.

    Cached on exactly those three, so a changed endpoint or a changed model is
    a different question and gets asked again.

    ``declared`` does **not** short-circuit the probe. Ollama is why: the
    provider sends ``num_ctx`` with every call, so the served window is the
    smaller of that and what the weights hold, and only ``/api/show`` knows the
    second. The same rule protects an OpenAI-compatible endpoint from a stale
    ``context_size`` left behind by a server that has since been restarted
    smaller. :func:`_combined` is where the two meet.

    ``probe=False`` answers from what is already known, the table and the
    fallback, without touching the network.
    """
    key = (str(provider), str(endpoint or ""), str(model or ""))
    asked, learned = _cached(key)
    if not asked and probe:
        learned = _remembered(
            key, probe_window(provider, endpoint=endpoint, model=model, api_key=api_key)
        )
    return _combined(int(declared), bool(declared_is_default), _preferred(learned, model))


async def alearn_window(
    provider: str,
    *,
    endpoint: object,
    model: str = "",
    api_key: str = "",
    declared: int = 0,
    declared_is_default: bool = False,
    probe: bool = True,
) -> WindowFact:
    """:func:`learn_window` on the caller's loop, for the settings probe.

    The same order, the same cache and the same combination rule; only the
    transport differs, because the API is async and the worker is not.
    """
    key = (str(provider), str(endpoint or ""), str(model or ""))
    asked, learned = _cached(key)
    if not asked and probe:
        learned = _remembered(
            key, await aprobe_window(provider, endpoint=endpoint, model=model, api_key=api_key)
        )
    return _combined(int(declared), bool(declared_is_default), _preferred(learned, model))


def _declared_fact(tokens: int, is_default: bool = False) -> WindowFact:
    """What a settings-named window says about itself.

    A deployment that never touched the field is not an operator statement,
    and saying so was how an untouched Ollama default came to be reported as
    "this deployment's own setting" for a number nobody chose.
    """
    said = (
        "the context size this platform requests by default"
        if is_default
        else "the window this deployment's settings name for the endpoint"
    )
    return WindowFact(tokens, DECLARED, said)


def _preferred(learned: WindowFact | None, model: str) -> WindowFact | None:
    """What the endpoint said, or the table, in that order.

    A probed answer wins. Anything else the probe produced is a refusal
    carrying its reason, and the vendored table is a better *number* than a
    refusal — but the reason travels with it. An endpoint reporting a window
    in the wrong unit for a model the table happens to name used to be
    reported as "the endpoint reported no window", which is the opposite of
    what happened, in the one place an operator most needs the truth.
    """
    if learned is not None and learned.source == PROBED:
        return learned
    table = table_window(model)
    if table is None:
        return learned
    if learned is not None and learned.source == FALLBACK and learned.detail:
        return WindowFact(table.tokens, TABLE, f"{learned.detail}; {table.detail}")
    return table


def _combined(declared: int, declared_is_default: bool, learned: WindowFact | None) -> WindowFact:
    """One window out of what the settings name and what was found.

    Where both are known and one was **probed**, the smaller wins: the server
    is the authority on what it serves, and a settings value left behind by a
    restart must not be allowed to overflow it. Where the other source is the
    vendored table or the fallback, the settings win instead — a figure
    published for a model family, or no figure at all, is not evidence against
    an operator describing their own deployment.
    """
    if declared <= 0:
        return learned or unknown_window()
    stated = _declared_fact(declared, declared_is_default)
    if learned is None or learned.source != PROBED:
        return stated
    return min((stated, learned), key=lambda fact: fact.tokens)


def _cached(key: tuple[str, str, str]) -> tuple[bool, WindowFact | None]:
    """``(asked recently, what came back)`` for one endpoint and model.

    Two answers, not one: a remembered *failure* is a ``None`` that must not be
    read as "never asked", or the failure cache would ask again every time and
    the amplification it exists to stop would come straight back.
    """
    with _learned_lock:
        held = _learned.get(key)
    if held is None:
        return False, None
    learned_at, fact = held
    if time.monotonic() - learned_at > WINDOW_CACHE_SECONDS:
        with _learned_lock:
            _learned.pop(key, None)
        return False, None
    return True, fact


def _remembered(key: tuple[str, str, str], fact: WindowFact | None) -> WindowFact | None:
    """Remember what the endpoint said, including that it said nothing.

    A failure is cached too, and that is deliberate: a job resolves several
    agents against one endpoint, and a dead endpoint asked once per agent cost
    a run four full plans. What keeps a recovered server from being written off
    for the life of the process is the age check in :func:`_cached` rather than
    a refusal to write the answer down.
    """
    with _learned_lock:
        _learned[key] = (time.monotonic(), fact)
    return fact


# What a server says when a request did not fit the window it is serving. Every
# OpenAI-compatible server and every vendor API words it differently; what they
# share is naming the length. Matched loosely on purpose — a false positive
# costs one re-probe and a false negative costs a stale window. That reasoning
# holds for retiring a cached window and for nothing else: a tool loop deciding
# whether a failure is a full window asks :func:`window_full_error`, which is
# strict, because there a false positive would swallow an agent's failure.
_OVERFLOW_SIGNATURES = (
    "context length",
    "context window",
    "context size",
    # llama.cpp with context shift off, when prompt and reply together reach
    # the window: the prompt fitted and the reply ran out of room.
    "context shift",
    "maximum context",
    "n_ctx",
    "max_model_len",
    "too many tokens",
    "prompt is too long",
)

_OVERFLOW_RE = re.compile("|".join(re.escape(word) for word in _OVERFLOW_SIGNATURES))


# The provider SDKs whose errors are a server's answer. Anything else raised
# inside a loop — a ``ValueError`` that happens to mention ``n_ctx`` — is the
# platform's own failure and is never read as a full window.
_PROVIDER_PACKAGES = frozenset({"openai", "anthropic", "ollama", "google"})

# The sentences servers say when the conversation itself has filled the
# window: llama.cpp with context shift off (prompt and reply reached it) and
# when the prompt alone exceeds it, OpenAI-compatible servers, and Anthropic.
_WINDOW_FULL_SIGNATURES = (
    "context shift is disabled",
    "exceeds the available context size",
    "maximum context length",
    "context_length_exceeded",
    "prompt is too long",
)


# The reply cap and the window, as a server that names ``max_tokens`` states
# them: "'max_tokens' … is too large: 8192. This model's maximum context length
# is 32768 tokens and your request has 24808 input tokens".
_REPLY_CAP_RE = re.compile(r"too large:\s*(\d[\d,]*)")
_WINDOW_RE = re.compile(r"maximum context length is\s*(\d[\d,]*)")


def _number(written: str) -> int:
    """A count as a server wrote it, with or without thousands separators."""
    return int(written.replace(",", ""))


def window_full_error(exc: BaseException) -> bool:
    """Whether ``exc`` is a model server saying the conversation filled its window.

    Strict where :func:`note_provider_error` is loose. Only an error a provider
    SDK raised for a server's answer counts, and only a sentence that says the
    request did not fit. A server that names the reply cap is read by its
    numbers: a cap at least as large as the window is a configuration fault
    that no conversation could avoid, and is not a full window; a cap that
    fits the window on its own means the prompt grew until the two together
    did not, which is. Named without numbers to read, it is taken as the
    fault, because a false positive here swallows an agent's failure. Never
    raises.
    """
    try:
        package = type(exc).__module__.split(".", 1)[0]
        if package not in _PROVIDER_PACKAGES:
            return False
        text = str(exc).lower()
        if not any(signature in text for signature in _WINDOW_FULL_SIGNATURES):
            return False
        if "max_tokens" not in text:
            return True
        cap = _REPLY_CAP_RE.search(text)
        window = _WINDOW_RE.search(text)
        if cap is None or window is None:
            return False
        return _number(cap.group(1)) < _number(window.group(1))
    except Exception:  # noqa: BLE001 — an error path never raises another error
        return False


def note_provider_error(message: object) -> bool:
    """Retire the learned windows when a server says a request did not fit.

    The cache believes a probed answer for :data:`WINDOW_CACHE_SECONDS`, and a
    server restarted with a smaller window inside that time is sized against
    the figure it used to serve — which the room check cannot catch, because
    the room check measures against the believed window. The server itself
    says so the first time a request overflows, and that sentence is the one
    free correction available: the entries are dropped and the next question
    is asked again.

    Every entry, not one: the message names a length and not an endpoint, and
    a re-probe costs three metadata requests once. Returns whether anything
    was retired, and never raises — this runs on an error path.
    """
    try:
        text = str(message or "").lower()
        if not text or not _OVERFLOW_RE.search(text):
            return False
        with _learned_lock:
            if not _learned:
                return False
            _learned.clear()
        logger.info(
            "a server reported a request past its context length; "
            "the learned context windows were dropped and will be asked again."
        )
        return True
    except Exception:  # noqa: BLE001 — a correction never breaks the error path
        return False


def declared_window(settings: Any, provider: str) -> tuple[int, bool]:
    """``(tokens, is_default)`` for the window this deployment's settings name.

    Ollama's ``num_ctx`` is sent with every call, so it is one half of the
    served window whether or not anybody chose it — which is why the second
    element exists: the field ships with a value, and reporting an untouched
    default as an operator's statement was a claim nobody had made. The
    OpenAI-compatible ``context_size`` ships at zero, so a positive value there
    is always somebody's decision.
    """
    try:
        if provider == "ollama":
            from maljan.core.config import OllamaConfig

            value = int(settings.llm.ollama.num_ctx)
            shipped = int(OllamaConfig.model_fields["num_ctx"].default)
            return value, value == shipped
        if provider == "openai":
            return int(getattr(settings.llm.openai, "context_size", 0) or 0), False
    except Exception as exc:  # noqa: BLE001 — an unreadable setting is not a window
        logger.debug("context window: the declared window could not be read (%s)", exc)
    return 0, False


def _provider_key(settings: Any, provider: str) -> str:
    """The credential ``provider`` authenticates with, as a plain string."""
    try:
        secret = getattr(getattr(settings.llm, provider, None), "api_key", None)
        reveal = getattr(secret, "get_secret_value", None)
        return str(reveal() if callable(reveal) else (secret or ""))
    except Exception:  # noqa: BLE001 — a probe without a key is still a probe
        return ""


def window_for_assignment(settings: Any, assignment: Any, *, probe: bool = True) -> WindowFact:
    """The served window of one model an agent calls, learned the way every window is."""
    declared, is_default = declared_window(settings, str(assignment.provider))
    return learn_window(
        str(assignment.provider),
        endpoint=assignment.endpoint,
        model=str(assignment.model or ""),
        api_key=_provider_key(settings, str(assignment.provider)),
        declared=declared,
        declared_is_default=is_default,
        probe=probe,
    )


@dataclass(frozen=True)
class OutputBudget:
    """How many tokens one reply may run to, and the numbers it was worked out from."""

    tokens: int
    window: WindowFact
    generation_cap: int
    derivation: str = ""

    def sentence(self) -> str:
        """The derivation in one sentence, so a reader can check the arithmetic."""
        return self.derivation


# What the window probe names when a server we run answered it: a model
# runtime, which has no API limit on output and caps generation at its context.
_LOCAL_SERVER_ANSWERS = (
    "llama.cpp /props",
    "the Ollama model description",
    "the server description",
)


def serves_locally(assignment: Any, window: WindowFact) -> bool:
    """Whether the model is served by a runtime we run rather than a hosted API.

    Only when the window probe received the runtime's own answer: llama.cpp's
    ``/props``, Ollama's ``/api/show`` or Text Generation Inference's ``/info``.
    A loopback address says nothing on its own — a gateway or tunnel on
    ``localhost:4000`` that forwards to a hosted API has that API's output
    limit — so an endpoint that did not answer as a runtime is asked for a
    declared maximum and otherwise takes the hosted fallback. ``assignment`` is
    kept for callers; what decides is what answered.
    """
    del assignment
    return window.source == PROBED and str(window.detail).startswith(_LOCAL_SERVER_ANSWERS)


def derived_reply(
    window: WindowFact, configured: int, model: object, what: str, *, local: bool = False
) -> tuple[int, str]:
    """``(tokens, sentence)`` for one reply of a model: the one rule, said out loud.

    Three cases, each bounded by ``configured`` (an operator's cap, named by
    ``what``) where it is set:

    1. The model's maximum output is declared — by the probe's model list or
       the vendored table's sourced ``max_output`` rows — and the reply is the
       smaller of that and a quarter of the window.
    2. A runtime we run serves it (``local``, :func:`serves_locally`): no API
       limits output, and the reply is a quarter of the window.
    3. A hosted API that declares no maximum: the documented fallback of
       :data:`DEFAULT_REPLY_TOKENS`, never more than a quarter of the window,
       because a quarter of a hosted model's window is routinely past what the
       API accepts and a refused ``max_tokens`` fails every call.

    A window nothing reported derives nothing: an operator's cap is used as
    set, and otherwise the documented fallback, and the sentence says so.
    """
    from maljan.llm.model_output_limits import declared_output_limit

    declared = declared_output_limit(model)
    if window.source == FALLBACK:
        if configured > 0:
            return configured, f"{configured} tokens — {what} is set to {configured}"
        tokens = min(DEFAULT_REPLY_TOKENS, declared) if declared > 0 else DEFAULT_REPLY_TOKENS
        return tokens, (
            f"{tokens} tokens — the documented fallback: no window was learned for the model "
            f"({window.detail})"
            + (f", and it declares a maximum output of {declared}" if declared > 0 else "")
        )
    quarter = max(1, window.tokens // REPLY_RESERVE_DIVISOR)
    parts = [
        f"a quarter ({quarter}) of the model's {window.tokens}-token context window "
        f"({window.source})"
    ]
    if declared > 0:
        tokens = reply_reserve_tokens(window.tokens, configured, declared)
        parts.append(f"the model's declared maximum output of {declared}")
    elif local:
        tokens = reply_reserve_tokens(window.tokens, configured)
        parts[0] += ", served by a runtime with no API output limit"
    else:
        tokens = reply_reserve_tokens(window.tokens, configured, DEFAULT_REPLY_TOKENS)
        parts.append(
            f"the documented fallback of {DEFAULT_REPLY_TOKENS}, because the hosted API "
            "declares no maximum output for this model"
        )
    if configured > 0:
        parts.append(f"{what} of {configured}")
    said = parts[0] if len(parts) == 1 else "the smallest of " + ", ".join(parts)
    return tokens, f"{tokens} tokens — {said}"


def reply_budget(settings: Any, assignment: Any, *, probe: bool = True) -> OutputBudget:
    """How long one reply of this model may run: the one rule (:func:`derived_reply`).

    The same rule the analysts' and the judge's derived caps follow: a quarter
    of the window the model serves, bounded by an operator's generation cap and
    the model's declared maximum output where they are set. A report section is
    one such reply, so it gets the same room, and a model's reasoning is spent
    inside it rather than past it.
    """
    window = window_for_assignment(settings, assignment, probe=probe)
    cap = generation_reserve(settings)
    tokens, sentence = derived_reply(
        window,
        cap,
        getattr(assignment, "model", ""),
        "the generation cap (the larger of llm.expert_max_tokens and llm.judge_max_tokens)",
        local=serves_locally(assignment, window),
    )
    return OutputBudget(tokens=tokens, window=window, generation_cap=cap, derivation=sentence)


def model_maximum_output(window: WindowFact, model: object) -> tuple[int, str]:
    """``(tokens, where from)`` for the most one answer of ``model`` can be, or ``(0, "")``.

    The maximum output its provider declares (:func:`declared_output`), and no
    more than the context window it serves, because an answer is written into
    that window. With neither known, zero: nothing is stated about it.
    """
    from maljan.llm.model_output_limits import declared_output

    declared, where = declared_output(model)
    learned = window.source != FALLBACK and window.tokens > 0
    if declared > 0 and (not learned or declared <= window.tokens):
        return declared, f"the model's declared maximum output of {declared} ({where})"
    if learned:
        return window.tokens, f"the model's {window.tokens}-token context window ({window.source})"
    return 0, ""


def call_output_bound(cap: int, window_tokens: int, prompt_chars: int) -> int | None:
    """The ``max_tokens`` one call is sent with when its budget would pass the window, or ``None``.

    A call's answer is written into the window its prompt already fills, so the
    most it can be is the window less the prompt, at :data:`CHARS_PER_TOKEN`
    characters a token. ``None`` — the budget stands — when the window is not
    known (``window_tokens`` 0: nothing to bound by) or the budget already fits.
    Never below one token: a prompt that fills the window is the caller's
    degradation to record, not a request for nothing.
    """
    if int(window_tokens) <= 0 or int(cap) <= 0:
        return None
    left = int(window_tokens) - -(-max(0, int(prompt_chars)) // CHARS_PER_TOKEN)
    if int(cap) <= left:
        return None
    return max(1, left)


# The chat model types a per-call ``max_tokens`` cannot be handed to: Ollama's
# client takes its cap only inside ``options`` and refuses an unknown keyword.
# A runtime we run stops at its own context rather than refusing the request,
# so leaving its cap as built costs no call.
_NO_PER_CALL_CAP = ("ChatOllama",)


def accepts_output_bound(llm: Any) -> bool:
    """Whether ``max_tokens`` may be passed to one call of ``llm`` (every model of a list)."""
    models = getattr(llm, "models", None)
    if isinstance(models, list) and models:
        return all(accepts_output_bound(model) for model in models)
    return not any(cls.__name__ in _NO_PER_CALL_CAP for cls in type(llm).__mro__)


def report_output_budget(
    settings: Any,
    assignment: Any,
    configured: int,
    configured_said: str,
    *,
    setting: str = "llm.judge_max_tokens",
    probe: bool = True,
) -> OutputBudget:
    """How long one answer of the report stage may run on one model, and why.

    The report stage writes the report, and a report is as long as its
    evidence needs; a quarter of the window is the analysts' rule, which keeps
    room in a conversation that is still gathering. So, in this order:

    1. ``configured`` above 0 is the operator's value (``configured_said`` says
       which setting, and what was added to it), used as set;
    2. else the model's declared maximum output — the endpoint's model list or
       the vendored table's sourced row;
    3. else the analysts' derivation (:func:`derived_reply`), with ``setting``
       named as the cap that was not set.

    Never more than the model's maximum (:func:`model_maximum_output`); a value
    held at it says so. The window is still learned: a section's evidence room
    is what the window leaves after this budget.
    """
    from maljan.llm.model_output_limits import declared_output_limit

    window = window_for_assignment(settings, assignment, probe=probe)
    model = getattr(assignment, "model", "")
    maximum, maximum_said = model_maximum_output(window, model)
    configured = int(configured or 0)
    if configured > 0:
        tokens = min(configured, maximum) if maximum > 0 else configured
        sentence = f"{tokens} tokens — {configured_said}"
        if tokens < configured:
            sentence += f", held at {maximum_said}"
    elif declared_output_limit(model) > 0:
        tokens, sentence = maximum, f"{maximum} tokens — {maximum_said}"
    else:
        tokens, sentence = derived_reply(
            window, 0, model, setting, local=serves_locally(assignment, window)
        )
    return OutputBudget(
        tokens=tokens, window=window, generation_cap=configured, derivation=sentence
    )


@dataclass(frozen=True)
class OutputCap:
    """One agent's output cap in tokens, and the sentence that says how it was reached."""

    tokens: int
    sentence: str


def output_cap_for(
    settings: Any, setting: str, agent: str = "", *, role: str = "expert", probe: bool = False
) -> OutputCap:
    """The output cap ``agent``'s calls are built with: the operator's, or derived.

    ``setting`` is ``expert_max_tokens`` or ``judge_max_tokens``. Above 0 it is
    the operator's value, used as set. At 0, the shipped default, it is derived
    from the smallest window of the models the agent may call — a quarter of
    it for a runtime we run, bounded by the model's declared maximum output
    where one is declared, and the documented fallback for a hosted API that
    declares none — the one rule the reply reserve and the composer's section
    budget follow (:func:`derived_reply`). Over a fallback list, the smallest
    of its models.
    A window nothing reported derives nothing: the documented fallback of
    :data:`DEFAULT_REPLY_TOKENS` applies, and the sentence says so.

    ``probe=False`` answers from what is already learned, the table and the
    declared window, without a request.
    """
    configured = int(getattr(getattr(settings, "llm", None), setting, 0) or 0)
    if configured > 0:
        return OutputCap(configured, f"{configured} tokens — llm.{setting} is set to {configured}")
    best: tuple[int, str] | None = None
    try:
        from maljan.core.model_assignments import assignment_chain_for

        for assignment in assignment_chain_for(settings, agent, role=role):
            window = window_for_assignment(settings, assignment, probe=probe)
            answer = derived_reply(
                window,
                0,
                assignment.model,
                f"llm.{setting}",
                local=serves_locally(assignment, window),
            )
            if best is None or answer[0] < best[0]:
                best = answer
    except Exception as exc:  # noqa: BLE001 — an unreadable assignment learns no window
        logger.debug("output cap: no window for %r (%s)", agent, exc)
    if best is None:
        best = derived_reply(
            unknown_window("the model's assignment could not be read"), 0, "", f"llm.{setting}"
        )
    tokens, said = best
    return OutputCap(tokens, f"llm.{setting} is 0, so derived: {said}")


def _questions(settings: Any, agents: list[str]) -> list[dict[str, Any]]:
    """The distinct windows this run has to learn, one per pair, in order.

    Deduplicated on ``(provider, endpoint, model)`` — the cache's own key —
    because that is the question, and a team of five agents on one endpoint is
    one question asked once. Asked per agent instead, a dead endpoint cost a
    run four full plans and twelve requests before it could start.
    """
    from maljan.core.model_assignments import assignments_for

    asked: dict[tuple[str, str, str], dict[str, Any]] = {}
    for assignment in assignments_for(settings, agents):
        declared, is_default = declared_window(settings, assignment.provider)
        asked.setdefault(
            (assignment.provider, assignment.endpoint, assignment.model),
            {
                "provider": assignment.provider,
                "endpoint": assignment.endpoint,
                "model": assignment.model,
                "api_key": _provider_key(settings, assignment.provider),
                "declared": declared,
                "declared_is_default": is_default,
            },
        )
    return list(asked.values())


def window_for_settings(settings: Any, agents: list[str], *, probe: bool = True) -> WindowFact:
    """The window one run may count on, across every model its agents call.

    The smallest of them, because one cap is handed to every tool server the
    job opens and a cap sized for the roomiest model would overflow the
    tightest. A run whose agents all sit on one endpoint — the ordinary shape —
    asks one question and gets one answer.
    """
    facts = [learn_window(probe=probe, **question) for question in _questions(settings, agents)]
    if not facts:
        return unknown_window("this run names no model")
    return min(facts, key=lambda fact: fact.tokens)


async def awindow_for_settings(
    settings: Any, agents: list[str], *, probe: bool = True
) -> WindowFact:
    """:func:`window_for_settings` on the caller's loop."""
    facts = [
        await alearn_window(probe=probe, **question) for question in _questions(settings, agents)
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

# Whose answer the guardrail is sizing right now. Set by the tool wrapper
# around each call — the one layer that knows both the agent and the call —
# and read by the budget, so the guardrails need to know nothing about agents
# to be charged against the right one. A context variable rather than an
# argument because the two are separated by the toolkit, which is shared by
# every agent of the job; it survives the ``asyncio.to_thread`` both tool
# paths hand the guardrail to, because that copies the context.
_ANSWERING_FOR: ContextVar[str] = ContextVar("maljan_answering_for", default="")


def current_agent() -> str:
    """The agent whose tool call is being answered, or ``""`` outside one."""
    return _ANSWERING_FOR.get()


@contextlib.contextmanager
def answering_for(agent: str) -> Iterator[None]:
    """Name the agent whose call is being answered, for the length of the call."""
    token = _ANSWERING_FOR.set(str(agent or ""))
    try:
        yield
    finally:
        _ANSWERING_FOR.reset(token)


def tool_definition_chars(tools: Iterable[Any]) -> int:
    """What the definitions of ``tools`` weigh in a request, in characters.

    Every request a tool loop makes carries them beside the messages — the
    name, the description and the argument schema of each tool, as the
    provider sends them — and none of it is in the conversation a loop
    measures. A static analyst with 35 tools spent over a quarter of a
    32,768-token window's tool budget on them before its first message, and a
    count that left them out said there was room until the server refused.

    Measured as the OpenAI-compatible definition, which is what the providers
    this platform uses send. A tool that cannot be described costs nothing
    here rather than failing the loop.
    """
    from langchain_core.utils.function_calling import convert_to_openai_tool

    total = 0
    for tool in tools:
        try:
            total += len(json.dumps(convert_to_openai_tool(tool), ensure_ascii=False))
        except Exception as exc:  # noqa: BLE001 — a definition is never worth a lost loop
            logger.debug("context window: a tool definition was not measured (%s)", exc)
    return total


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

    Reading is lock-protected and never raises.

    A budget over an **unknown** window derives nothing. There is no
    measurement to derive from, so it answers with
    :data:`UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS` — the constant this platform
    shipped with — and every surface says the window is unknown.
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
        # What each agent has been handed since its own conversation was last
        # measured. A model turn may request several tools at once and every
        # answer it produces is measured before the next turn is framed, so
        # without this each of them would be measured against the same free
        # room and the turn as a whole could spend it k times over. Cleared by
        # that agent's next measurement, which already contains the answers it
        # is clearing — and per agent, because one process-wide slot let a
        # second analyst's refresh clear a total the first was still spending
        # against, which under fan-out gave back the whole free room.
        self._handed: dict[str, int] = {}
        # The agents that have been told the room is gone. Told once each.
        self._no_room: set[str] = set()
        # And the agents whose run-state block carries the standing line about
        # it, which is only the ones there was room to say it to.
        self._run_state_said: set[str] = set()
        # Whether the invariant below has already been reported broken.
        self._warned_unnamed = False
        self._smallest = 0
        self._largest = 0

    @property
    def derives(self) -> bool:
        """Whether this budget has a measured window to derive a cap from."""
        return self.window.source != FALLBACK

    def note_conversation(self, agent: str, chars: int) -> None:
        """Record what one agent's conversation weighs as of this turn."""
        key = str(agent)
        with self._lock:
            self._held[key] = max(0, int(chars))
            self._handed.pop(key, None)

    def forget_conversation(self, agent: str) -> None:
        """Forget a loop that has finished, so its size stops binding."""
        key = str(agent)
        with self._lock:
            self._held.pop(key, None)
            self._handed.pop(key, None)
            self._no_room.discard(key)
            self._run_state_said.discard(key)

    def held_chars(self, agent: str = "") -> int:
        """What an answer for ``agent`` is measured against, in characters.

        The fullest live conversation, because one cap serves every agent and
        the fullest has least room to spare, plus what **this** agent has been
        handed since its own conversation was last measured. The second term is
        per agent: it is this turn's own spending, and charging one agent for
        another's would be as wrong as charging neither.
        """
        key = str(agent) or current_agent()
        with self._lock:
            return max(self._held.values(), default=0) + self._handed.get(key, 0)

    def charge(self, chars: int, agent: str = "") -> None:
        """Charge text that entered the conversation without being a capped answer.

        The refusal a tool call gets when the room has run out is text like any
        other, and so is the twenty characters a character cut appends after
        cutting: they reach the model, they cost the window, and leaving them
        uncharged is how the run's account of what a conversation holds drifts
        from what is in it.
        """
        key = self._whose(agent)
        with self._lock:
            self._handed[key] = self._handed.get(key, 0) + max(0, int(chars))

    def note_no_room(self, agent: str = "") -> None:
        """Record that this agent has been told the room is gone.

        The run-state block will carry :data:`NO_ROOM_RUN_STATE` from here on,
        so that line is charged now — once, because the block is rewritten
        on every model turn rather than appended to, so only one copy is ever
        in the conversation. Charged only if it fits, on the same rule as the
        two notices, and :meth:`says_no_room` is what the block asks before
        adding it, so nothing is added that was not paid for.
        """
        key = self._whose(agent)
        with self._lock:
            self._no_room.add(key)
        if self.room_for(len(NO_ROOM_RUN_STATE), key):
            self.charge(len(NO_ROOM_RUN_STATE), key)
            with self._lock:
                self._run_state_said.add(key)

    def says_no_room(self, agent: str = "") -> bool:
        """Whether the run-state block may carry the no-room line for this agent.

        A latch, not a per-turn question. The charge is made once, when the
        room runs out and only if there was room to make it; from the next
        model turn the line is inside the measured conversation like any other
        text. Clearing it on a measurement would drop the line the model is
        meant to keep reading, and charge it again the moment it came back.
        """
        with self._lock:
            return (str(agent) or current_agent()) in self._run_state_said

    def _whose(self, agent: str) -> str:
        """The agent a charge or a mark belongs to. Takes the lock itself.

        The invariant: a guardrail is reached from inside the tool wrapper,
        which names the agent for the length of the call
        (:func:`answering_for`). Nothing in the tree reaches one any other way
        — both places that wrap tools wrap every tool, and the name survives
        the thread the guardrail is handed to.

        If that ever stopped being true the failure would be the bad kind: the
        charge lands under a key nobody reads, the mark never reaches the
        agent, its tool phase never ends and the long sentence is repeated on
        every call. So an unnamed call is not quietly filed under the empty
        string. It is attributed to the conversation the cap was computed
        against — the fullest one — and it says so, once: a broken path is a
        hot one, and a warning per call would flood a log to report a thing
        that is true of the whole run. The log is written outside the lock for
        the same reason — a handler is not something a budget read should wait
        on.
        """
        named = str(agent) or current_agent()
        if named:
            return named
        with self._lock:
            fullest = max(self._held, key=lambda key: self._held[key], default="")
            first, self._warned_unnamed = not self._warned_unnamed, True
        if first:
            logger.warning(
                "a tool answer was sized outside the wrapper that names its agent; "
                "the charge is attributed to the fullest conversation (%r).",
                fullest,
            )
        return fullest

    def tool_budget_chars(self) -> int:
        """Everything a conversation may hold before the reply reserve begins."""
        return max(0, self.window.tokens - self.reply_tokens) * self.chars_per_token

    def room_for(self, chars: int, agent: str = "") -> bool:
        """Whether ``chars`` of the platform's own text still fits the tool budget.

        Asked about a notice rather than about an answer. A refusal is text
        like any other, and a loop whose model keeps asking after its tool
        phase ended would otherwise grow by one line a round with nothing able
        to stop it. Where a line does not fit, the honest thing to hand over is
        nothing.

        **Measured against the window less the reply reserve, not against the
        window.** The reserve is the room the forced synthesis writes its
        answer in, and that synthesis is this design's own answer to a
        conversation that has run out — so spending the reserve on saying that
        it has run out takes the room from the one thing left to do. Measured
        against the whole window instead, the refusals took half the reserve on
        a shipped 8,192-token row and three quarters of it on 4,096, which left
        the salvage 257 tokens to write in. A cap already comes out of this
        same budget, so with the notices inside it too, the whole of what the
        platform hands a model stays in the tool budget and the reserve is
        untouched.

        Always true where no window was measured: there is nothing to measure
        against, and refusing to speak on the strength of a number nobody has
        would be the same error as deriving a cap from one.
        """
        if not self.derives:
            return True
        return self.held_chars(agent) + max(0, int(chars)) <= self.tool_budget_chars()

    def out_of_room(self, agent: str = "") -> bool:
        """Whether this agent's tool phase has ended for want of room."""
        with self._lock:
            return (str(agent) or current_agent()) in self._no_room

    def chars_for_one_answer(self) -> int:
        """The cap a tool answer arriving now is given, and reserve it.

        Reserving the cap rather than the answer's real size is the
        conservative direction: an answer smaller than its cap leaves the turn
        looking fuller than it is, and the next measurement corrects it. The
        alternative — reserving nothing until the answer is sized — is what let
        eight tool calls in one turn each take an eighth of the same free room.

        Which agent is being answered comes from :func:`current_agent`, set by
        the tool wrapper around the call, so the guardrail needs to know
        nothing about agents to be charged against the right one.
        """
        if not self.derives:
            return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
        agent = current_agent()
        cap = derive_tool_output_chars(
            window_tokens=self.window.tokens,
            held_chars=self.held_chars(agent),
            reply_tokens=self.reply_tokens,
            chars_per_token=self.chars_per_token,
            share=self.share,
            floor=self.floor,
        )
        with self._lock:
            self._handed[agent] = self._handed.get(agent, 0) + cap
            self._smallest = cap if self._smallest == 0 else min(self._smallest, cap)
            self._largest = max(self._largest, cap)
        return cap

    def cap_without_recording(self, agent: str = "") -> int:
        """The cap as it stands, for a log line, a settings page or a guard.

        The same arithmetic with nothing written down: reading it must not
        reserve room a tool answer never took, and must not leave a run that
        called no tool reporting a cap range nothing used.
        """
        if not self.derives:
            return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
        return derive_tool_output_chars(
            window_tokens=self.window.tokens,
            held_chars=self.held_chars(agent),
            reply_tokens=self.reply_tokens,
            chars_per_token=self.chars_per_token,
            share=self.share,
            floor=self.floor,
        )

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
            "derives": self.derives,
            "remedy": "" if self.derives else UNKNOWN_WINDOW_REMEDY,
        }


def budget_for_settings(settings: Any, agents: list[str], *, probe: bool = True) -> ContextBudget:
    """This run's context budget, window learned and reply room reserved."""
    return ContextBudget(
        window_for_settings(settings, agents, probe=probe),
        reply_tokens=generation_reserve(settings),
    )


def upstream_block_chars(configured: int, budget: Any) -> tuple[int, str]:
    """``(characters, how)`` a stage's upstream findings block and triage pack may take.

    The same three answers as a tool answer's cap (:func:`output_limit`): a
    positive ``configured`` is the operator's
    ``core.reporting.upstream_findings_max_chars``, used unchanged; a budget
    over a measured window derives it — the share one answer may take of what
    the window leaves after the reply room, measured before the conversation
    holds anything, because the block is read before a stage starts; and
    anything else is the documented constant, stated as the fallback.
    """
    if int(configured) > 0:
        chars = int(configured)
        return chars, f"{chars} characters — reporting.upstream_findings_max_chars is set"
    if isinstance(budget, ContextBudget) and budget.derives:
        chars = derive_tool_output_chars(
            window_tokens=budget.window.tokens,
            reply_tokens=budget.reply_tokens,
            chars_per_token=budget.chars_per_token,
            share=budget.share,
            floor=budget.floor,
        )
        if chars > 0:
            return chars, (
                f"{chars} characters — derived from the {budget.window.tokens}-token "
                f"window ({budget.window.source}) less {budget.reply_tokens} tokens of "
                f"reply room, at {budget.chars_per_token} characters a token and a "
                f"share of {budget.share}"
            )
    return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS, (
        f"{UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS} characters — the documented fallback: no "
        f"window was learned ({UNKNOWN_WINDOW_REMEDY})"
    )


def output_limit(configured: int, budget: Any) -> int:
    """How many characters of one tool answer may reach the model right now.

    One function for both tool paths — the MCP toolkit's guardrail and the
    Ghidra HTTP client's — because they support one claim: what the model reads
    is inside the limit in force for this call.

    Three answers. A positive ``configured`` is the operator having set
    ``core.preprocessing.max_tool_output_chars`` themselves, used unchanged. A
    budget over a measured window derives the cap from what is left. Anything
    else — no budget at all, or a budget over a window nothing reported — is
    the documented constant, because a platform with no measurement has nothing
    to derive from and deriving anyway would be stating what it does not know.

    Deliberately no process-wide stand-in budget: one shared mutable object
    recording caps across every job and thread is global state for a path that
    needs a number rather than an object.
    """
    if int(configured) > 0:
        return int(configured)
    if isinstance(budget, ContextBudget):
        return budget.chars_for_one_answer()
    return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
