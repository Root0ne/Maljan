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
import time
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
# account of itself. When the floor binds, nothing new happens to the answer:
# it meets the structural shortener at this size, comes back as a document with
# its ``shortened`` map, and carries the notice naming the arguments that
# narrow it.
#
# What the floor costs is stated rather than hidden. It is the one place the
# derivation stops being self-limiting: everywhere else an answer takes a share
# of what is *free*, so the answers of one conversation sum to less than the
# room it began with, and at the floor they no longer do. Two thousand
# characters is about 667 tokens, so a conversation that has reached the floor
# grows by that much per further answer whatever is left — and what it spends
# first is the reply reserve, not the window.
#
# Measured over the largest loop the settings configure, the static analyst's
# twenty tool rounds:
#
#   window    floor first reached   conversation after 20 rounds
#   131,072   never                 114,375 tokens, 16,697 under the window
#    32,768   the 13th answer        24,958 tokens, 382 into the reply reserve
#     8,192   the 3rd answer         13,440 tokens, 5,248 past the window
#
# So on every window that was reported or looked up the floor costs a few
# hundred tokens of the reply's own room at worst. Where it genuinely overruns
# is the 8,192-token fallback — the case where nothing reported a window at
# all, which the run summary names as the fallback and which one field fixes
# (``core.llm.openai.context_size``). A run where the floor bound is visible
# either way: the smallest cap in force equals this number.
MIN_TOOL_OUTPUT_CHARS = 2000

# What is held back for the model's own reply when nothing configures it. The
# analyst and judge generation caps are both 8,192 tokens, and this is the
# figure used when both are left unbounded.
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

    **The result never exceeds the room that is really left.** The floor
    applies while the room affords it and is reduced to the room when it does
    not, and when what is left cannot hold an answer at all the result is
    ``0`` — the caller then hands the model no answer and says so
    (:func:`no_room_sentence`). A floor that overrode the room was how a
    twenty-round loop on a shipped 8,192-token window finished 5,248 tokens
    past the window it was sizing itself against.

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

    A deterministic fact about this conversation, not a judgement about the
    tool: the call was made, it answered, and there is no room left to show any
    of it. Saying so is the only alternative to handing over a fragment too
    small to read or overflowing the window the whole derivation exists to fit
    inside. The tool's own arguments are not named here — narrowing the answer
    would not help, because the room is gone rather than the answer too large.
    """
    return (
        f"This tool answered with {chars_in:,} characters and none of them could be added: "
        "the conversation has no room left for a tool answer. Nothing was left out of the "
        "record — the evidence ledger holds the whole answer under this call's id. "
        "Answer from what has already been gathered."
    )


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
#
# This bounds each *operation* — httpx applies a plain float to connect, read,
# write and pool separately — so a server that sends one byte every 1.9 s never
# trips it. ``PROBE_BUDGET_SECONDS`` is the wall around the whole plan, which
# is what makes the two seconds a real bound rather than a stated one.
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


def _read_answer(ask: Ask, answer: httpx.Response, model: str) -> tuple[int, str]:
    """The window this answer reports, or zero, with the body bounded.

    The body is measured before it is parsed. A metadata answer is kilobytes —
    the largest legitimate one, a public model catalogue, is a couple of
    megabytes — and a broken or hostile endpoint's is unbounded, so a probe
    that read it whole would be a memory cost nobody asked for on a machine
    that is also running a model.
    """
    if answer.status_code >= 400:
        return 0, ""
    if len(answer.content) > MAX_METADATA_BYTES:
        logger.debug("context window: %s answered with more than the probe reads", ask.what)
        return 0, ""
    try:
        payload = answer.json()
    except ValueError:
        return 0, ""
    try:
        reported = ask.read(payload, model)
    except Exception:  # noqa: BLE001 — a shape nobody anticipated is not a window
        return 0, ""
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
                    answer = _send(client, ask, api_key)
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
                    answer = await _asend(client, ask, api_key)
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
    carrying its reason, and the vendored table is a better window than a
    refusal — but the refusal stands when the table does not name the model,
    so the reason reaches the run summary instead of being replaced by a
    generic one.
    """
    if learned is not None and learned.source == PROBED:
        return learned
    return table_window(model) or learned


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
        # What has been handed out since a conversation was last measured. A
        # model turn may request several tools at once and every answer it
        # produces is measured before the next turn is framed, so without this
        # each of them would be measured against the same free room and the
        # turn as a whole could spend it k times over. Cleared by the next
        # measurement, which already contains the answers it is clearing.
        self._handed = 0
        self._smallest = 0
        self._largest = 0

    @property
    def derives(self) -> bool:
        """Whether this budget has a measured window to derive a cap from."""
        return self.window.source != FALLBACK

    def note_conversation(self, agent: str, chars: int) -> None:
        """Record what one agent's conversation weighs as of this turn."""
        with self._lock:
            self._held[str(agent)] = max(0, int(chars))
            self._handed = 0

    def forget_conversation(self, agent: str) -> None:
        """Forget a loop that has finished, so its size stops binding."""
        with self._lock:
            self._held.pop(str(agent), None)
            if not self._held:
                self._handed = 0

    def held_chars(self) -> int:
        """The fullest live conversation, plus what this turn has already spent."""
        with self._lock:
            return max(self._held.values(), default=0) + self._handed

    def chars_for_one_answer(self) -> int:
        """The cap a tool answer arriving now is given, and reserve it.

        Reserving the cap rather than the answer's real size is the
        conservative direction: an answer smaller than its cap leaves the turn
        looking fuller than it is, and the next measurement corrects it. The
        alternative — reserving nothing until the answer is sized — is what let
        eight tool calls in one turn each take an eighth of the same free room.
        """
        if not self.derives:
            return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
        cap = derive_tool_output_chars(
            window_tokens=self.window.tokens,
            held_chars=self.held_chars(),
            reply_tokens=self.reply_tokens,
            chars_per_token=self.chars_per_token,
            share=self.share,
            floor=self.floor,
        )
        with self._lock:
            self._handed += cap
            self._smallest = cap if self._smallest == 0 else min(self._smallest, cap)
            self._largest = max(self._largest, cap)
        return cap

    def cap_without_recording(self) -> int:
        """The cap as it stands, for a log line or a settings page.

        The same arithmetic with nothing written down: reading it must not
        reserve room a tool answer never took, and must not leave a run that
        called no tool reporting a cap range nothing used.
        """
        if not self.derives:
            return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
        return derive_tool_output_chars(
            window_tokens=self.window.tokens,
            held_chars=self.held_chars(),
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
