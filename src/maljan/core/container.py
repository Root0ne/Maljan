"""ServiceContainer — Dependency Injection / Composition Root.

Wires together all registries, loaders, and provides factory methods for
creating agents and LLM instances. Replaces scattered global state and
``_is_mock_mode()`` checks with a single, testable container.

Caching:
    LLM instances, agent instances, and loaded sample data are all cached so
    that repeated calls during the negotiation loop do not incur redundant
    object creation or I/O. Every getter is guarded by a single re-entrant
    lock so concurrent LangGraph fan-out nodes cannot double-build the cache.

Heterogeneous Model Ensemble:
    ``get_agent_llm(agent_name)`` returns a per-agent LLM instance using the
    ``LLMConfig.agents`` overrides. Agents without overrides fall back to the
    global expert LLM.

LangSmith Observability:
    When ``Settings.langchain_tracing_v2`` is true, ``_configure_langsmith()``
    sets the env vars LangChain reads automatically.

Sandbox Backend:
    ``get_sandbox_provider()`` builds the configured ``SandboxProvider`` from
    the registry (``mock`` when the container's own ``mock`` flag is set) and
    caches it for the lifetime of the container.
"""

from __future__ import annotations

import asyncio
import os
import threading
import uuid
import weakref
from collections.abc import Callable, Iterable
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.registry import AgentRegistry
from maljan.agents.run_evidence_corpus import RunEvidenceCorpus
from maljan.core.cancellation import Cancellation
from maljan.core.config import (
    MEDIATOR_AGENT_KEY,
    PROMPT_ROLES,
    REPORTER_AGENT_KEY,
    SUMMARIZER_AGENT_KEY,
    Settings,
)
from maljan.core.exceptions import ConfigurationError
from maljan.core.logger import logger
from maljan.core.token_ledger import TokenLedger
from maljan.core.truncation_ledger import TruncationLedger
from maljan.llm.agent_ceiling import attach_agent_ceiling
from maljan.llm.context_window import record_built_cap
from maljan.llm.generation_rate import GenerationRates, attach_rate_meter
from maljan.llm.registry import LLMProviderRegistry
from maljan.llm.transient import attach_retry_recorder
from maljan.loaders.file_loader import FileDataLoader
from maljan.parsers.registry import ParserRegistry
from maljan.schemas.evidence import EvidenceCounter

if TYPE_CHECKING:
    from pathlib import Path

    from maljan.agents.base_agent import BaseAnalyst
    from maljan.analysis.function_summarizer import FunctionSummarizer
    from maljan.loaders.binary_chunker import Room, TextChunk
    from maljan.memory.long_term_memory import MemoryStore
    from maljan.pipeline.events import EventSink
    from maljan.providers.base import SandboxProvider, StaticProvider
    from maljan.providers.servers import ServerRegistry


# Per-closer budget in ``aclose``. Each toolkit is already bounded internally;
# this is the second fence, because a teardown that hangs holds the whole job
# open and — with ``max_jobs = 1`` — every job after it.
#
# It has to be strictly larger than what a single handle's close can take, or
# this fence cancels the handle's own abandonment handling mid-flight and the
# child is never reaped: ``ServerHandle`` spends at most 14s routing the close
# and 4s reaping, and the numbers are kept coherent there (see the budget
# table at the top of ``providers/servers.py``).
_ACLOSE_BUDGET = 20.0

# The synchronous sweep's budget. Larger than ``_ACLOSE_BUDGET`` because it
# closes every synchronously-opened handle in one call, each with its own
# 20s bound — and because it runs in an executor, so the time it spends is a
# worker thread's, not the event loop's.
_CLOSE_ALL_BUDGET = 45.0

# What the job's end waits for the servers its readings ran on to remove what
# those readings staged there (``pipeline.nodes.release_reader_staging``). Every
# server is asked at once, each call capped at 5 s (``RELEASE_CALL_CAP_SECONDS``:
# a 4 s answer and a second of crossing), so the whole release is one call's
# time; a second more covers attaching a handle that rested. Against the
# worker's 60 s teardown cap (``WORKER_TEARDOWN_TIMEOUT``): the release's 6 s
# runs before the synchronous sweep's 45 s, 51 s in all, which leaves 9 s for
# the agents' and providers' closes that normally take a moment; a release that
# runs out of time is abandoned on its threads and never extends the sweep.
_RELEASE_BUDGET = 6.0


# Whether the load running on this thread is the outermost one: an agent's
# input is stated once, where the whole of it is known (``_note_chunking``),
# never again by a load it is built from.
_OUTERMOST_LOAD: ContextVar[bool] = ContextVar("maljan_outermost_chunk_load", default=True)


def _with_content(chunks: list[TextChunk], agent_name: str = "") -> list[TextChunk]:
    """The chunks that hold something: one of nothing but whitespace is no input to loop over."""
    held = [chunk for chunk in chunks if str(getattr(chunk, "content", "") or "").strip()]
    if len(held) < len(chunks):
        logger.debug(
            "%s: %d chunk(s) of nothing but whitespace left out of the input.",
            agent_name,
            len(chunks) - len(held),
        )
    return held


def _head_alone(head: Room | None, alone: bool) -> Room | None:
    """``head`` told whether its source is the agent's only one (``HeadRoom.alone_as``)."""
    from maljan.loaders.binary_chunker import HeadRoom

    return head.alone_as(alone) if isinstance(head, HeadRoom) else head


def _first_pass_room(container: Any, agent_name: str, room: Room | None) -> Room | None:
    """``room``, with the chunk size the agent's first analysis used where it measures nothing.

    A revision asks for the agent's room by its name; an agent that cannot be
    built then has no room to give. Its first analysis did measure one, and
    chunking the same input again at that size is what the revision is meant
    to read, so it is used in place of the unknown-window size.
    """
    from maljan.loaders.binary_chunker import HeadRoom

    store = getattr(container, "_first_pass_chunk_chars", None)
    remembered = store.get(agent_name) if isinstance(store, dict) else None
    if not isinstance(remembered, int) or isinstance(remembered, bool):
        return room

    def measured(text: str) -> int | None:
        chars = room(text) if room is not None else None
        return remembered if chars is None else chars

    # A head room stays one: what the node adds is still kept out of its first chunk.
    return room.over(measured) if isinstance(room, HeadRoom) else measured


def _markers_written_out(chunks: list[TextChunk]) -> list[TextChunk]:
    """``chunks`` with any run-state marker in their text written out; the same list when none."""
    from maljan.utils.written_forms import markers_written_out

    out: list[TextChunk] = []
    changed = False
    for chunk in chunks:
        content = chunk.content
        written = markers_written_out(content) if isinstance(content, str) else content
        if written != content:
            out.append(replace(chunk, content=written))
            changed = True
        else:
            out.append(chunk)
    return out if changed else chunks


def _note_chunking(
    container: Any, agent_name: str, chunks: list[TextChunk], head: Room | None = None
) -> None:
    """What sized agent ``agent_name``'s chunks, kept for its revision and stated where unknown.

    The first chunk size sized from the agent's window is kept
    (``_first_pass_room``). An input the shipped size split, because no window
    was learned, is a row in the run summary and a log line, each with the
    remedy: the split is kept, never silent. Split means more than one chunk
    once whole sources that fit the shipped size together are joined, as the
    analyst node joins them: after it adds the sample path and the upstream
    block to the first chunk, which ``head`` (a ``HeadRoom``) measures.
    """
    from maljan.llm.context_window import unknown_window_remedy
    from maljan.loaders.binary_chunker import (
        CHUNK_CHARS,
        SHIPPED_CHUNK_CHARS,
        SIZED_BY,
        SIZED_BY_ROOM,
        SIZED_BY_UNKNOWN_WINDOW,
        HeadRoom,
        joined_when_it_fits,
    )

    sized = [getattr(chunk, "metadata", None) or {} for chunk in chunks]
    store = getattr(container, "_first_pass_chunk_chars", None)
    if isinstance(store, dict) and agent_name not in store:
        for facts in sized:
            chars = facts.get(CHUNK_CHARS)
            if facts.get(SIZED_BY) == SIZED_BY_ROOM and isinstance(chars, int):
                store[agent_name] = chars
                break
    if len(chunks) < 2 or not any(f.get(SIZED_BY) == SIZED_BY_UNKNOWN_WINDOW for f in sized):
        return
    config = getattr(getattr(container, "config", None), "chunking", None)
    shown = chunks
    added = head.added_to(str(chunks[0].content)) if isinstance(head, HeadRoom) else 0
    if added > 0:
        # The node joins after the head carries what it adds: counted as it will be.
        grown = str(chunks[0].content) + " " * added
        shown = [replace(chunks[0], content=grown, char_count=len(grown)), *chunks[1:]]
    count = len(joined_when_it_fits(shown, config, None)) if config is not None else len(chunks)
    if count < 2:
        return
    remedy = unknown_window_remedy()
    ledger = getattr(container, "_truncation_ledger", None)
    record = getattr(ledger, "record_unknown_window_split", None)
    new = True
    if callable(record):
        try:
            new = bool(
                record(
                    agent=agent_name,
                    chunks=count,
                    chunk_chars=SHIPPED_CHUNK_CHARS,
                    remedy=remedy,
                )
            )
        except Exception as exc:  # noqa: BLE001 — a record never costs an analysis
            logger.debug("%s: the unknown-window split was not recorded (%s).", agent_name, exc)
    if new:
        logger.warning(
            "%s",
            unknown_window_split_line(agent_name, count, SHIPPED_CHUNK_CHARS, remedy),
        )


def unknown_window_split_line(agent_name: str, chunks: int, chunk_chars: int, remedy: str) -> str:
    """The log line for an input the shipped chunk size split because no window was learned."""
    return (
        f"Agent '{agent_name}': input split into {chunks} chunks at the shipped "
        f"{chunk_chars:,} characters, not at the room a window leaves: no context window "
        f"was learned. To size chunks from the window, {remedy}."
    )


# Every container that still exists, so a retired agent loop can invalidate the
# clients that were built on it. Weak, so a finished job's container is gone.
_LIVE_CONTAINERS: weakref.WeakSet[ServiceContainer] = weakref.WeakSet()
_RETIREMENT_HOOK_REGISTERED = threading.Event()


def _drop_llm_caches_on_retirement(loop: object) -> None:
    """Forget the retired loop's cached chat models.

    A LangChain chat model lazily builds an httpx async pool bound to the loop
    that first awaits it — the single-loop invariant ``base_agent`` documents.
    After a retirement those pools belong to a loop nothing will run again, and
    reusing one on the fresh loop parks on a future that can never complete, so
    that loop's partition is dropped and the next call rebuilds.

    Two partitions go, not all of them: the retired loop's own, and the
    ``None`` partition, whose models are used by the analyst tool loop — which
    is the loop being retired. Every other loop's models are still bound to a
    loop that is still running, and discarding them would throw away exactly
    the precision ``PerLoopModels`` was added for.

    Deliberately narrow: providers and server handles are *not* dropped here.
    Handles are handled at their own site (``providers.servers``), and an
    analyst holds only a reference to the model it was built with, which its
    next call refreshes through ``get_agent_llm``. The narrative agent and the
    report composer are dropped, because unlike an analyst they hold their
    model for their whole lifetime and never ask for it again.
    """
    from maljan.llm.openai_provider import clear_shared_httpx_clients

    for container in list(_LIVE_CONTAINERS):
        with container._lock:
            for cache in (
                container._mediator_llm_cache,
                container._judge_llm_cache,
                container._reporter_llm_cache,
                container._summarizer_llm_cache,
                container._agent_llm_cache,
            ):
                cache.drop(loop)
                cache.drop(None)
            container._function_summarizer_cache = None
            container._narrative_agent_cache = None
            container._report_composer_cache = None
    # Dropping the models is not enough on its own: ``langchain_openai``
    # caches its httpx clients with an ``lru_cache`` keyed on the endpoint, so
    # a rebuilt model was handed the same pool, still bound to the retired
    # loop, and the rebuild cleared nothing. Models this provider builds now
    # own their pools, and this clears any that were built elsewhere.
    clear_shared_httpx_clients()


def _reporter_reasons(config: Settings, provider: str) -> bool:
    """Whether the reporter's ``provider`` was left free to reason inside its cap.

    Some providers count the reasoning channel with the answer, and a
    reasoning model left thinking spends its budget there: a 900-token section
    cap came back as an empty section. The provider's adapter answers
    (``LLMProvider.reasoning_counts_against_cap``), from whether it was asked
    to keep reasoning out. Not asked, an operator's section budget is given the
    reporter's own cap on top for the reasoning, rather than the model being
    asked not to reason: a switch a model does not understand is an error on
    some runtimes, and the setting that sends it is the operator's.
    """
    from maljan.llm.provider_base import facts_of

    return bool(facts_of(provider).reasoning_counts_against_cap(config))


def _known_window(window: Any) -> int:
    """A learned window's tokens, or 0 for one nothing reported.

    The fallback window is a number to print beside the word ``fallback``, not
    a fact: a section's evidence is not sized against it, and a call's output
    is not bounded by it.
    """
    from maljan.llm.context_window import FALLBACK

    return 0 if getattr(window, "source", FALLBACK) == FALLBACK else int(window.tokens)


def report_stage_budget(config: Settings, assignment: Any, *, probe: bool = True) -> Any:
    """What one answer of the report stage's narrative round may run to on one model.

    The report stage runs on the reporter, which is built on the judge role, so
    the operator's cap it follows is ``llm.judge_max_tokens`` — the cap
    :meth:`ServiceContainer.get_reporter_llm` has always been built with; the
    analysts' ``llm.expert_max_tokens`` is not the reporter's. Above 0 it is
    used as set; at 0 the derivation every role's cap follows: the smaller of
    a quarter of the window and the model's declared maximum output
    (``context_window.report_output_budget``). Never more than the model's
    maximum.
    """
    from maljan.llm.context_window import report_output_budget

    judge = int(config.llm.judge_max_tokens or 0)
    return report_output_budget(
        config, assignment, judge, f"llm.judge_max_tokens is set to {judge}", probe=probe
    )


def composer_output_budget(config: Settings, assignment: Any) -> tuple[int, str, int]:
    """What one model of the reporter's list may generate for a section, and why.

    In order: ``reporting.composer_section_max_tokens`` above 0, the operator's
    section budget, plus the reporter's own cap as room for reasoning where the
    provider was not asked to keep reasoning out (:func:`_reporter_reasons`);
    else the operator's ``llm.judge_max_tokens``, the reporter's cap; else the
    derivation every role's cap follows, the smaller of a quarter of the window
    and the model's declared maximum output. Never more than the model's
    maximum output, the reasoning room included
    (``context_window.report_output_budget``). A section was
    dropped from a live report when its answer outgrew a fixed budget.

    Returns the tokens, the sentence that says how they were reached, which
    the run summary prints beside the section's wait and the worker log prints
    per section, and the model's context window in tokens, which a section's
    evidence is sized against: the window less this budget.
    """
    from maljan.llm.context_window import report_output_budget

    section = int(config.reporting.composer_section_max_tokens)
    if section <= 0:
        budget = report_stage_budget(config, assignment)
        return budget.tokens, budget.sentence(), _known_window(budget.window)
    said = f"reporting.composer_section_max_tokens is set to {section}"
    total = section
    if _reporter_reasons(config, str(assignment.provider)):
        reasoning = report_stage_budget(config, assignment)
        total += reasoning.tokens
        said += f", plus {reasoning.tokens} for its reasoning ({reasoning.sentence()})"
    budget = report_output_budget(config, assignment, total, said)
    return budget.tokens, budget.sentence(), _known_window(budget.window)


def _swap_healed_llm(replaced: object, healed: object) -> None:
    """Put the self-healed model where the one it replaced was cached.

    The 400 self-heal rebuilds a model without the llama.cpp extras the
    endpoint rejected. The model that raised is of no further use against that
    endpoint, and the container hands out one model per loop for the life of a
    job, so leaving it cached means every later caller reaches the endpoint
    through a wrapper that has already had to heal once.
    """
    for container in list(_LIVE_CONTAINERS):
        with container._lock:
            for cache in (
                container._mediator_llm_cache,
                container._judge_llm_cache,
                container._reporter_llm_cache,
                container._summarizer_llm_cache,
                container._agent_llm_cache,
            ):
                cache.replace(replaced, healed)


def _register_retirement_hook() -> None:
    """Subscribe once to agent-loop retirements. Imported late to avoid a cycle."""
    if _RETIREMENT_HOOK_REGISTERED.is_set():
        return
    from maljan.agents.base_agent import on_agent_loop_retired
    from maljan.llm.openai_provider import on_model_healed

    on_agent_loop_retired(_drop_llm_caches_on_retirement)
    on_model_healed(_swap_healed_llm)
    _RETIREMENT_HOOK_REGISTERED.set()


def _current_loop() -> Any | None:
    """The event loop the caller is running on, or ``None`` outside one."""
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


class PerLoopModels:
    """Chat models, partitioned by the event loop that will use them.

    A model's httpx connection pool belongs to the first event loop that awaits
    it, and this process makes LLM calls on two — the shared agent loop and the
    worker's own. One model handed to both fails inside httpx with "bound to a
    different event loop", which the openai SDK reports as a bare
    ``APIConnectionError("Connection error.")``.

    Keyed on the loop *object*, weakly, rather than on ``id(loop)``: CPython
    reuses the address of a collected loop, so an id key silently hands a fresh
    loop the dead one's model — measured, not feared, in the first version of
    this. A weak key cannot be confused with its successor and lets a finished
    loop's models go on their own.

    ``None`` is a partition of its own: a synchronous caller has no loop to be
    keyed by, and the model it builds is used by the analyst tool loop, which
    runs on the shared agent loop and nowhere else.
    """

    def __init__(self) -> None:
        self._by_loop: weakref.WeakKeyDictionary[Any, dict[str, Any]] = weakref.WeakKeyDictionary()
        self._without_loop: dict[str, Any] = {}

    def _slot(self, loop: Any | None) -> dict[str, Any]:
        if loop is None:
            return self._without_loop
        slot = self._by_loop.get(loop)
        if slot is None:
            slot = {}
            self._by_loop[loop] = slot
        return slot

    def lookup(self, loop: Any | None, name: str = "") -> Any | None:
        """The model cached for this loop under this name, or ``None``.

        Not called ``get``: a plain ``dict`` answers ``get(loop, name)`` with
        ``name`` itself, so a stand-in that was a dict returned the agent's
        name as its model and the failure read as nonsense rather than as a
        missing partition.
        """
        return self._slot(loop).get(name)

    def put(self, loop: Any | None, name: str, value: Any) -> None:
        self._slot(loop)[name] = value

    def replace(self, old: Any, new: Any) -> int:
        """Swap one cached model for another wherever it is held.

        For the 400 self-heal: the model that raised is never usable against
        that endpoint again, so leaving it in the cache means every later
        caller starts from the wrapper that has already healed once. Returns
        how many slots were swapped, which is what a test can assert on.
        """
        swapped = 0
        for slot in [self._without_loop, *self._by_loop.values()]:
            for name, value in list(slot.items()):
                if value is old:
                    slot[name] = new
                    swapped += 1
        return swapped

    def clear(self) -> None:
        self._by_loop = weakref.WeakKeyDictionary()
        self._without_loop = {}

    def drop(self, loop: Any | None) -> None:
        """Forget one loop's partition, leaving every other loop's alone."""
        if loop is None:
            self._without_loop = {}
            return
        with suppress(KeyError, TypeError):
            del self._by_loop[loop]

    def __len__(self) -> int:
        return len(self._without_loop) + sum(len(slot) for slot in self._by_loop.values())


class ServiceContainer:
    """Central service locator that manages all subsystem lifecycles."""

    def __init__(
        self,
        config: Settings,
        mock: bool = False,
        samples_dir: str = "data/samples",
        event_sink: EventSink | None = None,
        job_id: str = "",
        resolved_mode: Any = None,
        memory_owner: str | None = None,
        ignore_earlier_runs: bool = False,
    ) -> None:
        self.config = config
        self.mock = mock
        # Whose long-term memory this job reads and writes: the owner of the
        # job, as the caller that queued it knows it. ``None`` reads and
        # writes the unscoped memory (the command line, a caller naming no
        # owner); ``long_term_memory.recall`` states the rule.
        from maljan.memory.long_term_memory import owner_key

        self.memory_owner: str | None = owner_key(memory_owner)
        # Whether this job starts without what an earlier run on its sample
        # stored (``long_term_memory.earlier_case_of``): no earlier-run block
        # in any prompt and no earlier case on the bundle. Nothing stored is
        # read for it; once it completes, its own case is stored as any job's
        # is (``remember_the_run``), replacing its owner's case of the sample.
        self.ignore_earlier_runs: bool = ignore_earlier_runs is True
        # The job's analyst mode as the caller resolved it off its event loop
        # (``pipeline.analyst_mode.resolve_for``), or ``None`` to resolve it
        # here on first use.
        self._job_mode: Any = resolved_mode
        # The identity of the job this container serves, as the caller that
        # queued it knows it. Empty for the CLI and for tests, which run one
        # analysis per process and have no such id to give.
        self.job_id = str(job_id or "")
        # What ``job_key`` answers when nothing gave it one. Composed here, so
        # it belongs to this container and therefore to one run: the key names
        # the directory a tool server stages in, and a value derived from the
        # process alone would have a second run that drew the same pid — after
        # a recycle, ordinary in a container with a small ``pid_max`` — inherit
        # the first run's uploads, carved payloads and capture.
        self._run_key = f"cli-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        # Progress feed for the live transcript UI. ``None`` outside the API
        # worker (CLI, tests), which makes every emit a no-op — see
        # maljan.pipeline.events.
        self.event_sink = event_sink
        # The stages that have already announced their end on this run. A
        # stage's end is announced by whichever node runs after everything in
        # it is done, and for a terminal fan-out or a terminal debate that is
        # every one of its own nodes — so the announcement has to be claimed
        # rather than simply made. Guarded by a lock because a parallel
        # analysis stage's agents run in LangGraph worker threads.
        self._finished_stages: set[str] = set()
        self._finished_stages_lock = threading.Lock()

        self.agent_registry = AgentRegistry()
        self.parser_registry = ParserRegistry()

        self._llm_registry: LLMProviderRegistry | None = None
        if not mock:
            self._llm_registry = LLMProviderRegistry(config)

        from maljan.core.paths import resolve_data

        self.loader = FileDataLoader(
            samples_dir=str(resolve_data(samples_dir)),
            parser_registry=self.parser_registry,
            chunking_config=config.chunking,
        )

        # Re-entrant lock guarding every cache. RLock so that a helper holding
        # the lock can recursively call another guarded getter (e.g. agent
        # creation may call get_agent_llm()).
        self._lock = threading.RLock()

        # The chunk size, in characters, each agent's first analysis sized its
        # input at from its window, by agent name. A revision whose agent
        # cannot be built to measure its room chunks at this rather than at the
        # unknown-window size (``_first_pass_room``).
        self._first_pass_chunk_chars: dict[str, int] = {}

        # --- Caches ---
        # Every chat-model cache is keyed by the event loop the caller is on
        # (see ``PerLoopModels``). A model's httpx pool belongs to the first loop
        # that awaits it, and this process runs LLM calls on two loops — the
        # shared agent loop and the worker's own — so one cached model handed
        # to both is the "bound to a different event loop" failure that cost
        # the judge its first verdict request and the narrative round its
        # first attempt on every run.
        self._mediator_llm_cache = PerLoopModels()
        self._judge_llm_cache = PerLoopModels()
        self._reporter_llm_cache = PerLoopModels()
        self._summarizer_llm_cache = PerLoopModels()
        self._agent_llm_cache = PerLoopModels()
        self._agent_cache: dict[str, BaseAnalyst] = {}
        self._judge_agent_cache: dict[str, Any] = {}
        self._data_cache: dict[tuple[str, str], str] = {}
        self._memory_store_cache: MemoryStore | None = None
        # The long-term-memory case the judge built for this job, held until
        # the job completes (``remember_the_run``). A job that fails after its
        # judge leaves no entry behind.
        self.pending_memory_case: Any = None
        # The case an earlier run stored for this job's sample, by sha256,
        # read once (``long_term_memory.earlier_case_of``); ``None`` for none.
        self.earlier_cases: dict[str, Any] = {}
        # The similar cases of other samples the judge is shown, by the job's
        # sha256, read once (``long_term_memory.similar_cases``).
        self.similar_cases: dict[str, Any] = {}
        # The function-hash corpus write the judge decided on, as
        # ``(store, sample_id, family, functions)``, held for the same reason.
        self.pending_function_hashes: Any = None
        # The function hashes the triage pack read for this job's mirrored
        # sample, as ``(mirror path, hashes)``, kept only when the read was
        # whole: the judge's attribution reads them here rather than hashing
        # the same program a second time. ``None`` until the pack has read them.
        self.function_hashes_read: Any = None
        # Set by ``aclose``: a hold handed over after teardown (a judge thread a
        # timeout abandoned) is let go of at once.
        self._closed = False
        self._sandbox_provider_cache: SandboxProvider | None = None
        self._static_provider_cache: dict[str, StaticProvider] = {}
        self._server_registry_cache: ServerRegistry | None = None
        # The paths this job opened on each server that declares its open tool
        # (``providers.sample_open``): one note for the job, shared by its
        # static providers, its tool servers and the deterministic passes.
        from maljan.providers.sample_open import SampleNotes

        self.sample_notes = SampleNotes()
        self._function_summarizer_cache: FunctionSummarizer | None = None
        self._narrative_agent_cache: Any | None = None
        # The analyst run mode this job resolved (``pipeline.analyst_mode``),
        # with what every stage runs in, once; ``None`` until the first read.
        self._analyst_mode: Any = None
        # The active profile with its unset stage modes resolved, once per
        # job, keyed by the stored profile it was resolved from.
        self._resolved_profile: tuple[Any, Any] | None = None
        self._report_composer_cache: Any | None = None
        self._samples_dir = str(resolve_data(samples_dir))

        # The job sample's ``(file_type, platform)``, set by ``app.arun`` once
        # routing has answered and read by ``composition.builtin_prompt`` when
        # it assembles an agent's format fragment. It lives here rather than in
        # the graph state because agents are built lazily, by this container,
        # from nodes that do not all carry the state.
        self.sample_format: tuple[str, str] = ("unknown", "unknown")

        # The job's sandbox report, set by ``app.arun`` for the same reason
        # ``sample_format`` is: the sandbox tool set
        # (``providers.sandbox_tools``) is built during agent resolution, which
        # happens in nodes that do not all carry the graph state. ``None``
        # outside a job, and the tools then say so rather than answering empty.
        self.sandbox_report: dict[str, Any] | None = None
        # ``(provider, source_format, read_from)`` of the reader that produced
        # it (``schemas.sandbox_report.reader_of``), set by ``app.arun`` beside
        # it; read by the sandbox sections.
        self.sandbox_normalised: tuple[str, str, str] | None = None
        # The signature severity scale the job's sandbox provider declares for
        # that report (``SignatureScale.record()``), ``None`` where it declares
        # none; set by ``app.arun`` beside it and recorded on the run summary
        # (``report_formats.recorded_signature_scale``).
        self.sandbox_signature_scale: dict[str, Any] | None = None
        # Why the job has no sandbox report, in words, where its submission
        # failed (a refused report, a failed task state, an unreachable host);
        # set by ``app._submit_to_sandbox`` and carried into the report's
        # degradation reason (``pipeline.nodes.sandbox_degradation_reason``).
        # ``None`` where the sandbox answered or was never asked.
        self.sandbox_failure: str | None = None
        # The artefacts the sandbox offered beside its report that could not
        # be fetched, one ``ArtefactFetchFailed.record()`` each; set by
        # ``app._submit_to_sandbox`` and carried into the run's degradation
        # reasons and its coverage record. Empty where every offered artefact
        # was fetched, or none was offered.
        self.artefact_fetch_failures: list[dict[str, str]] = []
        # The target a detonating sandbox's report names
        # (``{"provider", "task_id", "sha256"}``, the hash as the provider's
        # reader put it in the neutral report), set by ``app._submit_to_sandbox``
        # and compared with the sample by the worker
        # (``analysis.sample_integrity.sandbox_target_record``). ``None`` for an
        # attached report, a stand-in, a recorded fixture, a task that ended
        # without a report, or no sandbox.
        self.sandbox_target_claim: dict[str, str] | None = None
        # Each submission of the sample to the job's sandbox provider
        # (``analysis.disclosure.upload_record``), set by ``app.arun`` as it
        # submits and read by the run's disclosure block. Empty outside a job.
        self.sample_uploads: list[dict[str, Any]] = []
        # Each upload of the sample to a tool server over its ``put_sample``
        # tools (``analysis.disclosure.staging_record``), written by
        # ``agents.sample_staging`` as it uploads; read by the same block.
        self.sample_stagings: list[dict[str, Any]] = []
        # The model endpoints whose window probe answered as a model runtime in
        # this job, by ``endpoint_label``, each with what answered
        # (``llm.context_window.runtime_answer``): recorded where the job's
        # windows are learned, read by the same block.
        self.runtime_answers: dict[str, str] = {}

        # The job's sample, for the one step that needs the bytes rather than
        # a report: staging the sample to a tool server that does not share
        # this filesystem (``agents.sample_staging``). Both ``None``/empty
        # outside a job, and staging is then a no-op.
        self.sample_path: str | None = None
        self.sample_sha256: str = ""
        # The path each tool server that declares a ``sample_mount`` opens the
        # worker's copy of the sample at, by server key; empty outside a job.
        self.server_sample_paths: dict[str, str] = {}
        # Where the worker places a file of the job's artefact store for a
        # server that declares a ``sample_mount``, as it places the sample:
        # ``(server key, the file, its sha256, its name)`` to the path that
        # server opens the copy at, or ``None``. Set by the worker for a job;
        # ``None`` outside one, and such a server is then handed no file
        # (``pipeline.artefacts``).
        self.place_for_server: Callable[[str, Path, str, str], str | None] | None = None
        # Every path a file of the job's artefact store was handed to a server
        # at (``pipeline.artefacts.hand_over``): read by the run's isolation
        # part as a path of what came out of the sample. Empty outside a job.
        self.artefact_paths: list[str] = []
        # The path each static provider's mirror of the sample is handed to
        # its server under, by provider; empty outside a job. Read by the run's
        # isolation part, which counts a call handed one as a read of the sample.
        self.static_sample_paths: dict[str, str] = {}

        # Per-run LLM token/cost ledger (findings-log §4 Item 1). Agents and the
        # judge add each call's usage; the judge node snapshots it into RunSummary.
        # With the job's spend meter, which prices each recorded call against
        # the operator's ceiling (``llm.max_spend_usd_per_job``).
        from maljan.core.spend import SpendMeter

        self._token_ledger = TokenLedger(spend=SpendMeter.from_settings(config))
        self._plan_the_verdict_and_report(self._token_ledger.spend)
        # What each agent's requests were made of, measured as they are sent
        # (``core.input_meter``); the report node reads it into
        # ``run_summary.efficiency``.
        from maljan.core.input_meter import InputMeter

        self.input_meter = InputMeter()
        # The job's setup as each agent was resolved: the resolution itself,
        # and the name and version every tool server attached by then gave for
        # itself. What the run fingerprint is made of (``analysis.efficiency``),
        # so nothing a run does later — a retry, a revision, a clear, a
        # mediation's tool call — moves it.
        self._resolved_agents: dict[str, Any] = {}
        self._setup_servers: dict[str, dict[str, str]] = {}
        # The tools each agent was set up with, by its key: an analyst's as it
        # was resolved, the judge's and the mediator's as their role binds them.
        self._setup_tools: dict[str, list[Any]] = {}
        # The analysts whose loop has bound its tools: from then on that list,
        # not the resolution's, is the analyst's setup.
        self._bound_agents: set[str] = set()
        # The judge's and the mediator's servers as their settings declare
        # them, for an agent the run never bound: never attached for the
        # fingerprint, so recorded with no version and no tool definitions.
        self._declared_setup: dict[str, dict[str, dict[str, Any]]] = {}
        # Each call, as it is recorded, on the job's event feed: the durable
        # trail of what the run spent, kept call by call by the worker.
        if event_sink is not None:
            from maljan.pipeline.events import MODEL_USAGE, emit

            self._token_ledger.on_call = lambda row: emit(event_sink, MODEL_USAGE, row)

        # What the report node has built so far, while it is still building
        # it: the deterministic report, then the narrative on it, with the
        # composer writing its sections into the same object as each one is
        # written. A run stopped part-way through its report keeps this as its
        # partial report (``pipeline.stopped_run``). ``None`` until the report
        # node has built one.
        self.report_in_progress: Any = None

        # Per-run generation rate of each model, read off every call's answer
        # by a meter attached where the model is built. The judge and the
        # composer size their per-call timeouts from it; the judge node and
        # the report node snapshot it into RunSummary.
        self._generation_rates = GenerationRates()

        # Whether this job has been cancelled. The worker sets it; the graph's
        # nodes, every model call and every call in flight on the agent loop
        # answer to it (``core.cancellation``).
        self.cancellation = Cancellation()
        # A cancelled job wakes every call waiting in the spend meter for
        # another call's reservation, and it gives up.
        _meter = getattr(self._token_ledger, "spend", None)
        if _meter is not None and hasattr(_meter, "close"):
            self.cancellation.track(_meter.close)

        # Per-run truncation ledger (pitfall P6). Same lifecycle as the token
        # ledger: written to at every bound, snapshotted by the judge node.
        # Truncation is designed into this pipeline and has never been counted.
        self._truncation_ledger = TruncationLedger()

        # What this run SAW, as opposed to what its ledger keeps. The evidence
        # byte budget blanks an entry after the model has read it, so a
        # grounding check over the stored ledger told a judge that a C2 a tool
        # really returned appears nowhere. In memory, per job, dropped with
        # this container; never in the graph state and never persisted.
        self._evidence_corpus: RunEvidenceCorpus | None = RunEvidenceCorpus(
            int(getattr(config.reporting, "evidence_corpus_bytes", 0) or 0)
        )

        # Where the parts of an answer a ledger entry does not keep whole are
        # kept whole (``schemas.evidence_spill``). Set by the caller that owns
        # a store, the analysis worker; ``None`` keeps nothing.
        self._evidence_spill: Any = None

        # Per-job source of evidence-ledger ids. One counter for the whole job
        # so ``ev_0007`` names one tool call rather than one per agent.
        self._evidence_counter = EvidenceCounter()
        # Everything that holds entries this counter issued before they reach
        # the run's ledger, asked by ``collect_undrained_evidence``: every agent
        # this container builds registers itself, and any other writer that
        # holds entries registers a way to hand them over. Entries whose holder
        # can no longer hand them to a node (a delegation answered after its
        # caller's loop ended) are parked on ``_handed_over_evidence``.
        self._evidence_holders: list[Callable[[], Iterable[Any]]] = []
        self._handed_over_evidence: list[Any] = []
        # Every entry ``collect_undrained_evidence`` has collected, by id, kept
        # for the job's length so no later caller can miss one.
        self._collected_evidence: dict[str, Any] = {}

        # The window this job's models were served with, and the cap it gives
        # one tool answer. Built on first use rather than here: learning the
        # window costs a metadata request to the operator's own endpoint, and a
        # container that never attaches a tool server should never make it.
        self._context_budget: Any | None = None
        self._reporter_context_budget: Any | None = None

        _LIVE_CONTAINERS.add(self)
        _register_retirement_hook()

        from maljan.agents.composition import analyst_keys

        logger.info(
            "ServiceContainer initialized (mock=%s, profile=%s, analysts=%s, parsers=%s)",
            mock,
            config.agents.profile,
            analyst_keys(config),
            self.parser_registry.list_parsers(),
        )

        self._configure_langsmith()
        self._announce_index_retry()
        self._announce_attck_refresh()

    @property
    def is_mock(self) -> bool:
        return self.mock

    def claim_stage_finished(self, key: str) -> bool:
        """Claim the right to announce ``key`` finished, once per run.

        Returns ``True`` to the first caller for a stage and ``False`` to every
        caller after it. Three shapes reach here more than once for the same
        stage: a terminal parallel analysis stage with no barrier and a
        terminal debate, whose own nodes all end at the same time and all see
        the finished state, and the report node's closing rollup, which exists
        to repair a run whose stages crashed before they could announce
        themselves. The console draws one row per stage, so the second and
        third announcements are noise at best and a duplicated row at worst.
        """
        with self._finished_stages_lock:
            if key in self._finished_stages:
                return False
            self._finished_stages.add(key)
            return True

    # ------------------------------------------------------------------
    # LLM accessors
    # ------------------------------------------------------------------

    def _expert_token_cap(self, agent: str) -> Any:
        """The output cap an analyst-role model is built with: the operator's, or derived.

        The analyst path was the only unbounded LLM call in the system while
        judge/narrative/composer were all capped. MEASURED:
        a 19-tool-call static loop produced a forced-synthesis call that ran 19+
        minutes against its 25-minute wall clock. Mirrors ``get_judge_llm``.
        """
        return self._built_cap("expert_max_tokens", agent)

    def _output_cap(self, setting: str, agent: str, *, role: str = "expert") -> int:
        """The output cap one agent's model is built with, in tokens (``_built_cap``)."""
        return int(self._built_cap(setting, agent, role=role).tokens)

    def _built_cap(self, setting: str, agent: str, *, role: str = "expert") -> Any:
        """The output cap one agent's model is built with, its derivation logged and recorded.

        ``llm.expert_max_tokens`` / ``llm.judge_max_tokens`` above 0 are the
        operator's; at 0 the cap is derived from the window the agent's model
        serves (``context_window.output_cap_for``), learned once per endpoint.
        The models are the chain the agent's model is built from
        (``assignment_chain_for(config, agent, role=role)``, the reading
        ``build_model_for_agent`` makes): its own entry with its fallbacks, or
        the global model of ``role`` — for the judge its ``llm.agents.judge``
        entry before the global judge model. A mock container asks no endpoint.
        The builder keeps it on the model it builds
        (``context_window.record_built_cap``), which is where every consumer
        of the cap reads it from.
        """
        from maljan.llm.context_window import output_cap_for

        cap = output_cap_for(self.config, setting, agent, role=role, probe=not self.mock)
        rates = getattr(self, "_generation_rates", None)
        if rates is not None:
            rates.note_output_cap(agent, cap.tokens, cap.sentence)
        logger.info("Output cap for %s: %s.", agent, cap.sentence)
        return cap

    def _report_output_cap(self) -> int:
        """The output cap the reporter's model is built with, its derivation logged and recorded.

        The report stage's budget (:func:`report_stage_budget`): the
        operator's ``llm.judge_max_tokens``, else the derivation every role's
        cap follows. Over a fallback list, the smallest of its models, as every
        other agent's cap is.
        """
        from maljan.core.model_assignments import assignment_chain_for

        best: Any | None = None
        try:
            for assignment in assignment_chain_for(self.config, REPORTER_AGENT_KEY, role="judge"):
                budget = report_stage_budget(self.config, assignment, probe=not self.mock)
                if best is None or budget.tokens < best.tokens:
                    best = budget
        except Exception as exc:  # noqa: BLE001 — an unreadable assignment takes the derived cap
            logger.warning(
                "Report stage: the reporter's list could not be budgeted per model (%s); "
                "its model takes the judge role's cap (llm.judge_max_tokens, or derived).",
                exc,
            )
        if best is None:
            cap = self._built_cap("judge_max_tokens", REPORTER_AGENT_KEY, role="judge")
            self._reporter_output_budget = (int(cap.tokens), cap.sentence, 0)
            return int(cap.tokens)
        rates = getattr(self, "_generation_rates", None)
        if rates is not None:
            rates.note_output_cap(REPORTER_AGENT_KEY, best.tokens, best.sentence())
        logger.info("Output cap for %s: %s.", REPORTER_AGENT_KEY, best.sentence())
        self._reporter_output_budget = (
            int(best.tokens),
            best.sentence(),
            _known_window(best.window),
        )
        return int(best.tokens)

    def get_mediator_llm(self) -> BaseChatModel:
        """The model the debate stage's mediator runs on.

        Through the per-agent path, like the judge and the reporter: a
        configured ``llm.agents.mediator`` decides provider, model,
        temperature, fallbacks and effort, and with no such entry the expert
        role picks the model exactly as it did before the entry existed. A
        judge entry does not move it. Its output cap is derived from the
        model it calls and recorded under its own name.
        """
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._mediator_llm_cache.lookup(loop)
            if cached is None:
                cap = self._expert_token_cap(MEDIATOR_AGENT_KEY)
                cached = self._llm_registry.build_model_for_agent(
                    MEDIATOR_AGENT_KEY, fallback_role="expert", max_tokens=cap.tokens
                )
                record_built_cap(cached, cap)
                attach_rate_meter(cached, getattr(self, "_generation_rates", None))
                # Its calls are recorded under the judge agent that runs on it.
                attach_retry_recorder(cached, getattr(self, "_token_ledger", None), "judge")
                # Its own ceiling is the mediator entry's, not the judge's.
                attach_agent_ceiling(
                    cached, getattr(self, "_token_ledger", None), MEDIATOR_AGENT_KEY
                )
                self._mediator_llm_cache.put(loop, "", cached)
            return cached

    def get_judge_llm(self) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._judge_llm_cache.lookup(loop)
            if cached is None:
                # Bound the verdict generation so a degenerate decode can't
                # consume the full wall-clock timeout (see LLMConfig.judge_max_tokens).
                cap = self._built_cap("judge_max_tokens", "judge", role="judge")
                extra: dict[str, Any] = {"max_tokens": cap.tokens}
                # Through the per-agent path so a configured
                # ``llm.agents.judge`` decides provider/model/temperature the
                # same way it does for an analyst; with no such entry the
                # judge role picks the model exactly as before. An entry that
                # sets provider and model but no temperature therefore runs at
                # the per-agent default of 0.1 rather than the role's 0.0 —
                # deliberate (the entry is an analyst-shaped override and is
                # read as one), and said out loud in the setting's help text.
                cached = self._llm_registry.build_model_for_agent(
                    "judge", fallback_role="judge", **extra
                )
                record_built_cap(cached, cap)
                attach_rate_meter(cached, getattr(self, "_generation_rates", None))
                attach_retry_recorder(cached, getattr(self, "_token_ledger", None), "judge")
                attach_agent_ceiling(cached, getattr(self, "_token_ledger", None), "judge")
                self._judge_llm_cache.put(loop, "", cached)
            return cached

    def get_reporter_llm(self) -> BaseChatModel:
        """The model the report stage's narrative and composer rounds run on.

        Through the per-agent path, like the judge: a configured
        ``llm.agents.reporter`` decides provider, model and temperature, and
        with no such entry the judge role picks the model exactly as it did
        when the report had no definition of its own to be configured through.
        """
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._reporter_llm_cache.lookup(loop)
            if cached is None:
                extra: dict[str, Any] = {"max_tokens": self._report_output_cap()}
                cached = self._llm_registry.build_model_for_agent(
                    REPORTER_AGENT_KEY, fallback_role="judge", **extra
                )
                attach_rate_meter(cached, getattr(self, "_generation_rates", None))
                attach_retry_recorder(
                    cached, getattr(self, "_token_ledger", None), REPORTER_AGENT_KEY
                )
                attach_agent_ceiling(
                    cached, getattr(self, "_token_ledger", None), REPORTER_AGENT_KEY
                )
                self._reporter_llm_cache.put(loop, "", cached)
            return cached

    def get_summarizer_llm(self) -> BaseChatModel:
        """The model the function summariser runs on, per loop like the rest.

        Through the per-agent path: a configured ``llm.agents.summarizer``
        decides provider, model, temperature, fallbacks and effort, and with
        no such entry it is the global expert model, which is what it always
        ran on. It is built with no output cap, as it always was; each call
        is held to what its window leaves (``generation_rate``).
        """
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build FunctionSummarizer LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._summarizer_llm_cache.lookup(loop)
            if cached is None:
                cached = self._llm_registry.build_model_for_agent(
                    SUMMARIZER_AGENT_KEY, fallback_role="expert"
                )
                attach_rate_meter(cached, getattr(self, "_generation_rates", None))
                attach_retry_recorder(cached, getattr(self, "_token_ledger", None), "summarizer")
                attach_agent_ceiling(
                    cached, getattr(self, "_token_ledger", None), SUMMARIZER_AGENT_KEY
                )
                self._summarizer_llm_cache.put(loop, "", cached)
            return cached

    def get_agent_llm(self, agent_name: str) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._agent_llm_cache.lookup(loop, agent_name)
            if cached is None:
                # Analysts share the expert budget cap — this is the path the
                # static/dynamic/network ReAct loops and their forced-synthesis
                # fallback actually use.
                cap = self._expert_token_cap(agent_name)
                cached = self._llm_registry.build_model_for_agent(agent_name, max_tokens=cap.tokens)
                record_built_cap(cached, cap)
                attach_rate_meter(cached, getattr(self, "_generation_rates", None))
                attach_retry_recorder(cached, getattr(self, "_token_ledger", None), agent_name)
                attach_agent_ceiling(cached, getattr(self, "_token_ledger", None), agent_name)
                self._agent_llm_cache.put(loop, agent_name, cached)
            return cached

    # ------------------------------------------------------------------
    # Memory / sandbox / agent accessors
    # ------------------------------------------------------------------

    def get_memory_store(self) -> MemoryStore:
        """The store ``memory.backend`` selects, built once by the factory every caller uses."""
        with self._lock:
            if self._memory_store_cache is None:
                from maljan.memory.store_factory import build_memory_store, configured_backend

                self._memory_store_cache = build_memory_store(self.config)
                logger.info(
                    "LTM backend: %s (%s).",
                    configured_backend(self.config),
                    type(self._memory_store_cache).__name__,
                )
            return self._memory_store_cache

    def remember_the_run(self) -> bool:
        """Write what the judge decided to remember, now that the job has completed.

        Never raises. The judge builds the long-term-memory case and picks the
        family its function hashes are filed under; this writes both, once. The
        caller calls it only after the job is recorded as completed, so a job
        that fails later — in a later node, or while the worker stores its
        report — leaves neither a case teaching the next run a verdict nobody
        kept nor functions filed under that verdict's family. Returns whether
        anything was written.
        """
        wrote = self._remember_the_case()
        return self._remember_the_function_hashes() or wrote

    def _remember_the_case(self) -> bool:
        case, self.pending_memory_case = self.pending_memory_case, None
        if case is None:
            return False
        from dataclasses import replace

        from maljan.memory.long_term_memory import keeps_owners

        try:
            store = self.get_memory_store()
            if self.memory_owner is not None and not keeps_owners(store):
                # Unscoped, it would reach every other owner's jobs.
                logger.info(
                    "LTM: case '%s' is not stored: the memory backend keeps no owners.",
                    case.sample_id,
                )
                return False
            store.store(
                case if self.memory_owner is None else replace(case, owner=self.memory_owner)
            )
        except Exception as exc:  # noqa: BLE001 — memory never costs a completed job
            logger.warning("LTM store failed (%s). The completed job is unaffected.", exc)
            return False
        logger.info(
            "LTM: stored case '%s' (category=%s, techniques=%d).",
            case.sample_id,
            case.malware_category,
            len(case.technique_ids),
        )
        return True

    def hold_function_hashes(
        self, store: Any, sample_id: str, family: str, functions: list
    ) -> None:
        """Take over the judge's hold on ``store`` with the corpus write it decided on.

        The hold ends with the write (``remember_the_run``) or at teardown. A
        write it replaces lets go of its own store; one handed over after
        teardown is let go of at once, never written.
        """
        from maljan.memory.store_factory import release_function_hash_store

        with self._lock:
            if self._closed:
                replaced, self.pending_function_hashes = (store,), None
            else:
                replaced = self.pending_function_hashes
                self.pending_function_hashes = (store, sample_id, family, list(functions))
        if replaced is not None:
            release_function_hash_store(replaced[0])

    def drop_function_hashes(self, reason: str) -> None:
        """Let go of the held corpus write unwritten, saying why. Never raises."""
        with self._lock:
            held, self.pending_function_hashes = self.pending_function_hashes, None
        if held is None:
            return
        from maljan.memory.store_factory import release_function_hash_store

        logger.info(
            "Function-hash corpus: '%s' is not filed under %s (%s).",
            str(held[1])[:16],
            held[2],
            reason,
        )
        release_function_hash_store(held[0])

    def _remember_the_function_hashes(self) -> bool:
        held, self.pending_function_hashes = self.pending_function_hashes, None
        if held is None:
            return False
        store, sample_id, family, functions = held
        from maljan.memory.long_term_memory import keeps_owners
        from maljan.memory.store_factory import release_function_hash_store

        # The provider answers ``(func_name, func_hash)``; the index files
        # ``(func_hash, func_name)``. Filed the provider's way round, every
        # name was stored as a hash and no later sample's hash could match it.
        pairs = [(func_hash, name) for name, func_hash in functions]
        # The verdict that files them, where the store records it, so an edit
        # of that verdict can take them back (``FunctionHashStore.unfile``).
        filer = (
            {"filed_by": self.job_id}
            if self.job_id and getattr(store, "keeps_filer", False)
            else {}
        )
        try:
            if self.memory_owner is None:
                written = int(store.upsert_sample(sample_id, family, pairs, **filer) or 0)
            elif keeps_owners(store):
                written = int(
                    store.upsert_sample(sample_id, family, pairs, owner=self.memory_owner, **filer)
                    or 0
                )
            else:
                # Unscoped, it would reach every other owner's jobs.
                logger.info(
                    "Function-hash corpus: '%s' is not filed: the store keeps no owners.",
                    str(sample_id)[:16],
                )
                return False
        except Exception as exc:  # noqa: BLE001 — the corpus never costs a completed job
            logger.warning(
                "Function-hash corpus write failed (%s). The completed job is unaffected.", exc
            )
            return False
        finally:
            # The judge's hold ends with the write: a store a settings change
            # replaced meanwhile is closed now, not under this job.
            release_function_hash_store(store)
        logger.info(
            "Function-hash corpus: filed %d function(s) of '%s' under %s.",
            written,
            str(sample_id)[:16],
            family,
        )
        return written > 0

    def get_sandbox_provider(self) -> SandboxProvider:
        """The configured sandbox adapter, or the mock one in mock mode.

        ``mock=True`` is the container's own switch (the CLI's ``--mock``, the
        API's mock jobs) and outranks the setting, exactly as it did when this
        method built clients directly.
        """
        with self._lock:
            if self._sandbox_provider_cache is not None:
                return self._sandbox_provider_cache
            from maljan.providers.registry import get_sandbox_provider as build

            cfg = self.config
            if self.mock and cfg.sandbox.provider != "mock":
                cfg = cfg.model_copy(deep=True)
                cfg.sandbox.provider = "mock"
            provider = build(cfg)
            fixtures = getattr(provider, "fixtures_dir", None)
            if fixtures is not None:
                provider.fixtures_dir = self._samples_dir  # type: ignore[attr-defined]
            # A provider whose server is measured for the run's isolation part
            # (CAPE's MCP server) is told whose job it serves.
            if hasattr(provider, "job_key"):
                provider.job_key = self.job_key()
            logger.info("Sandbox provider: %s.", provider.id)
            self._sandbox_provider_cache = provider
            return provider

    def get_static_provider(self, provider_id: str | None = None) -> StaticProvider:
        """The static provider for ``provider_id``, or the globally configured one.

        Cached per id rather than once, because a profile may hold two static
        analysts on two providers and each needs its own object: the providers
        are stateful (an open decompiler session, a loaded program), and
        sharing one between two analysts would have them fighting over which
        binary is loaded. ``get_static_provider()`` with no argument is the
        pre-existing call and returns exactly what it always did.
        """
        wanted = str(provider_id or self.config.static.provider)
        with self._lock:
            cached = self._static_provider_cache.get(wanted)
            if cached is None:
                from maljan.providers.registry import get_static_provider as build

                cfg = self.config
                if wanted != str(cfg.static.provider):
                    # The registry builds from ``cfg.static.provider``; a
                    # per-agent provider is that same construction against a
                    # copy, so no provider needs to learn a second entry point.
                    cfg = cfg.model_copy(deep=True)
                    cfg.static.provider = wanted  # type: ignore[assignment]
                cached = build(cfg)
                logger.info("Static provider: %s.", cached.id)
                # A provider whose server rests announces it to this job's sink.
                if hasattr(cached, "event_sink"):
                    cached.event_sink = self.event_sink
                if hasattr(cached, "sample_notes"):
                    cached.sample_notes = self.sample_notes
                # A provider that drives a tool server of its own counts each
                # attach of it on the job's change count.
                if hasattr(cached, "server_changes"):
                    cached.server_changes = self._evidence_counter.changes
                # A provider that does work of its own in the job's staging
                # directory (capa_yara's capa runs) is told whose it is.
                if hasattr(cached, "job_key"):
                    cached.job_key = self.job_key()
                self._static_provider_cache[wanted] = cached
            return cached

    def get_server_registry(self) -> ServerRegistry:
        """The tool servers this job may attach, built from the job's settings.

        One registry per container, and the container is per job, so a stdio
        server's subprocess lives for exactly one analysis and is closed by
        ``aclose`` at the end of it — the same lifetime the static and sandbox
        providers already have.

        It carries this job's truncation ledger, so every toolkit it opens
        records its guardrail decisions where the run summary reads them, and
        this job's context budget, so every answer those toolkits hand back is
        sized against the window the served model was found to have.
        """
        # Built before the lock is taken, because building it may make a
        # metadata request and no other thread's accessor should wait on a
        # network round trip to a model server.
        budget = self.get_context_budget()
        with self._lock:
            if self._server_registry_cache is None:
                from maljan.providers.servers import ServerRegistry

                self._server_registry_cache = ServerRegistry(
                    self.config,
                    sample_notes=self.sample_notes,
                    sample_sha256=lambda: self.sample_sha256,
                    truncation_ledger=self._truncation_ledger,
                    context_budget=budget,
                    event_sink=self.event_sink,
                    # The job's change count: an attach of a server is a change.
                    server_changes=self._evidence_counter.changes,
                )
                logger.info(
                    "Tool servers: %s.",
                    ", ".join(sorted(self.config.mcp.servers)) or "(none)",
                )
            return self._server_registry_cache

    def server_degradation_reasons(self) -> list[str]:
        """Tool servers that could not be attached this job, or an empty list.

        Reads the *cached* registry only: a job that never attached a tool
        server has nothing to report and must not build a registry here to
        discover that.
        """
        registry = self._server_registry_cache
        return list(registry.degradation_reasons) if registry is not None else []

    def server_not_configured_reasons(self) -> list[str]:
        """The reasons the attached servers' manifests mark unset settings, the operator's choice.

        Reads the cached registry only, as ``server_degradation_reasons`` does.
        """
        registry = self._server_registry_cache
        return list(registry.not_configured_reasons()) if registry is not None else []

    def server_without_reads(self) -> dict[tuple[str, str], frozenset[str]]:
        """By ``(server, tool)``, what a tool's missing part reads, from the cached registry."""
        registry = self._server_registry_cache
        return dict(registry.declared_without_reads()) if registry is not None else {}

    def server_rests(self) -> list[dict[str, Any]]:
        """Every tool-server rest this job gave, in order, or an empty list.

        Reads the cached registry only, for the same reason
        ``server_degradation_reasons`` does.
        """
        registry = self._server_registry_cache
        rests = [dict(row) for row in getattr(registry, "rests", None) or []]
        for provider in list(self._static_provider_cache.values()):
            rests.extend(dict(row) for row in getattr(provider, "rests", None) or [])
        return rests

    def _note_the_setup(self, name: str, resolved: Any) -> None:
        """Keep agent ``name``'s resolution and the servers attached by then. Never raises."""
        try:
            self._resolved_agents[name] = resolved
            self._setup_tools.setdefault(name, list(getattr(resolved, "tools", None) or []))
            self._note_setup_servers(None)
        except Exception as exc:  # noqa: BLE001 — telemetry never costs an agent
            logger.debug("the setup of '%s' was not noted (%s).", name, type(exc).__name__)

    def _note_setup_servers(self, names: set[str] | None) -> None:
        """The name and version each attached server gave, for ``names`` or every one."""
        registry = self._server_registry_cache
        versions = getattr(registry, "server_versions", None)
        if not callable(versions):
            return
        for server, info in versions().items():
            if names is None or server in names:
                self._setup_servers.setdefault(server, dict(info))

    def note_bound_tools(self, name: str, tools: Any) -> None:
        """The tools analyst ``name``'s first loop binds, as its setup. Never raises.

        A built-in role attaches its own servers after it was resolved, and its
        prompt and requests are written for what its loop binds; the first
        loop's list stands, and the servers attached by then are noted.
        """
        try:
            if name in self._bound_agents:
                return
            self._bound_agents.add(name)
            self._setup_tools[name] = list(tools or [])
            self._note_setup_servers(None)
        except Exception as exc:  # noqa: BLE001 — telemetry never costs an agent
            logger.debug("the tools of '%s' were not noted (%s).", name, type(exc).__name__)

    def note_role_setup(self, key: str, tools: Any, servers: set[str]) -> None:
        """The tools agent ``key`` (the judge, the mediator) is set up with, and its servers.

        Called where the agent's role binds its servers, as an analyst's are
        noted where it is resolved; the first record of an agent stands. Never
        raises.
        """
        try:
            self._setup_tools.setdefault(str(key), list(tools or []))
            self._note_setup_servers(set(servers))
        except Exception as exc:  # noqa: BLE001 — telemetry never costs an agent
            logger.debug("the setup of '%s' was not noted (%s).", key, type(exc).__name__)

    def note_judge_declared_setup(self) -> None:
        """The judge's and the mediator's servers from their settings, where the run bound none.

        No server is attached for the fingerprint, and no agent is built: an
        agent that never bound its role's servers in this run (the verdict's,
        which runs no tool loop) is recorded by what the settings declare for
        each server the ``judge`` role and definition bind — digests of its
        launch identity with this host's paths replaced and of its tool filter
        (``efficiency.declared_server``), never the values — marked not
        attached, with no version and no tool definitions. An agent
        the run set up is left as it is. Never raises.
        """
        try:
            from maljan.agents.composition import _excluded_servers, mcp_refs_for
            from maljan.analysis.efficiency import declared_server

            servers = getattr(getattr(self.config, "mcp", None), "servers", None) or {}
            registry = self.get_server_registry()
            names = {
                handle.name
                for handle in registry.for_agent(
                    "judge", exclude=_excluded_servers(self.config, "judge")
                )
            }
            names |= {
                str(ref.server)
                for ref in mcp_refs_for(self.config, "judge")
                if getattr(ref, "server", None)
            }
            declared = {
                name: declared_server(servers[name]) for name in sorted(names) if name in servers
            }
            for key in ("judge", MEDIATOR_AGENT_KEY):
                if key not in self._setup_tools and key not in self._declared_setup:
                    self._declared_setup[key] = {
                        name: dict(info) for name, info in declared.items()
                    }
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a report
            logger.debug("the judge's declared setup was not noted (%s).", type(exc).__name__)

    def declared_setup(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Per agent the run never bound, its servers as their settings declare them."""
        return {key: dict(held) for key, held in sorted(self._declared_setup.items())}

    def resolved_agents(self) -> dict[str, Any]:
        """Each agent this job resolved, by key, as it was resolved."""
        return dict(self._resolved_agents)

    def setup_tools(self) -> dict[str, list[Any]]:
        """The tools each agent was set up with, by key."""
        return {key: list(tools) for key, tools in sorted(self._setup_tools.items())}

    def setup_server_versions(self) -> dict[str, dict[str, str]]:
        """Per tool server attached by the time its agents were resolved, its name and version."""
        return dict(sorted(self._setup_servers.items()))

    def get_token_ledger(self) -> TokenLedger:
        """Return the per-run LLM token/cost ledger (findings-log §4 Item 1)."""
        return self._token_ledger

    def get_generation_rates(self) -> GenerationRates:
        """Return the per-run measured generation rate of each model."""
        return self._generation_rates

    def get_truncation_ledger(self) -> TruncationLedger:
        """Return the per-run truncation ledger (pitfall P6)."""
        return self._truncation_ledger

    def get_context_budget(self) -> Any:
        """The window this job's models serve, and what one tool answer may take.

        The window is the smallest any model the job's tool-calling agents
        call serves (``composition.window_assignments``): every analyst, the
        mediator of a debate and the function summariser while it is on, and
        the judge with the models it really calls, read on the judge role.

        Built once, on first use, because learning the window means asking the
        operator's own endpoint for its metadata — free, but a request, and a
        container that attaches no tool server never makes it. A mock container
        does not ask at all: nothing it builds reaches a model, and a unit test
        must not put a request on the network to find that out.

        The failure mode is a smaller answer, never a failed job: an endpoint
        that says nothing falls to the vendored table, and a window nothing
        could answer for is not derived from at all — the documented constant
        applies and the run summary says the window is unknown.

        The container's lock is **not** held while the window is learned. A
        probe is a network round trip, and holding the lock across one blocks
        every other accessor on every other thread for its whole duration;
        the last writer wins instead, which costs at most one redundant probe
        on the first two callers and is already answered from the cache.
        """
        held = self._context_budget
        if held is not None:
            return held
        from maljan.agents.composition import window_assignments
        from maljan.llm.context_window import budget_for_settings

        assignments = window_assignments(self.config)
        budget = budget_for_settings(
            self.config,
            assignments,
            probe=self._cap_is_derived() and not self.mock,
        )
        self._note_runtime_answers(assignments)
        with self._lock:
            if self._context_budget is None:
                self._context_budget = budget
            budget = self._context_budget
        window = budget.window
        # ``cap_without_recording``: reading the figure for a log line must not
        # reserve room a tool answer never took, nor leave a run that called no
        # tool reporting a cap range nothing used.
        logger.info(
            "Context window: %d (%s — %s); one tool answer may take %d characters.",
            window.tokens,
            window.source,
            window.detail,
            budget.cap_without_recording(),
        )
        return budget

    def get_reporter_context_budget(self) -> Any:
        """The window the reporter's own models serve, as a budget, built once.

        The reporter is left out of the job's window
        (``composition.window_assignments``), so what it reads before it starts
        — the triage pack — is cut on the smaller of the two
        (``pipeline.nodes.pack_text``). Its models are the chain
        ``get_reporter_llm`` builds, fallbacks included; learned as the job's
        window is, and never asked of an endpoint by a mock container.
        """
        held = self._reporter_context_budget
        if held is not None:
            return held
        from maljan.core.model_assignments import assignment_chain_for
        from maljan.llm.context_window import budget_for_settings

        assignments = assignment_chain_for(self.config, REPORTER_AGENT_KEY, role="judge")
        budget = budget_for_settings(
            self.config,
            assignments,
            probe=self._cap_is_derived() and not self.mock,
        )
        self._note_runtime_answers(assignments)
        with self._lock:
            if self._reporter_context_budget is None:
                self._reporter_context_budget = budget
            return self._reporter_context_budget

    def _note_runtime_answers(self, assignments: Any) -> None:
        """Keep which of these models' endpoints answered the window probe as a runtime.

        Read from what the probe that just ran learned, with no request of its
        own (``context_window.runtime_answers``); a mock container learns
        nothing and keeps nothing. Never raises.
        """
        if self.mock:
            return
        try:
            from maljan.llm.context_window import runtime_answers

            found = runtime_answers(assignments)
        except Exception as exc:  # noqa: BLE001 — a record of an answer is never worth a run
            logger.debug("runtime answers not kept (%s).", type(exc).__name__)
            return
        with self._lock:
            self.runtime_answers.update(found)

    def _cap_is_derived(self) -> bool:
        """Whether the tool-output cap comes from the window rather than a setting."""
        return int(getattr(self.config.preprocessing, "max_tool_output_chars", 0) or 0) <= 0

    def context_budget_snapshot(self) -> dict[str, Any]:
        """The window this job's tool-output caps were derived from, or ``{}``.

        Empty on a job that attached no tool server, because none was built,
        and empty on one whose operator set the cap themselves, because then no
        window decided anything and reporting one would describe a number
        nothing used. Never builds a budget: a record of what happened does not
        go and find out.
        """
        budget = self._context_budget
        if budget is None or not self._cap_is_derived():
            return {}
        return dict(budget.snapshot())

    def get_evidence_corpus(self) -> RunEvidenceCorpus | None:
        """Return the per-job record of what the run's tools answered, or ``None``.

        ``None`` once the container is closed. Every reader takes that as "no
        corpus", which is the answer that makes an absence a note rather than a
        reason to remove something.
        """
        return self._evidence_corpus

    def get_evidence_spill(self) -> Any:
        """Return the job's store for whole answers, or ``None`` when the run has none."""
        return getattr(self, "_evidence_spill", None)

    def set_evidence_spill(self, spill: Any) -> None:
        """Give the job a store for whole answers; agents already built get it too."""
        with self._lock:
            self._evidence_spill = spill
            for agent in (*self._agent_cache.values(), *self._judge_agent_cache.values()):
                agent.evidence_spill = spill

    def get_evidence_counter(self) -> EvidenceCounter:
        """Return the per-job counter that issues evidence-ledger ids."""
        return self._evidence_counter

    def register_evidence_holder(self, holder: Callable[[], Iterable[Any]]) -> None:
        """Name something that may hold ledger entries no node has written yet.

        ``holder`` returns the entries it still holds; it may hand over ones
        already on the run's ledger, which ``collect_undrained_evidence``
        leaves out by id. Every agent ``get_agent`` and ``get_judge_agent``
        build is registered with its own drain.
        """
        with self._lock:
            self._evidence_holders.append(holder)

    def _hold_the_evidence_of(self, agent: Any) -> None:
        drain = getattr(agent, "drain_evidence_entries", None)
        if callable(drain):
            self._evidence_holders.append(drain)

    def hand_over_evidence(self, entries: Iterable[Any]) -> None:
        """Keep entries for the run's ledger whose holder has no node left to drain it."""
        entries = list(entries)
        if not entries:
            return
        with self._lock:
            self._handed_over_evidence.extend(entries)

    def collect_undrained_evidence(self, known_ids: Iterable[str] = ()) -> list[Any]:
        """Every entry this job's counter issued that the caller's ledger lacks.

        The one place a path that persists or reports a ledger asks for what no
        node drained: entries handed over through ``hand_over_evidence``, and
        whatever every registered holder still holds — an analyst whose stage
        node never ran its drain (a revision that raised, an analyst asked at
        the verdict stage, a run stopped mid-stage), a judge loop. The ids were
        issued, and the report and the console may already have shown them, so
        the entries belong on the ledger.

        Collecting loses nothing. Every entry ever collected is kept here, and
        each call answers with all of them less ``known_ids``, the ids the
        caller's ledger already holds. A caller that collected and then never
        wrote what it got (a report node cancelled after its collection) leaves
        the entries for the next caller (the stopped run's keep), which finds
        them although the holders are already drained. An id collected twice
        keeps its first entry. In ``seq`` order. Never raises.
        """
        with self._lock:
            parked = self._handed_over_evidence
            self._handed_over_evidence = []
            holders = list(self._evidence_holders)
        found: list[Any] = list(parked)
        for holder in holders:
            try:
                found.extend(holder() or ())
            except Exception as exc:  # noqa: BLE001 — a ledger read never fails a run
                logger.warning("evidence: a holder's entries could not be read (%s).", exc)
        with self._lock:
            for entry in found:
                entry_id = str(getattr(entry, "id", "") or "")
                if entry_id and entry_id not in self._collected_evidence:
                    self._collected_evidence[entry_id] = entry
            kept = list(self._collected_evidence.items())
        known = {str(entry_id) for entry_id in known_ids}
        collected = [entry for entry_id, entry in kept if entry_id not in known]
        if collected:
            logger.warning(
                "evidence: %d entr(y/ies) no node had written reach the ledger now (%s).",
                len(collected),
                ", ".join(str(entry.id) for entry in collected[:20]),
            )
        collected.sort(key=lambda entry: int(getattr(entry, "seq", 0) or 0))
        return collected

    def drain_all_judge_evidence(self) -> list[Any]:
        """Every entry the judge agents gathered, drained from each cached role.

        The judge is cached per role and the roles are different objects: the
        negotiation node mediates on ``expert`` and the verdict runs on
        ``judge``. Only ``mediate`` reaches a tool loop, so a node that drained
        one instance by name drained the wrong one and the mediation's calls
        were never written down. Draining every cached role removes the
        question of which instance recorded what, and it is safe to call twice
        because a drain leaves nothing behind.
        """
        with self._lock:
            judges = list(self._judge_agent_cache.values())
        entries: list[Any] = []
        for judge in judges:
            drain = getattr(judge, "drain_evidence_entries", None)
            if drain is None:
                continue
            try:
                entries.extend(drain())
            except Exception as exc:  # noqa: BLE001 — a ledger read never fails a run
                logger.debug("evidence drain skipped for a judge agent: %s", exc)
        entries.sort(key=lambda entry: getattr(entry, "seq", 0))
        return entries

    def drain_all_judge_budget_records(self) -> list[dict[str, Any]]:
        """Every budget row the judge agents' loops left, from each cached role.

        Drained beside the ledger and for the same reason: the judge is cached
        per role, only some of those instances run a tool loop, and a meter
        that is never drained reports nothing for the one loop with a hard
        wall-clock timeout.
        """
        with self._lock:
            judges = list(self._judge_agent_cache.values())
        rows: list[dict[str, Any]] = []
        for judge in judges:
            drain = getattr(judge, "drain_budget_records", None)
            if drain is None:
                continue
            try:
                rows.extend(drain() or [])
            except Exception as exc:  # noqa: BLE001 — the meter never fails a run
                logger.debug("budget drain skipped for a judge agent: %s", exc)
        return rows

    # ------------------------------------------------------------------
    # Composition accessors
    # ------------------------------------------------------------------

    def active_profile(self) -> Any:
        """The ``ProfileDefinition`` this job runs, its unset stage modes resolved.

        An analysis stage with no run mode of its own runs in the job's
        resolved analyst mode (:meth:`analyst_mode`); a copy is returned and
        the stored profile is never changed.
        """
        from maljan.agents.composition import active_profile
        from maljan.pipeline.analyst_mode import with_resolved_modes

        profile = active_profile(self.config)
        if not any(s.kind == "analysis" and s.mode is None for s in profile.stages):
            return profile
        held = self._resolved_profile
        if held is not None and held[0] is profile:
            return held[1]
        resolved = with_resolved_modes(profile, self.analyst_mode())
        with self._lock:
            self._resolved_profile = (profile, resolved)
        return resolved

    def analyst_mode(self) -> Any:
        """Whether this job's analysts run in parallel, and why (``pipeline.analyst_mode``).

        Resolved once per job — handed in by the worker, which resolves it on
        a thread, or resolved here — and logged with what every analysis
        stage and every revision round runs in. A mock job asks nothing of
        any server; with ``llm.parallel_analysts`` on ``auto`` it runs its
        analysts one after another.
        """
        held = self._analyst_mode
        if held is not None:
            return held
        from dataclasses import replace

        from maljan.agents.composition import active_profile
        from maljan.pipeline.analyst_mode import (
            AnalystMode,
            resolve_for,
            stage_modes,
            stage_sentences,
            with_resolved_modes,
        )

        job = self._job_mode
        if not isinstance(job, AnalystMode):
            job = resolve_for(self.config, mock=self.mock)
        stored = active_profile(self.config)
        rows = stage_modes(stored, with_resolved_modes(stored, job), job)
        resolved = replace(job, stages=rows)
        with self._lock:
            if self._analyst_mode is None:
                self._analyst_mode = resolved
                logger.info("%s", resolved.sentence())
                for line in stage_sentences(rows):
                    logger.info("%s", line)
            return self._analyst_mode

    def analyst_keys(self) -> list[str]:
        """The ordered analyst keys of the active profile.

        The topology source for the builder, the negotiation and revision
        nodes, the judge node and the worker's roster announcement — all of
        them read the profile through this one call, because a profile that
        half the pipeline believes in is worse than no profile.
        """
        from maljan.agents.composition import analyst_keys

        return analyst_keys(self.config)

    def agent_role(self, key: str) -> str:
        """The role definition ``key`` plays: what the code may branch on.

        A clone of the static analyst runs under its own key, so ``key ==
        "static"`` stopped being the question anything should ask; this is the
        question they meant.
        """
        definition = self.config.agents.definitions.get(key)
        if definition is None:
            available = ", ".join(sorted(self.config.agents.definitions)) or "(none)"
            raise KeyError(f"No agent definition named {key!r}. Available: {available}")
        return str(definition.role)

    def job_key(self) -> str:
        """The job identity handed to every resolver and every handle.

        One key per job: the handles' same-job short circuit compares it, so a
        container that answered differently for two of its agents would close
        and reopen every server between them.

        A caller with no job id of its own — the command line, a probe, a
        script — gets one per run. The key names the directory a tool server
        stages in, and the constant it used to be meant two ``maljan`` runs on
        one machine writing into one directory, each able to name the other's
        upload and carved payloads by their paths. One per run rather than one
        per process, because a pid comes round again: this is fixed for the
        life of the container, different for the next one, and the run that
        composed it removes it (``MaljanApp.aclose``).
        """
        return self.job_id or self._run_key

    def get_agent(self, name: str) -> BaseAnalyst:
        """The agent definition ``name`` names, instantiated and wired.

        A built-in role runs its own class under the definition's key — a clone
        ``static_r2`` is a ``StaticAnalyst`` named ``static_r2`` — because
        those classes carry the provider-specific ISR extraction the goldens
        pin. A ``generic`` or ``lead`` role runs ``ConfigurableAnalyst``. Both get the
        per-run ledgers, a way back to this container, and their
        ``ResolvedAgent``, so nothing below re-derives a prompt or a tool set.
        """
        with self._lock:
            cached = self._agent_cache.get(name)
            if cached is not None:
                return cached

            from maljan.agents.composition import resolve_agent
            from maljan.agents.configurable_analyst import ConfigurableAnalyst

            role = self.agent_role(name)
            resolved = resolve_agent(name, self, self.job_key())
            llm = cast(BaseChatModel, resolved.llm)
            if role in PROMPT_ROLES:
                agent: BaseAnalyst = ConfigurableAnalyst(name, resolved, llm)
            else:
                agent = self.agent_registry.create(role, llm)
                # The class is chosen by role; the *identity* is the key. Every
                # per-agent lookup downstream — timeout overrides, LLM
                # overrides, ISR agent_id, the graph node name — reads
                # ``agent.name``, so this one assignment is what makes a clone
                # a separate participant rather than a second copy of its source.
                agent.name = name
                # The base class already childed the logger with the role's
                # own name at construction time; re-child only when the key
                # differs from the role, or a default-profile agent would log
                # as ``...static.static`` instead of ``...static``.
                if name != role:
                    agent.logger = agent.logger.getChild(name.lower())
            # Every attach in this job asks for the same key, so a handle
            # already open for it is reused rather than torn down and reopened.
            agent._job_id = self.job_key()
            agent.token_ledger = getattr(self, "_token_ledger", None)
            agent.truncation_ledger = getattr(self, "_truncation_ledger", None)
            agent.evidence_counter = getattr(self, "_evidence_counter", None)
            agent.evidence_corpus = getattr(self, "_evidence_corpus", None)
            agent.evidence_spill = getattr(self, "_evidence_spill", None)
            # Hand the agent a way back to this container. The static analyst
            # used to construct a *whole new* ServiceContainer on every failed
            # MCP init — per chunk, so up to ten of them per run.
            agent._container = self
            agent._resolved = resolved
            self._note_the_setup(name, resolved)
            self._agent_cache[name] = agent
            self._hold_the_evidence_of(agent)
            return agent

    def get_judge_agent(self, role: str = "judge") -> Any:
        with self._lock:
            cached = self._judge_agent_cache.get(role)
            if cached is None:
                from maljan.agents.judge_agent import JudgeAgent

                llm = self.get_judge_llm() if role == "judge" else self.get_mediator_llm()
                cached = JudgeAgent(
                    llm=llm,
                    # Without this the judge's structured-output capability
                    # check fell back to ``ChatOpenAI._llm_type`` and misread
                    # every provider — see _supports_structured_output.
                    config=self.config,
                )
                cached._job_id = self.job_key()
                # The mediator's instance is built on the mediator's model
                # (``llm.agents.mediator``, else the expert model), and its
                # calls are recorded under that model.
                cached._runs_on = "judge" if role == "judge" else MEDIATOR_AGENT_KEY
                cached.token_ledger = getattr(self, "_token_ledger", None)
                cached.generation_rates = getattr(self, "_generation_rates", None)
                cached.truncation_ledger = getattr(self, "_truncation_ledger", None)
                cached.evidence_counter = getattr(self, "_evidence_counter", None)
                cached.evidence_corpus = getattr(self, "_evidence_corpus", None)
                cached.evidence_spill = getattr(self, "_evidence_spill", None)
                # Hand the judge a way back to this container, the same way
                # ``get_agent`` does above. Without this, ``_server_registry()``
                # always read ``None`` and the judge ran with zero threat-intel
                # tools in production, silently — the guard on the caller is
                # ``if self.tools: return``, so a degraded judge looked exactly
                # like a healthy one that had already attached.
                cached._container = self
                self._judge_agent_cache[role] = cached
                self._hold_the_evidence_of(cached)
            return cached

    async def aclose(self) -> None:
        """Release everything this container handed out. Never raises.

        Correct only because the container is built **per job**
        (``MaljanApp.__init__`` -> ``run_analysis``): closing cached agents at
        job end is safe precisely because no later job will reuse them. If
        agent caching is ever hoisted to process scope, this silently breaks
        the *next* run rather than this one — so hoist the caching and this
        method together, or not at all.

        The two halves close on different loops, and that asymmetry is not
        incidental: the analysts entered their toolkits on the shared agent
        loop via ``_run_coro_blocking``, while the judge entered its own with a
        plain ``await`` on the graph's loop. Each stack has to unwind where it
        was wound.
        """
        # A job that ended before its corpus write (failed, cancelled, or never
        # told to remember) lets go of the function-hash store its judge held.
        with self._lock:
            self._closed = True
            unwritten, self.pending_function_hashes = self.pending_function_hashes, None
        if unwritten is not None:
            from maljan.memory.store_factory import release_function_hash_store

            release_function_hash_store(unwritten[0])
        # What the model calls still running here are charged from now on
        # landed after the job ended: the ledger marks and keeps it.
        ledger = getattr(self, "_token_ledger", None)
        if ledger is not None and hasattr(ledger, "end"):
            ledger.end()
        with self._lock:
            analysts = list(self._agent_cache.values())
            judges = list(self._judge_agent_cache.values())
            self._agent_cache.clear()
            self._judge_agent_cache.clear()

        # Every close is individually bounded *and* the whole set is bounded
        # again by the caller, because teardown that can hang is teardown that
        # blocks the next job — with ``max_jobs = 1`` that means all of them.
        for agent in analysts:
            try:
                await asyncio.wait_for(agent.close_tools(), timeout=_ACLOSE_BUDGET)
            except TimeoutError:
                logger.warning("Closing tools for %s timed out; abandoning.", agent.name)
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Closing agent tools failed (non-fatal): %s", exc)

        for judge in judges:
            closer = getattr(judge, "aclose", None)
            if closer is None:
                continue
            try:
                await asyncio.wait_for(closer(), timeout=_ACLOSE_BUDGET)
            except TimeoutError:
                logger.warning("Closing judge tools timed out; abandoning.")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Closing judge tools failed (non-fatal): %s", exc)

        # The static/sandbox providers may hold a subprocess or an HTTP pool of
        # their own (a CAPE REST client, an MCP stdio child); release them here
        # too, alongside the agents' and judges' toolkits above.
        #
        # M6 (final review): close the *cached* provider, never
        # ``get_static_provider()``/``get_sandbox_provider()`` — those build
        # one on demand, so a job that never touched a provider built one
        # here for the sole purpose of closing it, and a misconfigured
        # ``provider`` id turned a harmless teardown into a
        # ``ProviderConfigurationError`` landing in this warning handler.
        # ``close`` is synchronous and a provider may block in it (a Ghidra
        # bridge waits up to 20 s): run each in an executor so the loop, and
        # every fence on it, stays live. No limit of its own is added here.
        loop = asyncio.get_running_loop()
        closing: list[tuple[str, Any]] = [
            (f"Static provider '{provider.id}'", provider.close)
            for provider in list(self._static_provider_cache.values())
        ]
        if self._sandbox_provider_cache is not None:
            closing.append(("Sandbox provider", self._sandbox_provider_cache.close))
        # Every close is handed to the executor before any is awaited: if the
        # worker's fence cancels this wait, the closes already submitted still
        # run, and none is left unsubmitted behind a slow one.
        futures = [loop.run_in_executor(None, close) for _, close in closing]
        if futures:
            results = await asyncio.gather(*futures, return_exceptions=True)
            for (name, _), result in zip(closing, results, strict=True):
                if isinstance(result, Exception):
                    logger.warning("%s did not close cleanly: %s", name, result)

        # What this job's readings staged on a server of their own, removed
        # there now rather than at that server's staging TTL, while its handle
        # is still attached (``pipeline.nodes.release_reader_staging``). In an
        # executor and bounded, like the sweep below: a server that does not
        # answer costs a worker thread, never the job or the fences.
        if self._server_registry_cache is not None:
            from maljan.pipeline.nodes import release_reader_staging

            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, release_reader_staging, self),
                    timeout=_RELEASE_BUDGET,
                )
            except TimeoutError:
                logger.warning(
                    "Releasing the readings' staging exceeded %.0fs; it is left to the "
                    "servers' staging TTL.",
                    _RELEASE_BUDGET,
                )
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Releasing the readings' staging failed (non-fatal): %s", exc)

        # Same rule as the providers above: close the *cached* registry, never
        # ``get_server_registry()`` — a job that never attached a tool server
        # must not build one here for the sole purpose of closing it.
        if self._server_registry_cache is not None:
            registry = self._server_registry_cache
            # ``close_all`` is synchronous and blocks its thread: each handle
            # it closes hands the toolkit's exit stack to the agent loop and
            # waits for it. Run on the loop thread, that blocks the loop — and
            # a blocked loop cannot fire the worker's 60s fence, which is
            # precisely the way a teardown outlasts a budget nobody can
            # enforce. In an executor it costs a worker thread instead, and
            # every fence above stays live.
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, registry.close_all), timeout=_CLOSE_ALL_BUDGET
                )
            except TimeoutError:
                logger.warning(
                    "The synchronous tool-server sweep exceeded %.0fs; leaving it to "
                    "finish in its thread and closing whatever is still attached.",
                    _CLOSE_ALL_BUDGET,
                )
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Closing the tool-server registry failed (non-fatal): %s", exc)
            # A handle ``aopen`` attached is unwound on the loop that
            # opened it (``ServerHandle.aclose`` routes it there) rather than
            # through the synchronous sweep, which skips it. Read from the
            # registry rather than from the sweep's return value, so a sweep
            # that was abandoned above still leaves nothing attached. Normally
            # a no-op: ``JudgeAgent.aclose`` has closed these already, and this
            # only fires when the judge raised before reaching its own aclose.
            for handle in registry.still_open():
                try:
                    await asyncio.wait_for(handle.aclose(), timeout=_ACLOSE_BUDGET)
                except TimeoutError:
                    logger.warning(
                        "Closing async-opened mcp server '%s' timed out; abandoning.",
                        handle.name,
                    )
                except Exception as exc:  # noqa: BLE001 — teardown never propagates
                    logger.warning(
                        "Closing async-opened mcp server '%s' failed (non-fatal): %s",
                        handle.name,
                        exc,
                    )

        # The sample's parsed text and the per-job caches. Not a leak
        # on their own — the container dies with the job — but dropping them
        # here means a worker that is *not* recycled starts the next job with a
        # clean floor rather than one job's residue.
        with self._lock:
            self._data_cache.clear()
            self._function_summarizer_cache = None
            self._narrative_agent_cache = None
            self._report_composer_cache = None
            self._server_registry_cache = None

        # Last, and after the servers above are closed: what this run staged,
        # carved and fetched. Here rather than in one caller, because every
        # caller that has no worker behind it reaches teardown through this
        # method — the command line, a settings probe, a script — and each of
        # them would otherwise leave a directory of live malware for the TTL.
        # The worker removes it again in a ``finally`` of its own, and a
        # removal of what is already gone does nothing.
        try:
            from maljan.tools import staging

            staging.remove_job_staging(self.job_key())
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("Removing this run's staging failed (non-fatal): %s", exc)
        # What this run noted of the processes that read its sample, read by
        # its disclosure record inside the run.
        from maljan.analysis.isolation import forget as forget_isolation_notes

        forget_isolation_notes(self.job_key())

        # And what this run saw, which is the other thing it held that outlives
        # nothing. Dropping the container already frees it; this drops it here
        # so a caller that keeps the container object alive after closing it —
        # a test harness, a script reading a result off it — does not keep a
        # run's whole tool output with it. Every reader of the corpus runs
        # before teardown: the run summary is built in the judge node and the
        # export's second-source test in the report node, both inside the run.
        #
        # ``None`` rather than an empty corpus. An empty one reports itself
        # complete, so anything grounding after teardown would be told the
        # evidence was whole — a sentinel that fails open on the one rule this
        # whole thread exists to protect. No corpus reads as no corpus.
        self._evidence_corpus = None

        # The store for whole answers lets go of its writers; writes already
        # handed to it still finish, and the worker drains it before it
        # stores the ledger (``schemas.evidence_spill``).
        spill = getattr(self, "_evidence_spill", None)
        if spill is not None:
            try:
                spill.close()
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Closing the evidence store failed (non-fatal): %s", exc)

    def get_narrative_agent(self) -> Any | None:
        """Return the singleton NarrativeAgent or ``None`` in mock mode.

        Reuses ``get_judge_llm()`` — the judge LLM is already configured for
        structured-output prompts so no new provider build is needed. Callers
        receive ``None`` in mock mode and must fall back to the deterministic
        narrative template.

        One instance per container, holding the model it was built with, which
        is the shape the per-loop model store exists to avoid. It is safe
        because of the call site rather than because of this cache: the report
        node is the only caller and it runs on one loop. A second caller on
        another loop would need this to be per-loop as well.
        """
        if self.is_mock:
            return None
        with self._lock:
            if self._narrative_agent_cache is None:
                from maljan.reporting.narrative_agent import NarrativeAgent

                llm = self.get_reporter_llm()
                cap, why, window = getattr(self, "_reporter_output_budget", (0, "", 0))
                self._narrative_agent_cache = NarrativeAgent(
                    llm=llm,
                    token_ledger=getattr(self, "_token_ledger", None),
                    model_label=self._reporter_model_label(),
                    output_cap=cap,
                    budget_note=why,
                    generation_rates=getattr(self, "_generation_rates", None),
                    window_tokens=window,
                )
                self._narrative_agent_cache.event_sink = self.event_sink
            return self._narrative_agent_cache

    def _plan_the_verdict_and_report(self, meter: Any) -> None:
        """Tell the spend meter the verdict and report calls this job will make.

        The verdict is one call on the judge's model; the report is one call
        for each section the composer writes and one for its agreement question
        (when it is on), and one for the narrative round, on the reporter's
        model. Each is planned with the prompt the window accounting allows
        it: its model's window less its output budget, from what is already
        known of the window (nothing is asked of a server here), and ``0``
        where no window is known. The meter keeps what they will cost aside
        from the tool phases. Never raises.
        """
        if meter is None or getattr(meter, "ceiling_usd", None) is None:
            return
        try:
            from maljan.core.model_assignments import assignment_chain_for, model_label_for

            report_calls = 1
            if bool(getattr(self.config.reporting, "composer_enabled", False)):
                from maljan.reporting.composer import COMPOSED_SECTIONS

                # And the agreement question asked once the sections are written.
                report_calls += len(COMPOSED_SECTIONS) + 1
            judge_chain = assignment_chain_for(self.config, "judge", role="judge")
            reporter_chain = assignment_chain_for(self.config, REPORTER_AGENT_KEY, role="judge")
            meter.plan_tail(
                {
                    "verdict": (
                        model_label_for(self.config, "judge", role="judge"),
                        1,
                        self._prompt_allowance(judge_chain),
                        self._output_cap_of(judge_chain),
                    ),
                    "report": (
                        self._reporter_model_label(),
                        report_calls,
                        self._prompt_allowance(reporter_chain),
                        self._output_cap_of(reporter_chain),
                    ),
                }
            )
        except Exception as exc:  # noqa: BLE001 — a plan never costs a job
            logger.debug("the verdict and report were not planned for the spend meter: %s", exc)

    def _output_cap_of(self, chain: list[Any]) -> int:
        """The report-stage output cap of the first model of ``chain``, or ``0`` unknown.

        What a verdict or report call is admitted with (``llm.judge_max_tokens``,
        or its derivation), so the reserve plans the answer its admission demands.
        """
        if not chain:
            return 0
        return max(0, int(report_stage_budget(self.config, chain[0], probe=False).tokens))

    def _prompt_allowance(self, chain: list[Any]) -> int:
        """The prompt tokens the first model of ``chain`` leaves room for, or ``0`` unknown.

        Its window less its report-stage output budget, from the window this
        process already knows (the table, the operator's declaration, a window
        learned earlier); a window nothing answered for is not a fact to plan by.
        """
        if not chain:
            return 0
        from maljan.llm.context_window import FALLBACK

        budget = report_stage_budget(self.config, chain[0], probe=False)
        if budget.window.source == FALLBACK or budget.window.tokens <= 0:
            return 0
        return max(0, int(budget.window.tokens) - int(budget.tokens))

    def _reporter_model_label(self) -> str:
        """The label of the model ``get_reporter_llm`` builds for the report's rounds."""
        from maljan.core.model_assignments import model_label_for

        return model_label_for(self.config, REPORTER_AGENT_KEY, role="judge")

    def _summarizer_model_label(self) -> str:
        """The label of the model ``get_summarizer_llm`` builds first, or ``""``."""
        from maljan.core.model_assignments import model_label_for

        return model_label_for(self.config, SUMMARIZER_AGENT_KEY)

    def get_report_composer(self) -> Any | None:
        """Return the singleton section-wise ReportComposer, or ``None``.

        ``None`` in mock mode or when ``composer_enabled`` is
        off (callers then simply skip the professional spine). Runs on the
        reporter's model like the NarrativeAgent, built with each model's
        section budget as its output cap (:func:`composer_output_budget`), and
        pins it for the same reason and under the same condition: the report
        node is the one caller, on one loop.
        """
        registry = self._llm_registry
        if self.is_mock or not self.config.reporting.composer_enabled or registry is None:
            return None
        config = self.config
        budgets: dict[str, tuple[int, str, int]] = {}
        chain: list[Any] = []
        if getattr(self, "_report_composer_cache", None) is None:
            # Learned before the lock: learning a window may ask the model's
            # server, and nothing else the container serves should wait on it.
            from maljan.core.model_assignments import assignment_chain_for

            chain = assignment_chain_for(config, REPORTER_AGENT_KEY, role="judge")
            budgets = {a.label: composer_output_budget(config, a) for a in chain}
        with self._lock:
            if getattr(self, "_report_composer_cache", None) is None:
                from maljan.reporting.composer import ReportComposer

                rc = self.config.reporting
                # The reporter's model, built with the section's own output cap
                # rather than the judge's: the section budget is what a section
                # may generate, and a wait sized from it over a call allowed
                # ``judge_max_tokens`` would say something untrue.
                # Held by the composer, which is dropped with the loop it ran on.
                caps = {label: tokens for label, (tokens, _why, _window) in budgets.items()}
                # What each provider's model is built with: the budget of its
                # model on the list, the smaller where one provider serves two.
                by_provider: dict[str, int] = {}
                for a in chain:
                    tokens = budgets[a.label][0]
                    by_provider[a.provider] = min(by_provider.get(a.provider, tokens), tokens)
                # A section's tool answers are sized for the tightest window of
                # the list, since any model of it may be the one that answers.
                # A window nothing reported is left out: it is not a fact to
                # size evidence against.
                window_tokens = min(
                    (window for _tokens, _why, window in budgets.values() if window > 0),
                    default=0,
                )
                # The wait is sized for the most a model of the list may write.
                output_cap = max(caps.values(), default=0)
                budget_note = "; ".join(
                    why if len(budgets) == 1 else f"{label}: {why}"
                    for label, (_tokens, why, _window) in budgets.items()
                )
                if window_tokens > 0:
                    from maljan.llm.context_window import CHARS_PER_TOKEN

                    budget_note += (
                        f". A section's tool answers share what the {window_tokens}-token "
                        "window leaves after the output budget and the rest of the section's "
                        f"prompt, at {CHARS_PER_TOKEN} characters a token, evenly"
                    )
                composer_llm = registry.build_model_for_agent(
                    REPORTER_AGENT_KEY,
                    fallback_role="judge",
                    # Every model of the list is budgeted above, and held at
                    # its maximum; no other provider is built.
                    max_tokens_for=lambda provider: by_provider.get(provider, output_cap),
                )
                attach_rate_meter(composer_llm, getattr(self, "_generation_rates", None))
                attach_retry_recorder(
                    composer_llm, getattr(self, "_token_ledger", None), REPORTER_AGENT_KEY
                )
                attach_agent_ceiling(
                    composer_llm, getattr(self, "_token_ledger", None), REPORTER_AGENT_KEY
                )
                self._report_composer_cache = ReportComposer(
                    llm=composer_llm,
                    section_max_tokens=rc.composer_section_max_tokens,
                    per_section_timeout=rc.composer_per_section_timeout,
                    token_ledger=getattr(self, "_token_ledger", None),
                    model_label=self._reporter_model_label(),
                    generation_rates=getattr(self, "_generation_rates", None),
                    output_cap=output_cap,
                    caps_by_model=caps,
                    turn_share=float(config.llm.fallback_turn_share),
                    budget_note=budget_note,
                    window_tokens=window_tokens,
                    windows_by_model={
                        label: window for label, (_tokens, _why, window) in budgets.items()
                    },
                )
                self._report_composer_cache.event_sink = self.event_sink
            return self._report_composer_cache

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_data(self, sample_id: str, data_type: str) -> str:
        key = (sample_id, data_type)
        with self._lock:
            cached = self._data_cache.get(key)
            if cached is None:
                cached = self.loader.load(sample_id, data_type)
                self._data_cache[key] = cached
            return cached

    def load_chunked(
        self,
        sample_id: str,
        data_type: str,
        room: Room | None = None,
        boundary: str | None = None,
    ) -> list[TextChunk]:
        """Return a list of TextChunk objects for a sample and data type.

        Re-uses the parsed-text cache when available; chunking itself is cheap
        and stateless so the chunk list is not cached. ``room`` is the
        analyst's input room (``BaseAnalyst._input_room_chars``), which sizes
        a chunk where ``chunking.max_tokens_per_chunk`` is unset. ``boundary``
        is the source's declared unit start (``AgentDefinition.chunk_boundary``),
        passed on only where there is one.
        """
        declared: dict[str, str] = {"boundary": boundary} if boundary else {}
        outermost = _OUTERMOST_LOAD.get()
        token = _OUTERMOST_LOAD.set(False)
        try:
            room = _first_pass_room(self, data_type, room)
            key = (sample_id, data_type)
            with self._lock:
                cached_text = self._data_cache.get(key)
            if cached_text is not None:
                chunks = self.loader.chunk_text(data_type, cached_text, room=room, **declared)
            else:
                chunks = self.loader.load_chunked(sample_id, data_type, room=room, **declared)
        finally:
            _OUTERMOST_LOAD.reset(token)
        if outermost:
            _note_chunking(self, data_type, chunks, room)
        return chunks

    def load_data_for_agent(
        self,
        agent_name: str,
        *,
        file_hash: str,
        sandbox_report: dict[str, Any] | None = None,
        sample_path: str | None = None,
        room: Room | None = None,
        head_room: Room | None = None,
    ) -> list[TextChunk]:
        """The input text agent ``agent_name`` is handed, as chunks.

        Each source is chunked on its own at ``room``, the agent's input room
        (``None``: the operator's chunk size, or the unknown-window size). The
        source the first chunk comes from is chunked at ``head_room`` where it
        is given: the room its chunk has once the node adds to it
        (``binary_chunker.head_room``).

        Driven by ``AgentDefinition.data_sources``. An empty list means the
        slice the agent's *role* used to get, which is spelled out in
        ``_legacy_role_data`` below and is what every definition written before
        stages relies on: a static analyst read the sandbox report's ``target``
        block when there was one and the parsed sample otherwise, a dynamic
        analyst read the behaviour log, a network analyst the network block,
        and a generic agent read the sample plus the whole report.

        A non-empty list is taken literally and in order, which is the point of
        the field: a clone of the static analyst can be pointed at the network
        block without also becoming a network analyst.
        """
        definition = self.config.agents.definitions.get(agent_name)
        sources = list(definition.data_sources) if definition is not None else []
        outermost = _OUTERMOST_LOAD.get()
        token = _OUTERMOST_LOAD.set(False)
        try:
            room = _first_pass_room(self, agent_name, room)
            head_room = _first_pass_room(self, agent_name, head_room)
            if not sources:
                chunks = self._legacy_role_data(
                    agent_name, file_hash, sandbox_report, room, head_room
                )
            else:
                chunks = self._sources_data(
                    agent_name, sources, file_hash, sandbox_report, sample_path, room, head_room
                )
        finally:
            _OUTERMOST_LOAD.reset(token)
        if outermost:
            _note_chunking(self, agent_name, chunks, head_room)
            # The sample's text never carries the platform's run-state markers:
            # written out one character for one, so no size above changes.
            chunks = _markers_written_out(chunks)
        return chunks

    def _sources_data(
        self,
        agent_name: str,
        sources: list[str],
        file_hash: str,
        sandbox_report: dict[str, Any] | None,
        sample_path: str | None,
        room: Room | None,
        head_room: Room | None,
    ) -> list[TextChunk]:
        """``data_sources`` taken in order, each chunked on its own, the first at the head room."""
        head = head_room if head_room is not None else room
        head = _head_alone(head, len(sources) == 1)
        chunks: list[TextChunk] = []
        # A source that yields nothing but whitespace adds no chunk: beside
        # another source it would be a loop over nothing. The source after it
        # is then the head. Only an input of nothing at all keeps one such
        # chunk, the single input it always was.
        empty: list[TextChunk] = []
        for source in sources:
            got = self._data_source_chunks(
                agent_name,
                source,
                file_hash,
                sandbox_report,
                sample_path,
                room if chunks else head,
            )
            held = _with_content(got, agent_name)
            if got and not held:
                empty.append(got[0])
            chunks.extend(held)
        if not chunks and empty:
            chunks = empty[:1]
        return chunks

    def _data_source_chunks(
        self,
        agent_name: str,
        source: str,
        file_hash: str,
        sandbox_report: dict[str, Any] | None,
        sample_path: str | None,
        room: Room | None = None,
    ) -> list[TextChunk]:
        """One vocabulary entry, resolved. A source with nothing behind it is empty.

        Empty rather than a placeholder: an agent that asked for the sandbox
        network block on a sample that was never detonated has no network
        block, and the no-data guard in the analyst node is the right place for
        that to be reported once, not once per source.
        """
        if source == "sample.path":
            path = sample_path or ""
            if not path:
                return []
            return self.loader.chunk_text(agent_name, f"analysis_file_path: {path}", room=room)
        definition = self.config.agents.definitions.get(agent_name)
        named = getattr(definition, "chunk_boundary", None)
        named = named.get(source) if isinstance(named, dict) else None
        boundary = named if isinstance(named, str) and named else None
        if source == "sample.chunks":
            if boundary:
                return self.load_chunked(file_hash, agent_name, room=room, boundary=boundary)
            return self.load_chunked(file_hash, agent_name, room=room)
        if not sandbox_report:
            return []
        if boundary:
            return self._sandbox_slice(agent_name, source, sandbox_report, room, boundary)
        return self._sandbox_slice(agent_name, source, sandbox_report, room)

    def _sandbox_slice(
        self,
        agent_name: str,
        source: str,
        sandbox_report: dict[str, Any],
        room: Room | None = None,
        boundary: str | None = None,
    ) -> list[TextChunk]:
        """One slice of the sandbox report as the agent reads it, chunked at ``room``.

        ``sandbox_report`` is the neutral sandbox report's document
        (``schemas.sandbox_document``), each slice one of its parts by name.
        A slice handed over as JSON is compact — the same document without the
        indentation, which was characters of whitespace in every model request
        and nowhere else. It is model input only; the report the run stores is
        not this text.
        """
        from maljan.core.safe_json import dumps
        from maljan.schemas.sandbox_document import place

        # Passed on only where the source declares a boundary.
        declared: dict[str, str] = {"boundary": boundary} if boundary else {}

        def compact(document: Any) -> str:
            # Depth-safe: a report nested past the guard is written with a
            # marked placeholder there, never a raise (``core.safe_json``).
            return dumps(document, separators=(",", ":"), default=str)

        if source == "sandbox.target":
            return self.loader.chunk_text(
                agent_name, compact(place(sandbox_report, "target", {})), room=room, **declared
            )
        if source == "sandbox.network":
            network = sandbox_report.get("network", {})
            try:
                text = self.parser_registry.create("network").parse(network)
            except KeyError:
                text = compact(network)
            return self.loader.chunk_text(agent_name, text, room=room, **declared)
        if source == "sandbox.behavior":
            try:
                text = self.parser_registry.create("dynamic").parse(sandbox_report)
            except KeyError:
                text = compact(sandbox_report)
            return self.loader.chunk_text(agent_name, text, room=room, **declared)
        return self.loader.chunk_text(agent_name, compact(sandbox_report), room=room, **declared)

    def _legacy_role_data(
        self,
        agent_name: str,
        file_hash: str,
        sandbox_report: dict[str, Any] | None,
        room: Room | None = None,
        head_room: Room | None = None,
    ) -> list[TextChunk]:
        """What the agent's role read before ``data_sources`` existed.

        Kept as one branch rather than expressed as a default source list,
        because it is not a list: the static role's slice *depends on whether a
        sandbox report exists*, and writing that as ``["sandbox.target",
        "sample.chunks"]`` would hand a detonated sample both instead of one.
        """
        role = self.agent_role(agent_name)
        head = head_room if head_room is not None else room
        if role in PROMPT_ROLES:
            loaded = self.load_chunked(
                file_hash, agent_name, room=_head_alone(head, not sandbox_report)
            )
            static_context = _with_content(loaded, agent_name)
            sandbox_chunks: list[TextChunk] = []
            if sandbox_report:
                # The sandbox report is the head where the static context
                # holds nothing, and a context of nothing is no chunk of its own.
                sandbox_chunks = _with_content(
                    self._sandbox_slice(
                        agent_name,
                        "sandbox.full",
                        sandbox_report,
                        room if static_context else _head_alone(head, True),
                    ),
                    agent_name,
                )
            return [*static_context, *sandbox_chunks] or loaded[:1]
        if sandbox_report:
            slice_name = {
                "static": "sandbox.target",
                "network": "sandbox.network",
                "dynamic": "sandbox.behavior",
            }.get(role, "sandbox.full")
            return self._sandbox_slice(
                agent_name, slice_name, sandbox_report, _head_alone(head, True)
            )
        return self.load_chunked(file_hash, agent_name, room=_head_alone(head, True))

    def _prompt_room_chars(self) -> int | None:
        """What one prompt may carry before the reply room, or ``None`` with no window learned."""
        from maljan.llm.context_window import ContextBudget

        try:
            budget = self.get_context_budget()
        except Exception:  # noqa: BLE001 — no budget is no bound
            return None
        if not isinstance(budget, ContextBudget) or not budget.derives:
            return None
        return int(budget.tool_budget_chars())

    def get_function_summarizer(self) -> FunctionSummarizer | None:
        if not self.config.preprocessing.use_function_summarizer:
            return None
        with self._lock:
            if self._function_summarizer_cache is None:
                from maljan.analysis.function_summarizer import FunctionSummarizer

                if self._llm_registry is None:
                    raise ConfigurationError("Cannot build FunctionSummarizer LLM in mock mode.")
                summarizer_llm = self.get_summarizer_llm()
                self._function_summarizer_cache = FunctionSummarizer(
                    llm=summarizer_llm,
                    max_summary_words=self.config.preprocessing.summarizer_max_words,
                    token_ledger=getattr(self, "_token_ledger", None),
                    model_label=self._summarizer_model_label(),
                    room_chars=self._prompt_room_chars,
                    truncation_ledger=getattr(self, "_truncation_ledger", None),
                )
                logger.info(
                    "FunctionSummarizer initialized (%s, max_words=%d).",
                    self._summarizer_model_label(),
                    self.config.preprocessing.summarizer_max_words,
                )
            return self._function_summarizer_cache

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _announce_index_retry(self) -> None:
        """Put ``validation.index_retry_seconds`` where every consumer can read it.

        The knowledge sidecar is the process where an ATT&CK index build
        actually happens, and it reads the setting out of its own environment
        (``env_allow`` carries the name). This is the one place that puts it
        there, beside the tracing values: the container is what builds the
        sidecar registry, so a sidecar started from any entry point that has a
        container — a script, a test harness, the API — reads the deployment's
        number rather than the module default. It used to be announced from
        ``MaljanApp.arun``, which is one entry point of several.
        """
        from maljan.tools import knowledge as knowledge_tools

        seconds = int(getattr(getattr(self.config, "validation", None), "index_retry_seconds", 900))
        os.environ[knowledge_tools.INDEX_RETRY_ENV] = str(seconds)
        knowledge_tools.set_index_retry_after(seconds)

    def _announce_attck_refresh(self) -> None:
        """Put ``validation.attck_refresh_days`` where the ATT&CK loader reads it.

        The loader runs in this process and in the knowledge sidecar, which
        has an environment and no settings store (``env_allow`` carries the
        name), so the value travels the way ``index_retry_seconds`` does. This
        is the one place that writes it: the store is the only source, and the
        variable an operator used to set is retired.
        """
        from maljan.memory.attck_loader import ATTCK_REFRESH_DAYS_ENV, DEFAULT_MAX_AGE_DAYS

        days = int(
            getattr(
                getattr(self.config, "validation", None), "attck_refresh_days", DEFAULT_MAX_AGE_DAYS
            )
        )
        os.environ[ATTCK_REFRESH_DAYS_ENV] = str(days)

    def _configure_langsmith(self) -> None:
        """Propagate LangSmith tracing config into the OS environment, or undo it.

        The environment is the process's and outlives the job, so a job with
        the setting off puts back what the platform set for an earlier one
        (``core.tracing.apply_tracing_setting``), and an environment that
        traces on its own is warned about there.
        """
        from maljan.core.tracing import apply_tracing_setting

        if not self.config.langchain_tracing_v2:
            apply_tracing_setting(False)
            logger.debug("LangSmith tracing disabled (langchain_tracing_v2=False).")
            return

        api_key = self.config.langchain_api_key
        secret_value = ""
        if api_key:
            secret_value = (
                api_key.get_secret_value() if hasattr(api_key, "get_secret_value") else str(api_key)
            )
        apply_tracing_setting(
            True, project=str(self.config.langchain_project or ""), api_key=secret_value
        )
        if api_key:
            # No part of the key reaches the log: a fragment narrows a brute
            # force and is enough to confirm a key found elsewhere.
            logger.info(
                "LangSmith tracing enabled (project=%s).",
                self.config.langchain_project,
            )
        else:
            logger.warning(
                "LangSmith tracing enabled (project=%s) but no API key provided. "
                "Set LANGCHAIN_API_KEY in .env to authenticate with LangSmith.",
                self.config.langchain_project,
            )
