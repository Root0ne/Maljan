"""Ghidra MCP static analysis: the provider the static analysts drive Ghidra through.

The load_program path pin and the http/stdio attach path are the static
analyst's own code, transplanted here unchanged. What only Ghidra's REST API
serves is answered here through the static provider interface
(``providers.base.StaticProvider``): the open of the job's sample before an
analyst's loop (``open_sample``), the call graph the sink pre-pass ranks
(``call_graph``), the anti-analysis scan the triage pack makes
(``anti_analysis_scan``, ``passes``) and the function hashes
(``function_hashes``).
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from langchain_core.tools import BaseTool

from maljan.core import builtin_declarations, cancellation
from maljan.core.exceptions import SampleNotOpened
from maljan.core.logger import logger
from maljan.core.settings_overrides import redact_url
from maljan.core.undeclared_tools import categories_of
from maljan.providers.base import (
    CLAIM_CITATION,
    MirrorSpec,
    ProviderProbe,
    StaticCapabilities,
    StaticJobContext,
    StaticProvider,
)
from maljan.providers.registry import register_static_provider
from maljan.providers.sample_open import long_running_tools, server_note_key
from maljan.providers.server_guard import explicit_call_timeout, guard_from_settings
from maljan.providers.static.ghidra.call_graph import PRIORITY_FOLLOW_UP, call_graph_from_text
from maljan.providers.static.ghidra.passes import SCAN_CHECKS_SHORT
from maljan.tools.errors import SERVER_WORDS_LIMIT, TRANSPORT_MARKERS

if TYPE_CHECKING:
    from maljan.analysis.sink_reachability import CallGraph
    from maljan.core.config import MCPServerConfig, MemoryConfig, PreprocessingConfig, Settings
    from maljan.providers.static.ghidra.passes import GhidraPasses


# Ghidra's prompt: its opening sentence, its guidance about claims (the
# citation every static analyst is given and the verification discipline in
# the words Ghidra's prompt has always used; it goes with every call on a
# Ghidra run, tools or none), then the workflow its block declares
# (``core.builtin_declarations``), which goes only where Ghidra's tools do.
# ``GHIDRA_PROMPT_FRAGMENT`` is the whole fragment with the shipped workflow.
GHIDRA_LEAD = (
    "Analyze binary files (e.g. PE, ELF) utilizing Ghidra through your available tools. "
    "You can decompile functions, find cross-references, extract strings, and more. "
)
GHIDRA_GUIDANCE = CLAIM_CITATION + "\n\n" + builtin_declarations.GHIDRA_VERIFICATION_DISCIPLINE
GHIDRA_WORKFLOW = builtin_declarations.GHIDRA_WORKFLOW
GHIDRA_PROMPT_FRAGMENT = GHIDRA_LEAD + GHIDRA_GUIDANCE + "\n\n" + GHIDRA_WORKFLOW


# What an agent on Ghidra is stopped with when Ghidra answered that it could
# not load the job's sample. The server's own words go in the middle; the check
# names the two things that decide whether the container can see the file.
SAMPLE_NOT_OPENED: str = (
    "Ghidra could not open the job's sample: {words}; "
    "check core.static.ghidra.sample_mount / the container mount"
)

# And when the load got no answer from Ghidra at all: the connection failed,
# the server failed, or it refused the token. The samples path is not the
# remedy for any of those, so it is not named.
GHIDRA_NOT_ANSWERING: str = (
    "Ghidra at {address} did not answer the load of the job's sample ({what}); "
    "check the Ghidra container is running at that address and "
    "core.static.ghidra.auth_token matches its GHIDRA_MCP_AUTH_TOKEN"
)


def _one_line(words: str) -> str:
    return " ".join(str(words or "").split())[:SERVER_WORDS_LIMIT] or "an empty answer"


def sample_not_opened(words: str) -> SampleNotOpened:
    """The failure for a load of the job's sample that Ghidra answered with an error."""
    return SampleNotOpened(SAMPLE_NOT_OPENED.format(words=_one_line(words)), provider="ghidra")


# And when Ghidra loaded the sample but refused to make it the current
# program right after: nothing about the file or the mount, and not
# remembered, so the next loop loads it again.
GHIDRA_DID_NOT_MAKE_IT_CURRENT: str = (
    "Ghidra loaded the job's sample but refused to make it the current program "
    "({words}); this loop stops, and the next one loads the sample again"
)


# And when Ghidra loaded the sample but refused the declared analysis right
# after: an import holds no call or code reference for the agent to read. Not
# remembered either, so the next loop loads it again.
GHIDRA_DID_NOT_ANALYSE: str = (
    "Ghidra loaded the job's sample but refused to analyse it ({words}); this loop "
    "stops, and the next one loads the sample again"
)


def not_made_current(answer: str) -> SampleNotOpened | None:
    """The stop for a declared step the opener says was refused right after a fresh load.

    ``None`` when the answer carries neither marker. Read from the opener's
    own markers (``sample_open.SELECT_REFUSED_AFTER_OPEN``,
    ``sample_open.ANALYSIS_REFUSED_AFTER_OPEN``) with its one reader of
    answers; each names the step's refusal, not the samples mount, and the
    caller does not remember it.
    """
    from maljan.providers.sample_open import (
        ANALYSIS_REFUSED_AFTER_OPEN,
        SELECT_REFUSED_AFTER_OPEN,
        answer_object,
    )

    sentences = {
        SELECT_REFUSED_AFTER_OPEN: GHIDRA_DID_NOT_MAKE_IT_CURRENT,
        ANALYSIS_REFUSED_AFTER_OPEN: GHIDRA_DID_NOT_ANALYSE,
    }
    payload = answer_object(answer)
    sentence = sentences.get(str(payload.get("tool_error"))) if payload is not None else None
    if payload is None or sentence is None:
        return None
    words = _one_line(str(payload.get("detail") or ""))
    return SampleNotOpened(sentence.format(words=words), provider="ghidra")


# And when Ghidra answered the load but the job's guard for Ghidra did not send
# the step after it (the select or the analysis): Ghidra rests again after
# calls it did not answer. The guard's own sentence goes first; nothing about
# the file, so not remembered. What becomes of the opened program is said.
GHIDRA_RESTING: str = (
    "{words}; Ghidra opened the job's sample{name} but the step after the load was not "
    "sent, so it is neither current nor analysed; {kept}, and this loop stops"
)


def ghidra_resting(words: str, name: str | None) -> SampleNotOpened:
    """The failure for a step after the load that the job's guard did not send.

    ``name`` is the program the load opened when it is noted for the job's
    teardown to close, else ``None``, and the sentence says it is not.
    """
    return SampleNotOpened(
        GHIDRA_RESTING.format(
            words=_one_line(words),
            name=f" as {_one_line(name)}" if name else "",
            kept="it is noted for the job's teardown to close"
            if name
            else "it could not be noted, so the job's teardown does not close it",
        ),
        provider="ghidra",
    )


def ghidra_not_answering(address: str, what: str) -> SampleNotOpened:
    """The failure for a load of the job's sample that Ghidra gave no answer to."""
    return SampleNotOpened(
        GHIDRA_NOT_ANSWERING.format(address=address or "its address", what=_one_line(what)),
        provider="ghidra",
    )


def ghidra_address(url: str) -> str:
    """``scheme://host:port`` of Ghidra's URL, the port stated even when it is the default."""
    import httpx

    try:
        parsed = httpx.URL(str(url or ""))
    except Exception:  # noqa: BLE001 — an unreadable URL is said as nothing
        return ""
    if not parsed.host:
        return ""
    port = parsed.port or {"http": 80, "https": 443}.get(parsed.scheme, 0)
    return f"{parsed.scheme}://{parsed.host}:{port}" if port else f"{parsed.scheme}://{parsed.host}"


def load_failure(load_output: str) -> tuple[str, bool] | None:
    """What a ``load_program`` answer says went wrong, and whether Ghidra said it.

    ``None`` when the answer is a program, or is neither a program nor an
    error — the guardrail's sentence for a conversation with no room left is
    not a failed load. Otherwise ``(words, from_ghidra)``: ``from_ghidra`` is
    true for Ghidra's own ``{"error": "File not found: ..."}``, answered with
    HTTP 200, and false for a client marker saying the request itself failed
    (``tool_error`` of a transport kind). Read with the one rule the ledger
    uses for a returned error, ``tools.errors.error_parts``.
    """
    import json

    from maljan.providers.static.ghidra.program import program_name_from_load
    from maljan.tools.errors import error_parts

    if program_name_from_load(load_output):
        return None
    parts = error_parts(load_output)
    if parts is None:
        return None
    try:
        marker = json.loads(load_output).get("tool_error")
    except (ValueError, TypeError, AttributeError):
        marker = None
    return parts[1], marker not in TRANSPORT_MARKERS


def sample_notes_of(holder: Any) -> Any:
    """The job's note of opened samples: ``holder`` itself, or the one a provider holds,
    else a note of its own."""
    from maljan.providers.sample_open import SampleNotes

    if isinstance(holder, SampleNotes):
        return holder
    notes = getattr(holder, "sample_notes", None)
    return notes if isinstance(notes, SampleNotes) else SampleNotes()


def open_ghidra_sample(
    http: Any,
    base: str,
    file_path: str,
    spec: Any,
    notes: Any,
    *,
    key: str,
    open_call: Any = None,
) -> str:
    """Open ``file_path`` on Ghidra over its REST API; the open's answer.

    Through the general opener (``providers.sample_open``) with the tools the
    Ghidra block declares (``sample_open``), so a path the job already opened
    is a select answered from the note. With nothing declared, the file is
    loaded and made current, as before there was a declaration: Ghidra sets
    its current program only when none is current, so a load alone leaves it
    reading another binary (the one place Ghidra's own load tool is named:
    the behaviour before any declaration). ``open_call(tool, arguments)``
    answers the open tool's calls in the caller's own way (the load before the
    loop retries a connection and raises when Ghidra did not answer). ``key``
    names the server in the job's note (``sample_open.server_note_key``).
    """
    from maljan.providers.sample_open import (
        SELECT_REFUSED_AFTER_OPEN,
        SampleOpener,
        declared,
        is_refusal,
        refused_after_open,
    )
    from maljan.providers.static.ghidra.program import (
        SWITCH_PARAM,
        SWITCH_PATH,
        program_name_from_load,
        rest_tool_call,
    )

    if declared(spec):
        tool = spec.open_tool
        overrides = (
            {tool: lambda arguments: open_call(tool, arguments)} if open_call is not None else {}
        )
        call = rest_tool_call(http, base, overrides=overrides)
        return SampleOpener(key, spec, notes).open(file_path, call, held=file_path)
    loaded = (
        open_call(UNDECLARED_LOAD_TOOL, {"file": file_path})
        if open_call is not None
        else rest_tool_call(http, base)(UNDECLARED_LOAD_TOOL, {"file": file_path})
    )
    name = program_name_from_load(loaded)
    if name:
        switch = SWITCH_PATH.lstrip("/")
        switched = rest_tool_call(http, base)(switch, {SWITCH_PARAM: name})
        if is_refusal(switched):
            # Loaded but not made current: Ghidra reads another binary, so the
            # open is handed on as failed, with the switch's words.
            return refused_after_open(
                SELECT_REFUSED_AFTER_OPEN, switch, UNDECLARED_LOAD_TOOL, switched, loaded
            )
    return str(loaded)


# The call-graph request: the server's edge text, every function walked
# (``limit`` 0 is no limit; absent, the server walks 1000).
CALL_GRAPH_PARAMS: dict[str, Any] = {"format": "edges", "limit": 0}

# Ghidra's load tool, as the load is made when the block declares no open
# tool: the behaviour from before there was a declaration.
UNDECLARED_LOAD_TOOL = "load_program"


def _load(
    http: Any, base: str, tool: str, arguments: dict[str, Any], address: str, log: Any
) -> Any:
    """The load of the job's sample, or :class:`SampleNotOpened` when Ghidra gave no answer.

    A request that did not reach Ghidra is made once more before it counts: a
    container restarting under ``unless-stopped`` is back in seconds. An HTTP
    error — a 5xx, a refused token — is not retried. Neither is remembered on
    the provider, because neither says anything about the file: a Ghidra that
    comes back is asked again by the next loop.
    """
    import httpx

    for attempt in (1, 2):
        try:
            loaded = http.post(f"{base}/{tool}", json=dict(arguments))
            loaded.raise_for_status()
            return loaded
        except httpx.HTTPStatusError as exc:
            failure = ghidra_not_answering(address, f"HTTP {exc.response.status_code}")
            log.error("%s", failure)
            raise failure from exc
        except httpx.RequestError as exc:
            if attempt == 1:
                log.warning(
                    "Ghidra did not answer the load of the job's sample (%s); asking once more.",
                    type(exc).__name__,
                )
                continue
            failure = ghidra_not_answering(address, type(exc).__name__)
            log.error("%s", failure)
            raise failure from exc
    raise AssertionError("unreachable")  # pragma: no cover


class _Unanswered:
    """An HTTP client that notes each request its server did not answer, then raises it.

    Read as the job's guard reads a transport failure (``transport_failure``).
    """

    def __init__(self, client: Any, unanswered: list[str]) -> None:
        self._client = client
        self._unanswered = unanswered

    def _noted(self, call: Any, url: Any, **kwargs: Any) -> Any:
        from maljan.providers.server_guard import transport_failure

        try:
            return call(url, **kwargs)
        except Exception as exc:
            if transport_failure(exc) is not None:
                self._unanswered.append(type(exc).__name__)
            raise

    def get(self, url: Any, **kwargs: Any) -> Any:
        return self._noted(self._client.get, url, **kwargs)

    def post(self, url: Any, **kwargs: Any) -> Any:
        return self._noted(self._client.post, url, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def _wait_admissible(guard: Any, rests_begun: int, job: Any) -> bool:
    """``guard.wait_admissible``, woken and ended by ``job``'s cancel where there is a job."""
    if job is None:
        return bool(guard.wait_admissible(rests_begun))
    forget = job.track(guard.wake)
    try:
        return bool(guard.wait_admissible(rests_begun, stopped=lambda: job.is_cancelled))
    finally:
        forget()


def _known_failure(provider: Any, path: str) -> SampleNotOpened | None:
    """The failure ``provider`` already met opening ``path``, as a fresh exception."""
    known = getattr(provider, "sample_failure", None)
    failure = known(path) if callable(known) else None
    return failure if isinstance(failure, SampleNotOpened) else None


def _remember_failure(provider: Any, path: str, failure: SampleNotOpened) -> None:
    """Tell ``provider`` that ``path`` did not open, when the caller handed one over."""
    remember = getattr(provider, "note_sample_failure", None)
    if callable(remember):
        remember(path, failure)


@register_static_provider("ghidra")
class GhidraStaticProvider(StaticProvider):
    """Ghidra MCP, as the static analyst has always driven it.

    Every line of the attach path — the http/stdio branch, the shared-loop
    ``_run_async``, the load_program pin — is this file's, moved out of
    ``StaticAnalyst`` unchanged. What is new is only the seam: the analyst now
    asks a provider for tools instead of knowing how to build them.

    ``degrade_on_failure`` is False on purpose. Ghidra IS the static evidence;
    a toolless static run produces a confident-looking report grounded in
    nothing, which is why this analyst has always failed loudly while dynamic
    and network degrade.
    """

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "Ghidra"
    choice_order = 0
    title = "Ghidra MCP"
    description = "A running Ghidra MCP server decompiles and names functions on request."
    probe_label = "Test Ghidra MCP"
    settings_intro = "Where the Ghidra MCP server listens, and how it authenticates."
    priority_follow_up = PRIORITY_FOLLOW_UP
    scan_checks_short = SCAN_CHECKS_SHORT

    def __init__(
        self,
        cfg: MCPServerConfig,
        preprocessing: PreprocessingConfig,
        memory: MemoryConfig,
    ) -> None:
        self._cfg = cfg
        self._pre = preprocessing
        self._memory = memory
        self._job = StaticJobContext()
        # The container path an agent was pinned to (``pin_sample``), for an
        # attach whose job context names none: a generic agent's provider is
        # opened at resolution, before any sample path exists.
        self._pinned_path: str | None = None
        # The sentence each path this provider could not open was stopped
        # with, so a later loop of the job is stopped before it calls Ghidra.
        self._sample_failures: dict[str, str] = {}
        # The job's note of the paths it opened (``providers.sample_open``);
        # the container puts its own job-wide note here, shared with the
        # deterministic passes.
        from maljan.providers.sample_open import SampleNotes, new_instance

        self.sample_notes = SampleNotes()
        # This provider's own process, for a local Ghidra's note key.
        self.note_instance = new_instance()
        self._toolkit: Any = None
        self._all_tools: list[Any] = []
        self.tools: list[Any] = []
        # The tools withheld because they could not be made to carry the job's
        # program on a shared Ghidra, each with its reason.
        self.withheld_tools: dict[str, str] = {}
        # The job's breaker and call cap for Ghidra (``server_guard``), built on
        # first use and shared by the agents' calls and this provider's own
        # walks; the rests it gives go to the job's hook once an attach names
        # one, and are kept here (and announced on the job's sink) before.
        self._guard: Any = None
        self._guard_lock = threading.Lock()
        self._rest_hook: Any = None
        self.rests: list[dict[str, Any]] = []
        self.event_sink: Any = None

    @classmethod
    def from_settings(cls, cfg: Settings) -> GhidraStaticProvider:
        return cls(cfg.static.ghidra, cfg.preprocessing, cfg.memory)

    @property
    def capabilities(self) -> StaticCapabilities:
        # function hashes come from the headless REST API, so only the http
        # transport can produce them — the same condition nodes.py used to spell
        # out as ``mcp.ghidra.transport == "http"``.
        http = self._cfg.transport == "http"
        return StaticCapabilities(
            provides_tools=True,
            provides_evidence=False,
            provides_function_hashes=http,
            needs_sample_mirror=True,
            degrade_on_failure=False,
        )

    def prompt_lead(self) -> str:
        return GHIDRA_LEAD

    def prompt_fragment(self) -> str:
        """Ghidra's lead, its own guidance (its discipline as it has always read), its workflow."""
        workflow = self.workflow_fragment()
        text = self.prompt_lead() + self.guidance_fragment()
        return text + "\n\n" + workflow if workflow.strip() else text

    def workflow_fragment(self) -> str:
        """The workflow Ghidra's block declares (``static.ghidra.prompt_fragment``)."""
        return str(getattr(self._cfg, "prompt_fragment", "") or "")

    def guidance_fragment(self) -> str:
        return GHIDRA_GUIDANCE

    @property
    def label(self) -> str:
        return "Ghidra"

    def open(self, job: StaticJobContext) -> None:
        """Attach to Ghidra for ``job``. Idempotent, per the base contract.

        The expected repeat call is for the *same* sample: a multi-chunk
        static run calls ``analyze_isr`` once per chunk on one cached agent,
        ``ServiceContainer`` hands back the same memoized provider instance
        each time, and the analyst re-derives an equal ``StaticJobContext``
        per chunk. Before this guard, every one of those calls rebuilt the
        transport from scratch — a fresh ``GhidraHTTPClient.initialize()``
        round trip (up to the 120s hard cap) on http, a fresh subprocess on
        stdio — and the previous client was only dereferenced, never closed:
        N-1 leaked clients or subprocesses per N-chunk sample, for the life
        of the worker. A call whose job compares equal to the one already
        attached now returns immediately instead.

        A call with a job that differs from the one already attached — which
        the current per-job container lifecycle never produces, since each
        job gets its own provider instance — closes the stale toolkit first
        and attaches fresh for the new job, rather than leaking the old one
        silently or refusing the new attach outright.
        """
        if job.on_server_rest is not None:
            self._rest_hook = job.on_server_rest
        if self._toolkit is not None:
            if job == self._job:
                return
            logger.warning(
                "Ghidra provider re-opened for a job different from the one "
                "already attached; closing the stale toolkit before re-attaching."
            )
            self._close_toolkit()
            # Another job's rests are not this one's.
            with self._guard_lock:
                self._guard = None
        self._job = job
        if not self._cfg.enabled:
            logger.info("Ghidra MCP is disabled in config.")
            return

        output_guardrail = job.output_guardrail
        max_chars = job.max_output_chars

        # ------------------------------------------------------------------
        # HTTP transport (headless Docker server)
        # ------------------------------------------------------------------
        if self._cfg.transport == "http":
            from maljan.providers.static.ghidra.http_client import GhidraHTTPClient

            settings = get_settings_or_none()
            client = GhidraHTTPClient(
                base_url=self._cfg.url,
                auth_token=self._cfg.auth_token.get_secret_value(),
                output_guardrail=output_guardrail,
                max_output_chars=max_chars,
                truncation_ledger=job.truncation_ledger,
                context_budget=job.context_budget,
                long_running_tools=long_running_tools(getattr(self._cfg, "sample_open", None)),
                explicit_call_timeout=explicit_call_timeout(settings),
                categories=categories_of(getattr(self._cfg, "tool_facts", None)),
                # The breaker and call cap every other tool server's calls go
                # through, the one this provider's walks are held by too; none
                # where no settings can be read (a probe, a test).
                guard=self.server_guard(),
            )

            self._run_async(client.initialize())
            self._toolkit = client
            self._all_tools = self._with_aggregate_notes(
                self._pin_load_program_path(self._reading_errors(client.get_tools()))
            )
            self.tools = list(self._all_tools)
            logger.info("Initialized Ghidra HTTP tools: %d.", len(self.tools))
            return

        # ------------------------------------------------------------------
        # stdio transport (legacy local subprocess)
        # ------------------------------------------------------------------
        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.agents.subprocess_env import child_env
        from maljan.core.paths import resolve_mcp_args

        command = self._cfg.command
        args = self._cfg.args

        env = child_env(self._cfg.env, server=self.id)
        env.setdefault("PYTHONIOENCODING", "utf-8")

        args = resolve_mcp_args(args)
        server_params = StdioServerParameters(command=command, args=args, env=env)

        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=output_guardrail,
            max_output_chars=max_chars,
            truncation_ledger=job.truncation_ledger,
            context_budget=job.context_budget,
            categories=categories_of(getattr(self._cfg, "tool_facts", None)),
        )

        self._run_async(toolkit.initialize())
        self._toolkit = toolkit  # type: ignore[assignment]
        self._all_tools = self._with_aggregate_notes(
            self._pin_load_program_path(self._reading_errors(toolkit.get_tools()))
        )
        self.tools = list(self._all_tools)
        logger.info("Initialized Ghidra MCP tools: %d.", len(self.tools))

    def server_guard(self) -> Any:
        """This job's breaker and call cap for Ghidra, or ``None`` where no settings can be read.

        One per provider, and the provider is the job's: the agents' calls
        (its HTTP client) and its own walks over the REST API (the triage
        pass, the function-hash read) are held by the same breaker, so a rest
        either side earned holds the other. The cap counts each apart: the
        agents' calls take their loop's slots, and the walks, made in a worker
        thread, take the guard's own thread slots (``ServerGuard.held``).
        """
        with self._guard_lock:
            if self._guard is None:
                settings = get_settings_or_none()
                if settings is not None:
                    self._guard = guard_from_settings(
                        self.id,
                        settings,
                        on_open=self._rested,
                        sample_open=getattr(self._cfg, "sample_open", None),
                        block=self._cfg,
                    )
            return self._guard

    def _rested(self, record: dict[str, Any]) -> None:
        """One rest the guard gave: to the job's hook once an attach named one, else kept here."""
        hook = self._rest_hook
        if hook is not None:
            hook(record)
            return
        from maljan.pipeline.events import emit_tool_server_rested

        self.rests.append(dict(record))
        emit_tool_server_rested(self.event_sink, record)

    def _with_aggregate_notes(self, tools: list[Any]) -> list[Any]:
        """``tools`` with the note each declared aggregate tool carries (``aggregate_of``).

        Ghidra's tools are offered under their own names, so each note names
        the aggregated tools this attach offers as they are named
        (``core.undeclared_tools.with_aggregate_notes``).
        """
        from maljan.core.undeclared_tools import aggregates_of, with_aggregate_notes

        aggregates = aggregates_of(getattr(self._cfg, "tool_facts", None))
        if not aggregates:
            return tools
        offered = {str(t.name): str(t.name) for t in tools}
        return with_aggregate_notes(tools, aggregates, offered)

    def _reading_errors(self, tools: Any) -> list[Any]:
        """The tools, each answer held against this block's declared error patterns.

        By the one function every server's answers are read by
        (``providers.declared_errors``); a block that declares none keeps its
        tools as they are.
        """
        from maljan.providers.declared_errors import with_declared_errors

        patterns = tuple(getattr(self._cfg, "error_patterns", None) or ())
        return with_declared_errors(list(tools), patterns, self._held_path)

    def _run_async(self, coro: Any) -> None:
        """Run an MCP-client init coroutine on the *shared agent loop*.

        The Ghidra HTTP client builds its long-lived ``httpx.AsyncClient`` inside
        ``initialize()`` (via ``_get_http``); httpx binds that client's
        connection pool — and the asyncio primitives behind it — to whichever
        loop first creates it. The ReAct tool calls later run on the
        process-wide agent loop (``base_agent._get_agent_loop``), so the old
        implementation here — which ran init on a throwaway ``new_event_loop()``
        (LangGraph runs sync nodes in a worker thread with no running loop) —
        bound the client to a *different* loop than the ReAct. The first chunk's
        tool call then raised ``<asyncio.locks.Event ...> is bound to a different
        event loop`` and that chunk was lost on every run (and, under the CLI's
        ``asyncio.run``, the whole static analyst). Submitting init to the same
        shared loop the ReAct uses keeps client creation and use on one loop.

        Only ever called from a synchronous setup path (``analyze`` /
        ``analyze_isr``) on the main/worker thread — never from within the agent
        loop itself — so blocking on the result cannot deadlock.
        """
        from maljan.agents.base_agent import run_coro_blocking

        run_coro_blocking(coro, hard_timeout=120.0, label="ghidra-mcp-init")

    def get_tools(self) -> list[BaseTool]:
        return self._all_tools

    def pin_sample(self, path: str | None) -> None:
        """The container path ``load_program`` is held to, without re-attaching.

        A generic agent given Ghidra's tools opens this provider when it is
        resolved, with no sample path yet, so the ``load_program`` wrapper had
        nothing to hold a model's ``file`` to. The analyst node pins the path
        the agent's tools read before its loop starts, and from then on a host
        path or an invented one a model sends is replaced with it. ``None``
        clears it, for an agent cached into a run with no mirror.
        """
        self._pinned_path = path or None

    def _held_path(self) -> str | None:
        """The path ``load_program`` is held to: the pin, else the job's mirror."""
        pinned = getattr(self, "_pinned_path", None) or getattr(
            getattr(self, "_job", None), "mirror_sample_path", None
        )
        return pinned if isinstance(pinned, str) and pinned else None

    def sample_failure(self, path: str | None = None) -> SampleNotOpened | None:
        """The failure this provider met opening ``path`` (the held path by default).

        A fresh exception each time, because each one ends a different loop
        and says whose. ``None`` when that path opened, or was never tried.
        """
        wanted = path or self._held_path()
        said = getattr(self, "_sample_failures", {}).get(wanted) if wanted else None
        return SampleNotOpened(said, provider="ghidra") if said else None

    def note_sample_failure(self, path: str, failure: SampleNotOpened) -> None:
        """Remember that ``path`` did not open, and the sentence that says so."""
        if path:
            if not hasattr(self, "_sample_failures"):
                self._sample_failures = {}
            self._sample_failures[path] = str(failure)

    def _pin_load_program_path(self, tools: list[Any]) -> list[Any]:
        """Wrap ``load_program`` so a hallucinated ``file`` arg is overridden.

        Ghidra-path fix (2026-07-12, job 60df48cb): on a fresh sample whose
        chunk lacked ``analysis_file_path`` the LLM invented
        ``/home/user/data/bin.<sha>`` and load_program failed with
        "File not found" even though the mirror to ``/data/samples/`` had
        succeeded. The wrapper deterministically substitutes the known
        container path (``self._job.mirror_sample_path``, set per-sample by
        nodes.py) whenever the model supplies a different one. Fail-safe:
        any wrapping error keeps the original tool.
        """
        from maljan.providers.sample_open import (
            is_shared_address,
            pin_program_argument,
            wrap_open_tool,
        )

        # First the general opener, with the tools the Ghidra block declares;
        # then, on a Ghidra other jobs share, every call held to the job's own
        # programs and sample (Ghidra's current program is the server's); then
        # the pin around load_program, outermost, so a model's invented path is
        # replaced with the held one before anything is checked or sent.
        cfg = getattr(self, "_cfg", None)
        key = server_note_key(cfg, str(getattr(self, "note_instance", "") or ""))
        spec = getattr(cfg, "sample_open", None)
        notes = getattr(self, "sample_notes", None)
        shared = is_shared_address(cfg)
        tools = wrap_open_tool(
            tools,
            tools,
            server=key,
            spec=spec,
            notes=notes,
            held_path=self._held_path,
            shared=shared,
        )
        withheld: dict[str, str] = {}
        tools = pin_program_argument(
            tools,
            server=key,
            spec=spec,
            notes=notes,
            shared=shared,
            held_path=self._held_path,
            withheld=withheld,
        )
        self.withheld_tools = withheld
        out: list[Any] = []
        # The tool that loads the sample is the one the block declares; the
        # name every Ghidra build has used is the fallback for no declaration.
        from maljan.providers.sample_open import declared

        load_name = str(getattr(spec, "open_tool", "")) if declared(spec) else UNDECLARED_LOAD_TOOL
        for tool in tools:
            if getattr(tool, "name", "") == load_name:
                try:
                    tool = self._wrap_load_program(tool)
                except Exception as e:  # noqa: BLE001
                    logger.warning("load_program pin skipped: %s", e)
            out.append(tool)
        return out

    def withheld_reasons(self) -> list[str]:
        """Why each tool Ghidra offers is withheld for this job, for the run's degraded record."""
        withheld = dict(getattr(self, "withheld_tools", None) or {})
        return [withheld[name] for name in sorted(withheld)]

    def _wrap_load_program(self, tool: Any) -> Any:
        """Rebuild the load_program StructuredTool with a path-pinning coroutine.

        A fresh tool is built rather than mutating ``tool.coroutine`` in
        place — the original lives in the client's own tool list, and
        in-place mutation would leak the wrapper across samples.

        A load of the held path that answers with an error raises
        :class:`SampleNotOpened`: the evidence recorder files the call as
        failed, with the arguments actually sent and the server's words, and
        hands the exception on, which ends the agent's loop. Ghidra's own
        error is remembered, so a held path that already failed raises without
        a call; a request that got no answer from Ghidra is not. With no held
        path the model's own call runs as it was made.
        """
        from langchain_core.tools import StructuredTool

        inner = getattr(tool, "coroutine", None)
        if inner is None:
            return tool  # sync/stdio tool variant — leave untouched

        provider = self
        from maljan.providers.sample_open import declared

        spec = getattr(getattr(self, "_cfg", None), "sample_open", None)
        path_arg = str(getattr(spec, "path_argument", "")) if declared(spec) else "file"

        async def pinned_load_program(**kwargs: Any) -> str:
            pinned = provider._held_path()
            if pinned is None:
                return str(await inner(**kwargs))
            known = provider.sample_failure(pinned)
            if known is not None:
                raise known
            if kwargs.get(path_arg) != pinned:
                logger.warning(
                    "load_program: overriding model-supplied path %r with known container path %r.",
                    kwargs.get(path_arg),
                    pinned,
                )
                kwargs[path_arg] = pinned
            answer = str(await inner(**kwargs))
            refused = not_made_current(answer)
            if refused is not None:
                # Not remembered: it says nothing about the file.
                refused.sent_args = dict(kwargs)
                logger.error("%s", refused)
                raise refused
            # The job's own sample did not open. Every Ghidra call after this
            # one would answer "No program loaded", or about whichever program
            # is still current, for as long as the model kept asking.
            said = load_failure(answer)
            if said is None:
                return answer
            words, from_ghidra = said
            if from_ghidra:
                failure = sample_not_opened(words)
                provider.note_sample_failure(pinned, failure)
            else:
                # No answer from Ghidra: said as such, and not remembered, so
                # a Ghidra that comes back is asked again by the next loop.
                address = ghidra_address(str(getattr(getattr(provider, "_cfg", None), "url", "")))
                failure = ghidra_not_answering(address, words)
            # What was sent, which is the held path and not the model's.
            failure.sent_args = dict(kwargs)
            logger.error("%s", failure)
            raise failure

        return StructuredTool.from_function(
            func=None,
            coroutine=pinned_load_program,
            name=tool.name,
            description=tool.description,
            args_schema=tool.args_schema,
        )

    def _over_http(self) -> bool:
        """Whether Ghidra is switched on and reached over its REST API.

        The open before the loop, the call graph and the scan are REST calls,
        which Ghidra over stdio does not serve.
        """
        return self._cfg.transport == "http" and bool(getattr(self._cfg, "enabled", True))

    def preprocessing(self) -> Any:
        """The preprocessing settings this provider was built with."""
        return self._pre

    def _rest_client(self) -> Any:
        """A client for Ghidra's REST API, with the token, each request waiting one call's budget.

        What one call to Ghidra may take (``call_budget``:
        ``core.mcp.breaker.call_timeout_seconds``, else Ghidra's block's own
        ``call_timeout_seconds``); zero, as long as Ghidra takes.
        """
        import httpx

        token = self._cfg.auth_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        budget = self.call_budget(get_settings_or_none())
        return httpx.Client(timeout=budget if budget > 0 else None, headers=headers)

    def open_sample(self, path: str | None = None) -> bool:
        """Open the job's sample on Ghidra before the agent's loop; whether it opened.

        The load is the precondition of the agent's loop. A load that opens
        nothing — Ghidra answers HTTP 200 with ``{"error": "File not found: ..."}``
        when the path is not one its container can see — raises
        :class:`SampleNotOpened` with the server's words before any model turn is
        spent, and is remembered, so no later loop of the job calls Ghidra for
        that path. A load Ghidra gave no answer to — a connection that failed
        twice, a 5xx, a refused token — raises too, with a sentence naming
        Ghidra's address and token rather than the samples path, and is not
        remembered. Every request is one call held by the job's guard for
        Ghidra (``server_guard``), the one the agents' calls and this
        provider's walks go through. A load the resting server is not sent
        waits for the guard to admit a call again (``wait_admissible``: the
        rest's cooldown, then the one trial let through) and is made then, so
        opens made together after a rest all open once the trial answers; a
        trial that fails stops the open as a Ghidra that did not answer, with
        the guard's sentence. A step after a load Ghidra answered that the
        guard did not send stops the loop with the guard's sentence; the
        program the load opened is noted for the job's teardown to close. A
        load that opens the program makes it the current one, and Ghidra's
        auto-analysis runs on it, waited for without a limit: an import holds
        no call or code reference for the agent's callers, callees and
        cross-references to read. The open goes through the general opener
        (``providers.sample_open``) with the tools the Ghidra block declares,
        so a path the job already opened (here, in the triage pass or by a
        model) is a switch answered from the job's note.

        Only over ``http``: anything else returns ``False`` and calls nothing.
        """
        from maljan.providers.server_guard import ServerResting
        from maljan.providers.static.ghidra.program import program_name_from_load

        target = path or self._held_path()
        if not target or not self._over_http():
            return False
        known = _known_failure(self, target)
        if known is not None:
            raise known
        base = self._cfg.url.rstrip("/")
        address = ghidra_address(self._cfg.url)
        key = server_note_key(self._cfg, str(getattr(self, "note_instance", "") or ""))
        guard = self.server_guard()
        job = cancellation.current()
        while True:
            # The loads Ghidra answered in this attempt (a step after one that
            # the guard does not send leaves a program open on Ghidra), and its
            # requests Ghidra did not answer.
            loaded: list[str] = []
            unanswered: list[str] = []
            try:
                answer = self._open_once(target, base, address, key, guard, loaded, unanswered)
                break
            except ServerResting as exc:
                if loaded:
                    failure = ghidra_resting(str(exc), self._own_opened(key, loaded[-1]))
                    logger.error("%s", failure)
                    raise failure from exc
                admissible = (
                    guard is not None
                    and not unanswered
                    and _wait_admissible(guard, exc.rests_begun, job)
                )
                if job is not None:
                    # A job cancelled meanwhile sends no load: its teardown may
                    # already have closed its programs.
                    job.check("before Ghidra's load of the job's sample, after its rest")
                if not admissible:
                    # This open's own request was not answered, or a rest began
                    # while it waited: the trial was not answered.
                    failure = ghidra_not_answering(address, str(exc))
                    logger.error("%s", failure)
                    raise failure from exc
        refused = not_made_current(answer)
        if refused is not None:
            logger.error("%s", refused)
            raise refused
        if not program_name_from_load(answer):
            # A failed load answers **200**, so raise_for_status sees nothing
            # wrong. Carrying on would hand the model a Ghidra with no program,
            # or with whichever program is still current: every call after it
            # answers about nothing, or about a different binary. This is
            # Ghidra's own answer about the file, so it is remembered.
            said = load_failure(answer)
            failure = sample_not_opened(said[0] if said else answer)
            _remember_failure(self, target, failure)
            logger.error("%s", failure)
            raise failure
        return True

    def _open_once(
        self,
        target: str,
        base: str,
        address: str,
        key: str,
        guard: Any,
        loaded: list[str],
        unanswered: list[str],
    ) -> str:
        """One attempt at :meth:`open_sample`'s open, each request held by ``guard``.

        Each load Ghidra answered is appended to ``loaded``, and each request
        it did not answer, as the guard reads that, to ``unanswered``. A
        request the guard does not send raises :class:`ServerResting`.
        """
        from maljan.providers.server_guard import guarded_http

        with self._rest_client() as raw:
            http = guarded_http(_Unanswered(raw, unanswered), guard, base)

            def load(tool: str, arguments: dict[str, Any]) -> str:
                text = str(_load(http, base, tool, arguments, address, logger).text)
                loaded.append(text)
                return text

            return open_ghidra_sample(
                http,
                base,
                target,
                getattr(self._cfg, "sample_open", None),
                sample_notes_of(self),
                key=key,
                open_call=load,
            )

    def _own_opened(self, key: str, load_answer: str) -> str | None:
        """Note the program a load opened as the job's, for its teardown to close; its name.

        ``None`` when the load named no program or the provider holds no note
        of the job's to keep it in.
        """
        from maljan.providers.sample_open import SampleNotes
        from maljan.providers.static.ghidra.program import program_name_from_load

        name = program_name_from_load(load_answer)
        notes = getattr(self, "sample_notes", None)
        if not name or not isinstance(notes, SampleNotes):
            return None
        notes.own(key, name)
        return name

    def call_graph(self, path: str) -> CallGraph | None:
        """The job's program's whole call graph, read from Ghidra's REST API.

        The program the job opened at ``path`` (its note), named in the
        request by the argument Ghidra's block declares, never Ghidra's
        current program, which is the server's and not the job's. ``None``
        when Ghidra is not reached over ``http`` or the job opened no program
        at ``path``; a request that fails raises, and the pre-pass reads that
        as no hint.

        The whole graph, in one answer: the server's ``limit`` counts distinct
        call edges, defaults to 1000 when absent, and ``0`` means none; the
        endpoint has no pages. The server answers ``edges`` (as any format it
        does not name, ``json`` among them) with one ``CALLER -> CALLEE`` line
        per call, the text ``call_graph_from_text`` reads.

        The request is one call held by the job's guard for Ghidra; one the
        resting server is not sent is ``None`` too, with the guard's sentence
        in a warning saying the pre-pass is skipped.
        """
        from maljan.providers.sample_open import SampleOpener, is_shared_address, program_argument
        from maljan.providers.server_guard import ServerResting, guarded_http

        if not self._over_http():
            return None
        params = dict(CALL_GRAPH_PARAMS)
        spec = getattr(self._cfg, "sample_open", None)
        argument = program_argument(spec)
        key = server_note_key(self._cfg, str(getattr(self, "note_instance", "") or ""))
        program = SampleOpener(key, spec, sample_notes_of(self)).name_of(path) if argument else None
        if argument and program:
            params[argument] = program
        elif is_shared_address(self._cfg):
            # Ghidra's current program is the server's: the graph it would
            # answer may be another job's sample. No graph is said, not wrong.
            logger.warning(
                "Ghidra call graph: %s; no graph rather than whichever program is current on "
                "%s, which other jobs share.",
                f"{path} is not a program this job opened"
                if argument
                else "the Ghidra block declares no program argument (sample_open)",
                key,
            )
            return None
        base = self._cfg.url.rstrip("/")
        try:
            with self._rest_client() as raw:
                http = guarded_http(raw, self.server_guard(), base)
                resp = http.get(f"{base}/get_full_call_graph", params=params)
                resp.raise_for_status()
        except ServerResting as exc:
            logger.warning(
                "Ghidra call graph: %s; the request was not sent, so the sink-reachability "
                "pre-pass is skipped.",
                exc,
            )
            return None
        return call_graph_from_text(resp.text)

    def anti_analysis_scan(
        self, job: StaticJobContext, *, notes: Any = None, call_budget: float = 0.0
    ) -> GhidraPasses:
        """Ghidra's anti-analysis scan of this job, or the sentence saying why there is none.

        Ghidra has to be switched on, reached over its REST API (``http``:
        Ghidra over stdio serves no endpoint the pack can call), and holding a
        copy of this job's sample where it reads (``job.mirror_sample_path``,
        the mirror the worker made for it).
        """
        from maljan.providers.static.ghidra.passes import (
            GHIDRA_HAS_NO_COPY,
            GHIDRA_NOT_OVER_HTTP,
            GHIDRA_SWITCHED_OFF,
            GhidraPasses,
        )

        key = server_note_key(self._cfg)
        path = job.mirror_sample_path
        if not bool(getattr(self._cfg, "enabled", True)):
            reason = GHIDRA_SWITCHED_OFF
        elif self._cfg.transport != "http":
            reason = GHIDRA_NOT_OVER_HTTP.format(transport=self._cfg.transport)
        elif not path:
            reason = GHIDRA_HAS_NO_COPY
        else:
            if job.on_server_rest is not None:
                self._rest_hook = job.on_server_rest
            return GhidraPasses(
                guard=self.server_guard(),
                base_url=str(self._cfg.url),
                token=self._cfg.auth_token.get_secret_value(),
                sample_path=str(path),
                call_timeout=call_budget if call_budget > 0 else None,
                sample_open=getattr(self._cfg, "sample_open", None),
                sample_notes=notes,
                note_key=key,
                provider=self.id,
            )
        return GhidraPasses(unavailable=reason, note_key=key, provider=self.id)

    def mirror_spec(self) -> MirrorSpec:
        """Where this server's block declares the sample goes and is seen."""
        return MirrorSpec.of(self._cfg)

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        """Ghidra's per-function hashes of the job's mirror, over its REST API."""
        from maljan.providers.sample_open import is_shared_address
        from maljan.providers.static.ghidra.function_hashes import fetch_bulk_function_hashes

        if not self.capabilities.provides_function_hashes or not job.mirror_sample_path:
            return []
        if job.on_server_rest is not None:
            self._rest_hook = job.on_server_rest
        return fetch_bulk_function_hashes(
            base_url=self._cfg.url,
            auth_token=self._cfg.auth_token.get_secret_value(),
            file_path=job.mirror_sample_path,
            min_instructions=self._pre.function_hash_min_instructions,
            sample_open=getattr(self._cfg, "sample_open", None),
            sample_notes=getattr(self, "sample_notes", None),
            note_key=server_note_key(self._cfg, str(getattr(self, "note_instance", "") or "")),
            shared=is_shared_address(self._cfg),
            # The walk is one call's worth of the job's guard budget for this
            # server, so a server answering pages forever cannot hold the job.
            walk_budget=self.call_budget(get_settings_or_none()),
            # And the deadline of the stage or job it runs in, where there is one.
            deadline=job.deadline,
            # Each page held by the guard the agents' calls go through.
            guard=self.server_guard(),
        )

    async def probe(self) -> ProviderProbe:
        """The tool schema, with the configured token.

        ``/check_connection`` answers without a token, so it proved the address
        and nothing else; ``/mcp/schema`` is the first authenticated call a job
        makes, so a token the server rejects fails here as it would there.
        """
        import time

        import httpx

        t0 = time.perf_counter()
        token = self._cfg.auth_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        url = f"{self._cfg.url.rstrip('/')}/mcp/schema"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        latency = int((time.perf_counter() - t0) * 1000)
        if response.status_code >= 400:
            return ProviderProbe(False, f"HTTP {response.status_code}", latency)
        # The tool names the model will call, read the way the client reads
        # the schema, for the editor's tick boxes.
        from maljan.providers.static.ghidra.http_client import schema_tool_names

        try:
            names = schema_tool_names(response.json())
        except ValueError:
            return ProviderProbe(
                False, f"HTTP {response.status_code}; the schema was not JSON", latency
            )
        return ProviderProbe(True, f"{len(names)} tools", latency, names)

    async def readiness(self) -> ProviderProbe:
        """Whether a job on Ghidra can start: its schema answering, and no analysis.

        Over http the schema endpoint with the configured token is the check —
        the first call a job makes. Over stdio the job starts the server
        itself, so what can be checked before then is that there is a command
        and that it names an executable. The shipped transport is stdio with no
        command, which an operator who switched Ghidra on and left the
        transport alone meets as a run that fails when the agent starts; it is
        said here instead. Switched off is ``switched_off``'s answer.
        """
        if self._cfg.transport == "http":
            return await self.probe()
        command = str(self._cfg.command or "").strip()
        if not command:
            return ProviderProbe(
                ok=False,
                detail=(
                    f"transport is {self._cfg.transport!r} with no command; set "
                    "core.static.ghidra.transport to 'http' and its url for the "
                    "Ghidra container"
                ),
            )
        import os
        import shutil

        # Named by its last segment only: the refusal reaches any user, and a
        # command is a path on this host.
        name = os.path.basename(command)
        found = shutil.which(command)
        if found is None:
            return ProviderProbe(
                ok=False,
                detail=f"stdio command {name!r} is not an executable this host finds",
            )
        return ProviderProbe(ok=True, detail=f"stdio: {name!r} is started with the job")

    def switched_off(self) -> bool:
        """``core.static.ghidra.enabled`` is false: the provider attaches nothing."""
        return not self._cfg.enabled

    def address(self) -> str:
        """The server's scheme and host over http; ``""`` over stdio, which is reached nowhere."""
        if self._cfg.transport == "http":
            from maljan.core.model_assignments import endpoint_label

            return endpoint_label(str(self._cfg.url or ""))
        return ""

    def _close_toolkit(self) -> None:
        """Release whatever client or subprocess is currently attached, if any.

        The one release path, shared by ``close()`` (job-end teardown) and
        ``open()`` (mid-life re-attach for a job that differs from the one
        already open) — so there is never a point where two toolkits are
        live at once, and never a point where releasing one is written twice.
        Teardown that can throw is teardown nobody calls, so every failure
        here is a warning.
        """
        from maljan.agents.base_agent import run_coro_blocking

        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            run_coro_blocking(closer(), hard_timeout=20.0, label="ghidra-close")
        except Exception as exc:  # noqa: BLE001 - teardown never propagates
            logger.warning("Ghidra provider teardown failed (non-fatal): %s", exc)

    def _close_job_programs(self) -> None:
        """Close the programs this job opened on a Ghidra other jobs share, where declared.

        Through the close tool the block's ``sample_open`` names; with none
        declared, nothing is called. Never raises.

        Not held by the job's guard for Ghidra: a close the resting server was
        not sent would leave the job's programs open on a Ghidra other jobs
        share, so the close is always sent, and a Ghidra that does not answer
        it is a warning.
        """
        from maljan.providers.sample_open import close_job_programs, is_shared_address
        from maljan.providers.static.ghidra.program import rest_tool_call

        spec = getattr(self._cfg, "sample_open", None)
        if not is_shared_address(self._cfg) or not getattr(spec, "close_tool", ""):
            return
        if not self._over_http():
            return
        try:
            with self._rest_client() as http:
                close_job_programs(
                    server_note_key(self._cfg, str(getattr(self, "note_instance", "") or "")),
                    spec,
                    sample_notes_of(self),
                    rest_tool_call(http, self._cfg.url.rstrip("/")),
                )
        except Exception as exc:  # noqa: BLE001 - teardown never propagates
            logger.warning("Ghidra program close failed (non-fatal): %s", exc)

    def close(self) -> None:
        self._close_job_programs()
        self._close_toolkit()


def get_settings_or_none() -> Any:
    """The deployment's settings, or ``None`` where none can be read (a probe, a test)."""
    try:
        from maljan.core.config import get_settings

        return get_settings()
    except Exception:  # noqa: BLE001 - no settings means no operator budget
        return None
