"""Ghidra MCP static analysis — moved out of the static analyst.

The load_program path pin and the http/stdio attach path are the static
analyst's own code (``StaticAnalyst``, pre-2026-09), transplanted here
unchanged. The analyst's ``_initialize_mcp_client`` now calls this provider
instead of driving its own copy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langchain_core.tools import BaseTool

from maljan.core import builtin_declarations
from maljan.core.exceptions import SampleNotOpened
from maljan.core.logger import logger
from maljan.core.settings_overrides import redact_url
from maljan.providers.base import (
    MirrorSpec,
    ProviderProbe,
    StaticCapabilities,
    StaticJobContext,
    StaticProvider,
)
from maljan.providers.registry import register_static_provider
from maljan.providers.sample_open import long_running_tools, server_note_key
from maljan.providers.server_guard import explicit_call_timeout
from maljan.tools.errors import SERVER_WORDS_LIMIT

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig, MemoryConfig, PreprocessingConfig, Settings


# Ghidra's prompt is its declaration's text (``core.builtin_declarations``):
# the guidance about claims, which goes with every call on a Ghidra run, the
# workflow, which goes only where Ghidra's tools do, and the whole fragment.
GHIDRA_GUIDANCE = builtin_declarations.GHIDRA_GUIDANCE
GHIDRA_WORKFLOW = builtin_declarations.GHIDRA_WORKFLOW
GHIDRA_PROMPT_FRAGMENT = builtin_declarations.GHIDRA_PROMPT_FRAGMENT


# What an agent on Ghidra is stopped with when Ghidra answered that it could
# not load the job's sample. The server's own words go in the middle; the check
# names the two things that decide whether the container can see the file.
SAMPLE_NOT_OPENED: str = (
    "Ghidra could not open the job's sample: {words}; "
    "check GHIDRA_CONTAINER_SAMPLES_PATH / the container mount"
)

# And when the load got no answer from Ghidra at all: the connection failed,
# the server failed, or it refused the token. The samples path is not the
# remedy for any of those, so it is not named.
GHIDRA_NOT_ANSWERING: str = (
    "Ghidra at {address} did not answer the load of the job's sample ({what}); "
    "check the Ghidra container is running at that address and "
    "core.static.ghidra.auth_token matches its GHIDRA_MCP_AUTH_TOKEN"
)

# The client markers that mean the request itself failed, as opposed to
# Ghidra answering with an error of its own.
TRANSPORT_MARKERS = frozenset(
    {"http_status", "request_failed", "exception", "mcp_session_inactive"}
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


def not_made_current(answer: str) -> SampleNotOpened | None:
    """The stop for a select the opener says was refused right after a fresh load, or ``None``.

    Read from the opener's own marker (``sample_open.SELECT_REFUSED_AFTER_OPEN``)
    with its one reader of answers; it names the select's refusal, not the
    samples mount, and the caller does not remember it.
    """
    from maljan.providers.sample_open import SELECT_REFUSED_AFTER_OPEN, answer_object

    payload = answer_object(answer)
    if payload is None or payload.get("tool_error") != SELECT_REFUSED_AFTER_OPEN:
        return None
    words = _one_line(str(payload.get("detail") or ""))
    return SampleNotOpened(GHIDRA_DID_NOT_MAKE_IT_CURRENT.format(words=words), provider="ghidra")


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

    from maljan.analysis.ghidra_program import program_name_from_load
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


def _ghidra_over_http(cfg: Settings, provider_id: str) -> bool:
    """Whether this agent's provider is a switched-on Ghidra reached over its REST API."""
    ghidra = cfg.static.ghidra
    return (
        provider_id == "ghidra"
        and ghidra.transport == "http"
        and bool(getattr(ghidra, "enabled", True))
    )


def prepare_sample(
    cfg: Settings,
    provider_id: str,
    file_path: str,
    log: Any = None,
    provider: Any = None,
) -> str:
    """Open the job's sample on Ghidra, then the sink pre-pass: a priority hint, or ``""``.

    The load is the precondition of the agent's loop. A load that opens
    nothing — Ghidra answers HTTP 200 with ``{"error": "File not found: ..."}``
    when the path is not one its container can see — raises
    :class:`SampleNotOpened` with the server's words before any model turn is
    spent, and ``provider`` (the agent's Ghidra provider, when the caller has
    it) remembers it, so no later loop of the job calls Ghidra for that path.
    A load Ghidra gave no answer to — a connection that failed twice, a 5xx,
    a refused token — raises too, with a sentence naming Ghidra's address and
    token rather than the samples path, and is not remembered.
    A load that opens the program makes it the current one, and Ghidra's
    auto-analysis runs on it, waited for without a limit: an import holds no
    call or code reference for the agent's callers, callees and
    cross-references to read. The open goes through the general opener
    (``providers.sample_open``) with the tools the Ghidra block declares, so a
    path the job already opened (here, in the triage pass or by a model) is a
    switch answered from the job's note.

    Then, with ``preprocessing.use_sink_reachability`` on, the pre-pass:
    the whole call graph, and the functions that reach
    sensitive sinks rendered as a hint, so the loop decompiles the malicious
    core first. The pre-pass is fail-safe: any error in it, or a binary with
    no named sink reachable, returns ``""``.

    Only for an agent whose own static provider is Ghidra over ``http``: the
    calls are Ghidra's REST API, which no other provider speaks and Ghidra
    over stdio does not serve. Anything else returns ``""`` and calls nothing.

    Each request waits what one tool call of this deployment may take
    (``core.mcp.breaker.call_timeout_seconds``, else the longest tool budget
    configured), and with neither set, as long as Ghidra takes.
    """
    import logging

    logger_ = log if log is not None else logging.getLogger(__name__)
    if not _ghidra_over_http(cfg, provider_id):
        return ""
    known = _known_failure(provider, file_path)
    if known is not None:
        raise known

    import httpx

    from maljan.analysis.ghidra_program import program_name_from_load
    from maljan.providers.server_guard import deployment_call_budget

    ghidra = cfg.static.ghidra
    base = ghidra.url.rstrip("/")
    token = ghidra.auth_token.get_secret_value()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    call_budget = deployment_call_budget(cfg)
    with httpx.Client(timeout=call_budget if call_budget > 0 else None, headers=headers) as http:
        address = ghidra_address(ghidra.url)
        answer = open_ghidra_sample(
            http,
            base,
            file_path,
            getattr(ghidra, "sample_open", None),
            sample_notes_of(provider),
            key=server_note_key(ghidra, str(getattr(provider, "note_instance", "") or "")),
            open_call=lambda tool, arguments: (
                _load(http, base, tool, arguments, address, logger_).text
            ),
        )
        refused = not_made_current(answer)
        if refused is not None:
            logger_.error("%s", refused)
            raise refused
        if not program_name_from_load(answer):
            # A failed load answers **200**, so raise_for_status sees nothing
            # wrong. Carrying on would hand the model a Ghidra with no program,
            # or with whichever program is still current: every call after it
            # answers about nothing, or about a different binary. This is
            # Ghidra's own answer about the file, so it is remembered.
            said = load_failure(answer)
            failure = sample_not_opened(said[0] if said else answer)
            _remember_failure(provider, file_path, failure)
            logger_.error("%s", failure)
            raise failure
        if not getattr(cfg.preprocessing, "use_sink_reachability", False):
            return ""
        return _sink_priority_hint(cfg, http, base, file_path, logger_)


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
    from maljan.analysis.ghidra_program import (
        SWITCH_PARAM,
        SWITCH_PATH,
        program_name_from_load,
        rest_tool_call,
    )
    from maljan.providers.sample_open import SampleOpener, declared

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
        rest_tool_call(http, base)(SWITCH_PATH.lstrip("/"), {SWITCH_PARAM: name})
    return str(loaded)


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


def _sink_priority_hint(cfg: Settings, http: Any, base: str, file_path: str, log: Any) -> str:
    """The sink-reachability pre-pass over the program just opened. Fail-safe: ``""``."""
    try:
        from maljan.analysis.sink_reachability import build_priority_hint

        resp = http.get(
            f"{base}/get_full_call_graph",
            params={"format": "json", "limit": 20000},
        )
        resp.raise_for_status()
        hint = build_priority_hint(
            resp.text, max_funcs=cfg.preprocessing.sink_reachability_max_funcs
        )
    except Exception as exc:  # fail-safe: never break analysis over a hint
        log.warning(
            "Sink-reachability pre-pass failed (%s: %s); continuing without hint.",
            type(exc).__name__,
            exc,
        )
        return ""
    if hint:
        log.info(
            "Sink-reachability pre-pass: priority-functions hint built (%d chars) for '%s'.",
            len(hint),
            file_path,
        )
    else:
        log.info(
            "Sink-reachability pre-pass: no named sink APIs reachable "
            "(stripped/static binary?) — no hint emitted."
        )
    return hint


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

    def __init__(
        self,
        cfg: MCPServerConfig,
        preprocessing: PreprocessingConfig,
        memory: MemoryConfig,
        container_samples_path: str = "/data/samples",
    ) -> None:
        self._cfg = cfg
        self._pre = preprocessing
        self._memory = memory
        self._container_samples_path = container_samples_path
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

    def prompt_fragment(self) -> str:
        return GHIDRA_PROMPT_FRAGMENT

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
        if self._toolkit is not None:
            if job == self._job:
                return
            logger.warning(
                "Ghidra provider re-opened for a job different from the one "
                "already attached; closing the stale toolkit before re-attaching."
            )
            self._close_toolkit()
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
            from maljan.agents.ghidra_http_client import GhidraHTTPClient

            client = GhidraHTTPClient(
                base_url=self._cfg.url,
                auth_token=self._cfg.auth_token.get_secret_value(),
                output_guardrail=output_guardrail,
                max_output_chars=max_chars,
                truncation_ledger=job.truncation_ledger,
                context_budget=job.context_budget,
                long_running_tools=long_running_tools(getattr(self._cfg, "sample_open", None)),
                explicit_call_timeout=explicit_call_timeout(get_settings_or_none()),
            )

            self._run_async(client.initialize())
            self._toolkit = client
            self._all_tools = self._pin_load_program_path(list(client.get_tools()))
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

        env = child_env(self._cfg.env)
        env.setdefault("PYTHONIOENCODING", "utf-8")

        args = resolve_mcp_args(args)
        server_params = StdioServerParameters(command=command, args=args, env=env)

        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=output_guardrail,
            max_output_chars=max_chars,
            truncation_ledger=job.truncation_ledger,
            context_budget=job.context_budget,
        )

        self._run_async(toolkit.initialize())
        self._toolkit = toolkit  # type: ignore[assignment]
        self._all_tools = self._pin_load_program_path(list(toolkit.get_tools()))
        self.tools = list(self._all_tools)
        logger.info("Initialized Ghidra MCP tools: %d.", len(self.tools))

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
        from maljan.providers.sample_open import wrap_open_tool

        # First the general opener, with the tools the Ghidra block declares,
        # then the pin around it.
        tools = wrap_open_tool(
            tools,
            tools,
            server=server_note_key(
                getattr(self, "_cfg", None), str(getattr(self, "note_instance", "") or "")
            ),
            spec=getattr(getattr(self, "_cfg", None), "sample_open", None),
            notes=getattr(self, "sample_notes", None),
            held_path=self._held_path,
        )
        out: list[Any] = []
        for tool in tools:
            if getattr(tool, "name", "") == "load_program":
                try:
                    tool = self._wrap_load_program(tool)
                except Exception as e:  # noqa: BLE001
                    logger.warning("load_program pin skipped: %s", e)
            out.append(tool)
        return out

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

        async def pinned_load_program(**kwargs: Any) -> str:
            pinned = provider._held_path()
            if pinned is None:
                return str(await inner(**kwargs))
            known = provider.sample_failure(pinned)
            if known is not None:
                raise known
            if kwargs.get("file") != pinned:
                logger.warning(
                    "load_program: overriding model-supplied path %r with known container path %r.",
                    kwargs.get("file"),
                    pinned,
                )
                kwargs["file"] = pinned
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

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=".work", container_prefix=self._container_samples_path)

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        """Two lines of delegation: the pre-pass itself already lives in analysis/."""
        from maljan.analysis.function_hash_attribution import fetch_bulk_function_hashes

        if not self.capabilities.provides_function_hashes or not job.mirror_sample_path:
            return []
        return fetch_bulk_function_hashes(
            base_url=self._cfg.url,
            auth_token=self._cfg.auth_token.get_secret_value(),
            file_path=job.mirror_sample_path,
            min_instructions=self._pre.function_hash_min_instructions,
            sample_open=getattr(self._cfg, "sample_open", None),
            sample_notes=getattr(self, "sample_notes", None),
            note_key=server_note_key(self._cfg, str(getattr(self, "note_instance", "") or "")),
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
        return ProviderProbe(
            ok=response.status_code < 400,
            detail=f"HTTP {response.status_code}",
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

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

    def close(self) -> None:
        self._close_toolkit()


def get_settings_or_none() -> Any:
    """The deployment's settings, or ``None`` where none can be read (a probe, a test)."""
    try:
        from maljan.core.config import get_settings

        return get_settings()
    except Exception:  # noqa: BLE001 - no settings means no operator budget
        return None
