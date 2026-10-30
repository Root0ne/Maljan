"""Every MCP server Maljan attaches, and the one lifecycle they share.

There used to be three copies of "start an MCP server and take
its tools": ``GhidraStaticProvider.open``, ``GenericMCPStaticProvider.open``,
and a hand-rolled pair inside the network analyst and the judge. They drifted
— only one of them honoured an output guardrail, only one closed its child on
a re-attach, and none of them could be exercised by a settings probe, so the
UI's "Test" button spoke a different dialect to the same server than the job
did. ``ServerHandle`` is that code, once; ``ServerRegistry`` is the set of
them a job holds, keyed by the operator's own slug.

The registry never decides policy. It attaches what settings say to attach,
filters to the allow-list the operator ticked, renames a colliding tool, and
reports which servers failed. Whether a failure degrades a run or fails it is
the analyst's question, answered by the provider's capability flags — and for
a registry server the answer is always "degrade", because a server an operator
added is never the evidence the run was measured on.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import weakref
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError
from maljan.tools.capabilities import CAPABILITIES_TOOL, ServerCapabilities

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.core.config import MCPServerConfig, Settings

# The reason string a failed server contributes to ``degradation_reasons``.
UNAVAILABLE_REASON = "mcp server '{name}' unavailable"

# A server that answered but does not offer the tool a definition asked for by
# name. Distinct from ``UNAVAILABLE_REASON``: the server is fine, the
# *reference* is stale, and an operator fixes those two things differently.
AGENT_TOOL_UNAVAILABLE_REASON = "agent tool '{server}.{name}' unavailable"
# What follows it for a server the operator switched off.
SERVER_DISABLED = "server disabled"

# The teardown budgets, and why they are these numbers.
#
# Every one of them has to fit strictly inside the budget of whoever is
# waiting, or the outer fence cancels the inner one mid-flight and the work
# the inner fence exists to do — reaping an abandoned child — never happens.
# The chain a job's teardown actually walks:
#
#     run_analysis        60.0s   (analysis_worker._TEARDOWN_BUDGET)
#     └ container.aclose  20.0s   per closer (container._ACLOSE_BUDGET)
#       └ handle.aclose   14.0s   routed close, then
#                          4.0s   the reap, shielded
#
# So a routed close plus its reap is 18s against the container's 20s, and the
# container's own fence is what ends a handle that misbehaves beyond that.
#
# How long one toolkit's own cleanup may take before its child is taken away
# from it. An ``mcp`` stdio exit stack closes the child's stdin, waits 2s, then
# escalates SIGTERM -> SIGKILL over another 2s; this is comfortably past that
# escalation, so reaching it means the escalation itself did not run.
CLEANUP_TIMEOUT = 10.0

# How long the transport then gets to finish unwinding, with its child already
# killed. Every wait inside the stack — the child wait, the pipe readers —
# returns on its own once the process is gone, so this covers the unwind only.
# ``CLEANUP_TIMEOUT + CHILD_EXIT_GRACE`` is the whole local budget and is what
# the routed fence below is measured against.
CHILD_EXIT_GRACE = 2.0

# Extra headroom for a cleanup routed to another loop: the owning loop still
# applies its own budget, so this only has to outlast the hop.
CROSS_LOOP_GRACE = 2.0

# The fence the *calling* loop puts around a routed close: the owning loop's
# whole budget plus the hop. Named rather than spelled out at both use sites,
# because it is the number the comment block above balances.
ROUTED_CLOSE_TIMEOUT = CLEANUP_TIMEOUT + CHILD_EXIT_GRACE + CROSS_LOOP_GRACE

# How long a child gets between SIGTERM and SIGKILL in the backstop reap.
CHILD_TERM_GRACE = 2.0

# The whole reap, signals and grace included. Small on purpose: it runs in a
# ``finally`` while the caller's own budget may already be expiring.
REAP_BUDGET = CHILD_TERM_GRACE + 2.0

# The synchronous close path's budget. It blocks the calling thread, so it is
# kept at the value it had before the loop-routing work rather than inheriting
# the routed budget: ``ServiceContainer.aclose`` runs it in an executor, and a
# thread that blocks for 20s is 20s of a worker thread, not of the loop.
SYNC_CLOSE_TIMEOUT = 20.0


def _start_time(pid: int) -> str | None:
    """The start time of ``pid`` (field 22 of ``/proc/<pid>/stat``), ``None`` where unreadable.

    With the pid it names one process for good: a pid the kernel hands out
    again has a start time of its own.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            stat = fh.read().decode("ascii", "replace")
    except OSError:
        return None
    # The command name is in parentheses and may hold spaces; fields from the
    # third on follow the last parenthesis.
    rest = stat[stat.rfind(")") + 2 :].split()
    return rest[19] if len(rest) > 19 else None


def _own_child_pids() -> set[int]:
    """The pids of this process's direct children, empty where /proc is absent.

    Read rather than tracked, because the ``mcp`` stdio transport owns the
    subprocess and never hands it out: ``stdio_client`` keeps the anyio
    ``Process`` in a generator frame. Snapshotting before and after
    ``initialize`` names the child a handle spawned precisely enough to signal
    it — and only it — when the transport's own shutdown never gets to run.
    """
    import os

    try:
        children: set[int] = set()
        for task in os.listdir("/proc/self/task"):
            try:
                with open(f"/proc/self/task/{task}/children") as fh:
                    children.update(int(pid) for pid in fh.read().split())
            except (OSError, ValueError):
                continue
        return children
    except OSError:
        return set()


# Child pids already attributed to a handle, by the handle that owns each. Two
# handles of one server share an argv, so the argv check alone would give both
# the other's child; a pid that is another handle's is never taken twice.
_CLAIMED_PIDS: dict[tuple[int, str | None], int] = {}
_CLAIMED_LOCK = threading.Lock()
# One lock per launch argv, held from the snapshot of our children before an
# attach until its child is claimed (not across the handshake): two handles
# that launch the same argv and start together would otherwise each see both
# children appear.
_LAUNCH_LOCKS: dict[tuple[str, ...], threading.Lock] = {}


def _launch_lock(argv: tuple[str, ...]) -> threading.Lock | None:
    """The lock serialising attaches that launch ``argv``; ``None`` for no child."""
    if not argv:
        return None
    with _CLAIMED_LOCK:
        return _LAUNCH_LOCKS.setdefault(argv, threading.Lock())


class _LaunchWindow:
    """The launch lock of one attach, released once, by whoever gets there first."""

    def __init__(self, lock: threading.Lock | None) -> None:
        self._lock = lock
        self.held = lock is not None
        self._mutex = threading.Lock()

    def release(self) -> None:
        with self._mutex:
            if self.held and self._lock is not None:
                self.held = False
                self._lock.release()


def _refuse_on_the_agent_loop(name: str) -> None:
    """Refuse a blocking attach from the agent loop's own thread, as the attach always has.

    Its handshake runs on the agent loop and is waited for here, so the thread
    serving that loop can never make it. Another loop's thread may block.
    """
    from maljan.agents.base_agent import _get_agent_loop, _on_agent_loop_thread

    if _on_agent_loop_thread(_get_agent_loop()):
        raise RuntimeError(
            f"mcp server '{name}' was opened with a blocking call from the agent loop's own "
            "thread, which cannot serve it: await aopen there, or call open from "
            "asyncio.to_thread"
        )


async def _acquire_launch(lock: threading.Lock) -> None:
    """Take ``lock`` off the event loop, leaving it free if the wait is cancelled.

    The executor's ``acquire`` cannot be cancelled: it goes on and takes the
    lock after the waiter is gone. So the future is shielded and, when the
    waiter is cancelled, released as soon as it has been taken.
    """
    future = asyncio.get_running_loop().run_in_executor(None, lock.acquire)
    try:
        await asyncio.shield(future)
    except asyncio.CancelledError:

        def _give_back(done: Any) -> None:
            if not done.cancelled() and done.exception() is None and done.result():
                lock.release()

        future.add_done_callback(_give_back)
        raise


class _Watch:
    """The thread that watches for an attach's child; ``stop`` it, then join ``thread``."""

    def __init__(self, thread: threading.Thread, halt: threading.Event) -> None:
        self.thread = thread
        self._halt = halt

    def stop(self) -> None:
        self._halt.set()


def _watch_for_child(handle: ServerHandle, before: set[int], window: _LaunchWindow) -> _Watch:
    """Free the launch window as soon as any child appears, claiming it when its argv is ours.

    The child is spawned inside ``initialize``, which may take long; the
    window closes at the spawn, not at the end of the handshake. A child that
    appears is in the next attach's ``before``, so the window is released
    whether or not its argv is this handle's (a launcher such as ``npx`` or
    ``env`` runs another argv); the final note claims by argv afterwards.
    Polling backs off from 5 ms, doubling up to 100 ms.
    """
    halt = threading.Event()

    def _run() -> None:
        delay = 0.005
        while not halt.is_set():
            handle._note_child_pids(before)
            if handle._child_pids or (_own_child_pids() - before):
                window.release()
                return
            halt.wait(delay)
            delay = min(delay * 2, 0.1)

    thread = threading.Thread(target=_run, name="child-watch", daemon=True)
    thread.start()
    return _Watch(thread, halt)


def _run_async(coro: Any, label: str) -> None:
    """Run an MCP-client coroutine on the shared agent loop.

    Same rationale as ``GenericMCPStaticProvider._run_async``: a toolkit's
    transport binds its async primitives to whichever loop first creates it,
    and the ReAct tool calls later run on the process-wide agent loop, so init
    has to run there too rather than on a throwaway loop. A module-level
    function rather than a method so a test can replace it in one place.
    """
    from maljan.agents.base_agent import run_coro_blocking

    run_coro_blocking(coro, hard_timeout=120.0, label=label)


def _run_async_result(coro: Any, label: str, hard_timeout: float) -> Any:
    """``_run_async`` for a call whose answer is wanted: the manifest read."""
    from maljan.agents.base_agent import run_coro_blocking

    return run_coro_blocking(coro, hard_timeout=hard_timeout, label=label)


# How long a server gets to answer ``capabilities``. It is computed at the
# server's start and returned from memory, so a slow answer is a wedged server
# and not a slow probe.
CAPABILITIES_TIMEOUT_SECONDS = 10.0


# Every handle that still exists, so a retired agent loop can be told which of
# them it took with it. Weak, so a handle nobody holds is simply gone.
_LIVE_HANDLES: weakref.WeakSet[ServerHandle] = weakref.WeakSet()

# Every handle that is attached right now, held strongly until it is closed.
# ``_LIVE_HANDLES`` is weak so a handle nobody holds can simply go; an
# *attached* handle cannot be allowed to. Its toolkit's stdio transport is an
# async generator, and when the last reference to an open one is dropped the
# agent loop's async-generator finalizer schedules ``aclose()`` as a fresh task
# on that loop. That unwinds the transport's task group from a task other than
# the one that entered it: anyio cancels the scope, cannot deliver the
# cancellation to tasks it no longer hosts, and re-arms the delivery with
# ``call_soon`` on every iteration, so the agent loop spins at 100 % CPU for
# the rest of the process (BUG 13, 2026-09-08: a prompt test dropped a
# container that had resolved the judge, and every later test ran starved of
# the GIL). Ownership of an open handle therefore belongs to the process, and
# ends only in ``_forget_attachment``, which every detach path reaches.
_ATTACHED_HANDLES: set[ServerHandle] = set()
_HOOK_REGISTERED = threading.Event()


def _abandon_handles_on(loop: asyncio.AbstractEventLoop) -> None:
    """Drop every handle bound to a retired loop and reap its child.

    An exit stack can only be unwound on the loop that wound it, so a handle
    whose loop has been retired can never be closed properly again — which is
    exactly the case ``_close_on_owner`` already refuses to enter, and the same
    answer applies here: forget the toolkit and take the child directly. Doing
    it at retirement rather than at the next ``aclose`` means the sidecar goes
    away even when nothing ever closes that handle again, and it means the next
    user of the server re-attaches on the fresh loop instead of parking on a
    future the retired loop will never complete.

    Runs on the watchdog thread, and the grace period is paid **once** for the
    whole set rather than once per handle. A retirement that met sixty-one
    abandoned handles used to spend ``CHILD_TERM_GRACE`` on each of them in
    turn — two minutes of a daemon thread, which is how one of them came to be
    writing a log line after the interpreter had closed the stream under it.
    Every child is signalled first, the grace is waited out once, and the
    survivors are killed; the whole set is one log line rather than one per
    handle. A process already shutting down is left to the operating system.
    """
    import time

    if sys.is_finalizing():
        return
    abandoned = [handle for handle in list(_LIVE_HANDLES) if handle._owner_loop is loop]
    if not abandoned:
        return
    signalled: list[tuple[ServerHandle, list[int]]] = []
    for handle in abandoned:
        handle._toolkit = None
        handle._all_tools = []
        handle._opened_async = False
        try:
            pids = handle._terminate_children()
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server %r child reap failed (non-fatal): %s", handle.name, exc)
            pids = []
        if pids:
            signalled.append((handle, pids))
    logger.error(
        "%d mcp server(s) were attached to the agent loop that has just been retired; "
        "abandoning their toolkits and reaping %d child process(es). servers=%s",
        len(abandoned),
        sum(len(pids) for _handle, pids in signalled),
        ", ".join(sorted({handle.name for handle in abandoned})),
    )
    if signalled and not sys.is_finalizing():
        time.sleep(CHILD_TERM_GRACE)
        killed: list[tuple[str, int]] = []
        for handle, pids in signalled:
            try:
                killed.extend((handle.name, pid) for pid in handle._kill_survivors(pids, say=False))
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("mcp server %r child kill failed (non-fatal): %s", handle.name, exc)
        if killed:
            logger.warning(
                "%d child process(es) of %d abandoned mcp server(s) ignored SIGTERM and were "
                "killed: %s",
                len(killed),
                len({name for name, _pid in killed}),
                ", ".join(f"{name}={pid}" for name, pid in killed),
            )
    for handle in abandoned:
        handle._forget_attachment()


def _register_retirement_hook() -> None:
    """Subscribe once to agent-loop retirements. Imported late to avoid a cycle."""
    if _HOOK_REGISTERED.is_set():
        return
    from maljan.agents.base_agent import on_agent_loop_retired

    on_agent_loop_retired(_abandon_handles_on)
    _HOOK_REGISTERED.set()


# The declared kind of the readers' delivery primitive (``tools.readers``), and
# how long the session of a block that declares it waits for an answer's next
# bytes: a day, past any reading's own clock, which each call is held to.
READER_DELIVERY_KIND = "reader_delivery"
# The declared kind of the release of what those readings staged for a job
# (``tools.readers.RELEASE_JOB``): a kind of its own, so a server that declares
# only the release is never chosen to run a reading.
RELEASE_DELIVERY_KIND = "staging_release"
READING_SESSION_READ_TIMEOUT_SECONDS = 24 * 3600.0


class ServerHandle:
    """One configured MCP server, attached for at most one job at a time."""

    def __init__(self, name: str, config: MCPServerConfig) -> None:
        # The tools decided for the manifest this handle holds (``tools``),
        # and how many times a manifest was attached: the key it is kept by.
        self._tools_cache: tuple[Any, list[Any]] | None = None
        self._attach_count = 0
        self.name = name
        self.config = config
        # The job's count of what may have changed on each server
        # (``schemas.evidence.ServerChanges``), set by the registry: every
        # attach is a fresh process or session whose state no earlier answer
        # describes, so it counts as a change (``_note_attach``).
        self.server_changes: Any = None
        self._toolkit: Any = None
        self._all_tools: list[Any] = []
        self._job_id: str = ""
        self._sample_sha256: str = ""
        # True once ``aopen`` has attached this handle: its exit stack was
        # wound on whichever loop called it, so it must be unwound there too
        # (see ``close``).
        self._opened_async = False
        # *Which* loop that was. ``_opened_async`` alone was not enough: it
        # says "not the synchronous path" and the close paths then assumed the
        # graph loop, but the mediator judge attaches its servers from inside
        # ``run_on_agent_loop`` (``pipeline/nodes.py``), so the exit stack is
        # wound on the shared agent loop and the graph loop's ``await`` on it
        # can never complete or be cancelled. See ``_close_on_owner``.
        self._owner_loop: asyncio.AbstractEventLoop | None = None
        # The child this handle spawned, for the backstop reap when the
        # transport's own SIGTERM -> SIGKILL shutdown never gets to run.
        self._child_pids: tuple[int, ...] = ()
        # When each of those started, read as it was claimed: with its pid it
        # is the child's identity, so a reused pid is never the old child.
        self._child_starts: dict[int, str | None] = {}
        # The argv that child was launched with, which is what makes the pid
        # above this handle's rather than merely contemporaneous.
        self._launch_argv: tuple[str, ...] = ()
        # The names of the environment that child was handed, which the run's
        # isolation part reads the platform's own variables from, by name.
        self._launch_env_names: tuple[str, ...] = ()
        # The source this server's calls are recorded under
        # (``LedgerEntry.source``); a provider that drives the handle under a
        # block of its own names that block instead.
        self.declared_source = f"mcp:{name}"
        # Whether an attach measures the process it started for the job's
        # isolation part: set by the job's registry and by a provider that
        # drives a handle for a job. A connection test is no job, and notes
        # nothing.
        self.measures_isolation = False
        # What the server said it can do on its host, read once per attach
        # from its ``capabilities`` tool when it offers one; ``None`` for a
        # server that does not, or whose answer could not be read.
        self._capabilities: ServerCapabilities | None = None
        # The tools withheld because they could not be made to carry the
        # job's program on a shared server (``sample_open.pin_program_argument``),
        # each with its reason; read with the manifest's in ``withheld_reasons``.
        self._unpinned: dict[str, str] = {}
        # The name and version the server gave for itself at its last attach
        # (MCP ``serverInfo``), kept after the handle closes: the run
        # fingerprint is read once the run's last tool call is made.
        self.server_info: dict[str, str] = {}
        self.attached_once = False
        # Whether the next attach keeps each tool's definition as the server
        # listed it (``tool_definitions``). Only the settings probe asks, to
        # propose declarations; a run's handle keeps none.
        self.keeps_tool_definitions = False
        # The job's breaker and call cap for this server, set by the registry
        # that owns the handle (``maljan.providers.server_guard``). A handle
        # built outside a registry — a probe, a test — has none and sends
        # every call as it always did.
        self.guard: Any = None
        # The job's note of the paths this server opened
        # (``providers.sample_open``), set by the registry that owns the
        # handle; a handle built outside one has none and offers its open tool
        # as it is.
        self._sample_notes: Any = None
        # How this server's answers say "error" is its declaration
        # (``error_patterns``), read by one function for every server
        # (``providers.declared_errors``). An adapter that reads them itself,
        # with a step of its own around a failure, sets ``reads_own_errors``;
        # ``error_sample_path`` answers the path the server can open for the
        # job's sample, which a remediation may name.
        self.reads_own_errors = False
        self.error_sample_path: Callable[[], str | None] | None = None
        # The job's own copy of the sample on this server, set by the job's
        # registry once an agent's sample is mirrored or staged there
        # (``ServerRegistry.hold_sample_path``): on a server other jobs share,
        # the only path an open may name. ``None`` refuses every open there.
        self.held_sample_path: str | None = None
        # This handle's own process, for a local server's note key; a number
        # never reused, unlike an object's id.
        from maljan.providers.sample_open import new_instance

        self._note_instance = new_instance()
        _LIVE_HANDLES.add(self)
        _register_retirement_hook()

    @property
    def capabilities(self) -> ServerCapabilities | None:
        """What the server said it can do on its host, read at its attach."""
        return self._capabilities

    @capabilities.setter
    def capabilities(self, manifest: ServerCapabilities | None) -> None:
        # Another host manifest withholds other tools.
        self._capabilities = manifest
        self._tools_cache = None

    @property
    def sample_notes(self) -> Any:
        """The job's note of the paths this server opened (``providers.sample_open``)."""
        return self._sample_notes

    @sample_notes.setter
    def sample_notes(self, notes: Any) -> None:
        # Another job's note is another decision about the tools.
        self._sample_notes = notes
        self._tools_cache = None

    @property
    def is_open(self) -> bool:
        return self._toolkit is not None

    async def deliver(
        self, tool_name: str, args: dict[str, Any], timeout: float | None = None
    ) -> Any:
        """One call of a delivery primitive on this open handle, answered whole.

        Only a delivery primitive (``agents.tool_pinning.DELIVERY_TOOLS``): its
        answer is the platform's input, never shown to a model, so no model's
        output limit applies (``MCPLangChainToolkit.deliver``).
        """
        from maljan.agents.tool_pinning import DELIVERY_TOOLS

        if tool_name not in DELIVERY_TOOLS:
            raise ValueError(f"{tool_name} is no delivery primitive")
        if self._toolkit is None:
            raise RuntimeError(f"mcp server '{self.name}' is not open")
        return await self._toolkit.deliver(tool_name, args, timeout)

    @property
    def note_key(self) -> str:
        """The server this handle's opens are noted under (``sample_open.server_note_key``):
        its address for a remote server, shared by every handle to it; its command and
        this handle's own process for a local one."""
        from maljan.providers.sample_open import server_note_key

        return server_note_key(self.config, self._note_instance)

    @property
    def label(self) -> str:
        return self.config.label or self.name

    @property
    def server_instructions(self) -> str:
        """What the server said about itself when this attach initialised it (MCP
        ``instructions``), as served; "" when it said nothing or is not attached."""
        return str(getattr(self._toolkit, "server_instructions", "") or "")

    def _resolve_cwd(self) -> str | None:
        """The child's working directory, refused when it escapes the project.

        ``cwd`` is an operator setting that becomes a subprocess's working
        directory, so it gets the same treatment every other path-shaped
        setting gets: a relative value is rooted at the project directory and
        must stay inside it; an absolute value is allowed but must exist.
        Neither check is a sandbox — an operator who can edit settings can
        already run a command — it is there so a typo fails loudly at attach
        time instead of starting a server in an unexpected directory
        (``subprocess_env.launch_cwd``, read alike by a trust grant).
        """
        from maljan.agents.subprocess_env import LaunchCwdError, launch_cwd

        try:
            return launch_cwd(self.config.cwd)
        except LaunchCwdError as exc:
            raise ProviderConfigurationError(f"mcp server {self.name!r}: {exc}") from exc

    def _withdraw_a_grant_that_no_longer_holds(self) -> None:
        """Turn off a console trust grant the launch about to start no longer matches.

        A grant is recorded with the launch it was given for
        (``tool_declarations.granted_launch``, the files the launch resolves
        to); read again here, where the server is started, a block whose
        command, script or environment now resolves elsewhere does not trust
        what its server declares: the trust is dropped for this handle, and
        said.
        """
        from maljan.core.tool_declarations import granted_launch

        granted = getattr(self.config, "trust_granted_for", None)
        if self.config.trusts_served_declaration is not True or not granted:
            return
        if granted == granted_launch(self.config):
            return
        logger.warning(
            "mcp server '%s' no longer starts the launch its trust was granted for; "
            "what it declares of its tools is not trusted until the trust is granted again.",
            self.name,
        )
        self.config = self.config.model_copy(
            update={"trusts_served_declaration": False, "trust_granted_for": None}
        )

    def _stages_per_job(self) -> bool:
        """Whether this server writes or reads a staging directory at all.

        A built-in that is required to see ``MALJAN_STAGING_DIR`` does, and so
        does a server an operator configured with that name — the same sidecar
        under a key of their own. Every other server is told nothing: a job id
        is not a fact a third-party tool server needs.
        """
        from maljan.core.config import REQUIRED_ENV_ALLOW
        from maljan.tools.staging import STAGING_DIR_ENV

        if STAGING_DIR_ENV in REQUIRED_ENV_ALLOW.get(self.name, ()):
            return True
        return STAGING_DIR_ENV in self.config.env_allow or STAGING_DIR_ENV in self.config.env

    def _name_the_job_staging(self, env: dict[str, str]) -> None:
        """Give the child the one directory name this job may stage under.

        Written after ``child_env`` rather than into it, and as a leaf rather
        than as a path: the operator's ``MALJAN_STAGING_DIR`` is applied last by
        ``child_env`` and stays the base, and the sidecar joins the two itself.
        The name is recorded so this job's teardown can remove exactly what it
        pointed its sidecars at.

        Cleared first, and unconditionally. ``child_env`` applies a server's own
        ``env`` map on top of everything, so a stored mapping naming this
        variable would otherwise reach the child verbatim — pointing a server at
        a directory belonging to whichever job the operator had written down,
        for every job it is attached to, and having this job's teardown remove
        it under that other job's name. The leaf is the spawn's to compose or
        nobody's; settings validation refuses the name as well, and this is the
        fence for a mapping that reached a handle by some other path.
        """
        from maljan.tools import staging

        env.pop(staging.STAGING_JOB_ENV, None)
        if not self._job_id or not self._stages_per_job():
            return
        leaf = staging.job_directory_name(self._job_id)
        env[staging.STAGING_JOB_ENV] = leaf
        staging.note_job_directory(self._job_id, staging.staging_base(env) / leaf)

    def _name_the_sample(self, env: dict[str, str]) -> None:
        """Give a server that asks for it the run's sample sha256.

        Only a server that names ``MALJAN_SAMPLE_SHA256`` in its ``env_allow`` (or
        its own ``env``) is told: a third party's tool server learns nothing of
        the sample it was not set up to see. Cleared first and unconditionally,
        as the staging leaf is: a stored ``env`` value is never the run's.
        """
        from maljan.core.config import REQUIRED_ENV_ALLOW
        from maljan.tools.knowledge import SAMPLE_SHA256_ENV

        env.pop(SAMPLE_SHA256_ENV, None)
        wanted = (
            SAMPLE_SHA256_ENV in REQUIRED_ENV_ALLOW.get(self.name, ())
            or SAMPLE_SHA256_ENV in self.config.env_allow
            or SAMPLE_SHA256_ENV in self.config.env
        )
        if wanted and self._sample_sha256:
            env[SAMPLE_SHA256_ENV] = self._sample_sha256

    def _build_toolkit(
        self,
        output_guardrail: Callable[[str], str] | None,
        max_output_chars: int,
        truncation_ledger: Any | None,
        context_budget: Any | None = None,
    ) -> Any:
        """Everything ``open`` does except awaiting ``initialize``.

        Factored out because the judge enters its toolkit with a plain
        ``await`` on the graph's own loop while the analysts hand theirs to
        the shared agent loop — the asymmetry ``JudgeAgent.aclose`` documents
        — and the only safe way to have both is one construction path and two
        ways of running the coroutine it returns.
        """
        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.core.undeclared_tools import categories_of

        self._withdraw_a_grant_that_no_longer_holds()
        if self.config.transport == "stdio":
            from mcp import StdioServerParameters

            from maljan.agents.subprocess_env import LaunchCwdError, stdio_launch
            from maljan.core.config import BUILTIN_SERVER_KEYS

            # One reading of the launch, the one a trust grant holds for.
            try:
                launch = stdio_launch(self.config, server=self.name)
            except LaunchCwdError as exc:
                raise ProviderConfigurationError(f"mcp server {self.name!r}: {exc}") from exc
            env = launch.env
            self._name_the_job_staging(env)
            self._name_the_sample(env)
            if self.name not in BUILTIN_SERVER_KEYS:
                # Byte-for-byte with the pre-branch built-ins (spec S3.2): the
                # in-repo network/threatintel sidecars were launched with a
                # bare ``child_env(...)``, which carries PYTHONIOENCODING only
                # when the parent process already has it set. A server the
                # operator adds through the catalog gets the more predictable
                # default instead.
                env.setdefault("PYTHONIOENCODING", "utf-8")
            args = launch.args
            # Kept so the backstop reap can tell this handle's child from any
            # other subprocess that happened to start in the same window; see
            # ``_child_matches``.
            self._launch_argv = (self.config.command, *args)
            self._launch_env_names = tuple(env)
            params = StdioServerParameters(
                command=self.config.command,
                args=args,
                env=env,
                cwd=launch.cwd,
            )
            return MCPLangChainToolkit(
                params,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
                context_budget=context_budget,
                guard=self.guard,
                categories=categories_of(self._tools_in_force()),
                categories_with_served=self._categories_with_served,
                keep_tool_definitions=self.keeps_tool_definitions,
                label=self.label,
            )
        # An http/sse transport has no child of ours to reap.
        self._launch_argv = ()
        self._launch_env_names = ()
        # A ``SecretStr`` as settings hold it, or a plain string a caller set.
        raw = self.config.auth_token
        token = raw.get_secret_value() if hasattr(raw, "get_secret_value") else str(raw or "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return MCPLangChainToolkit(
            transport=self.config.transport,
            http_url=self.config.url,
            http_headers=headers,
            output_guardrail=output_guardrail,
            max_output_chars=max_output_chars,
            truncation_ledger=truncation_ledger,
            context_budget=context_budget,
            guard=self.guard,
            categories=categories_of(self._tools_in_force()),
            categories_with_served=self._categories_with_served,
            keep_tool_definitions=self.keeps_tool_definitions,
            **self._reading_session(),
        )

    def _reading_session(self) -> dict[str, Any]:
        """The session's read timeout for a block that declares the readers' delivery primitive.

        A reading on such a server (capa, FLOSS) runs for as long as its own
        clock allows, past the HTTP session's usual wait for the next bytes
        of an answer, and sends none while it works. Its session waits
        :data:`READING_SESSION_READ_TIMEOUT_SECONDS`; each call is still held
        to its own clock (``MCPLangChainToolkit.deliver``) and an agent's to
        the job's breaker. Any other block keeps the library's wait.
        """
        facts = self._tools_in_force()
        if any(getattr(f, "kind", None) == READER_DELIVERY_KIND for f in facts.values()):
            return {"http_read_timeout": READING_SESSION_READ_TIMEOUT_SECONDS}
        return {}

    def open(
        self,
        job_id: str,
        *,
        output_guardrail: Callable[[str], str] | None = None,
        max_output_chars: int = 0,
        truncation_ledger: Any | None = None,
        context_budget: Any | None = None,
        sample_sha256: str = "",
    ) -> None:
        """Attach for ``job_id``. Same id is a no-op; a different id reattaches."""
        if self._toolkit is not None:
            if job_id == self._job_id:
                return
            logger.info(
                "mcp server '%s' re-opened for a different job; closing the stale toolkit first.",
                self.name,
            )
            self.close()
        self._job_id = job_id
        self._sample_sha256 = sample_sha256
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return

        toolkit = self._build_toolkit(
            output_guardrail, max_output_chars, truncation_ledger, context_budget
        )

        launch = _launch_lock(self._launch_argv)
        if launch is not None:
            _refuse_on_the_agent_loop(self.name)
            launch.acquire()
        window = _LaunchWindow(launch)
        try:
            before = _own_child_pids()
            watch = _watch_for_child(self, before, window) if launch is not None else None
            try:
                self._init_sync(toolkit)
            finally:
                if watch is not None:
                    watch.stop()
                    watch.thread.join()
            self._settle_children(before, window)
        except BaseException:
            self._release_claims()
            raise
        finally:
            window.release()
        self._finish_open_sync(toolkit)

    def _settle_children(self, before: set[int], window: _LaunchWindow) -> None:
        """Claim the child by its argv, if the watch did not."""
        if not self._child_pids:
            self._note_child_pids(before)

    def _release_claims(self) -> None:
        """Give back the pids this handle claimed."""
        with _CLAIMED_LOCK:
            for key in [k for k, owner in _CLAIMED_PIDS.items() if owner == id(self)]:
                del _CLAIMED_PIDS[key]
        self._child_pids = ()
        self._child_starts = {}

    def _init_sync(self, toolkit: Any) -> None:
        """Initialise ``toolkit``, or tear it down and raise."""
        try:
            _run_async(toolkit.initialize(), label=f"{self.name}-mcp-init")
        except Exception:
            # A transport or subprocess can be partly up (a socket connected,
            # a child process spawned) before ``initialize`` itself fails —
            # e.g. the handshake times out or the server rejects the token.
            # Nothing else ever gets a reference to this toolkit (``_toolkit``
            # is not assigned until initialize succeeds), so if this does not
            # close it, nothing does. The original exception is what the
            # caller (and the registry's degrade path) needs to see, so it is
            # re-raised unchanged after teardown.
            logger.warning(
                "mcp server '%s' failed to initialize; closing the partial attach.",
                self.name,
            )
            self._teardown(toolkit)
            raise
        self._toolkit = toolkit
        self.server_info = dict(getattr(toolkit, "server_info", None) or {})
        self.attached_once = True
        _ATTACHED_HANDLES.add(self)
        self._opened_async = False
        # ``_run_async`` hands the coroutine to the shared agent loop, so that
        # is the loop this toolkit's exit stack was wound on.
        from maljan.agents.base_agent import _get_agent_loop

        self._owner_loop = _get_agent_loop()

    def _finish_open_sync(self, toolkit: Any) -> None:
        """What an attach does once its child is noted."""
        self._note_isolation()
        self._all_tools = list(toolkit.get_tools())
        self._note_served_declarations(toolkit)
        self._read_capabilities()
        self._attach_count += 1
        self._note_attach()
        allowed = self.config.tools
        if allowed:
            manifest = {str(getattr(t, "name", "")) for t in self._all_tools}
            missing = [name for name in allowed if name not in manifest]
            if missing:
                logger.warning(
                    "mcp server '%s': allow-listed tool(s) not offered by the server: %s",
                    self.name,
                    ", ".join(missing),
                )
        logger.info(
            "mcp server '%s': %d/%d tools exposed.",
            self.name,
            len(self.tools()),
            len(self._all_tools),
        )

    async def aopen(self, job_id: str, **context: Any) -> None:
        """Attach on the caller's own loop; the exit stack stays where it was wound.

        ``initialize`` is guarded the way the synchronous ``open`` guards
        ``_run_async(toolkit.initialize(), ...)``: a transport or subprocess
        can be partly up (a socket connected, a child process spawned) before
        ``initialize`` itself fails or is cancelled — e.g. ``handshake_tools``'s
        ``asyncio.wait_for`` timing out mid-handshake. ``_toolkit`` is never
        assigned until ``initialize`` succeeds, so if this does not close the
        partial attach, nothing does; the original exception (cancellation
        included) is what the caller needs to see, so it is re-raised
        unchanged after teardown.
        """
        if self._toolkit is not None:
            if job_id == self._job_id:
                return
            await self.aclose()
        self._job_id = job_id
        self._sample_sha256 = str(context.get("sample_sha256") or "")
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return
        toolkit = self._build_toolkit(
            context.get("output_guardrail"),
            int(context.get("max_output_chars", 0)),
            context.get("truncation_ledger"),
            context.get("context_budget"),
        )
        # Recorded *before* ``initialize``, so the failure path below unwinds
        # on the loop that wound the partial attach too.
        self._owner_loop = asyncio.get_running_loop()
        launch = _launch_lock(self._launch_argv)
        if launch is not None:
            # Taken off the loop: a holder on another loop may be waiting on
            # this thread's loop for something, and a blocked loop would never
            # let it finish.
            await _acquire_launch(launch)
        window = _LaunchWindow(launch)
        try:
            before = _own_child_pids()
            watch = _watch_for_child(self, before, window) if launch is not None else None
            try:
                await self._ainit(toolkit, before, window)
            finally:
                if watch is not None:
                    watch.stop()
                    # Joined off the loop: the thread may be mid-poll.
                    await asyncio.get_running_loop().run_in_executor(None, watch.thread.join)
            self._settle_children(before, window)
        except BaseException:
            self._release_claims()
            raise
        finally:
            window.release()
        await self._afinish_open(toolkit)

    async def _ainit(self, toolkit: Any, before: set[int], window: _LaunchWindow) -> None:
        """Initialise ``toolkit`` and note the child it started, or tear it down and raise."""
        try:
            await toolkit.initialize()
        except (Exception, asyncio.CancelledError):
            logger.warning(
                "mcp server '%s' failed to initialize; closing the partial attach.",
                self.name,
            )
            # The child a half-open transport already spawned is this handle's
            # too, and nothing else knows about it.
            self._settle_children(before, window)
            if not await self._acleanup(toolkit):
                await self._reap_after_abandon()
            self._child_pids = ()
            raise
        self._toolkit = toolkit
        self.server_info = dict(getattr(toolkit, "server_info", None) or {})
        self.attached_once = True
        _ATTACHED_HANDLES.add(self)
        self._opened_async = True

    async def _afinish_open(self, toolkit: Any) -> None:
        """What an async attach does once its child is noted."""
        self._note_isolation()
        self._all_tools = list(toolkit.get_tools())
        self._note_served_declarations(toolkit)
        await self._aread_capabilities()
        self._attach_count += 1
        self._note_attach()

    def _note_served_declarations(self, toolkit: Any) -> None:
        """Keep what the server declared of its tools when it listed them, under its source.

        Under the source this handle's tools are declared under
        (``declared_source``), so a provider driving the server reads it as
        its own; laid under what that source's block puts in force
        (``core.served_declarations``). A toolkit that read no declaration
        keeps none.
        """
        from maljan.core.served_declarations import register_served, served_digest
        from maljan.core.tool_declarations import launch_identity

        held = getattr(toolkit, "served_tool_facts", None)
        if not isinstance(held, Mapping):
            return
        # And what the platform read of the tools it does not declare
        # (``core.derived_declarations``), kept beside it.
        # A reading that failed (``None``) keeps what was read before.
        read = getattr(toolkit, "derived_tool_facts", None)
        program = getattr(toolkit, "derived_program", None)
        register_served(
            self._source_text(),
            held,
            launch_identity(self.config),
            read if isinstance(read, Mapping) else None,
            getattr(toolkit, "derived_closed", None) or None,
            program if isinstance(program, Mapping) else None,
        )
        # What it declared is recorded by its own digest, beside the name and
        # version it gave (``server_versions``); the run's recorded declaration
        # digests are of the blocks alone.
        digest = served_digest(held)
        if digest:
            self.server_info = {**self.server_info, "declaration_digest": digest}
        # Its tools' budgets and long-running flags as they are now in force,
        # its own declaration under its block's, for every call from here on.
        if self.guard is not None:
            self.guard.declare_tool_facts(self._tools_in_force())

    def _categories_with_served(
        self,
        held: Mapping[str, Any],
        read: Mapping[str, Any] | None = None,
        closed: Mapping[str, Any] | None = None,
        program: Mapping[str, Any] | None = None,
    ) -> dict[str, str]:
        """The description tags in force with ``held``, what the server declared, laid under.

        Asked by the toolkit before it builds the tools, so the first attach
        tags them as every later one does. Nothing is kept here: what the
        server declared is kept only once the attach succeeded
        (:meth:`_note_served_declarations`).
        """
        from maljan.core.declared_reading import tools_in_force
        from maljan.core.undeclared_tools import categories_of

        return categories_of(
            tools_in_force(self._source_text(), self.config, held, read, closed, program)
        )

    def _source_text(self) -> str:
        """The source this handle's tools are declared under."""
        return str(self.declared_source or f"mcp:{self.name}")

    def _tools_in_force(self) -> Mapping[str, Any]:
        """The tool declarations in force for this handle's source; the block's own as fallback."""
        from maljan.core.declared_reading import tools_in_force

        return tools_in_force(self._source_text(), self.config)

    def _note_attach(self) -> None:
        """Count an attach as a possible change of this server, for every answer held of it.

        A reconnect, a restart or a per-loop replica is a session whose state
        (an open program, a loaded file) no answer read before it describes.
        """
        changes = self.server_changes
        if changes is not None:
            changes.bump(self.name)
            # Its tools are keyed by where they are declared where no server
            # key is stamped on them (a provider driving the server).
            source = str(getattr(self, "declared_source", "") or "")
            if source and source != self.name:
                changes.bump(source)

    async def _acleanup(self, toolkit: Any) -> bool:
        """Best-effort async close of ``toolkit`` **on the caller's loop**.

        Shared by ``aclose`` (a healthy, attached toolkit) and ``aopen``'s own
        exception handler (a toolkit that never made it into ``_toolkit``) —
        one teardown path so a partial attach and a normal close cannot drift.

        The caller is responsible for being on the owning loop:
        ``_close_on_owner`` is what guarantees that.

        Returns True when the toolkit closed itself, False when it was
        abandoned — the caller reaps the child in that case, once, from a
        place a cancellation cannot skip.

        Bounded by ``_close_bounded``.
        """
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return True
        return await self._close_bounded(closer, CLEANUP_TIMEOUT)

    async def _close_bounded(self, closer: Callable[[], Any], budget: float) -> bool:
        """Await ``closer()`` under ``budget``, killing its child before any cancel.

        **The child dies first; only then may the unwind be cancelled.** That
        is the opposite of what the bound used to do.
        A stdio transport's exit stack waits on its child process, and a child
        that does not exit waits forever; the obvious answer — a plain
        ``asyncio.wait_for`` — cancels the unwind while the child is still
        running, and that is what wedged the worker on 2026-09-07:

        * The cancellation is delivered **once**, and ``mcp``'s stdio shutdown
          block consumes it (``mcp/client/stdio/__init__.py:190-216``). That
          block is unshielded, so the ``CancelledError`` raises out of
          ``await process.wait()`` at once — and its ``except TimeoutError:``,
          the SIGTERM -> SIGKILL escalation, does not catch a
          ``CancelledError`` and never runs. The child therefore *outlives* the
          cancellation that was supposed to end the wait on it.
        * The unwind then continues into anyio's ``Process.aclose``, whose
          ``await self.wait()`` is *not* shielded (``_backends/_asyncio.py``
          drops the shield first, and kills the child if a cancellation lands
          there) — but the cancellation has already been delivered and
          consumed, so nothing re-cancels it and it simply parks on a child
          that is still running.
        * That task is still in the task group's cancel scope, and
          ``CancelScope._deliver_cancellation`` sets ``should_retry`` for every
          task in ``self._tasks``, re-arming itself with ``loop.call_soon`` on
          every iteration. A scope that can never empty therefore spins its
          loop thread at 100 % CPU — 80 minutes of it, starving the worker of
          the GIL and stopping the job's heartbeat.

        So a timer takes the child away at ``budget``, and the unwind is given
        ``CHILD_EXIT_GRACE`` more to finish by itself. With the process gone
        every wait inside the stack returns, the scope empties, and the fence
        usually has nothing left to cancel. If it does cancel, it is cancelling
        a stack whose child is already dead, so each wait in it completes
        rather than parking.

        The close is awaited in the caller's own task, never wrapped in one:
        anyio cancel scopes are task-bound, and running the unwind in a
        separate task turns every close into "Attempted to exit cancel scope in
        a different task" plus a cancellation delivered to the wrong task.

        Returns True when the toolkit closed itself, False when it was
        abandoned — the caller reaps the child in that case.
        """
        loop = asyncio.get_running_loop()
        killer = loop.call_later(budget, self._kill_children_now)
        try:
            await asyncio.wait_for(closer(), timeout=budget + CHILD_EXIT_GRACE)
        except TimeoutError:
            logger.warning(
                "mcp server '%s' cleanup did not finish within %.0fs of its child being "
                "killed; abandoning it.",
                self.name,
                CHILD_EXIT_GRACE,
            )
            return False
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)
            return False
        finally:
            killer.cancel()
        return True

    async def _close_on_owner(self, toolkit: Any) -> bool:
        """Unwind ``toolkit`` on the loop that wound it. Bounded, never raises.

        The Critical this exists for: a handle the mediator judge attached ran
        its ``aopen`` inside ``run_on_agent_loop``, so its exit stack — an
        anyio task group and, for stdio, a child process — belongs to the
        shared agent loop, while ``JudgeAgent.aclose`` and
        ``ServiceContainer.aclose`` await ``handle.aclose()`` on the graph
        loop. Awaiting that stack from the graph loop parks the teardown task
        on a Future owned by the agent loop, and such a task cannot be woken
        *or cancelled* from here: the worker's 60s ``wait_for`` fires, its
        cancellation is dropped on the floor, and teardown never returns —
        live evidence, a job that completed at 05:58:44 and still held
        ``j_ongoing=1`` ten minutes later with both sidecars still running.

        So the close is submitted to the owning loop with
        ``run_coroutine_threadsafe`` and awaited through ``wrap_future``, which
        is cross-loop safe in both directions: the wait is a real ``await`` (no
        busy poll, no blocked loop) and cancelling it cancels the task on the
        owning loop rather than being silently discarded.

        Returns True when the toolkit closed itself; False leaves the child to
        the caller's reap.
        """
        owner = self._owner_loop
        running = asyncio.get_running_loop()
        if owner is None or owner is running:
            # ``None`` means nothing here opened the toolkit — a probe or a
            # test that set it directly — so there is no other loop to route
            # to and the caller's is the only one there is.
            return await self._acleanup(toolkit)
        if owner.is_closed() or not owner.is_running():
            # The one thing never worth doing: unwinding an exit stack on a
            # loop that did not wind it. That is the Critical this method
            # exists to prevent, and a dead owner is no licence to re-enter it
            # — a stack awaiting a future of a stopped loop parks forever, and
            # the fence around it cannot end a task nothing will resume. Leave
            # the stack where it is and take the child directly instead.
            logger.warning(
                "mcp server '%s' cannot be unwound: the loop that opened it is gone. "
                "Skipping the cleanup and reaping the child instead.",
                self.name,
            )
            return False
        # Submitted through the agent-loop helper rather than
        # ``run_coroutine_threadsafe`` directly, so the task itself is kept:
        # cancelling the future below says nothing about whether the
        # cancellation was ever delivered, and this is the exact teardown the
        # 2026-09-07 hang was captured in. ``_cancel_and_watch`` does the
        # cancel and watches the task behind it.
        from maljan.agents.base_agent import _cancel_and_watch, _submit_to_agent_loop

        future, cleanup_task = _submit_to_agent_loop(self._acleanup(toolkit), owner)
        try:
            return await asyncio.wait_for(asyncio.wrap_future(future), timeout=ROUTED_CLOSE_TIMEOUT)
        except TimeoutError:
            _cancel_and_watch(owner, future, cleanup_task, f"mcp server {self.name!r} cleanup")
            logger.warning(
                "mcp server '%s' cleanup did not finish on its own loop in %.0fs; abandoning it.",
                self.name,
                ROUTED_CLOSE_TIMEOUT,
            )
            return False
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)
            return False

    def _child_matches(self, pid: int) -> bool:
        """True when ``pid`` is still running the argv this handle launched.

        The pid itself comes from a before/after snapshot of our direct
        children (``_note_child_pids``), which on its own would attribute any
        subprocess another thread happened to start in that window to this
        handle — and the reap sends signals. The argv check is what makes the
        attribution real, and it doubles as protection against pid reuse
        between the snapshot and the kill.

        The alternative, taking the pid from the transport, is not available:
        ``mcp``'s ``stdio_client`` keeps its anyio ``Process`` in a generator
        frame inside the exit stack and exposes it nowhere.
        """
        if not self._launch_argv:
            return False
        if pid in self._child_starts and _start_time(pid) != self._child_starts[pid]:
            return False
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                argv = fh.read().split(b"\0")
        except OSError:
            return False
        expected = [part.encode() for part in self._launch_argv]
        return argv[: len(expected)] == expected

    def _note_child_pids(self, before: set[int]) -> None:
        """Record the children that appeared while ``initialize`` ran."""
        now = _own_child_pids()
        appeared = now - before
        with _CLAIMED_LOCK:
            # A claim on a pid that is no longer our child is stale (the pid
            # may be reused), so it is dropped before it can exclude anyone.
            live = {(pid, _start_time(pid)) for pid in now}
            for key in [k for k in _CLAIMED_PIDS if k not in live]:
                del _CLAIMED_PIDS[key]
            starts = {pid: _start_time(pid) for pid in appeared}
            mine = tuple(
                sorted(
                    pid
                    for pid in appeared
                    if _CLAIMED_PIDS.get((pid, starts[pid]), id(self)) == id(self)
                    and self._child_matches(pid)
                )
            )
            for pid in mine:
                _CLAIMED_PIDS[(pid, starts[pid])] = id(self)
        self._child_pids = mine
        self._child_starts = {pid: starts[pid] for pid in mine}

    def _note_isolation(self) -> None:
        """Measure each process this attach started, for the run's isolation part.

        Read once the server has initialised and before its first tool call,
        with every process under it (``analysis.isolation.measure_tree``): a
        launcher starts the real server as its own child. Noted under this
        job's key and this server's source. A child that could not be
        identified is not measured, and the run then says its isolation cannot
        be told.
        """
        if not self.measures_isolation or not self._child_pids or not self._job_id:
            return
        from maljan.analysis.isolation import measure_tree, note_process

        for pid in self._child_pids:
            try:
                measured = measure_tree(pid, self._launch_env_names)
            except Exception as exc:  # noqa: BLE001 — an unmeasured child is said, never guessed
                logger.warning(
                    "mcp server '%s': its process was not measured (%s); the run says its "
                    "isolation cannot be told.",
                    self.name,
                    type(exc).__name__,
                )
                continue
            note_process(self._job_id, self.declared_source, measured)

    def _live_children(self) -> list[int]:
        """The pids this handle spawned that are still our children."""
        live = _own_child_pids()
        return [pid for pid in self._child_pids if pid in live and self._child_matches(pid)]

    def _signal_children(self, pids: list[int], sig: int) -> None:
        """Send ``sig`` to recorded pids only, never to a name or a pattern."""
        import contextlib
        import os

        for pid in pids:
            with contextlib.suppress(OSError):
                os.kill(pid, sig)

    def _kill_children_now(self) -> None:
        """SIGKILL this handle's children at once, no grace. Never raises.

        The polite path is already spent by the time this runs: the transport's
        own shutdown closes stdin, waits, then escalates SIGTERM -> SIGKILL,
        and reaching ``CLEANUP_TIMEOUT`` means all of that either did not run
        or did not work. A second SIGTERM would only add its grace period to a
        teardown that has already overrun — and the live case, the network
        sidecar inside its capture library, was exactly a child that sat through one.
        """
        import signal

        pids = self._live_children()
        if not pids:
            return
        self._signal_children(pids, signal.SIGKILL)
        logger.warning(
            "mcp server '%s' child(ren) %s killed so its transport can finish unwinding.",
            self.name,
            ", ".join(str(pid) for pid in pids),
        )

    def _terminate_children(self) -> list[int]:
        """SIGTERM this handle's children and hand back the pids that got it.

        The first half of a reap, on its own so a caller with many handles to
        release can signal all of them before waiting out a single grace period
        rather than paying one per handle.

        No finalisation check of its own: both callers that can reach it from
        the watchdog thread stand down before this, and a reap that began in
        time is entitled to finish its SIGTERM — it is the *kill*, after the
        grace, that a finalising interpreter must not reach.
        """
        import signal

        pids = self._live_children()
        if pids:
            self._signal_children(pids, signal.SIGTERM)
        return pids

    def _kill_survivors(self, pids: list[int], *, say: bool = True) -> list[int]:
        """SIGKILL whichever of ``pids`` sat through the SIGTERM.

        Returns the pids it killed. ``say=False`` for a caller releasing many
        handles at once, which says it once for all of them instead.

        Not once the interpreter is finalising: this is reached from a daemon
        thread after a grace period long enough for a process to have decided
        to exit inside it, and the line it logs would be written to a stream
        that is already closed.
        """
        import signal

        if sys.is_finalizing():
            return []
        survivors = [pid for pid in pids if pid in _own_child_pids()]
        if not survivors:
            return []
        self._signal_children(survivors, signal.SIGKILL)
        if say:
            logger.warning(
                "mcp server '%s' child(ren) %s ignored SIGTERM; killed.",
                self.name,
                ", ".join(str(pid) for pid in survivors),
            )
        return survivors

    async def _areap_children(self) -> None:
        """Terminate, then kill, the child this handle spawned. Never raises.

        The last fence. ``mcp``'s stdio transport escalates SIGTERM -> SIGKILL
        itself, but only inside the exit stack — the code that does not run
        when a cleanup is abandoned. Without this the child outlives the job
        and, with ``max_jobs = 1``, accumulates one sidecar per analysis.
        """
        pids = self._terminate_children()
        if not pids:
            return
        await asyncio.sleep(CHILD_TERM_GRACE)
        self._kill_survivors(pids)

    def _reap_children(self) -> None:
        """``_areap_children`` for the synchronous close path.

        Reached from the retirement hook on a daemon thread, so it stands down
        once the interpreter is going: the child is the operating system's to
        collect by then, and what this would otherwise do is sleep through the
        grace and log into a closed stream.
        """
        import time

        if sys.is_finalizing():
            return
        pids = self._terminate_children()
        if not pids:
            return
        time.sleep(CHILD_TERM_GRACE)
        self._kill_survivors(pids)

    def _forget_attachment(self) -> None:
        """Drop what only an attached handle carries. Call after the reap."""
        _ATTACHED_HANDLES.discard(self)
        self._owner_loop = None
        self._release_claims()
        self._launch_argv = ()

    async def _reap_after_abandon(self) -> None:
        """Reap the child of a cleanup that did not finish. Never raises.

        Shielded, and that is the point. This runs from a ``finally`` while
        the caller's own budget may already be cancelling us —
        ``ServiceContainer.aclose`` bounds each closer, and ``run_analysis``
        bounds the lot — and a reap that is skipped because the fence above it
        fired first is a reap that never happens on precisely the runs that
        need it. ``shield`` keeps the kill running on this loop even when the
        ``await`` on it is cancelled; the loop outlives the job, so it lands.
        """
        import contextlib

        with contextlib.suppress(Exception, asyncio.CancelledError):
            await asyncio.shield(asyncio.wait_for(self._areap_children(), timeout=REAP_BUDGET))

    async def aclose(self) -> None:
        """Close on the loop that opened this handle. Bounded, and never raises."""
        if self._toolkit is not None:
            await self._aclose_job_programs()
        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        self._opened_async = False
        if toolkit is None:
            self._forget_attachment()
            return
        closed = False
        try:
            closed = await self._close_on_owner(toolkit)
        finally:
            if not closed:
                await self._reap_after_abandon()
            self._forget_attachment()

    async def _aclose_job_programs(self) -> None:
        """Close the programs this job opened on a server other jobs share, where declared.

        Through the close tool the block's ``sample_open`` names, on the
        server's own tool list. Without that declaration nothing is called.
        """
        from maljan.providers.sample_open import aclose_job_programs, is_shared_address

        spec = getattr(self.config, "sample_open", None)
        if spec is None or not is_shared_address(self.config) or not spec.close_tool:
            return
        tool = self.advertised_tool(spec.close_tool)
        if tool is None:
            return

        async def call(_tool: str, arguments: dict[str, Any]) -> Any:
            return await tool.ainvoke(arguments)

        await aclose_job_programs(self.note_key, spec, self.sample_notes, call)

    def all_tool_names(self) -> list[str]:
        """Every tool the server advertises, allow-list ignored."""
        return [str(getattr(t, "name", "")) for t in self._all_tools]

    def tool_definitions(self) -> list[Any]:
        """Each tool's definition as the server listed it (MCP ``Tool``), allow-list ignored.

        For the settings probe's declaration proposals; empty before an
        attach and for a handle that did not ask to keep them
        (``keeps_tool_definitions``).
        """
        return list(getattr(self._toolkit, "tool_definitions", None) or [])

    def advertised_tool(self, name: str) -> Any | None:
        """The tool the server advertises under ``name``, allow-list ignored, or ``None``."""
        for tool in self._all_tools:
            if str(getattr(tool, "name", "")) == name:
                return tool
        return None

    def _capabilities_tool(self) -> Any | None:
        for tool in self._all_tools:
            if str(getattr(tool, "name", "")) == CAPABILITIES_TOOL:
                return tool
        return None

    def _keep_capabilities(self, payload: Any) -> None:
        parsed = ServerCapabilities.from_payload(self.name, payload)
        if parsed is not None and parsed.server != self.name:
            # A manifest speaks for the server that answered it and no other:
            # one naming another server's key would put its words in that
            # server's reasons (``pipeline.operator_choice``). Kept under this
            # handle's own name.
            logger.warning(
                "mcp server '%s': its manifest names the server %r; read as its own.",
                self.name,
                str(parsed.server)[:80],
            )
            parsed.server = self.name
        self.capabilities = parsed
        # The budgets the server declares for its own tools set how long the
        # guard lets one of their calls run before it counts as unanswered.
        if parsed is not None and self.guard is not None:
            self.guard.declare(parsed.tools)
        if parsed is None:
            logger.warning("mcp server '%s': capabilities answer was not a manifest.", self.name)
            return
        missing = parsed.unavailable()
        if missing:
            logger.info(
                "mcp server '%s': %d tool(s) unavailable on its host: %s",
                self.name,
                len(missing),
                ", ".join(f"{u.tool} ({u.reason})" for u in missing),
            )

    def _read_capabilities(self) -> None:
        """Read the manifest on the synchronous attach path. Never raises."""
        self.capabilities = None
        tool = self._capabilities_tool()
        if tool is None:
            return
        try:
            payload = _run_async_result(
                tool.ainvoke({}),
                label=f"{self.name}-capabilities",
                hard_timeout=CAPABILITIES_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 — a manifest is never worth a lost attach
            logger.warning("mcp server '%s': capabilities could not be read (%s).", self.name, exc)
            return
        self._keep_capabilities(payload)

    async def _aread_capabilities(self) -> None:
        """Read the manifest on the caller's own loop. Never raises."""
        self.capabilities = None
        tool = self._capabilities_tool()
        if tool is None:
            return
        try:
            payload = await asyncio.wait_for(tool.ainvoke({}), CAPABILITIES_TIMEOUT_SECONDS)
        except Exception as exc:  # noqa: BLE001 — a manifest is never worth a lost attach
            logger.warning("mcp server '%s': capabilities could not be read (%s).", self.name, exc)
            return
        self._keep_capabilities(payload)

    def _held_path(self) -> str | None:
        """The job's own copy of the sample on this server: the path the job
        holds there (``held_sample_path``), else the one its provider answers."""
        if self.held_sample_path:
            return self.held_sample_path
        answer = self.error_sample_path() if self.error_sample_path is not None else None
        return answer if isinstance(answer, str) and answer else None

    def tools(self) -> list[BaseTool]:
        """The tools the model may call, decided once per manifest (:meth:`_build_tools`).

        Every reader (an agent's merge, a reference, ``withheld_reasons``)
        reads the same decision, so the wrappers are built once for each
        manifest, allow-list, host manifest, declaration and job note this
        handle holds, not once per reader.
        """
        allowed = self.config.tools
        key = (
            tuple(str(getattr(tool, "name", "")) for tool in self._all_tools),
            self._attach_count,
            None if allowed is None else tuple(allowed),
            self.config.transport,
            repr(getattr(self.config, "sample_open", None)),
            self.reads_own_errors,
        )
        if self._tools_cache is None or self._tools_cache[0] != key:
            self._tools_cache = (key, self._build_tools())
        return list(self._tools_cache[1])

    def _build_tools(self) -> list[BaseTool]:
        """The tools the model may call: the allow-list applied to the manifest.

        ``None`` is "everything the server offers" and is what the two
        built-in sidecars carry, so their tool lists are byte-for-byte what
        the agents attached before this existed. ``[]`` is "nothing", which is
        what a newly registered custom server carries until the operator ticks
        tools off its probe result — a server is connected and inert until
        somebody says which of its tools may run.

        A tool this host cannot run is dropped either way. The manifest the
        server computed at start-up says which those are, and offering one is
        offering the model a step that can only fail; the manifest still names
        it, so the reason and the remedy reach the operator and the degraded
        block. A server that answered no manifest is offered whole, as before.
        """
        from maljan.providers.sample_open import (
            is_shared_address,
            mark_open_tool,
            pin_program_argument,
            wrap_open_tool,
        )

        allowed = self.config.tools
        withheld = self.capabilities.unusable() if self.capabilities else frozenset()
        keep = None if allowed is None else set(allowed)
        offered = [
            tool
            for tool in self._all_tools
            for name in (str(getattr(tool, "name", "")),)
            if name not in withheld and (keep is None or name in keep)
        ]
        every_tool = list(self._all_tools)
        if not self.reads_own_errors:
            from maljan.providers.declared_errors import with_declared_errors

            # Every answer, the open, select and analyse calls the opener
            # makes included, is held against the declared error patterns.
            reading = {
                id(tool): wrapped
                for tool, wrapped in zip(
                    every_tool,
                    with_declared_errors(
                        every_tool, self.config.error_patterns, self.error_sample_path
                    ),
                    strict=True,
                )
            }
            offered = [reading.get(id(tool), tool) for tool in offered]
            every_tool = [reading[id(tool)] for tool in every_tool]
        # A server that declares its open tool has that tool answered through
        # the job's note: a path opened once is not opened again.
        spec = getattr(self.config, "sample_open", None)
        shared = is_shared_address(self.config)
        marked = mark_open_tool(
            wrap_open_tool(
                offered,
                every_tool,
                server=self.note_key,
                spec=spec,
                notes=self.sample_notes,
                held_path=self._held_path,
                shared=shared,
            ),
            spec,
            every_tool,
        )
        # On a server other jobs share, every call is held to the job's own
        # programs and sample: the server's current program is every client's.
        unpinned: dict[str, str] = {}
        offered = pin_program_argument(
            marked,
            server=self.note_key,
            spec=spec,
            notes=self.sample_notes,
            shared=shared,
            held_path=self._held_path,
            withheld=unpinned,
        )
        self._unpinned = unpinned
        return offered

    def _decide_unpinned(self) -> None:
        """Make the shared-server withholding decisions for the tools this handle holds."""
        if self._all_tools:
            self.tools()

    def not_configured_reasons(self) -> list[str]:
        """The reasons of the tools this host's manifest marks unset, which are the operator's.

        A server's own manifest could claim any loss is a setting, so the
        claim is held to what the platform knows of this server. A tool is one
        only when all of these hold: its cell's code is ``not_configured``; it
        names at least one setting; each is one the platform can hand this
        server (a key of its ``env``, or a name in its ``env_allow``); none of
        them holds a value on the platform's side, since one that does never
        reached the server and is a loss; and its reason is exactly what the
        probe says of those settings unset (``Requirement.probe``). The reason
        carries this handle's name, never one the manifest gave
        (``_keep_capabilities``). Anything else is a loss
        (``pipeline.operator_choice``).
        """
        import os

        from maljan.tools.errors import NOT_CONFIGURED

        if self.capabilities is None:
            return []
        env = dict(self.config.env or {})
        allowed = set(self.config.env_allow or ())
        out: list[str] = []
        for missing in self.capabilities.unavailable():
            names = missing.requires
            if (
                missing.code != NOT_CONFIGURED
                or missing.server != self.name
                or not names
                or any(name not in env and name not in allowed for name in names)
                or missing.reason != "; ".join(f"{name} is not configured" for name in names)
            ):
                continue
            held = [
                name
                for name in names
                if env.get(name) or (name in allowed and os.environ.get(name))
            ]
            if not held:
                out.append(missing.degradation_reason)
        return out

    def declared_without_reads(self) -> dict[str, frozenset[str]]:
        """By tool, the routed formats its missing part reads, as this host's manifest says."""
        if self.capabilities is None:
            return {}
        return {
            name: frozenset(str(f) for f in cell["without_reads"])
            for name, cell in self.capabilities.tools.items()
            if isinstance(cell.get("without_reads"), list)
        }

    def withheld_reasons(self) -> list[str]:
        """The degradation reasons for the tools this host cannot run.

        Said where the tool is withheld rather than where it would have been
        bound, so dropping it from the model's list does not also drop the
        sentence that explains the gap. The tools withheld on a shared server
        for want of the job's program (``pin_program_argument``) are decided
        here afresh, so the answer does not depend on ``tools`` being read first.
        """
        self._decide_unpinned()
        unpinned = [self._unpinned[name] for name in sorted(self._unpinned)]
        if self.capabilities is None:
            return unpinned
        withheld = self.capabilities.unusable()
        if not withheld:
            return unpinned
        found = self.capabilities.unavailable(sorted(withheld))
        return [u.degradation_reason for u in found] + unpinned

    def withheld_reason(self, name: str) -> str | None:
        """Why the tool ``name`` is withheld on this host, or ``None`` when it is not.

        A caller asking for one tool by name is told the manifest's reason (a
        credential not configured, a library not installed) and its remedy,
        not only that the tool is missing.
        """
        self._decide_unpinned()
        if name in self._unpinned:
            return self._unpinned[name]
        if self.capabilities is None or name not in self.capabilities.unusable():
            return None
        found = self.capabilities.unavailable([name])
        return found[0].degradation_reason if found else None

    def _teardown(self, toolkit: Any) -> None:
        """Best-effort close of ``toolkit``, attached or abandoned mid-open. Never raises.

        Same rule as ``_close_on_owner``: the exit stack unwinds on the loop
        that wound it. For this path that is the shared agent loop, because
        ``open`` runs ``initialize`` through ``_run_async`` — but the owner is
        read rather than assumed, so a handle that reaches here having been
        opened elsewhere is routed rather than corrupted.

        The close itself goes through ``_close_bounded`` for the same reason
        the async path does: the hard cap in ``_run_coro_blocking`` cancels
        whatever it is waiting on, and cancelling a transport that is still
        parked on a live child is what spins the agent loop (BUG 7). The child
        is killed inside the budget, before that cap can fire.
        """
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        from maljan.agents.base_agent import _get_agent_loop, run_coro_blocking

        owner = self._owner_loop
        budget = SYNC_CLOSE_TIMEOUT
        # The inner fence has to finish strictly inside the hard cap, or the
        # two race and the cap — which cancels, and cancels a transport whose
        # child may still be alive — can win. ``_close_bounded`` spends
        # ``inner + CHILD_EXIT_GRACE``, so the whole of it lands
        # ``CROSS_LOOP_GRACE`` before the cap, the same headroom the routed
        # path leaves.
        inner = budget - CHILD_EXIT_GRACE - CROSS_LOOP_GRACE
        try:
            if owner is None or owner is _get_agent_loop():
                run_coro_blocking(
                    self._close_bounded(closer, inner),
                    hard_timeout=budget,
                    label=f"{self.name}-mcp-close",
                )
            else:
                # Blocking on a loop that is running in *this* thread would
                # deadlock; ``close`` never does that (it skips async-opened
                # handles), and if some future caller tries, say so and let
                # the async path reclaim it.
                closer().close()
                logger.warning(
                    "mcp server '%s' was opened on another loop; the synchronous "
                    "close cannot unwind it, use aclose().",
                    self.name,
                )
                return
        except TimeoutError:
            logger.warning(
                "mcp server '%s' cleanup did not finish in %.0fs; abandoning it "
                "and reaping the child directly.",
                self.name,
                budget,
            )
            self._reap_children()
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)

    def close(self) -> None:
        """Release the client or subprocess. Never raises.

        A handle ``aopen`` attached must be released through ``aclose`` on the
        loop that opened it: the synchronous path here runs the toolkit's
        exit stack through ``_run_coro_blocking`` on the *shared agent loop*,
        which is not the graph loop ``aopen`` wound it on, and produces
        anyio's "cancel scope in a different task" on unwind. Skip it here and
        let the async caller (``ServiceContainer.aclose``) close it instead;
        on the normal path that has already happened by the time this runs.
        """
        if self._opened_async and self._toolkit is not None:
            logger.warning(
                "mcp server '%s' was opened asynchronously and is still attached; "
                "it must be closed through aclose() on the loop that opened it, "
                "skipping the cross-loop teardown here.",
                self.name,
            )
            return
        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            self._forget_attachment()
            return
        try:
            self._teardown(toolkit)
        finally:
            self._forget_attachment()


def _declared_fragment(handle: Any) -> str:
    """The workflow text a handle's server declares (``prompt_fragment``); "" for none."""
    return str(getattr(getattr(handle, "config", None), "prompt_fragment", "") or "")


def _handle_tools_in_force(handle: Any) -> Mapping[str, Any]:
    """The tool declarations in force for a handle's source: its block's, its server's under."""
    from maljan.core.declared_reading import tools_in_force

    source = getattr(handle, "declared_source", None) or f"mcp:{getattr(handle, 'name', '')}"
    return tools_in_force(str(source), getattr(handle, "config", None))


def _declared_aggregates(handle: Any) -> dict[str, tuple[str, ...]]:
    """What a handle's server's tools declare themselves the aggregate form of; {} for none."""
    from maljan.core.undeclared_tools import aggregates_of

    return aggregates_of(_handle_tools_in_force(handle))


def _offered_names(server: str, incoming: Sequence[Any], seen: dict[str, str]) -> dict[str, str]:
    """Each tool of ``server`` a request offers, by its own name, to the name it is offered under.

    The tools arriving now, named by :func:`offered_name` over ``seen`` before
    the merge claims anything, and the ones the server claimed earlier in the
    same tool set.
    """
    prefix = f"{server}__"
    out = {
        name.removeprefix(prefix) if name.startswith(prefix) else name: name
        for name, owner in seen.items()
        if owner == server
    }
    claimed = dict(seen)
    for tool in incoming:
        name = str(getattr(tool, "name", "") or "")
        if name:
            out.setdefault(name, offered_name(server, name, claimed))
    return out


def settle_tool_notes(tools: Sequence[Any], settings: Any = None) -> list[Any]:
    """An agent's whole tool list, each tool with the notes its declaration gives it.

    The one place the notes after a tool's description are settled once every
    name the agent is offered is known: ``aggregate_of`` (each aggregated tool
    named as offered, ``<server>__<tool>`` after a collision, and left out when
    it is not offered) and, while ``mcp.answer_scope_notes`` is on, what the
    tool's answer shows and does not show (``ToolFacts.shows`` /
    ``does_not_show``). Tools are grouped by the source they are declared under
    (``mcp:<key>``, a provider's, the sandbox report's;
    ``tool_pinning.declared_source_of``), so a server's tools merged in several
    halves (bound by ``agents``, named by a ``ToolRef``) are read as one set,
    whatever order they arrived in. A delivery tool, never offered to the model
    (``tool_pinning.DELIVERY_TOOLS``), is not named. Each note is written from
    the tool's own description (``undeclared_tools.with_declared_notes``), so
    a note a provider or a merge wrote earlier is replaced, not repeated, and
    one naming no offered tool is taken off. ``settings`` is the job's
    (default: the process's). A tool with no declared source, or whose source
    declares nothing it reads, is the same object.
    """
    from maljan.agents.tool_pinning import DELIVERY_TOOLS, declared_name_of, declared_source_of
    from maljan.core.declared_reading import declarations
    from maljan.core.undeclared_tools import (
        OWN_DESCRIPTION_METADATA_KEY,
        aggregates_of,
        answer_scopes_of,
        with_declared_notes,
    )

    if settings is None:
        from maljan.core.config import get_settings

        settings = get_settings()
    offered: dict[str, dict[str, str]] = {}
    for tool in tools:
        source = declared_source_of(tool)
        name = str(getattr(tool, "name", "") or "")
        declared = declared_name_of(tool)
        if source is None or not name or declared in DELIVERY_TOOLS:
            continue
        offered.setdefault(source, {}).setdefault(declared, name)
    if not offered:
        return list(tools)
    try:
        held = declarations(settings)
    except Exception as exc:  # noqa: BLE001 — an unreadable declaration adds no note
        logger.debug("tool notes not settled (%s).", type(exc).__name__)
        return list(tools)
    scoped = bool(getattr(getattr(settings, "mcp", None), "answer_scope_notes", False))
    notes: dict[str, tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, str]]]] = {}
    for source in offered:
        try:
            facts = getattr(held.source(source), "tools", None) or {}
        except ValueError:  # a source that does not parse declares nothing
            facts = {}
        notes[source] = (aggregates_of(facts), answer_scopes_of(facts) if scoped else {})
    out: list[Any] = []
    for tool in tools:
        source = declared_source_of(tool)
        aggregates, scopes = notes.get(source or "", ({}, {}))
        noted = OWN_DESCRIPTION_METADATA_KEY in (getattr(tool, "metadata", None) or {})
        if source is not None and (aggregates or scopes or noted):
            tool = with_declared_notes(
                [tool],
                aggregates,
                offered.get(source, {}),
                scopes=scopes,
                declared=declared_name_of,
            )[0]
        out.append(tool)
    return out


def offered_name(server: str, name: str, seen: dict[str, str]) -> str:
    """The name ``server``'s tool ``name`` is offered under, given the names ``seen`` claimed.

    The collision rule of :meth:`ServerRegistry.merge_tools`: a name another
    server claimed is taken as ``<server>__<name>``.
    """
    owner = seen.get(name)
    return name if owner is None or owner == server else f"{server}__{name}"


def _own_words(handle: Any, tools: list[BaseTool], seen: dict[str, str] | None = None) -> str:
    """What a server that declares no workflow text says about itself, for ``tools``.

    Only for a server whose block declares no ``prompt_fragment`` and that
    offers a tool nothing in force declares (its block's ``tool_facts``, and
    what the server declares of itself under them): its served
    MCP ``instructions`` and its offered tools' own descriptions
    (``prompt_fragments.undeclared_server_text``), each tool named as the
    request offers it (:func:`offered_name` over ``seen``, before the merge
    claims anything). A server whose every offered tool is declared says what
    its declaration says, and nothing more. "" otherwise.
    """
    if _declared_fragment(handle).strip():
        return ""
    from maljan.agents.prompt_fragments import undeclared_server_text
    from maljan.agents.tool_pinning import DELIVERY_TOOLS
    from maljan.core.undeclared_tools import declares_a_kind

    declared = _handle_tools_in_force(handle)
    undeclared = [
        tool
        for tool in tools
        for name in (str(getattr(tool, "name", "") or ""),)
        if name not in DELIVERY_TOOLS and not declares_a_kind(declared.get(name))
    ]
    if not undeclared:
        return ""
    server = str(getattr(handle, "name", "") or "")
    claimed = dict(seen or {})
    names = {
        name: offered_name(server, name, claimed)
        for tool in tools
        for name in (str(getattr(tool, "name", "") or ""),)
    }
    instructions = str(getattr(handle, "server_instructions", "") or "")
    return undeclared_server_text(server, instructions, tools, names=names)


def _handle_marks(server: str, handle: ServerHandle) -> dict[str, Any]:
    """The marks each of ``handle``'s tools carries: its token, and whether its server is quiet.

    The server changes nothing when every tool it offers changes nothing
    (``tool_pinning.changes_nothing``: its server or its declaration marks it
    read-only and no declaration vetoes it), read off each tool as stamped with
    the server. A server that offers no tool changes nothing it can be asked to.
    """
    from maljan.agents.tool_pinning import (
        SERVER_CHANGES_NOTHING_METADATA_KEY,
        SERVER_HANDLE_METADATA_KEY,
        changes_nothing,
    )

    def _stamped(tool: Any) -> Any:
        metadata = {**(getattr(tool, "metadata", None) or {}), "maljan_server": server}
        try:
            return tool.model_copy(update={"metadata": metadata})
        except Exception:  # noqa: BLE001 — a tool that cannot be copied may change anything
            return None

    try:
        stamped = [_stamped(tool) for tool in handle.tools()]
        quiet = all(tool is not None and changes_nothing(tool) for tool in stamped)
    except Exception:  # noqa: BLE001 — an unread manifest may hold anything
        quiet = False
    return {
        SERVER_HANDLE_METADATA_KEY: f"{handle.name}#{id(handle)}",
        SERVER_CHANGES_NOTHING_METADATA_KEY: quiet,
    }


class ServerRegistry:
    """The tool servers one job may attach, built from ``cfg.mcp.servers``."""

    def __init__(
        self,
        cfg: Settings,
        *,
        truncation_ledger: Any | None = None,
        context_budget: Any | None = None,
        event_sink: Any | None = None,
        sample_notes: Any | None = None,
        sample_sha256: Callable[[], str] | None = None,
        server_changes: Any | None = None,
    ) -> None:
        from maljan.providers.sample_open import SampleNotes
        from maljan.providers.server_guard import guard_from_settings

        self._handles = {
            name: ServerHandle(name, config) for name, config in cfg.mcp.servers.items()
        }
        # What an agent's merged tool list is settled against (``settle_tool_notes``).
        self._settings = cfg
        # The job's note of the paths each server opened, for the servers
        # that declare their open tool; one per job, given to every handle.
        self.sample_notes = sample_notes if sample_notes is not None else SampleNotes()
        for handle in self._handles.values():
            handle.sample_notes = self.sample_notes
            # A job's server: its process is measured for the run's isolation part.
            handle.measures_isolation = True
            # The job's change count, which each attach of the server bumps.
            handle.server_changes = server_changes
        # Every rest this job gave a server, in the order the breakers opened;
        # the judge node reads it into the run summary. Written from whichever
        # loop's call tripped the breaker, so appended under the lock.
        self.rests: list[dict[str, Any]] = []
        self._event_sink = event_sink
        # Weakly: a guard lives on the handle and the handle may outlive the
        # registry (``_LIVE_HANDLES``), and a guard holding its registry
        # would keep a finished job's whole registry, and every handle in
        # it, alive with it.
        rested = weakref.WeakMethod(self._rested)

        def _on_open(record: dict[str, Any]) -> None:
            method = rested()
            if method is not None:
                method(record)

        for name, handle in self._handles.items():
            handle.guard = guard_from_settings(
                name,
                cfg,
                on_open=_on_open,
                sample_open=getattr(handle.config, "sample_open", None),
                block=handle.config,
                label=str(getattr(handle.config, "label", "") or ""),
            )
        # The job's own bound-hit ledger and the job's own tool-output limit,
        # put on every toolkit this registry opens. Both used to be left to the
        # caller: every attach but the static provider's passed neither, so the
        # guardrail on a tool server's answer counted on nothing and cut at the
        # signature's own default rather than at the number the operator set.
        self._truncation_ledger = truncation_ledger
        # The run's sample, read when a server is attached (it is known only
        # once the job has started): the platform's fact, never the model's.
        self._sample_sha256 = sample_sha256
        self._max_output_chars = int(getattr(cfg.preprocessing, "max_tool_output_chars", 0) or 0)
        # What that limit means when it is zero: the window the served model
        # was found to have, spent per call. The budget travels with the attach
        # for the same reason the ledger does — a toolkit opened without it
        # would size its answers against a window nobody measured.
        self._context_budget = context_budget
        # A handle is bound to the loop that opened it, so a caller on another
        # running loop cannot be handed it — see ``_handle_for``. These are
        # the extra handles that answer for those callers, keyed by server and
        # loop identity. Empty in the default profile, where every attach
        # happens on the shared agent loop.
        self._loop_handles: dict[tuple[str, int], ServerHandle] = {}
        # ``_loop_handles`` is reached from the agent loop's thread and the
        # graph loop's thread, which is the whole point of it existing.
        self._lock = threading.Lock()
        # Every reason ``tools_for`` has produced this job, in order and
        # without duplicates. The judge node reads it into
        # ``degradation_reasons`` so the run summary says which server was
        # missing, rather than the report simply being thinner than the last.
        self.degradation_reasons: list[str] = []

    def answer_sizer(self) -> Any:
        """The MCP toolkit's own answer guardrail, for an in-process tool's answer.

        An in-process tool — the sandbox report's views — has no server and so
        no toolkit, and its answers used to reach the model at whatever size
        they had. This is the same guardrail an MCP answer goes through, with
        this job's limit, ledger and context budget: the size measured against
        the room the conversation has, a JSON answer shortened as a document
        with its bookkeeping key, and the budget charged. One path, not a copy.
        """
        from maljan.agents.mcp_client import MCPLangChainToolkit

        return MCPLangChainToolkit(
            None,
            max_output_chars=self._max_output_chars,
            truncation_ledger=self._truncation_ledger,
            context_budget=self._context_budget,
        )

    def rest_hook(self) -> Callable[[dict[str, Any]], None]:
        """What a provider that guards its own server calls when its breaker opens.

        Weak, like the registry's own guards: a context outliving the registry
        must not keep it alive.
        """
        rested = weakref.WeakMethod(self._rested)

        def hook(record: dict[str, Any]) -> None:
            method = rested()
            if method is not None:
                method(record)

        return hook

    def _rested(self, record: dict[str, Any]) -> None:
        """Keep one breaker opening for the run summary and announce it."""
        from maljan.pipeline.events import emit_tool_server_rested

        with self._lock:
            self.rests.append(dict(record))
        emit_tool_server_rested(self._event_sink, record)

    def _attach(self, context: dict[str, Any]) -> dict[str, Any]:
        """The attach context, with this job's ledger, limit and budget in it.

        One ledger per job: the registry's is the job's, so a toolkit it opens
        records where the run summary reads, whatever the caller thought to
        pass. A caller naming a different ledger is told, because a second
        ledger is a count that reaches no reader.

        The limit is written unconditionally, zero included. Zero is the
        operator asking for the derived cap, and a ``setdefault`` guarded on a
        positive number would have left that request looking exactly like a
        caller who said nothing — which is how every attach but one came to cut
        at a signature default in the first place.
        """
        out = dict(context)
        if self._truncation_ledger is not None:
            named = out.get("truncation_ledger")
            if named is not None and named is not self._truncation_ledger:
                logger.warning(
                    "a tool server was asked to record on a ledger other than the job's; "
                    "the job's ledger is used."
                )
            out["truncation_ledger"] = self._truncation_ledger
        named_limit = out.get("max_output_chars")
        if named_limit is not None and int(named_limit) != self._max_output_chars:
            logger.warning(
                "a tool server was asked to cut its answers at %s rather than the job's %s; "
                "the job's limit is used.",
                named_limit,
                self._max_output_chars,
            )
        out["max_output_chars"] = self._max_output_chars
        if self._context_budget is not None:
            out["context_budget"] = self._context_budget
        # Written unconditionally: a caller's own value is never the job's.
        out["sample_sha256"] = (self._sample_sha256() if self._sample_sha256 else "") or ""
        return out

    def _handle_for(self, handle: ServerHandle, loop: asyncio.AbstractEventLoop) -> ServerHandle:
        """The handle ``loop`` may use for this server, its own if need be.

        A ``ClientSession`` and the anyio scopes under it belong to the loop
        that opened them; handing the same handle to a second live loop is how
        a tool call ends up awaiting a future the calling loop can never
        complete — the call-time twin of the teardown hang, and a property the
        pre-branch judge had for free because every ``JudgeAgent`` built its
        own toolkit and its own subprocess.

        So: an unopened handle, or one already bound to ``loop``, is shared as
        before. A handle bound elsewhere is replaced for this caller by a
        second handle over the same config — its own transport, its own child,
        the same name, the same allow-list, so the tool set and the
        degradation reasons are unchanged.
        """
        with self._lock:
            owner = handle._owner_loop
            if owner is None or owner is loop:
                return handle
            key = (handle.name, id(loop))
            replica = self._loop_handles.get(key)
            if replica is None or replica._owner_loop not in (None, loop):
                replica = ServerHandle(handle.name, handle.config)
                # The same server to the job: a rest one loop's calls earned
                # is a rest for every loop's.
                replica.guard = handle.guard
                # The job's note: a remote server's opens are noted under its
                # address, a local process's under its own handle.
                replica.sample_notes = handle.sample_notes
                # The job's own copy of the sample there, the same for every loop.
                replica.held_sample_path = handle.held_sample_path
                replica.declared_source = handle.declared_source
                replica.measures_isolation = handle.measures_isolation
                # Its own process or session: its attach counts as a change.
                replica.server_changes = handle.server_changes
                self._loop_handles[key] = replica
                logger.info(
                    "mcp server '%s' is attached on another loop; the caller gets "
                    "its own handle rather than sharing a session across loops.",
                    handle.name,
                )
            return replica

    def hold_sample_path(self, server: str, path: str | None, *, fallback: bool = False) -> None:
        """Note ``path`` as the job's own copy of the sample on ``server``, on every handle.

        The path the server opens for the job (its mirror under the declared
        mount, or where the sample was staged to it): on a server other jobs
        share, the only path an open may name (``pin_program_argument``). Set
        on the handle and on each of its per-loop replicas; a replica made
        later copies it. A ``fallback`` path (an agent's own, not the
        server's) never replaces one already held.
        """
        if not path:
            return
        with self._lock:
            handles = [h for h in (self._handles.get(server),) if h is not None]
            handles += [h for (name, _loop), h in self._loop_handles.items() if name == server]
        for handle in handles:
            if fallback and handle.held_sample_path:
                continue
            handle.held_sample_path = path

    def _all_handles(self) -> list[ServerHandle]:
        """Every handle this registry has handed out, per-loop ones included."""
        with self._lock:
            return [*self._handles.values(), *self._loop_handles.values()]

    def not_configured_reasons(self) -> list[str]:
        """Each attached server's unset settings (``ServerHandle.not_configured_reasons``)."""
        out: list[str] = []
        for handle in self._all_handles():
            out.extend(r for r in handle.not_configured_reasons() if r not in out)
        return out

    def declared_without_reads(self) -> dict[tuple[str, str], frozenset[str]]:
        """By ``(server, tool)``, the routed formats each tool's missing part reads."""
        out: dict[tuple[str, str], frozenset[str]] = {}
        for handle in self._all_handles():
            for tool, formats in handle.declared_without_reads().items():
                out.setdefault((handle.name, tool), formats)
        return out

    def handles_for(self, role: str, *, exclude: str = "") -> list[ServerHandle]:
        """``for_agent``, plus the per-loop handles for the same servers.

        For a caller that has to release a role's servers without knowing
        which loop attached them — ``JudgeAgent.aclose``. Each handle closes
        on its own loop, so the caller does not have to care.
        """
        names = {handle.name for handle in self.for_agent(role, exclude=exclude)}
        return [handle for handle in self._all_handles() if handle.name in names]

    def get(self, name: str) -> ServerHandle:
        handle = self._handles.get(name)
        if handle is None:
            available = ", ".join(sorted(self._handles)) or "(none)"
            raise ProviderConfigurationError(
                f"Unknown mcp server: {name!r}. Available: {available}"
            )
        return handle

    def for_agent(
        self, role: str, *, exclude: str = "", builtin: bool | None = None
    ) -> list[ServerHandle]:
        """Enabled servers bound to ``role``, built-ins first then by key.

        Order is what makes the collision rule predictable: a built-in is
        attached before any custom server, so a custom server that happens to
        name a tool ``extract_dns`` is the one that gets renamed, and the
        pinned built-in tool names never move. Across an agent's whole tool
        set the same holds through :meth:`agent_tools`, which claims the bound
        built-ins, then the servers the agent's own definition names, and only
        then the operator's servers bound by ``agents``.

        ``builtin`` keeps only the built-in servers (``True``) or only the
        others (``False``); ``None`` keeps both, in the order above.

        ``exclude`` drops handles by name — the server a provider already
        opened itself, so the registry does not hand the same tools out twice,
        and the set a profile withholds (``ProfileDefinition.exclude_servers``,
        which is how the ``measurement`` baseline runs the same analysts with
        no tools). One name or several comma-separated; the single-name form is
        the older caller and stays exactly what it was. ``*`` among them means
        every server, so a baseline stays tool-free against servers that did
        not exist when it was written.
        """
        from maljan.core.config import ALL_SERVERS, BUILTIN_SERVER_KEYS

        excluded = {name.strip() for name in exclude.split(",") if name.strip()}
        if ALL_SERVERS in excluded:
            return []
        bound = [
            handle
            for handle in self._handles.values()
            if handle.config.enabled
            and role in handle.config.agents
            and handle.name not in excluded
            and (builtin is None or (handle.name in BUILTIN_SERVER_KEYS) is builtin)
        ]
        return sorted(bound, key=lambda h: (h.name not in BUILTIN_SERVER_KEYS, h.name))

    def merge_tools(
        self,
        server: str,
        incoming: list[BaseTool],
        tools: list[BaseTool],
        seen: dict[str, str],
        *,
        fragment: str = "",
        own_words: str = "",
        aggregates: Mapping[str, Sequence[str]] | None = None,
        handle: ServerHandle | None = None,
    ) -> int:
        """Append ``incoming`` to ``tools`` under the collision rule.

        ``seen`` maps a claimed tool name to the server that claimed it, which
        is what lets the rule span an agent's whole tool set rather than one
        ``tools_for`` call: a name another server already claimed is taken by
        this server as ``<server>__<tool>``, while the *same* server's same
        tool arriving twice — bound by ``agents`` and named again by a
        ``ToolRef`` — collapses to one copy. Nothing is dropped for a
        collision; only an exact repeat of one server's own tool is.

        Every merged tool is stamped with the server it came from
        (``metadata["maljan_server"]``). ``agents.tool_pinning`` reads that to
        pick the right sample path per server: a remote tool server was handed
        the bytes at a path of its own, and a wrapper that pinned one path for
        every tool would send the local one to the remote server.

        ``fragment`` is the workflow text the server declares (its
        ``prompt_fragment``); it rides with each tool
        (``metadata["maljan_server_fragment"]``), so the prompt built from the
        list shows it only while the server's tools are there. ``own_words``
        is what a server that declares none says about itself
        (:func:`_own_words`), carried the same way
        (``metadata["maljan_server_own_words"]``). ``aggregates`` is what the
        server's tools declare themselves the aggregate form of
        (``ToolFacts.aggregate_of``): such a tool's description gains a note
        naming each aggregated tool this request offers, under the name it is
        offered (``core.undeclared_tools.with_aggregate_notes``), the names
        settled before anything is claimed, as :func:`_own_words` settles them.

        ``handle`` is the server handle the tools call through: each tool is
        stamped with its token and with whether that server exposes no tool
        that may change it (:func:`_handle_marks`), which decide whether an
        answer read through one handle is served to a call through another
        (``agents.evidence_recorder``).

        Returns how many tools were renamed, so the caller can log it once
        per server instead of per tool.
        """
        if aggregates:
            from maljan.core.undeclared_tools import with_aggregate_notes

            offered_as = _offered_names(server, incoming, seen)
            incoming = with_aggregate_notes(incoming, aggregates, offered_as)
        renamed = 0
        marks = _handle_marks(server, handle) if handle is not None else {}
        for tool in incoming:
            name = str(getattr(tool, "name", ""))
            owner = seen.get(name)
            if owner == server:
                continue
            offered = offered_name(server, name, seen)
            metadata = {
                **(getattr(tool, "metadata", None) or {}),
                "maljan_server": server,
                **marks,
            }
            if fragment.strip():
                metadata["maljan_server_fragment"] = fragment
            elif own_words.strip():
                metadata["maljan_server_own_words"] = own_words
            update: dict[str, Any] = {"metadata": metadata}
            if offered != name:
                if seen.get(offered) == server:
                    continue
                update["name"] = offered
                # The server declares the tool under the name it gave it.
                from maljan.agents.tool_pinning import DECLARED_NAME_METADATA_KEY

                metadata[DECLARED_NAME_METADATA_KEY] = name
                name = offered
                renamed += 1
            tool = tool.model_copy(update=update)
            seen[name] = server
            tools.append(tool)
        return renamed

    def _merge(self, handle: ServerHandle, tools: list[BaseTool], seen: dict[str, str]) -> int:
        # A tool the host cannot run is no longer put in front of the model, so
        # the stage that binds it can no longer be the thing that reports it.
        # It is reported here instead, where it is withheld, and reaches the
        # degraded block exactly as it did before.
        offered = handle.tools()
        self._record(handle.withheld_reasons())
        return self.merge_tools(
            handle.name,
            offered,
            tools,
            seen,
            fragment=_declared_fragment(handle),
            own_words=_own_words(handle, offered, seen),
            aggregates=_declared_aggregates(handle),
            handle=handle,
        )

    def tools_for(
        self,
        role: str,
        job_id: str,
        *,
        exclude: str = "",
        seen: dict[str, str] | None = None,
        builtin: bool | None = None,
        **context: Any,
    ) -> tuple[list[BaseTool], list[str]]:
        """Open every server bound to ``role`` and concatenate their tools.

        Returns the tools and the degradation reasons: one per server that
        could not be opened. A failure here is never raised — the caller keeps
        the tools it did get, and the run summary says which server is missing
        rather than the report quietly being thinner than the last one.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen = {} if seen is None else seen
        context = self._attach(context)
        from maljan.agents.base_agent import _get_agent_loop

        # ``open`` hands ``initialize`` to the shared agent loop, so that is
        # the loop this caller is really attaching on.
        agent_loop = _get_agent_loop()
        for bound in self.for_agent(role, exclude=exclude, builtin=builtin):
            handle = self._handle_for(bound, agent_loop)
            try:
                handle.open(job_id, **context)
            except Exception as exc:  # noqa: BLE001 — a registry server always degrades
                logger.warning(
                    "mcp server '%s' could not be attached for the %s analyst: %s",
                    handle.name,
                    role,
                    exc,
                )
                reason = UNAVAILABLE_REASON.format(name=handle.name)
                reasons.append(reason)
                if reason not in self.degradation_reasons:
                    self.degradation_reasons.append(reason)
                continue
            renamed = self._merge(handle, tools, seen)
            if renamed:
                logger.info(
                    "mcp server '%s': %d tool name(s) already taken, prefixed with '%s__'.",
                    handle.name,
                    renamed,
                    handle.name,
                )
        return tools, reasons

    async def atools_for(
        self,
        role: str,
        job_id: str,
        *,
        exclude: str = "",
        seen: dict[str, str] | None = None,
        builtin: bool | None = None,
        **context: Any,
    ) -> tuple[list[BaseTool], list[str]]:
        """``tools_for``, but ``await``ed on the caller's own loop.

        For a caller already inside an event loop (the judge's graph node),
        where handing the attach to the shared agent loop would bind the
        toolkit's transport to a loop other than the one that later awaits
        its tool calls.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen = {} if seen is None else seen
        context = self._attach(context)
        loop = asyncio.get_running_loop()
        for bound in self.for_agent(role, exclude=exclude, builtin=builtin):
            handle = self._handle_for(bound, loop)
            try:
                await handle.aopen(job_id, **context)
            except Exception as exc:  # noqa: BLE001 — a registry server always degrades
                logger.warning(
                    "mcp server '%s' could not be attached for the %s analyst: %s",
                    handle.name,
                    role,
                    exc,
                )
                reason = UNAVAILABLE_REASON.format(name=handle.name)
                reasons.append(reason)
                if reason not in self.degradation_reasons:
                    self.degradation_reasons.append(reason)
                continue
            renamed = self._merge(handle, tools, seen)
            if renamed:
                logger.info(
                    "mcp server '%s': %d tool name(s) already taken, prefixed with '%s__'.",
                    handle.name,
                    renamed,
                    handle.name,
                )
        return tools, reasons

    def _ref_tools(self, handle: ServerHandle, ref: Any) -> tuple[list[BaseTool], list[str]]:
        """The tools one open handle contributes for ``ref``, and any reason it did not.

        ``ref.name is None`` is the whole allow-listed set — the same list
        ``tools_for`` would have merged had the server been bound by ``agents``.
        A name is one tool of it, matched against the server's own manifest —
        collision prefixing happens later, in ``merge_tools``, so a manifest
        name reaching here is always raw.
        """
        if not handle.config.enabled:
            # A reference to a server the operator switched off is a stale
            # reference, and says so, whether it named one tool or the set.
            unavailable = AGENT_TOOL_UNAVAILABLE_REASON.format(
                server=handle.name, name=ref.name or "*"
            )
            return [], [f"{unavailable}: {SERVER_DISABLED}"]
        available = handle.tools()
        if ref.name is None:
            return list(available), handle.withheld_reasons()
        wanted = str(ref.name)
        picked = [tool for tool in available if str(getattr(tool, "name", "")) == wanted]
        if not picked:
            unavailable = AGENT_TOOL_UNAVAILABLE_REASON.format(server=handle.name, name=wanted)
            withheld = handle.withheld_reason(wanted)
            return [], [f"{unavailable}: {withheld}" if withheld else unavailable]
        return picked, []

    def _record(self, reasons: list[str]) -> None:
        for reason in reasons:
            if reason not in self.degradation_reasons:
                self.degradation_reasons.append(reason)

    def tools_for_ref(
        self, ref: Any, job_id: str, *, seen: dict[str, str] | None = None, **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """One ``ToolRef(kind="mcp")``'s tools, opened on the shared agent loop.

        The reference half of an agent's tool set. Never raises, for the same
        reason ``tools_for`` never does: a definition that points at a server
        which is down costs the agent depth, not the job.
        """
        from maljan.agents.base_agent import _get_agent_loop

        context = self._attach(context)
        try:
            handle = self._handle_for(self.get(str(ref.server)), _get_agent_loop())
        except ProviderConfigurationError:
            reasons = [
                AGENT_TOOL_UNAVAILABLE_REASON.format(server=ref.server, name=ref.name or "*")
            ]
            self._record(reasons)
            return [], reasons
        try:
            handle.open(job_id, **context)
        except Exception as exc:  # noqa: BLE001 — a referenced server always degrades
            logger.warning("mcp server '%s' could not be attached: %s", handle.name, exc)
            reasons = [UNAVAILABLE_REASON.format(name=handle.name)]
            self._record(reasons)
            return [], reasons
        picked, reasons = self._ref_tools(handle, ref)
        self._record(reasons)
        tools: list[BaseTool] = []
        claimed: dict[str, str] = {} if seen is None else seen
        renamed = self.merge_tools(
            handle.name,
            picked,
            tools,
            claimed,
            fragment=_declared_fragment(handle),
            own_words=_own_words(handle, picked, claimed),
            aggregates=_declared_aggregates(handle),
            handle=handle,
        )
        if renamed:
            logger.info(
                "mcp server '%s': %d referenced tool name(s) already taken, prefixed with '%s__'.",
                handle.name,
                renamed,
                handle.name,
            )
        return tools, reasons

    async def atools_for_ref(
        self, ref: Any, job_id: str, *, seen: dict[str, str] | None = None, **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """``tools_for_ref``, awaited on the caller's own loop."""
        context = self._attach(context)
        loop = asyncio.get_running_loop()
        try:
            handle = self._handle_for(self.get(str(ref.server)), loop)
        except ProviderConfigurationError:
            reasons = [
                AGENT_TOOL_UNAVAILABLE_REASON.format(server=ref.server, name=ref.name or "*")
            ]
            self._record(reasons)
            return [], reasons
        try:
            await handle.aopen(job_id, **context)
        except Exception as exc:  # noqa: BLE001 — a referenced server always degrades
            logger.warning("mcp server '%s' could not be attached: %s", handle.name, exc)
            reasons = [UNAVAILABLE_REASON.format(name=handle.name)]
            self._record(reasons)
            return [], reasons
        picked, reasons = self._ref_tools(handle, ref)
        self._record(reasons)
        tools: list[BaseTool] = []
        claimed: dict[str, str] = {} if seen is None else seen
        renamed = self.merge_tools(
            handle.name,
            picked,
            tools,
            claimed,
            fragment=_declared_fragment(handle),
            own_words=_own_words(handle, picked, claimed),
            aggregates=_declared_aggregates(handle),
            handle=handle,
        )
        if renamed:
            logger.info(
                "mcp server '%s': %d referenced tool name(s) already taken, prefixed with '%s__'.",
                handle.name,
                renamed,
                handle.name,
            )
        return tools, reasons

    def agent_tools(
        self,
        role: str,
        job_id: str,
        refs: Iterable[Any],
        *,
        exclude: str = "",
        seen: dict[str, str] | None = None,
        **context: Any,
    ) -> tuple[list[BaseTool], list[str]]:
        """An agent's server tools under one collision rule: its own names never move.

        Three halves under one ``seen`` map, claimed in this order: the
        built-in servers bound to ``role`` by ``MCPServerConfig.agents``, the
        servers the agent's own definition names (``refs``, its ``ToolRef``
        servers), then every other server bound to ``role`` by ``agents``. A
        server an operator binds to a role is an addition to the agent: where
        one of its tool names is taken by a built-in or by a server the agent
        names itself, it is the operator's tool that is offered as
        ``<server>__<tool>``, and the tool names the agent's prompt and
        workflow text were written against stay bare. ``seen`` may arrive
        holding the names the agent's in-process tools claimed (its provider's,
        its sandbox's), which therefore never move either. A server both bound
        and named contributes one copy.

        The notes after each tool's description are settled once over the
        merged list (:func:`settle_tool_notes`), so a server's tool reached in
        one half names the tools of the same server another half offered.
        """
        seen = {} if seen is None else seen
        tools, reasons = self.tools_for(
            role, job_id, exclude=exclude, seen=seen, builtin=True, **context
        )
        for ref in refs:
            picked, ref_reasons = self.tools_for_ref(ref, job_id, seen=seen, **context)
            tools.extend(picked)
            reasons.extend(ref_reasons)
        added, added_reasons = self.tools_for(
            role, job_id, exclude=exclude, seen=seen, builtin=False, **context
        )
        tools.extend(added)
        reasons.extend(added_reasons)
        return settle_tool_notes(tools, getattr(self, "_settings", None)), reasons

    async def aagent_tools(
        self,
        role: str,
        job_id: str,
        refs: Iterable[Any],
        *,
        exclude: str = "",
        seen: dict[str, str] | None = None,
        **context: Any,
    ) -> tuple[list[BaseTool], list[str]]:
        """:meth:`agent_tools`, awaited on the caller's own loop."""
        seen = {} if seen is None else seen
        tools, reasons = await self.atools_for(
            role, job_id, exclude=exclude, seen=seen, builtin=True, **context
        )
        for ref in refs:
            picked, ref_reasons = await self.atools_for_ref(ref, job_id, seen=seen, **context)
            tools.extend(picked)
            reasons.extend(ref_reasons)
        added, added_reasons = await self.atools_for(
            role, job_id, exclude=exclude, seen=seen, builtin=False, **context
        )
        tools.extend(added)
        reasons.extend(added_reasons)
        return settle_tool_notes(tools, getattr(self, "_settings", None)), reasons

    def server_versions(self) -> dict[str, dict[str, str]]:
        """Per configured server this job attached, the name and version it gave for itself.

        A server attached on more than one loop gave the same answer each
        time; the first handle's is kept. A server that gave neither is
        listed with nothing, so it is told apart from one never attached.
        """
        out: dict[str, dict[str, str]] = {}
        for handle in self._all_handles():
            info = getattr(handle, "server_info", None) or {}
            if handle.name in out:
                continue
            if info or handle.is_open or getattr(handle, "attached_once", False):
                out[handle.name] = dict(info)
        return dict(sorted(out.items()))

    def still_open(self) -> list[ServerHandle]:
        """Every handle still attached, per-loop ones included.

        What ``ServiceContainer.aclose`` awaits after the synchronous sweep,
        rather than the sweep's return value: the sweep now runs in an
        executor and may be abandoned, and a handle that is still open needs
        closing whether or not the call that should have closed it came back.
        """
        return [handle for handle in self._all_handles() if handle.is_open]

    def close_all(self) -> list[ServerHandle]:
        """Close every handle this job attached synchronously.

        Returns the handles ``close()`` could not touch because ``aopen``
        attached them — still open, so the caller must ``await
        handle.aclose()``, which routes each one back to the loop that opened
        it; ``ServiceContainer.aclose`` does exactly that. Per-loop handles
        are included: a job that attached the same server from two loops has
        two children to release, on two loops.
        """
        skipped = []
        for handle in self._all_handles():
            handle.close()
            if handle.is_open:
                skipped.append(handle)
        return skipped
