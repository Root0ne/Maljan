"""Every MCP server Maljan attaches, and the one lifecycle they share.

Before sub-project B there were three copies of "start an MCP server and take
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
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.core.config import MCPServerConfig, Settings

# The reason string a failed server contributes to ``degradation_reasons``.
UNAVAILABLE_REASON = "mcp server '{name}' unavailable"

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
# How long one toolkit's own cleanup may take before it is abandoned. An
# ``mcp`` stdio exit stack closes the child's stdin, waits, then escalates
# SIGTERM -> SIGKILL; this is comfortably past that escalation.
CLEANUP_TIMEOUT = 12.0

# Extra headroom for a cleanup routed to another loop: the owning loop still
# applies ``CLEANUP_TIMEOUT`` itself, so this only has to outlast the hop.
CROSS_LOOP_GRACE = 2.0

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


def _run_async(coro: Any, label: str) -> None:
    """Run an MCP-client coroutine on the shared agent loop.

    Same rationale as ``GenericMCPStaticProvider._run_async``: a toolkit's
    transport binds its async primitives to whichever loop first creates it,
    and the ReAct tool calls later run on the process-wide agent loop, so init
    has to run there too rather than on a throwaway loop. A module-level
    function rather than a method so a test can replace it in one place.
    """
    from maljan.agents.base_agent import _run_coro_blocking

    _run_coro_blocking(coro, hard_timeout=120.0, label=label)


class ServerHandle:
    """One configured MCP server, attached for at most one job at a time."""

    def __init__(self, name: str, config: MCPServerConfig) -> None:
        self.name = name
        self.config = config
        self._toolkit: Any = None
        self._all_tools: list[Any] = []
        self._job_id: str = ""
        # True once ``aopen`` has attached this handle: its exit stack was
        # wound on whichever loop called it, so it must be unwound there too
        # (see F6 / ``close``).
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
        # The argv that child was launched with, which is what makes the pid
        # above this handle's rather than merely contemporaneous.
        self._launch_argv: tuple[str, ...] = ()

    @property
    def is_open(self) -> bool:
        return self._toolkit is not None

    @property
    def label(self) -> str:
        return self.config.label or self.name

    def _resolve_cwd(self) -> str | None:
        """The child's working directory, refused when it escapes the project.

        ``cwd`` is an operator setting that becomes a subprocess's working
        directory, so it gets the same treatment every other path-shaped
        setting gets: a relative value is rooted at the project directory and
        must stay inside it; an absolute value is allowed but must exist.
        Neither check is a sandbox — an operator who can edit settings can
        already run a command — it is there so a typo fails loudly at attach
        time instead of starting a server in an unexpected directory.
        """
        from maljan.core.paths import get_project_root

        if not self.config.cwd:
            return None
        root = Path(get_project_root()).resolve()
        candidate = Path(self.config.cwd)
        if candidate.is_absolute():
            resolved = candidate.resolve()
            if not resolved.is_dir():
                raise ProviderConfigurationError(
                    f"mcp server {self.name!r}: cwd {resolved} does not exist"
                )
            return str(resolved)
        resolved = (root / candidate).resolve()
        if not resolved.is_relative_to(root):
            raise ProviderConfigurationError(
                f"mcp server {self.name!r}: cwd {self.config.cwd!r} resolves outside the project"
            )
        if not resolved.is_dir():
            raise ProviderConfigurationError(
                f"mcp server {self.name!r}: cwd {resolved} does not exist"
            )
        return str(resolved)

    def _build_toolkit(
        self,
        output_guardrail: Callable[[str], str] | None,
        max_output_chars: int,
        truncation_ledger: Any | None,
    ) -> Any:
        """Everything ``open`` does except awaiting ``initialize``.

        Factored out because the judge enters its toolkit with a plain
        ``await`` on the graph's own loop while the analysts hand theirs to
        the shared agent loop — the asymmetry ``JudgeAgent.aclose`` documents
        — and the only safe way to have both is one construction path and two
        ways of running the coroutine it returns.
        """
        from maljan.agents.mcp_client import MCPLangChainToolkit

        if self.config.transport == "stdio":
            from mcp import StdioServerParameters

            from maljan.agents.subprocess_env import child_env
            from maljan.core.config import BUILTIN_SERVER_KEYS
            from maljan.core.paths import resolve_mcp_args

            env = child_env(self.config.env, allow=tuple(self.config.env_allow))
            if self.name not in BUILTIN_SERVER_KEYS:
                # Byte-for-byte with the pre-branch built-ins (spec S3.2): the
                # in-repo network/threatintel sidecars were launched with a
                # bare ``child_env(...)``, which carries PYTHONIOENCODING only
                # when the parent process already has it set. A server the
                # operator adds through the catalog gets the more predictable
                # default instead.
                env.setdefault("PYTHONIOENCODING", "utf-8")
            args = resolve_mcp_args(list(self.config.args))
            # Kept so the backstop reap can tell this handle's child from any
            # other subprocess that happened to start in the same window; see
            # ``_child_matches``.
            self._launch_argv = (self.config.command, *args)
            params = StdioServerParameters(
                command=self.config.command,
                args=args,
                env=env,
                cwd=self._resolve_cwd(),
            )
            return MCPLangChainToolkit(
                params,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
            )
        # An http/sse transport has no child of ours to reap.
        self._launch_argv = ()
        token = self.config.auth_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return MCPLangChainToolkit(
            transport=self.config.transport,
            http_url=self.config.url,
            http_headers=headers,
            output_guardrail=output_guardrail,
            max_output_chars=max_output_chars,
            truncation_ledger=truncation_ledger,
        )

    def open(
        self,
        job_id: str,
        *,
        output_guardrail: Callable[[str], str] | None = None,
        max_output_chars: int = 8000,
        truncation_ledger: Any | None = None,
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
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return

        toolkit = self._build_toolkit(output_guardrail, max_output_chars, truncation_ledger)

        before = _own_child_pids()
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
        self._opened_async = False
        # ``_run_async`` hands the coroutine to the shared agent loop, so that
        # is the loop this toolkit's exit stack was wound on.
        from maljan.agents.base_agent import _get_agent_loop

        self._owner_loop = _get_agent_loop()
        self._note_child_pids(before)
        self._all_tools = list(toolkit.get_tools())
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
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return
        toolkit = self._build_toolkit(
            context.get("output_guardrail"),
            int(context.get("max_output_chars", 8000)),
            context.get("truncation_ledger"),
        )
        # Recorded *before* ``initialize``, so the failure path below unwinds
        # on the loop that wound the partial attach too.
        self._owner_loop = asyncio.get_running_loop()
        before = _own_child_pids()
        try:
            await toolkit.initialize()
        except (Exception, asyncio.CancelledError):
            logger.warning(
                "mcp server '%s' failed to initialize; closing the partial attach.",
                self.name,
            )
            # The child a half-open transport already spawned is this handle's
            # too, and nothing else knows about it.
            self._note_child_pids(before)
            if not await self._acleanup(toolkit):
                await self._reap_after_abandon()
            self._child_pids = ()
            raise
        self._toolkit = toolkit
        self._opened_async = True
        self._note_child_pids(before)
        self._all_tools = list(toolkit.get_tools())

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
        """
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return True
        try:
            # A stdio transport's exit stack waits on the child process, and a
            # child that does not exit waits forever — the 42-minute teardown
            # ``JudgeAgent.aclose`` was written for.
            await asyncio.wait_for(closer(), timeout=CLEANUP_TIMEOUT)
        except TimeoutError:
            logger.warning(
                "mcp server '%s' cleanup did not finish in %.0fs; abandoning it.",
                self.name,
                CLEANUP_TIMEOUT,
            )
            return False
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)
            return False
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
        future = asyncio.run_coroutine_threadsafe(self._acleanup(toolkit), owner)
        try:
            return await asyncio.wait_for(
                asyncio.wrap_future(future), timeout=CLEANUP_TIMEOUT + CROSS_LOOP_GRACE
            )
        except TimeoutError:
            future.cancel()
            logger.warning(
                "mcp server '%s' cleanup did not finish on its own loop in %.0fs; abandoning it.",
                self.name,
                CLEANUP_TIMEOUT + CROSS_LOOP_GRACE,
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
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                argv = fh.read().split(b"\0")
        except OSError:
            return False
        expected = [part.encode() for part in self._launch_argv]
        return argv[: len(expected)] == expected

    def _note_child_pids(self, before: set[int]) -> None:
        """Record the children that appeared while ``initialize`` ran."""
        appeared = _own_child_pids() - before
        self._child_pids = tuple(sorted(pid for pid in appeared if self._child_matches(pid)))

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

    def _kill_survivors(self, pids: list[int]) -> None:
        """SIGKILL whichever of ``pids`` sat through the SIGTERM."""
        import signal

        survivors = [pid for pid in pids if pid in _own_child_pids()]
        if not survivors:
            return
        self._signal_children(survivors, signal.SIGKILL)
        logger.warning(
            "mcp server '%s' child(ren) %s ignored SIGTERM; killed.",
            self.name,
            ", ".join(str(pid) for pid in survivors),
        )

    async def _areap_children(self) -> None:
        """Terminate, then kill, the child this handle spawned. Never raises.

        The last fence. ``mcp``'s stdio transport escalates SIGTERM -> SIGKILL
        itself, but only inside the exit stack — the code that does not run
        when a cleanup is abandoned. Without this the child outlives the job
        and, with ``max_jobs = 1``, accumulates one sidecar per analysis.
        """
        import signal

        pids = self._live_children()
        if not pids:
            return
        self._signal_children(pids, signal.SIGTERM)
        await asyncio.sleep(CHILD_TERM_GRACE)
        self._kill_survivors(pids)

    def _reap_children(self) -> None:
        """``_areap_children`` for the synchronous close path."""
        import signal
        import time

        pids = self._live_children()
        if not pids:
            return
        self._signal_children(pids, signal.SIGTERM)
        time.sleep(CHILD_TERM_GRACE)
        self._kill_survivors(pids)

    def _forget_attachment(self) -> None:
        """Drop what only an attached handle carries. Call after the reap."""
        self._owner_loop = None
        self._child_pids = ()
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

    def all_tool_names(self) -> list[str]:
        """Every tool the server advertises, allow-list ignored."""
        return [str(getattr(t, "name", "")) for t in self._all_tools]

    def tools(self) -> list[BaseTool]:
        """The tools the model may call: the allow-list applied to the manifest.

        ``None`` is "everything the server offers" and is what the two
        built-in sidecars carry, so their tool lists are byte-for-byte what
        the agents attached before this existed. ``[]`` is "nothing", which is
        what a newly registered custom server carries until the operator ticks
        tools off its probe result — a server is connected and inert until
        somebody says which of its tools may run.
        """
        allowed = self.config.tools
        if allowed is None:
            return list(self._all_tools)
        keep = set(allowed)
        return [t for t in self._all_tools if str(getattr(t, "name", "")) in keep]

    def _teardown(self, toolkit: Any) -> None:
        """Best-effort close of ``toolkit``, attached or abandoned mid-open. Never raises.

        Same rule as ``_close_on_owner``: the exit stack unwinds on the loop
        that wound it. For this path that is the shared agent loop, because
        ``open`` runs ``initialize`` through ``_run_async`` — but the owner is
        read rather than assumed, so a handle that reaches here having been
        opened elsewhere is routed rather than corrupted.
        """
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        from maljan.agents.base_agent import _get_agent_loop, _run_coro_blocking

        owner = self._owner_loop
        budget = SYNC_CLOSE_TIMEOUT
        try:
            if owner is None or owner is _get_agent_loop():
                _run_coro_blocking(closer(), hard_timeout=budget, label=f"{self.name}-mcp-close")
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
        loop that opened it (F6): the synchronous path here runs the toolkit's
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


class ServerRegistry:
    """The tool servers one job may attach, built from ``cfg.mcp.servers``."""

    def __init__(self, cfg: Settings) -> None:
        self._handles = {
            name: ServerHandle(name, config) for name, config in cfg.mcp.servers.items()
        }
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
                self._loop_handles[key] = replica
                logger.info(
                    "mcp server '%s' is attached on another loop; the caller gets "
                    "its own handle rather than sharing a session across loops.",
                    handle.name,
                )
            return replica

    def _all_handles(self) -> list[ServerHandle]:
        """Every handle this registry has handed out, per-loop ones included."""
        with self._lock:
            return [*self._handles.values(), *self._loop_handles.values()]

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

    def for_agent(self, role: str, *, exclude: str = "") -> list[ServerHandle]:
        """Enabled servers bound to ``role``, built-ins first then by key.

        Order is what makes the collision rule predictable: a built-in is
        attached before any custom server, so a custom server that happens to
        name a tool ``extract_dns`` is the one that gets renamed, and the
        pinned built-in tool names never move.

        ``exclude`` drops one handle by name — the server a provider already
        opened itself, so the registry does not hand the same tools out twice.
        """
        from maljan.core.config import BUILTIN_SERVER_KEYS

        bound = [
            handle
            for handle in self._handles.values()
            if handle.config.enabled and role in handle.config.agents and handle.name != exclude
        ]
        return sorted(bound, key=lambda h: (h.name not in BUILTIN_SERVER_KEYS, h.name))

    def _merge(self, handle: ServerHandle, tools: list[BaseTool], seen: set[str]) -> int:
        """Append ``handle``'s tools to ``tools``, renaming any name collision.

        Returns how many tools were renamed, so the caller can log it once
        per handle instead of per tool.
        """
        renamed = 0
        for tool in handle.tools():
            name = str(getattr(tool, "name", ""))
            if name in seen:
                tool = tool.model_copy(update={"name": f"{handle.name}__{name}"})
                name = str(tool.name)
                renamed += 1
            seen.add(name)
            tools.append(tool)
        return renamed

    def tools_for(
        self, role: str, job_id: str, *, exclude: str = "", **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """Open every server bound to ``role`` and concatenate their tools.

        Returns the tools and the degradation reasons: one per server that
        could not be opened. A failure here is never raised — the caller keeps
        the tools it did get, and the run summary says which server is missing
        rather than the report quietly being thinner than the last one.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen: set[str] = set()
        from maljan.agents.base_agent import _get_agent_loop

        # ``open`` hands ``initialize`` to the shared agent loop, so that is
        # the loop this caller is really attaching on.
        agent_loop = _get_agent_loop()
        for bound in self.for_agent(role, exclude=exclude):
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
        self, role: str, job_id: str, *, exclude: str = "", **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """``tools_for``, but ``await``ed on the caller's own loop.

        For a caller already inside an event loop (the judge's graph node),
        where handing the attach to the shared agent loop would bind the
        toolkit's transport to a loop other than the one that later awaits
        its tool calls.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen: set[str] = set()
        loop = asyncio.get_running_loop()
        for bound in self.for_agent(role, exclude=exclude):
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
        attached them (F6) — still open, so the caller must ``await
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
