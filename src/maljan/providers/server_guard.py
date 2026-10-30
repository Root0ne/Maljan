"""A tool server that keeps failing is rested, and says so; a slow one is not piled onto.

One :class:`ServerGuard` per server per job, held by the job's
``ServerRegistry`` and shared by every handle it opens for that server — a
handle opened for a second event loop is the same server to the job, and a
rest that one loop's calls earned is a rest for the other's too.

**The breaker.** ``failures_to_open`` unanswered calls in a row open it. An
unanswered call is a transport failure — a timeout, a refused or dropped
connection, the server's process gone — or a call that did not finish within
its caller's own budget while it waited on the server. A tool that *answers* — with
its result or with its own error, a bad argument, a missing file — has
answered, and that is a success as far as the transport is concerned; it
resets the count and never opens anything. While the breaker is open, a call
is not sent: the platform answers it with an authored tool error in the
structured shape every tool failure has (``maljan.tools.errors``), naming the
server, that it is resting and when it will be tried again. After the
cooldown one call is let through; if it succeeds the breaker closes, and if it
fails at the transport the server rests again.

**The cap.** ``max_concurrent_calls`` calls may be in flight to one server at
once for this job; the rest wait. A semaphore belongs to the loop that awaits
it, so there is one per event loop — a handle is also per loop, and for a
stdio server that is one child process per loop, which is the thing being
protected. Calls made outside any loop — a provider's own walk over the
server's API in a worker thread (:meth:`ServerGuard.held`) — take the
guard's own thread slots, ``max_concurrent_calls`` of them apart from each
loop's, and the same breaker: a rest either side earned holds the other.

Every opening is recorded for the run summary and announced as an event.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

from maljan.core.logger import logger
from maljan.tools.errors import SERVER_RESTING

# How long past its budget a call is given for the server to report its own
# overrun. The same thirty seconds the tool loop gives a model past its soft
# timeout before the hard cap (``base_agent.HARD_CAP_GRACE``).
CALL_TIMEOUT_GRACE_SECONDS = 30.0

# The class names a transport raises for a peer that is gone or never came.
# Matched by name because the stdio transport, the HTTP transport and anyio
# each raise their own.
_GONE = frozenset({"ClosedResourceError", "BrokenResourceError", "EndOfStream", "BrokenPipeError"})
_UNREACHABLE = frozenset(
    {"ConnectError", "RemoteProtocolError", "ReadError", "WriteError", "NetworkError"}
)
_TIMED_OUT = frozenset(
    {"ReadTimeout", "WriteTimeout", "ConnectTimeout", "PoolTimeout", "TimeoutException"}
)

# ``mcp``'s own error codes for a transport that failed rather than a server
# that answered: the connection closed under the request, and the request
# timed out waiting for a response.
_MCP_CONNECTION_CLOSED = -32000
_MCP_REQUEST_TIMEOUT = 408


def transport_failure(exc: BaseException) -> str | None:
    """What went wrong at the transport, in words, or ``None`` when the server answered.

    An ``McpError`` is the server's own answer unless its code is one of the
    two the client library writes for itself when the transport fails. Never
    raises; an exception it cannot read is not a transport failure.
    """
    try:
        name = type(exc).__name__
        if name == "McpError":
            code = getattr(getattr(exc, "error", None), "code", None)
            if code == _MCP_CONNECTION_CLOSED:
                return "the connection to the server closed"
            if code == _MCP_REQUEST_TIMEOUT:
                return "the server did not answer in time"
            return None
        if name in _TIMED_OUT or isinstance(exc, TimeoutError):
            return "the server did not answer in time"
        if name in _GONE:
            return "the server's process or connection is gone"
        if name in _UNREACHABLE or isinstance(exc, ConnectionError):
            return "the server could not be reached"
    except Exception:  # noqa: BLE001 — unreadable is not a transport failure
        return None
    return None


class ServerResting(Exception):
    """A call outside an event loop that a resting server's guard did not send.

    The exception's text is the sentence a call through :meth:`ServerGuard.admit`
    is answered with, for a walk to state; ``answer`` is that authored tool error.
    ``rests_begun`` is the guard's count of rests when it refused, the number a
    caller waits on (:meth:`ServerGuard.wait_admissible`).
    """

    def __init__(self, tool: str, message: str, rests_begun: int = 0) -> None:
        super().__init__(message)
        self.tool = tool
        self.answer = _resting_answer(tool, message)
        self.rests_begun = rests_begun


class ServerGuard:
    """The breaker and the concurrency cap for one server, for one job."""

    def __init__(
        self,
        server: str,
        *,
        failures_to_open: int = 3,
        cooldown_seconds: float = 60.0,
        max_concurrent_calls: int = 4,
        call_timeout_seconds: float = 0.0,
        on_open: Callable[[dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        explicit_call_timeout: bool = False,
        label: str = "",
    ) -> None:
        self.server = server
        # The server's display name (``MCPServerConfig.label``), given to the
        # rest's record beside the key where it names the server otherwise.
        self.label = str(label or "").strip()
        self.failures_to_open = max(1, int(failures_to_open))
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self.max_concurrent_calls = max(0, int(max_concurrent_calls))
        # The budget every call of this server gets at least, before the
        # grace; a tool the server's own manifest declares a longer budget
        # for gets that one. Zero sends calls with no deadline of their own.
        self.call_timeout_seconds = max(0.0, float(call_timeout_seconds))
        # Whether the operator set that budget (``mcp.breaker.call_timeout_seconds``)
        # rather than it being derived. Only an operator's number bounds a
        # long-running tool.
        self.explicit_call_timeout = bool(explicit_call_timeout)
        self._declared: dict[str, float] = {}
        self._long_running: frozenset[str] = frozenset()
        # The budgets and long-running tools the server's settings block
        # declares for its tools (``ToolFacts.timeout_seconds`` and
        # ``long_running``), held beside the manifest's: a server with no
        # manifest of its own is held to what its declaration says.
        self._facts_declared: dict[str, float] = {}
        self._facts_long_running: frozenset[str] = frozenset()
        # The tools the server's settings block declares to open and analyse a
        # sample (``sample_open``), held as long-running like a manifest's.
        self._opening: frozenset[str] = frozenset()
        self._on_open = on_open
        self._clock = clock
        self._lock = threading.Lock()
        # Told each time the breaker's state changes (``wait_admissible``).
        self._changed = threading.Condition(self._lock)
        self._failures = 0
        self._reopen_at: float | None = None
        self._trial_in_flight = False
        # How many rests have begun, a failed trial's renewal among them.
        self._rests_begun = 0
        self._semaphores: dict[int, tuple[asyncio.AbstractEventLoop, asyncio.Semaphore]] = {}
        # The slots of the calls made outside any loop (``held``).
        self._thread_slots = (
            threading.BoundedSemaphore(self.max_concurrent_calls)
            if self.max_concurrent_calls > 0
            else None
        )

    # -- the call deadline ---------------------------------------------------

    def declare(self, tools: dict[str, dict[str, Any]]) -> None:
        """Keep the budgets the server's own ``capabilities`` manifest declares, per tool."""
        declared: dict[str, float] = {}
        long_running: set[str] = set()
        for name, cell in (tools or {}).items():
            value = cell.get("timeout_s") if isinstance(cell, dict) else None
            if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
                declared[str(name)] = float(value)
            elif isinstance(cell, dict) and cell.get("long_running") is True:
                long_running.add(str(name))
        with self._lock:
            self._declared = declared
            self._long_running = frozenset(long_running)

    def declare_tool_facts(self, tool_facts: Any) -> None:
        """Keep the budgets the server's settings block declares, per tool (``tool_facts``).

        ``ToolFacts.timeout_seconds`` is a budget like a manifest's
        ``timeout_s`` (the larger of the two is kept), and
        ``ToolFacts.long_running`` holds a tool long-running like a manifest's
        own flag. Read for any server, declared by an operator or shipped.
        """
        declared: dict[str, float] = {}
        long_running: set[str] = set()
        for name, facts in (tool_facts or {}).items():
            value = getattr(facts, "timeout_seconds", None)
            if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
                declared[str(name)] = float(value)
            if getattr(facts, "long_running", False) is True:
                long_running.add(str(name))
        with self._lock:
            self._facts_declared = declared
            self._facts_long_running = frozenset(long_running)

    def declare_sample_open(self, spec: Any) -> None:
        """Hold the tools ``spec`` (a block's ``sample_open``) declares to open and analyse a
        sample as long-running, as a manifest's own declaration is held."""
        from maljan.providers.sample_open import long_running_tools

        opening = long_running_tools(spec)
        with self._lock:
            self._opening = opening

    def long_running(self, tool: str) -> bool:
        """Whether ``tool`` runs with no wall clock: by the server's manifest, by the open
        and analysis tools its settings block declares (``sample_open``), or by its
        declared ``long_running``."""
        with self._lock:
            return (
                tool in self._long_running
                or tool in self._opening
                or tool in self._facts_long_running
            )

    def call_timeout(self, tool: str) -> float | None:
        """How long one call of ``tool`` may take before it is a transport failure, or ``None``.

        The larger of the tool's own declared budget and the deployment's,
        plus :data:`CALL_TIMEOUT_GRACE_SECONDS` for the server to report its
        own overrun: a tool that gives up at its budget answers with its own
        timeout error, which is an answer; one that says nothing past the
        grace is a server that did not answer.
        """
        if self.call_timeout_seconds <= 0:
            return None
        if self.long_running(tool) and not self.explicit_call_timeout:
            # The server runs it with no clock of its own, so a client deadline
            # would only abandon a call the server is still working on.
            return None
        with self._lock:
            declared = max(self._declared.get(tool, 0.0), self._facts_declared.get(tool, 0.0))
        return max(self.call_timeout_seconds, declared) + CALL_TIMEOUT_GRACE_SECONDS

    # -- the breaker ---------------------------------------------------------

    def admit(self, tool: str) -> tuple[str | None, bool]:
        """``(refusal, trial)`` for one call: the authored answer when the server rests.

        ``refusal`` is ``None`` when the call may be sent. ``trial`` is true
        for the one call let through after the cooldown; the caller hands it
        back to :meth:`failed` or :meth:`abandoned`, because only the trial's
        own outcome decides whether the server rests again. Every other call
        is refused until the trial has answered.
        """
        message, trial, _ = self._admission()
        return (_resting_answer(tool, message) if message is not None else None), trial

    def _admission(self, *, claim: bool = True) -> tuple[str | None, bool, int]:
        """:meth:`admit`'s decision, with a refusal as its sentence, and the count of rests.

        With ``claim`` false nothing changes: a call that would be the trial
        is only reported as admitted, and the trial stays unclaimed.
        """
        with self._lock:
            rests = self._rests_begun
            if self._reopen_at is None:
                return None, False, rests
            left = self._reopen_at - self._clock()
            if left <= 0 and not self._trial_in_flight:
                if claim:
                    self._trial_in_flight = True
                return None, claim, rests
            failures = self._failures
        when = (
            f"it will be tried again in {max(1, round(left))} s"
            if left > 0
            else "one call has been let through to try it again, and no other is sent "
            "until that call is answered"
        )
        return (
            f"tool server '{self.server}' is resting after {failures} call"
            f"{'' if failures == 1 else 's'} in a row it did not answer; {when}",
            False,
            rests,
        )

    def refusal(self, tool: str) -> str | None:
        """The answer :meth:`admit` would give ``tool`` now, without claiming the trial.

        A look, not a call: after the cooldown it answers ``None`` and leaves
        the trial to the next call actually sent.
        """
        message, _, _ = self._admission(claim=False)
        return _resting_answer(tool, message) if message is not None else None

    def wake(self) -> None:
        """Wake every :meth:`wait_admissible`, to look again at what it waits for."""
        with self._changed:
            self._changed.notify_all()

    @property
    def rests_begun(self) -> int:
        """How many rests this guard has begun; a failed trial's new rest counts as one."""
        with self._lock:
            return self._rests_begun

    def wait_admissible(
        self, rests_begun: int, *, stopped: Callable[[], bool] | None = None
    ) -> bool:
        """Block a thread until a call would be admitted; whether no new rest began meanwhile.

        Returns ``True`` once the server is not resting, or its cooldown has
        passed with no trial in flight; the trial is not claimed here, the
        caller's next call is admitted (or refused) as any other. Returns
        ``False`` as soon as a rest begins after ``rests_begun`` (the count
        the refusal carried, :attr:`ServerResting.rests_begun`): the trial
        failed, and the server rests again. Also ``False`` once ``stopped()``
        is true, looked at whenever :meth:`wake` is called (a job's cancel).
        No limit of its own: the wait ends when the guard's state changes,
        its cooldown ends or its caller is stopped.
        """
        with self._changed:
            while self._rests_begun == rests_begun:
                if stopped is not None and stopped():
                    return False
                if self._reopen_at is None:
                    return True
                left = self._reopen_at - self._clock()
                if left <= 0 and not self._trial_in_flight:
                    return True
                self._changed.wait(timeout=left if left > 0 else None)
            return False

    def answered(self) -> None:
        """The server answered — with its result or with its own error — so it is up."""
        with self._lock:
            closing = self._reopen_at is not None
            self._failures = 0
            self._reopen_at = None
            self._trial_in_flight = False
            self._changed.notify_all()
        if closing:
            logger.info("tool server '%s' answered again; its rest is over.", self.server)

    def abandoned(self, *, trial: bool = False) -> None:
        """A call ended without an answer either way — cancelled with its caller.

        Nothing was learned about the server, so nothing is counted; a trial
        cut short is simply no longer in flight, and the next caller becomes
        the trial instead of the server being refused for good.
        """
        if not trial:
            return
        with self._lock:
            self._trial_in_flight = False
            self._changed.notify_all()

    def failed(self, reason: str, *, trial: bool = False) -> None:
        """One transport failure; opens the breaker when it fills the run, or fails the trial.

        A failure of a call sent before the rest began is counted and opens
        nothing more: only the trial's own failure starts another rest.
        """
        with self._lock:
            self._failures += 1
            # A trial counts as one only while the rest it was let through for
            # is still on: a call sent before the rest answered and closed it,
            # and this trial's failure is then the first of a new run.
            trial = trial and self._reopen_at is not None
            if trial:
                self._trial_in_flight = False
            elif self._reopen_at is not None or self._failures < self.failures_to_open:
                return
            self._reopen_at = self._clock() + self.cooldown_seconds
            self._rests_begun += 1
            self._changed.notify_all()
            record = {
                "server": self.server,
                "failures": self._failures,
                "cooldown_s": self.cooldown_seconds,
                "reason": str(reason),
            }
            if self.label and self.label != self.server:
                record["label"] = self.label
        logger.warning(
            "tool server '%s' is resting for %.0f s after %d unanswered call(s) in a row (%s).",
            self.server,
            self.cooldown_seconds,
            record["failures"],
            reason,
        )
        if self._on_open is not None:
            try:
                self._on_open(record)
            except Exception as exc:  # noqa: BLE001 — a record is never worth a call
                logger.debug("tool server rest not recorded (%s).", exc)

    # -- the cap -------------------------------------------------------------

    def _semaphore(self) -> asyncio.Semaphore | None:
        if self.max_concurrent_calls <= 0:
            return None
        loop = asyncio.get_running_loop()
        with self._lock:
            held = self._semaphores.get(id(loop))
            if held is None or held[0] is not loop:
                held = (loop, asyncio.Semaphore(self.max_concurrent_calls))
                self._semaphores[id(loop)] = held
            return held[1]

    @contextlib.asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Hold one of this server's call slots on the running loop."""
        semaphore = self._semaphore()
        if semaphore is None:
            yield
            return
        async with semaphore:
            yield

    @contextlib.contextmanager
    def held(self, tool: str) -> Iterator[None]:
        """One call made outside an event loop, held to this server's breaker and cap.

        For a walk a provider makes over the server's own API in a worker
        thread: counted and rested as a call through :meth:`slot` is. One of
        the guard's thread slots is taken first, then the call is admitted
        once; a resting server raises :class:`ServerResting` and nothing is
        sent. A transport failure (:func:`transport_failure`) counts toward
        the rest; any other HTTP error (``httpx.HTTPError``) is the server
        having answered; anything else, an error of the caller's own or a
        call its caller ended, says nothing about the server and is nothing.
        """
        import httpx

        slots = self._thread_slots
        if slots is not None:
            slots.acquire()
        try:
            message, trial, rests = self._admission()
            if message is not None:
                raise ServerResting(tool, message, rests)
            try:
                yield
            except Exception as exc:
                reason = transport_failure(exc)
                if reason is not None:
                    self.failed(reason, trial=trial)
                elif isinstance(exc, httpx.HTTPError):
                    self.answered()
                else:
                    self.abandoned(trial=trial)
                raise
            except BaseException:
                self.abandoned(trial=trial)
                raise
            self.answered()
        finally:
            if slots is not None:
                slots.release()


class GuardedHTTP:
    """A synchronous HTTP client whose every request is one call held by ``guard``.

    Each request goes through :meth:`ServerGuard.held`, named by its path past
    ``base`` as a tool is (``/a/b`` is ``a_b``), and is made by the wrapped
    client's own method of that name (``get`` by its ``get``). A response
    with an error status is an answer. Everything else is the wrapped
    client's own.
    """

    def __init__(self, client: Any, guard: ServerGuard, base: str = "") -> None:
        self._client = client
        self._guard = guard
        self._base = base.rstrip("/")

    def _tool(self, url: Any) -> str:
        path = str(url)
        if self._base and path.startswith(self._base):
            path = path[len(self._base) :]
        elif "://" in path:
            path = "/" + path.split("://", 1)[1].partition("/")[2]
        return path.split("?", 1)[0].strip("/").replace("/", "_") or "request"

    def request(self, method: str, url: Any, **kwargs: Any) -> Any:
        with self._guard.held(self._tool(url)):
            return self._client.request(method, url, **kwargs)

    def get(self, url: Any, **kwargs: Any) -> Any:
        with self._guard.held(self._tool(url)):
            return self._client.get(url, **kwargs)

    def post(self, url: Any, **kwargs: Any) -> Any:
        with self._guard.held(self._tool(url)):
            return self._client.post(url, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def guarded_http(client: Any, guard: ServerGuard | None, base: str = "") -> Any:
    """``client`` with each request held by ``guard``; ``client`` itself with no guard."""
    return client if guard is None else GuardedHTTP(client, guard, base)


def _resting_answer(tool: str, message: str) -> str:
    from maljan.tools.errors import tool_error

    return json.dumps(tool_error(SERVER_RESTING, message, tool=tool))


def guard_from_settings(
    server: str,
    cfg: Any,
    on_open: Callable[[dict[str, Any]], None] | None = None,
    sample_open: Any = None,
    block: Any = None,
    label: str = "",
    source: str = "",
) -> ServerGuard:
    """A guard for ``server`` with the thresholds ``cfg.mcp.breaker`` sets.

    ``sample_open`` is the server's own block's declaration: its open and
    analysis tools are held long-running. ``block`` is the server's settings
    block, whose ``call_timeout_seconds`` is the budget each of its calls gets
    (:func:`server_call_budget`) and whose ``tool_facts`` declare each tool's
    own budget and long-running flag (:meth:`ServerGuard.declare_tool_facts`);
    with none given it is ``cfg.mcp.servers[server]``. ``label`` is the
    server's display name, where it has one. ``source`` is where the block's
    tools are declared (``provider:<id>`` for a provider's own block), so what
    the server declared of them under it is read too; ``mcp:<server>`` when
    not given.
    """
    breaker = getattr(getattr(cfg, "mcp", None), "breaker", None)
    if block is None:
        servers = getattr(getattr(cfg, "mcp", None), "servers", None)
        block = servers.get(server) if isinstance(servers, dict) else None
    guard = ServerGuard(
        server,
        failures_to_open=int(getattr(breaker, "failures_to_open", 3)),
        cooldown_seconds=float(getattr(breaker, "cooldown_seconds", 60.0)),
        max_concurrent_calls=int(getattr(breaker, "max_concurrent_calls", 4)),
        call_timeout_seconds=server_call_budget(cfg, block),
        on_open=on_open,
        explicit_call_timeout=explicit_call_timeout(cfg) > 0,
        label=label,
    )
    guard.declare_sample_open(sample_open)
    guard.declare_tool_facts(_tools_in_force(source or f"mcp:{server}", block))
    return guard


def operator_guard(
    server: str,
    cfg: Any,
    *,
    block: Any = None,
    on_open: Callable[[dict[str, Any]], None] | None = None,
    sample_open: Any = None,
    label: str = "",
) -> ServerGuard:
    """A guard that limits only what the operator set; for a server outside the job's registry.

    A deadline only from ``mcp.breaker.call_timeout_seconds`` or the block's
    own ``call_timeout_seconds``; a concurrency cap, and a breaker (its
    failure count and cooldown), only when ``mcp.breaker`` was given them.
    Otherwise the call has no deadline, no cap and a breaker that never opens,
    which is what such a server had before it had a guard.
    """
    breaker: Any = getattr(getattr(cfg, "mcp", None), "breaker", None)
    given: set[str] = getattr(breaker, "model_fields_set", set())
    explicit = explicit_call_timeout(cfg)
    declared = getattr(block, "call_timeout_seconds", None)
    own = float(declared) if isinstance(declared, int | float) and declared > 0 else 0.0
    breaker_set = breaker is not None and (
        "failures_to_open" in given or "cooldown_seconds" in given
    )
    guard = ServerGuard(
        server,
        failures_to_open=int(breaker.failures_to_open) if breaker_set else 2**31,
        cooldown_seconds=float(breaker.cooldown_seconds) if breaker_set else 0.0,
        max_concurrent_calls=int(breaker.max_concurrent_calls)
        if breaker is not None and "max_concurrent_calls" in given
        else 0,
        call_timeout_seconds=explicit or own,
        on_open=on_open,
        explicit_call_timeout=explicit > 0,
        label=label,
    )
    guard.declare_sample_open(sample_open)
    guard.declare_tool_facts(_tools_in_force(f"mcp:{server}", block))
    return guard


def _tools_in_force(source: str, block: Any) -> Any:
    """``block``'s tool declarations, with what its server declared of them laid under.

    ``core.declared_reading.tools_in_force`` under ``source``; the block's
    own map for anything that is not a settings block.
    """
    from pydantic import BaseModel

    if not isinstance(block, BaseModel):
        return getattr(block, "tool_facts", None)
    from maljan.core.declared_reading import tools_in_force

    return tools_in_force(source, block)


def explicit_call_timeout(cfg: Any) -> float:
    """The per-call budget an operator set (``mcp.breaker.call_timeout_seconds``), or ``0``.

    Only an operator's number bounds a long-running tool.
    """
    breaker = getattr(getattr(cfg, "mcp", None), "breaker", None)
    return max(0.0, float(getattr(breaker, "call_timeout_seconds", 0.0) or 0.0))


def server_call_budget(cfg: Any, block: Any) -> float:
    """The budget each call to one server gets at least: the operator's, or the server's own.

    ``core.mcp.breaker.call_timeout_seconds`` when an operator set it, for
    every server. Otherwise the ``call_timeout_seconds`` the server's own
    block declares (``MCPServerConfig``; zero sends its calls with no deadline
    of their own). A block that declares none (every built-in), or no block,
    gets the deployment's budget for such a server
    (``core.mcp.breaker.default_call_timeout_seconds``), whatever the server
    or its tools are called. A tool that declares a longer budget of its own
    gets that one (:meth:`ServerGuard.call_timeout`).
    """
    explicit = explicit_call_timeout(cfg)
    if explicit > 0:
        return explicit
    declared = getattr(block, "call_timeout_seconds", None) if block is not None else None
    if isinstance(declared, int | float) and not isinstance(declared, bool):
        return max(0.0, float(declared))
    return default_call_timeout(cfg)


def default_call_timeout(cfg: Any) -> float:
    """The budget of a server that declares none (``mcp.breaker.default_call_timeout_seconds``).

    ``0`` for settings that hold none.
    """
    breaker = getattr(getattr(cfg, "mcp", None), "breaker", None)
    value = getattr(breaker, "default_call_timeout_seconds", 0.0)
    if not isinstance(value, int | float) or isinstance(value, bool):
        return 0.0
    return max(0.0, float(value))
