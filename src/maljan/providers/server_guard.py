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
protected.

Every opening is recorded for the run summary and announced as an event.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
from collections.abc import AsyncIterator, Callable
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
    ) -> None:
        self.server = server
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
        self._on_open = on_open
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._reopen_at: float | None = None
        self._trial_in_flight = False
        self._semaphores: dict[int, tuple[asyncio.AbstractEventLoop, asyncio.Semaphore]] = {}

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

    def long_running(self, tool: str) -> bool:
        """Whether the server's manifest declares ``tool`` long-running with no wall clock."""
        with self._lock:
            return tool in self._long_running

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
            declared = self._declared.get(tool, 0.0)
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
        with self._lock:
            if self._reopen_at is None:
                return None, False
            left = self._reopen_at - self._clock()
            if left <= 0 and not self._trial_in_flight:
                self._trial_in_flight = True
                return None, True
            failures = self._failures
        when = (
            f"it will be tried again in {max(1, round(left))} s"
            if left > 0
            else "one call has been let through to try it again, and no other is sent "
            "until that call is answered"
        )
        return (
            _resting_answer(
                tool,
                f"tool server '{self.server}' is resting after {failures} call"
                f"{'' if failures == 1 else 's'} in a row it did not answer; {when}",
            ),
            False,
        )

    def refusal(self, tool: str) -> str | None:
        """:meth:`admit` for a caller that only needs the answer."""
        return self.admit(tool)[0]

    def answered(self) -> None:
        """The server answered — with its result or with its own error — so it is up."""
        with self._lock:
            closing = self._reopen_at is not None
            self._failures = 0
            self._reopen_at = None
            self._trial_in_flight = False
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
            record = {
                "server": self.server,
                "failures": self._failures,
                "cooldown_s": self.cooldown_seconds,
                "reason": str(reason),
            }
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


def _resting_answer(tool: str, message: str) -> str:
    from maljan.tools.errors import tool_error

    return json.dumps(tool_error(SERVER_RESTING, message, tool=tool))


def guard_from_settings(
    server: str, cfg: Any, on_open: Callable[[dict[str, Any]], None] | None = None
) -> ServerGuard:
    """A guard for ``server`` with the thresholds ``cfg.mcp.breaker`` sets."""
    breaker = getattr(getattr(cfg, "mcp", None), "breaker", None)
    return ServerGuard(
        server,
        failures_to_open=int(getattr(breaker, "failures_to_open", 3)),
        cooldown_seconds=float(getattr(breaker, "cooldown_seconds", 60.0)),
        max_concurrent_calls=int(getattr(breaker, "max_concurrent_calls", 4)),
        call_timeout_seconds=deployment_call_budget(cfg),
        on_open=on_open,
        explicit_call_timeout=float(getattr(breaker, "call_timeout_seconds", 0.0) or 0.0) > 0,
    )


def deployment_call_budget(cfg: Any) -> float:
    """The budget every tool call gets at least: the setting, or the longest tool budget configured.

    ``core.mcp.breaker.call_timeout_seconds`` when it is set. Zero means
    "derive it": the longest budget the deployment gives a tool — capa's
    ``core.static.capa.timeout_seconds`` (300 by default, raised to 900 for a
    slow host) and YARA's — so a call never times out at the transport before
    the analysis it runs is allowed to finish.
    """
    breaker = getattr(getattr(cfg, "mcp", None), "breaker", None)
    explicit = float(getattr(breaker, "call_timeout_seconds", 0.0) or 0.0)
    if explicit > 0:
        return explicit
    static = getattr(cfg, "static", None)
    budgets = [
        float(getattr(getattr(static, name, None), "timeout_seconds", 0) or 0)
        for name in ("capa", "yara")
    ]
    return max([b for b in budgets if b > 0], default=0.0)
