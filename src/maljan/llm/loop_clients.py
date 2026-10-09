"""Async HTTP clients that are only ever used on the event loop they were built on.

A pooled connection belongs to the event loop that opened it: its stream waits
on an ``asyncio.Event`` bound to that loop. This process makes model calls on
more than one loop — the shared agent loop the analysts and the judge run on
(``agents.base_agent``), and the worker's own, where the report node awaits the
narrative and the composer — and a connection opened on one and reused on the
other fails inside httpcore with "bound to a different event loop". The SDKs'
own retry hid it by opening a fresh connection; with the retries spent, or on a
client that sends one attempt, the call failed.

Every provider's async client goes through one of the two adapters here, which
hold one real client (or transport) per running loop, built on that loop the
first time it sends there:

* :func:`loop_bound_async_client` for an ``httpx``/``httpx2`` client handed to
  an SDK (Anthropic, OpenAI, Gemini). Requests are still built by one client
  built exactly as before, so every request is byte-for-byte what it was; only
  the sending is routed to the client the running loop owns.
* :class:`LoopBoundTransport` for a client that is built inside a library and
  takes a transport (Ollama).

A loop's client is closed on that loop when the loop shuts its asynchronous
generators down, which ``asyncio.run`` and every ``asyncio.Runner`` do before
closing. A loop closed without that (a retired agent loop) is forgotten the
next time any loop sends through the same adapter, and the operating system
sockets of its connections are closed when they are collected, as asyncio
closes any transport it is no longer given a loop to close on.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Hashable
from typing import Any

from maljan.core.logger import logger


class _Entry[T]:
    """One loop's value, and the generator that closes it with its loop."""

    __slots__ = ("closed", "guard", "value")

    def __init__(self, value: T) -> None:
        self.value = value
        self.guard: AsyncIterator[None] | None = None
        self.closed = False


class PerLoop[T]:
    """One value per running event loop, built there on first use and closed with it.

    ``build`` makes a value and ``close`` closes one; both are called on the
    loop the value belongs to. Safe to share between threads: each loop only
    ever reads its own entry, and the map is guarded by a lock.
    """

    def __init__(self, build: Callable[[], T], close: Callable[[T], Awaitable[Any]]) -> None:
        self._build = build
        self._close = close
        self._lock = threading.Lock()
        self._by_loop: dict[asyncio.AbstractEventLoop, _Entry[T]] = {}

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_loop)

    def _forget_closed_loops(self) -> None:
        """Drop every entry whose loop is closed. Called with the lock held."""
        for loop in [loop for loop in self._by_loop if loop.is_closed()]:
            del self._by_loop[loop]

    async def get(self) -> T:
        """The value for the running loop, built on first use."""
        loop = asyncio.get_running_loop()
        with self._lock:
            self._forget_closed_loops()
            entry = self._by_loop.get(loop)
            if entry is not None:
                return entry.value
            entry = _Entry(self._build())
            self._by_loop[loop] = entry
        # An asynchronous generator first iterated on this loop is one the
        # loop's ``shutdown_asyncgens`` closes, which runs the ``finally``
        # below on this loop while it still runs.
        guard = self._guard(loop, entry)
        entry.guard = guard
        await guard.__anext__()
        return entry.value

    async def _guard(
        self, loop: asyncio.AbstractEventLoop, entry: _Entry[T]
    ) -> AsyncIterator[None]:
        try:
            yield
        finally:
            with self._lock:
                if self._by_loop.get(loop) is entry:
                    del self._by_loop[loop]
            await self._close_entry(entry)

    async def _close_entry(self, entry: _Entry[T]) -> None:
        if entry.closed:
            return
        entry.closed = True
        try:
            await self._close(entry.value)
        except Exception as exc:  # noqa: BLE001 — a client that fails to close is still let go
            logger.debug("a loop-bound client did not close cleanly: %s", exc)

    async def aclose(self) -> None:
        """Close every loop's value: this loop's here, a running loop's on that loop."""
        try:
            current: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        with self._lock:
            entries = list(self._by_loop.items())
            self._by_loop.clear()
        for loop, entry in entries:
            if loop is current:
                await self._close_entry(entry)
            elif not loop.is_closed() and loop.is_running():
                try:
                    asyncio.run_coroutine_threadsafe(self._close_entry(entry), loop)
                except RuntimeError:
                    continue


def _client_base(client: Any) -> type:
    """The ``AsyncClient`` class of the httpx flavour ``client`` is built from."""
    for cls in type(client).__mro__:
        if cls.__name__ == "AsyncClient" and cls.__module__.split(".")[0] in ("httpx", "httpx2"):
            return cls
    raise TypeError(f"{type(client).__name__} is not an httpx AsyncClient")


_ROUTING_CLASSES: dict[type, type] = {}
_ROUTING_LOCK = threading.Lock()


def _routing_class(base: type) -> type:
    """A subclass of ``base`` that builds requests on one client and sends on the loop's own."""
    with _ROUTING_LOCK:
        cached = _ROUTING_CLASSES.get(base)
        if cached is not None:
            return cached

        def __getattr__(self: Any, name: str) -> Any:
            # Everything not overridden below (``timeout``, ``headers``,
            # ``base_url`` ...) reads the client every request is built on.
            # Never reached for the adapter's own slots once they are set.
            if name.startswith("_loop_bound_"):
                raise AttributeError(name)
            return getattr(self._loop_bound_template, name)

        def build_request(self: Any, *args: Any, **kwargs: Any) -> Any:
            return self._loop_bound_template.build_request(*args, **kwargs)

        async def send(self: Any, request: Any, **kwargs: Any) -> Any:
            client = await self._loop_bound_clients.get()
            return await client.send(request, **kwargs)

        def is_closed(self: Any) -> bool:
            return bool(self._loop_bound_closed)

        async def aclose(self: Any) -> None:
            self._loop_bound_closed = True
            await self._loop_bound_clients.aclose()
            await self._loop_bound_template.aclose()

        async def __aenter__(self: Any) -> Any:
            return self

        async def __aexit__(self: Any, *exc: Any) -> None:
            await self.aclose()

        routing = type(
            f"LoopBound{base.__name__}",
            (base,),
            {
                "__getattr__": __getattr__,
                "build_request": build_request,
                "send": send,
                "is_closed": property(is_closed),
                "aclose": aclose,
                "__aenter__": __aenter__,
                "__aexit__": __aexit__,
                "__module__": __name__,
            },
        )
        _ROUTING_CLASSES[base] = routing
        return routing


def loop_bound_async_client(build: Callable[[], Any], *, template: Any = None) -> Any:
    """An ``httpx``/``httpx2`` ``AsyncClient`` whose connections never cross event loops.

    ``build`` makes the client exactly as the caller would have; it is called
    once for the client every request is built on (unless ``template`` is that
    client already) and once per event loop the result sends on. The result is
    an instance of the same flavour's ``AsyncClient``, so an SDK that checks
    for one takes it, and SDKs only build, send and close through it.
    """
    template = build() if template is None else template
    routing = _routing_class(_client_base(template))

    def build_for_loop() -> Any:
        built = build()
        # One cookie jar for all of them: a client stores a response's cookies
        # in the jar of the client that sent it, and a request is given the
        # jar of the client that built it — the template. Shared, a cookie the
        # server set on any loop is sent back as it was by the one client.
        if hasattr(template, "_cookies") and hasattr(built, "_cookies"):
            built._cookies = template._cookies
        return built

    client: Any = object.__new__(routing)
    client._loop_bound_template = template
    client._loop_bound_closed = False
    client._loop_bound_clients = PerLoop(build_for_loop, lambda c: c.aclose())
    return client


_SHARED: dict[Hashable, Any] = {}
_SHARED_LOCK = threading.Lock()


def shared_loop_bound_async_client(key: Hashable, build: Callable[[], Any]) -> Any:
    """:func:`loop_bound_async_client`, one per ``key`` for the life of the process.

    For a client a library shared between every model for one endpoint (an
    ``lru_cache``), shared the same way here: one set of connections per
    endpoint and loop, as there was one per endpoint.
    """
    with _SHARED_LOCK:
        client = _SHARED.get(key)
        if client is None or client.is_closed:
            client = loop_bound_async_client(build)
            _SHARED[key] = client
        return client


class LoopBoundTransport:
    """An async transport that sends on a transport of the running loop's own.

    Made a subclass of the given flavour's ``AsyncBaseTransport`` by
    :func:`loop_bound_transport`, so a client that checks takes it.
    """

    def __init__(self, build: Callable[[], Any]) -> None:
        self._transports: PerLoop[Any] = PerLoop(build, lambda t: t.aclose())

    async def handle_async_request(self, request: Any) -> Any:
        transport = await self._transports.get()
        return await transport.handle_async_request(request)

    async def aclose(self) -> None:
        await self._transports.aclose()

    # A model's fields are copied with it (``model_copy``); a copy sends
    # through the same per-loop transports, which is what makes it safe.
    def __copy__(self) -> LoopBoundTransport:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> LoopBoundTransport:
        return self

    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()


_TRANSPORT_CLASSES: dict[type, type] = {}


def loop_bound_transport(base: type, build: Callable[[], Any]) -> Any:
    """A :class:`LoopBoundTransport` that is also a ``base`` (an ``AsyncBaseTransport``)."""
    with _ROUTING_LOCK:
        cls = _TRANSPORT_CLASSES.get(base)
        if cls is None:
            cls = type(f"LoopBound{base.__name__}", (LoopBoundTransport, base), {})
            _TRANSPORT_CLASSES[base] = cls
    return cls(build)
