"""An upload's size bound, held before a byte of its body is spooled.

A route that takes an ``UploadFile`` gets the file only after Starlette has
parsed the whole multipart body, and that parse spools the file to disk. A cap
checked inside the route therefore comes after the disk has already taken
whatever the client chose to send. This middleware holds the route's own bound
at the door: a ``Content-Length`` above it is refused before the body is read,
and a body that keeps coming past it (chunked, or a length that lied) is cut off
at the first chunk over it. Either way the answer is the 413 the route itself
gives.

The bound is the route's, never one of this module's: a route declares the
reader of its operator setting with :func:`upload_bound`, and a request no
route declares one for passes through untouched. A body on such a route that
is not multipart is refused with 415 unread: an upload route takes one file,
and a urlencoded form would otherwise be parsed whole into memory. The
middleware sits inside logging, the rate limiter and CORS, so its refusals
carry their headers and the bound's settings read comes after the limiter;
none of those layers reads a body. The body may run a little past
the file's bound by the multipart framing around it (boundaries and part
headers), so the cut-off allows ``MULTIPART_FRAMING_BYTES`` over it; the route
still holds the file itself to the exact bound.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.routing import Match
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.logging_config import get_logger

logger = get_logger("middleware.upload_bound")

# The attribute a route's endpoint carries its bound reader under.
UPLOAD_BOUND_ATTR = "__maljan_upload_bound__"

# What a multipart body carries around its one file: the boundary lines and the
# part's headers (a 255-character filename among them). Slack over the route's
# bound, not a bound of its own.
MULTIPART_FRAMING_BYTES = 64 * 1024

BoundReader = Callable[[], Awaitable[int]]


def upload_bound(reader: BoundReader) -> Callable[[Any], Any]:
    """Declare the bound reader of an upload route's endpoint (``reader() -> bytes``)."""

    def mark(endpoint: Any) -> Any:
        setattr(endpoint, UPLOAD_BOUND_ATTR, reader)
        return endpoint

    return mark


def too_large_detail(bound: int, what: str = "File") -> str:
    """The 413's sentence, the one the upload routes use."""
    return f"{what} too large. Maximum: {bound // (1024 * 1024)} MB"


class _BodyTooLarge(Exception):
    """The body passed the route's bound; raised out of ``receive``."""


def _is_multipart(scope: Scope) -> bool:
    for name, value in scope.get("headers") or ():
        if name == b"content-type":
            return bytes(value).split(b";", 1)[0].strip().lower() == b"multipart/form-data"
    return False


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers") or ():
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def _bound_reader(scope: Scope) -> BoundReader | None:
    """The bound reader the route this request reaches declares, if any."""
    app = scope.get("app")
    router = getattr(app, "router", None)
    for route in getattr(router, "routes", ()):
        try:
            match, _ = route.matches(scope)
        except Exception:  # noqa: BLE001 — a route that cannot match is not this one
            continue
        if match == Match.FULL:
            return getattr(getattr(route, "endpoint", None), UPLOAD_BOUND_ATTR, None)
    return None


async def _refuse(send: Send, bound: int) -> None:
    await _answer(send, 413, too_large_detail(bound))


async def _refuse_shape(send: Send) -> None:
    await _answer(send, 415, "An upload is sent as multipart/form-data.")


async def _answer(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class UploadBoundMiddleware:
    """Hold each upload route's declared bound before its body is spooled (pure ASGI)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        reader = _bound_reader(scope)
        if reader is None:
            await self.app(scope, receive, send)
            return
        if not _is_multipart(scope):
            # An upload route takes one multipart file. Any other body (a
            # urlencoded form is parsed whole into memory, before the route's
            # dependencies run) is refused unread, so no body passes the bound
            # by arriving in another shape.
            await _refuse_shape(send)
            return
        try:
            bound = int(await reader())
        except Exception as exc:  # noqa: BLE001 — the route still holds its own bound
            logger.warning(
                "Upload bound could not be read (%s); the route checks it after parsing.",
                type(exc).__name__,
            )
            await self.app(scope, receive, send)
            return
        allowed = bound + MULTIPART_FRAMING_BYTES
        declared = _content_length(scope)
        if declared is not None and declared > allowed:
            await _refuse(send, bound)
            return

        state = {"received": 0, "exceeded": False, "answered": False}

        async def bounded_receive() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                state["received"] += len(message.get("body", b""))
                if state["received"] > allowed:
                    state["exceeded"] = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            if state["exceeded"]:
                # Whatever the app answers to a body cut off mid-parse (a 400
                # for a form it could not read), the reason is the bound.
                if not state["answered"]:
                    state["answered"] = True
                    await _refuse(send, bound)
                return
            await send(message)

        try:
            await self.app(scope, bounded_receive, guarded_send)
        except Exception:
            if not state["exceeded"]:
                raise
        if state["exceeded"] and not state["answered"]:
            state["answered"] = True
            await _refuse(send, bound)
