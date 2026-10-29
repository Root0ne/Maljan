"""MCP Client wrapper that exposes MCP server tools as LangChain tools.

This module connects to an MCP server and converts its tools into LangChain
BaseTool objects for use with create_react_agent. Two transports are
supported:

  - "stdio": local subprocess (the default). Pass a ``StdioServerParameters``.
  - "http" / "sse": a remote MCP server reachable over HTTP (e.g. a CAPEv2
    MCP server running on a separate Ubuntu VM). Pass ``transport`` plus
    ``http_url`` (and optional ``http_headers`` for auth).
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import timedelta
from typing import Any, cast

from anyio.abc import ObjectReceiveStream
from langchain_core.tools import BaseTool
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import Field, ValidationError

from maljan.agents.argument_schema import (
    PLAIN_TYPES,
    UnusableSchema,
    holds_ref,
    is_plain,
    plain_type,
)
from maljan.agents.argument_schema import annotation as argument_annotation
from maljan.agents.null_arguments import NullRules, argument_model, schema_rules
from maljan.agents.server_names import ServerNamedTool, field_names, to_server_names
from maljan.core.logger import logger
from maljan.llm.context_window import note_call_began


def tool_error_marker(kind: str, tool: str, **fields: str) -> str:
    """The marker an MCP call's failure is handed on in, as JSON the ledger reads.

    ``{"tool_error": <kind>, "tool": <name>, ...}``, written with ``json.dumps``
    so any text in it survives: the markers used to be f-strings, and an
    ``isError`` reply's content written as a Python repr, or an exception
    message with a quote in it, was not JSON. ``tools.errors.error_parts``
    then read no failure and the ledger filed the call as ok.
    """
    import json

    return json.dumps({"tool_error": kind, "tool": tool, **fields})


def _json_width(text: str) -> int:
    """How many characters ``text`` takes inside a JSON string, as ``json.dumps`` writes it."""
    import json

    return len(json.dumps(text)) - 2


def _json_fit(text: str, room: int) -> int:
    """How many of ``text``'s first characters fit ``room`` once JSON writes them. Linear."""
    import json

    used = 0
    for count, ch in enumerate(text):
        width = len(json.dumps(ch)) - 2
        if used + width > room:
            return count
        used += width
    return len(text)


_HEX = frozenset(b"0123456789abcdefABCDEF")


def _fully_unquoted(text: str) -> str:
    """``text`` with percent-encoding decoded until none is left, as repeated ``unquote`` would.

    A double-encoded URL (``%253A``) decodes to the URL it is, not to one more
    encoding of it. One pass over the bytes, each reduced at most once: an
    escape is decoded as soon as its three bytes stand at the top, and the byte
    it gives may complete the escape before it. Linear in ``text``.
    """
    if "%" not in text:
        return text
    out = bytearray()
    for byte in text.encode("utf-8", "surrogatepass"):
        out.append(byte)
        while len(out) >= 3 and out[-3] == 0x25 and out[-2] in _HEX and out[-1] in _HEX:
            value = int(out[-2:].decode("ascii"), 16)
            del out[-3:]
            out.append(value)
    return out.decode("utf-8", "replace")


# Where a URL quoted in a message ends: a closing quote or bracket.
_URL_CLOSERS = frozenset("\"'`)]}>")


def _quoted_end(text: str, begin: int, end: int) -> int:
    """``end`` pulled back to the first closing quote or bracket after ``begin``.

    Not one inside the authority's ``[...]``: an IPv6 literal
    (``http://[::1]:8080/``) is the host, whole.
    """
    start = begin
    authority = text.find("://", begin, end) + 3
    if 2 < authority < end and text[authority] == "[":
        closing = text.find("]", authority, end)
        if closing >= 0:
            start = closing + 1
    for index in range(start, end):
        if text[index] in _URL_CLOSERS:
            return index
    return end


# The port a URL scheme means when it writes none.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _host_and_port(url: str) -> tuple[str, int | None] | None:
    """``(host, port)`` of ``url``, the host lowercased and the scheme's default port filled in.

    ``None`` for a text with no host, or one that cannot be read as a URL.
    """
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    return host, port if port is not None else _DEFAULT_PORTS.get(parts.scheme.lower())


class StructuredAnswer(str):
    """A tool's text answer, carrying the structured answer its server returned beside it.

    MCP lets a server answer with ``structuredContent`` (a JSON object) as
    well as its text content. The text is what the model reads, exactly as
    before; the object rides on the string to the evidence recorder, which
    files it as the entry's ``structured`` (``LedgerEntry.structured_from_server``), so a
    reader of the entry reads the server's own structure whatever its text
    says. A wrapper that returns the answer unchanged keeps it; one that
    builds a new string drops it, and the entry then has none.
    """

    structured_content: dict[str, Any] | None = None


def with_structured_content(text: str, content: Any, limit: int) -> str:
    """``text``, carrying ``content`` when it is the JSON object MCP's ``structuredContent`` is.

    Held to ``limit``, the number of characters the model could be shown of
    this call's answer (the guardrail's limit for the call, in its unit,
    characters): a structure whose JSON is longer is not carried, and the
    text goes on alone, as it always did. A limit of zero (no room for any
    answer) carries nothing. Nothing is serialised for a text that is JSON
    or an object that only wraps the text. CPU-bound on a large answer: a
    coroutine runs it on a thread.
    """
    import json

    from maljan.schemas.evidence import parse_structured

    if not isinstance(content, dict) or not content or limit <= 0:
        return text
    # Decided before anything is serialised: a JSON text already is the
    # answer's structure (every built-in's case), and an object that only
    # wraps the text again adds nothing.
    if len(content) == 1 and next(iter(content.values())) == text:
        return text
    if parse_structured(text) is not None:
        return text
    try:
        size = len(json.dumps(content, ensure_ascii=False))
    except (TypeError, ValueError):
        return text
    if size > limit:
        return text
    answer = StructuredAnswer(text)
    answer.structured_content = content
    return answer


def structured_content_of(value: Any) -> dict[str, Any] | None:
    """The ``structuredContent`` a tool's answer carries (:class:`StructuredAnswer`), or ``None``."""
    content = getattr(value, "structured_content", None)
    return content if isinstance(content, dict) and content else None


# What a character cut leaves behind, and the room kept back for it.
#
# The marker goes *inside* the limit rather than after it, which is the same
# rule ``output_shortening.shorten_target`` follows for the notice a shortened
# answer carries: the limit is how much may reach the model, and the marker
# reaches the model. Appended after the cut instead, it left twenty characters
# a call unaccounted — self-correcting between model turns, because the next
# measurement sees the true size, and not self-correcting inside one, where
# every answer of a wide fan-out leaked its own.
TRUNCATION_MARKER = "\n\n[OUTPUT TRUNCATED]"


def truncation_target(limit: int) -> int:
    """How much of an answer a character cut keeps, so the marker fits the limit."""
    return max(0, int(limit) - len(TRUNCATION_MARKER))


def next_request_id(session: Any) -> Any:
    """The id the session will give its next request, or ``None`` where it cannot say.

    The ``mcp`` client has no public way to learn a request's id, so this is
    the one place its private counter is read: ``BaseSession._request_id``,
    which ``send_request`` takes as the request's id before its first await,
    and ``ClientSession.call_tool`` reaches ``send_request`` with no await in
    between. Read immediately before the call, it is that call's id, which is
    how a call this client gives up on is cancelled at the server by name. A
    test pins that behaviour to the installed version.
    """
    value = getattr(session, "_request_id", None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


async def _cancel_at_the_server(session: Any, request_id: Any, reason: str) -> None:
    """Tell the server to stop the request this client gave up on. Never raises.

    The client library abandons a request it times out or is cancelled on and
    says nothing to the server, which then works on with no one waiting — a
    capa or FLOSS child of a large sample for as long as it takes. The server
    cancels the request's work when told, and a long-running tool kills its
    child process with it (``tools.children``).
    """
    if request_id is None:
        return
    try:
        from mcp import types

        note = types.ClientNotification(
            types.CancelledNotification(
                params=types.CancelledNotificationParams(requestId=request_id, reason=reason)
            )
        )
        await asyncio.shield(asyncio.wait_for(session.send_notification(note), 5.0))
    except BaseException as exc:  # noqa: BLE001 — a notice that cannot be sent changes nothing
        logger.debug("the cancellation of request %s was not sent (%s).", request_id, exc)


# The record the SDK's stdio reader logs, with a traceback, for each stdout line
# that is not a protocol message. Every stdio connection is opened by the
# toolkit below, whose read stream states those lines itself
# (``_ProtocolLinesOnly``), so the per-line record is left out.
_SDK_STDIO_LOGGER = "mcp.client.stdio"
_SDK_PARSE_FAILURE = "Failed to parse JSONRPC message from server"


class _OneLinePerServer(logging.Filter):
    """Leaves out the SDK's per-line record of a stdout line that is not a protocol message."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage() != _SDK_PARSE_FAILURE


_PER_LINE_RECORD = _OneLinePerServer()


def _leave_out_the_per_line_record() -> None:
    """Attach the filter to the SDK's stdio logger, once per process."""
    sdk_logger = logging.getLogger(_SDK_STDIO_LOGGER)
    if _PER_LINE_RECORD not in sdk_logger.filters:
        sdk_logger.addFilter(_PER_LINE_RECORD)


def _message_after_a_redraw(line: str) -> Any:
    """The protocol message a progress bar's redraw left at the end of ``line``, or ``None``.

    A progress bar redraws its line with carriage returns and can end without
    a newline, so the server's next message lands on the bar's line, after its
    last carriage return. Only there is a message read out of a line: from the
    first ``{`` after the last carriage return (a CRLF line's own ``\\r`` taken
    off first), or a whole line after a byte-order mark. A message after any
    other text is never read as one: a log line that echoes text the server
    read (a string found in a sample) could end with a message the sample's
    author wrote. Asked only during the toolkit's setup
    (``_ProtocolLinesOnly.reads_redraws``), whose answers carry nothing from a
    sample. One parse at most.
    """
    from mcp import types
    from mcp.shared.message import SessionMessage

    if line.endswith("\r"):
        line = line[:-1]
    marked = line.startswith("\ufeff")
    if marked:
        line = line[1:]
    if "\r" in line:
        tail = line.rsplit("\r", 1)[1]
        brace = tail.find("{")
        if brace < 0:
            return None
        candidate = tail[brace:]
    elif marked:
        candidate = line
    else:
        return None
    try:
        return SessionMessage(types.JSONRPCMessage.model_validate_json(candidate))
    except ValidationError:
        return None


def _where_it_fails(error: ValidationError) -> str:
    """What failed a line's validation, by error type and location, never by content."""
    failed = {
        f"{detail.get('type')} at {'.'.join(str(part) for part in detail.get('loc', ())) or 'top'}"
        for detail in error.errors(include_url=False)
    }
    return "; ".join(sorted(failed))


class _ProtocolLinesOnly(ObjectReceiveStream[Any]):
    """A stdio transport's read stream, with each stdout line that is not a protocol message
    stated and left out.

    The SDK's stdio reader parses every line of the server's stdout as JSON-RPC
    and puts each parse failure into the stream it hands the session, with a
    traceback in the log: a log line or a dependency's progress bar on a
    server's stdout cost a traceback per line. Here two kinds are told apart.
    Log or progress output (a line that is not JSON, or JSON that does not
    claim to be a protocol message, such as a log record) is counted and left
    out, with a warning at the first one of the connection. A line that claims
    to be a protocol message (an object with a ``jsonrpc`` member) and is not a
    valid one is an answer the server got wrong, so each one is stated when it
    comes, with what failed its validation. Every message, and every other
    item the transport sends, reaches the session as it came, and the
    connection stays as it is.

    Only during the toolkit's setup is a message a progress bar's redraw left
    on a stray line read out and handed on (``_message_after_a_redraw``): the
    answers to ``initialize`` and ``tools/list`` carry nothing from a sample,
    and no tool has been called yet. A server whose first answer followed a
    startup bar never finished initialising before. Once the toolkit has the
    tool list it clears ``reads_redraws``, and from then on every stray line is
    skipped as it always was: a tool's answer can echo text a sample's author
    wrote, and an absent answer, which fails its call, beats a forged one.
    """

    def __init__(self, inner: Any, server: str) -> None:
        self._inner = inner
        self._server = server
        self.noise = 0
        self.invalid = 0
        self.recovered = 0
        # Open from the start of the connection until the toolkit has the
        # tool list (``MCPLangChainToolkit.initialize``).
        self.reads_redraws = True

    async def receive(self) -> Any:
        while True:
            item = await self._inner.receive()
            if not isinstance(item, ValidationError):
                return item
            details = item.errors(include_url=False)
            found = details[0].get("input") if details else None
            if details and details[0].get("type") == "json_invalid" and isinstance(found, str):
                self._note_noise()
                if self.reads_redraws:
                    message = _message_after_a_redraw(found)
                    if message is not None:
                        self.recovered += 1
                        return message
                continue
            if not (isinstance(found, dict) and "jsonrpc" in found):
                # JSON that does not claim to be a protocol message, such as a
                # log record a server writes as JSON: log output like any other.
                self._note_noise()
                continue
            self.invalid += 1
            logger.warning(
                "MCP server %r wrote a line to stdout that claims to be a protocol message and "
                "is not a valid one (%s: %s); it was skipped, so an answer it carried is lost.",
                self._server,
                type(item).__name__,
                _where_it_fails(item),
            )

    def _note_noise(self) -> None:
        self.noise += 1
        if self.noise == 1:
            logger.warning(
                "MCP server %r wrote a line to stdout that is not a protocol message; such "
                "lines are skipped and counted, and the count is stated when the connection "
                "closes. A server's stdout carries protocol messages only: its logs and "
                "progress output belong on stderr.",
                self._server,
            )

    async def aclose(self) -> None:
        await self._inner.aclose()


def served_info(info: Any) -> dict[str, str]:
    """``{name, version}`` as an MCP server gave them for itself, each only where it gave one."""
    out: dict[str, str] = {}
    for key in ("name", "version"):
        value = getattr(info, key, None)
        if isinstance(value, str) and value.strip():
            out[key] = value.strip()
    return out


# The most a delivery primitive's answer may hold, in characters (64 MiB): far
# past any reading's answer, and short of what would exhaust the worker.
DELIVERY_ANSWER_MAX_CHARS = 64 * 1024 * 1024

# How long a streamable-HTTP or SSE session waits for the next bytes of an
# answer, as the client library ships it.
HTTP_READ_TIMEOUT_SECONDS = 300.0


class MCPLangChainToolkit:
    """Toolkit that connects to an MCP server and exposes its tools to LangChain."""

    def __init__(
        self,
        server_params: StdioServerParameters | None = None,
        output_guardrail: Callable[[str], str] | None = None,
        max_output_chars: int = 0,
        *,
        transport: str = "stdio",
        http_url: str = "",
        http_headers: dict[str, str] | None = None,
        truncation_ledger: Any | None = None,
        context_budget: Any | None = None,
        guard: Any | None = None,
        categories: Mapping[str, str] | None = None,
        keep_tool_definitions: bool = False,
        label: str = "",
        http_read_timeout: float = HTTP_READ_TIMEOUT_SECONDS,
        categories_with_served: Callable[..., Mapping[str, str]] | None = None,
    ):
        self.server_params = server_params
        # The server's name in what this toolkit logs about it; a stdio
        # server's command name when none is given.
        self._label = label
        # The stdio transport's read stream as the session reads it, which
        # counts the stdout lines that are not protocol messages.
        self._stdout_lines: _ProtocolLinesOnly | None = None
        self.transport = (transport or "stdio").lower()
        self.http_url = http_url
        self.http_headers = http_headers or {}
        # How long an HTTP session waits for the next bytes of an answer: the
        # library's own unless the server's block runs readings whose own
        # clocks are longer (``ServerHandle``), each call still held to its own.
        self.http_read_timeout = float(http_read_timeout)
        self.session: ClientSession | None = None
        self._exit_stack: Any = None
        self._tools: list[BaseTool] = []
        self._output_guardrail = output_guardrail
        # Zero is the ordinary case and means "ask the budget below". A
        # positive number is the operator's own cap and wins over it.
        self._max_output_chars = max_output_chars
        # Optional TruncationLedger (pitfall P6). Typed loosely so this module
        # keeps no core import it does not otherwise need; None disables counting.
        self._truncation_ledger = truncation_ledger
        # The job's context budget, which knows the window the served model has
        # and what the conversation currently holds. None outside a job, and the
        # conservative window then answers.
        self._context_budget = context_budget
        # The job's breaker and call cap for this server
        # (``maljan.providers.server_guard``). None outside a job's registry,
        # and every call is then sent exactly as it always was.
        self._guard = guard
        # The tag each tool's description is shown with, as its server's block
        # declares it (``ToolFacts.category``); an undeclared tool's is read
        # from its name (``core.undeclared_tools.category_tag``).
        self._categories = dict(categories or {})
        # The tags as they are in force once the server's own declaration of
        # its tools is read (``core.served_declarations``), asked of the
        # handle before the tools are built; ``None`` keeps ``categories``.
        self._categories_with_served = categories_with_served
        # What the server says about itself when it is initialised (the MCP
        # ``instructions``), exactly as served; "" for a server that says
        # nothing. Tool-supplied text: shown to a model only as the server's
        # quoted words (``agents.prompt_fragments.undeclared_server_text``).
        self.server_instructions = ""
        # The name and version the server gave for itself when it was
        # initialised (MCP ``serverInfo``), each only where it gave one; read
        # into the run fingerprint (``analysis.efficiency``).
        self.server_info: dict[str, str] = {}
        # Each tool's definition exactly as the server listed it (MCP
        # ``Tool``: its input and output schemas, annotations, title and
        # description), kept only when asked. Read by the settings probe
        # alone, which proposes a declaration from it
        # (``core.declaration_proposals``); a run keeps none, so a server's
        # listing is held no longer than it was before.
        self._keep_tool_definitions = keep_tool_definitions
        self.tool_definitions: list[Any] = []
        # What the server declares of each of its tools under the listing's
        # ``_meta`` (``core.served_declarations``), by the name it lists it
        # under; the handle keeps it as the server's declaration.
        self.served_tool_facts: dict[str, Any] = {}
        # What the platform reads of the tools the listing does not declare
        # (``core.derived_declarations``); the handle keeps it beside it.
        # ``None`` when the listing could not be read: what was read before
        # is then kept as it is.
        self.derived_tool_facts: dict[str, Any] | None = {}
        # What a trusted block reads of the tools whose disclosure only their
        # server's own hints could lift (``derived_declarations.closed_by_hints``).
        self.derived_closed: dict[str, Any] = {}
        # What each listed tool is read as on a program-analysis server
        # (``derived_declarations.program_readings_of``), kept beside it.
        self.derived_program: dict[str, Any] = {}

    async def initialize(self) -> None:
        """Initialize the connection to the MCP server and fetch available tools.

        Once per connection: a call while the toolkit is connected, or still
        connecting, is refused before it touches anything, so the setup window
        of a stdio server's read stream (``_ProtocolLinesOnly.reads_redraws``)
        can never reopen and the open connection is neither abandoned nor
        doubled.
        """
        from contextlib import AsyncExitStack

        if self._exit_stack is not None:
            raise RuntimeError(
                f"MCP server {self._server_name()!r} is already connected or connecting; a "
                "second initialize() is refused. Call cleanup() before connecting again."
            )
        self._exit_stack = AsyncExitStack()

        # The session's wait for an answer's next bytes, named only where it
        # is not the library's own, so every other session opens as before.
        waits: dict[str, Any] = (
            {"sse_read_timeout": self.http_read_timeout}
            if self.http_read_timeout != HTTP_READ_TIMEOUT_SECONDS
            else {}
        )
        try:
            if self.transport in ("http", "streamable-http"):
                from mcp.client.streamable_http import streamablehttp_client

                logger.info("Connecting to MCP server over streamable-http: %s", self._host_label())
                streams = await self._exit_stack.enter_async_context(
                    streamablehttp_client(self.http_url, headers=self.http_headers, **waits)
                )
                # streamablehttp_client yields (read, write, get_session_id).
                read, write = streams[0], streams[1]
            elif self.transport == "sse":
                from mcp.client.sse import sse_client

                logger.info("Connecting to MCP server over SSE: %s", self._host_label())
                read, write = await self._exit_stack.enter_async_context(
                    sse_client(self.http_url, headers=self.http_headers, **waits)
                )
            else:
                if self.server_params is None:
                    raise ValueError("stdio transport requires server_params (command/args).")
                from maljan.core.settings_masking import masked_args

                logger.info(
                    "Connecting to MCP server over stdio: %s %s",
                    self.server_params.command,
                    masked_args(list(self.server_params.args or [])),
                )
                # A line of the server's stdout that is not a protocol message
                # is stated and left out rather than handed to the session, and
                # the count is stated again when the connection closes.
                _leave_out_the_per_line_record()
                read, write = await self._exit_stack.enter_async_context(
                    stdio_client(self.server_params)
                )
                self._stdout_lines = _ProtocolLinesOnly(read, self._server_name())
                read = cast(Any, self._stdout_lines)
            self.session = await self._exit_stack.enter_async_context(ClientSession(read, write))
            initialized = await self.session.initialize()
            served = getattr(initialized, "instructions", None)
            self.server_instructions = served if isinstance(served, str) else ""
            self.server_info = served_info(getattr(initialized, "serverInfo", None))

            # Fetch available tools
            response = await self.session.list_tools()
            # The setup's answers are in. From here a stray line on the
            # server's stdout is skipped, never read for a message: a tool's
            # answer can echo text a sample's author wrote.
            if self._stdout_lines is not None:
                self._stdout_lines.reads_redraws = False
            # What the server declares of its tools, read before they are
            # built so their tags are the ones in force from the first attach.
            self.served_tool_facts = self._served_tool_facts(response.tools)
            self.derived_tool_facts, self.derived_closed = self._derived_readings(response.tools)
            self.derived_program = self._program_readings(response.tools)
            self._settle_categories()
            for tool in response.tools:
                lc_tool = self._create_langchain_tool(tool)
                self._tools.append(lc_tool)
                if self._keep_tool_definitions:
                    self.tool_definitions.append(tool)

            logger.info(f"Successfully loaded {len(self._tools)} tools from MCP server.")
        except BaseException as e:
            # ``BaseException``, not ``Exception``, and that distinction is the
            # whole bug. ``mcp``'s streamable-http and stdio transports run in
            # an anyio task group; when the transport child dies — a peer that
            # accepts TCP and immediately closes, i.e. a stale port-forward —
            # the group cancels its scope and delivers ``asyncio.CancelledError``
            # into this coroutine. That is a ``BaseException``, so the old
            # ``except Exception`` missed it entirely: nothing was logged and
            # ``cleanup()`` never ran, leaking the exit stack and its transport
            # tasks onto the process-wide agent loop on every single run.
            #
            # Cleanup is best-effort and must not mask the original failure:
            # anyio raises ``RuntimeError: Attempted to exit cancel scope in a
            # different task`` when the stack is closed from a task other than
            # the one that entered it, and a cancelled scope is exactly when
            # that happens.
            #
            # The cancellation is deliberately NOT converted to a typed error
            # here. At this depth a hard-cap cancel (ours) and a transport-death
            # cancel (theirs) are indistinguishable; swallowing the former would
            # break the timeout contract in ``_run_coro_blocking``. The
            # conversion belongs at the loop boundary, which can tell them apart.
            logger.error(
                "Failed to initialize MCP client (%s): %s",
                type(e).__name__,
                self._said(e) or "—",
            )
            with suppress(BaseException):
                await self.cleanup()
            raise

    def _settle_categories(self) -> None:
        """The tags in force with what the server declared; those given where it cannot be read."""
        ask = self._categories_with_served
        if ask is None:
            return
        try:
            # With what the platform read of the same listing: the first
            # attach's tags read it as every later one does.
            self._categories = dict(
                ask(
                    self.served_tool_facts,
                    self.derived_tool_facts,
                    self.derived_closed,
                    self.derived_program,
                )
            )
        except Exception as exc:  # noqa: BLE001 — a tag never costs an attach
            logger.warning(
                "The tool tags of %s were not read with its declaration (%s).",
                self._server_name(),
                type(exc).__name__,
            )

    def _served_tool_facts(self, definitions: Sequence[Any]) -> dict[str, Any]:
        """What the listing declares of each tool; nothing when it cannot be read.

        Read for every server alike (``core.served_declarations``); a
        declaration is the server's data, and one that cannot be read never
        costs the attach.
        """
        from maljan.core.served_declarations import served_tool_facts

        try:
            return served_tool_facts(definitions, where=f"{self._server_name()}.")
        except Exception as exc:  # noqa: BLE001 — a declaration never costs an attach
            logger.warning(
                "The tool declarations %s listed were not read (%s).",
                self._server_name(),
                type(exc).__name__,
            )
            return {}

    def _derived_readings(
        self, definitions: Sequence[Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        """What is read of each listed tool, and what a trusted block keeps where hints lift it.

        ``None`` for the reading when the listing cannot be read: what was
        read before is then kept. Read for every server alike, each
        definition once (``core.derived_declarations``); a reading that fails
        never costs the attach.
        """
        from maljan.core.derived_declarations import derived_readings

        try:
            return derived_readings(definitions, where=f"{self._server_name()}.")
        except Exception as exc:  # noqa: BLE001 — a reading never costs an attach
            logger.warning(
                "The tools %s listed were not read (%s); what was read before is kept.",
                self._server_name(),
                type(exc).__name__,
            )
            return None, {}

    def _program_readings(self, definitions: Sequence[Any]) -> dict[str, Any]:
        """What each listed tool is read as on a program-analysis server; nothing on a failure.

        Read for every server alike (``core.program_reading``); it is in force
        only under a block whose roles hold a program role. A reading that
        fails never costs the attach.
        """
        from maljan.core.derived_declarations import program_readings_of

        try:
            return program_readings_of(definitions, where=f"{self._server_name()}.")
        except Exception as exc:  # noqa: BLE001 — a reading never costs an attach
            logger.warning(
                "The tools %s listed were not read as program tools (%s).",
                self._server_name(),
                type(exc).__name__,
            )
            return {}

    def get_tools(self) -> list[BaseTool]:
        """Return the list of LangChain tools exposed by the MCP server."""
        return self._tools

    async def deliver(
        self, tool_name: str, args: dict[str, Any], timeout: float | None = None
    ) -> Any:
        """One call of a delivery primitive, answered whole, for the platform alone.

        A delivery primitive's answer is the platform's input, never a model's
        (``agents.tool_pinning.DELIVERY_TOOLS``), so it is not held to a
        model's output limit: its text read as strict JSON (no ``NaN`` or
        ``Infinity``), else the server's structured answer. The server may
        have opened hostile bytes, so an answer past
        :data:`DELIVERY_ANSWER_MAX_CHARS` is refused rather than read, and an
        answer the server marked as an error is raised with its words.
        ``timeout`` is how long the call waits for its answer.
        """
        import json

        def refused(constant: str) -> Any:
            raise ValueError(f"{tool_name}: the answer holds {constant}, which is no JSON value")

        session = self.session
        if session is None:
            raise RuntimeError(f"{tool_name}: the server's session is not open")
        timing: dict[str, Any] = (
            {"read_timeout_seconds": timedelta(seconds=timeout)} if timeout else {}
        )
        result = await session.call_tool(tool_name, arguments=args, **timing)
        text = "\n".join(str(getattr(c, "text", "") or "") for c in result.content or [])
        if len(text) > DELIVERY_ANSWER_MAX_CHARS:
            raise ValueError(
                f"{tool_name}: the answer is {len(text)} characters, past the "
                f"{DELIVERY_ANSWER_MAX_CHARS} a delivery answer may hold"
            )
        if result.isError:
            raise RuntimeError(f"{tool_name}: {self._said_text(text.strip())}")
        if text.strip():
            return json.loads(text, parse_constant=refused)
        content = getattr(result, "structuredContent", None)
        if isinstance(content, dict) and content:
            return content
        raise ValueError(f"{tool_name}: the server answered nothing")

    async def cleanup(self) -> None:
        """Close the MCP server connection. Total: never raises, safe to repeat.

        Teardown that can throw is teardown nobody calls, and this method had
        exactly one caller in the whole repository — its own failure branch in
        ``initialize()``. On the success path the stack was simply abandoned,
        which for stdio transports also meant the MCP server subprocess was
        never reaped. Now that ``ServiceContainer.aclose()`` drives this at the
        end of every job, it has to survive anything it meets: a cancelled
        scope, a half-open socket, a loop that has moved on.

        The references are cleared even when the close fails, so a caller that
        retries does not attempt to re-close a stack that is already unwinding.
        """
        stack, self._exit_stack, self.session = self._exit_stack, None, None
        if stack is None:
            return
        try:
            await stack.aclose()
        except RuntimeError as exc:
            # anyio raises this when the stack is closed from a task other than
            # the one that entered it — the ordinary case here, since a
            # registry's close runs as a task of its own on the owning loop.
            # The refusal is anyio's task-group bookkeeping, not the transport:
            # the stack's exits still run, a stdio transport still closes the
            # server's stdin, waits for it and terminates it if it does not
            # exit, and no process or task is left behind
            # (``tests/unit/agents/test_mcp_cleanup_from_another_task.py``).
            if "cancel scope" in str(exc).lower():
                logger.info(
                    "MCP connection closed from a different task than the one that "
                    "opened it; anyio reported %r, and the transport's own shutdown "
                    "still ran, so nothing is left open.",
                    str(exc),
                )
            else:
                logger.warning("MCP cleanup failed (non-fatal): %s", exc)
        except BaseException as exc:  # noqa: BLE001 — teardown must not propagate
            logger.warning("MCP cleanup failed (%s, non-fatal): %s", type(exc).__name__, exc or "—")
        # After the close, whichever way it went. Lines a server writes once
        # the session has stopped reading are neither read nor counted.
        self._state_the_stray_stdout()

    def _host_label(self) -> str:
        """Where a network server is reached, as a log may name it: scheme, host and port.

        Never the URL whole: its user name and password, its path and its query
        can each carry a credential. A URL that cannot be read is named by its
        transport alone.
        """
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(str(self.http_url or ""))
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return self.transport
        if not host:
            return self.transport
        shown = f"[{host}]" if ":" in host else host
        where = f"{parts.scheme}://{shown}" if parts.scheme else shown
        return f"{where}:{port}" if port is not None else where

    def _said(self, exc: BaseException) -> str:
        """What ``exc`` says, with this server's URLs and any credential in a URL masked.

        The message is kept, because it is what tells the model and the operator
        what went wrong (:meth:`_said_text`).
        """
        return self._said_text(str(exc))

    def _said_text(self, text: str) -> str:
        """``text`` with every URL of this server named by its host label, every other masked.

        Percent-encoding is decoded first, until none is left, so an encoded
        URL is read as the URL it is, and every control character is then
        written out (``utils.written_forms.controls_written_out``); a URL quoted
        in the text ends at its closing quote or bracket. A URL whose host and port are this server's (host case aside, a
        scheme's default port written or not) is replaced whole, path included,
        by :meth:`_host_label`: a path can carry a key. Every other URL has its
        user name and password, query values and fragment masked
        (``core.settings_masking``). Linear in ``text``.
        """
        from maljan.core.settings_masking import masked_text, url_spans
        from maljan.utils.written_forms import controls_written_out

        # Decoded, then every control character written out: an encoded line
        # break or escape sequence never reaches the log or the ledger as one.
        text = controls_written_out(_fully_unquoted(str(text or "")))
        ours = _host_and_port(str(self.http_url or ""))
        if ours is None or "://" not in text:
            return masked_text(text)
        out: list[str] = []
        last = 0
        for begin, whole_end in url_spans(text):
            end = _quoted_end(text, begin, whole_end)
            if _host_and_port(text[begin:end]) == ours:
                out.append(text[last:begin])
                out.append(self._host_label())
                last = end
        out.append(text[last:])
        return masked_text("".join(out))

    def _server_name(self) -> str:
        """The server's name in what this toolkit logs: its label, else its command's name.

        A server reached over the network with no label is named by its
        transport alone: its URL can carry a credential.
        """
        command = str(getattr(self.server_params, "command", "") or "")
        return self._label or os.path.basename(command) or self.transport

    def _state_the_stray_stdout(self) -> None:
        """One line per server at close: what it wrote to stdout that was not a protocol message."""
        counted, self._stdout_lines = self._stdout_lines, None
        if counted is None or not (counted.noise or counted.invalid):
            return
        written = []
        if counted.noise:
            written.append(f"{counted.noise} line(s) of log or progress output, skipped")
        if counted.invalid:
            written.append(
                f"{counted.invalid} line(s) that claim to be a protocol message and are not "
                "a valid one, each stated when it came"
            )
        delivered = (
            f"; {counted.recovered} protocol message(s) left after a progress bar's carriage "
            "return during setup were read out and handed on"
            if counted.recovered
            else ""
        )
        logger.warning(
            "MCP server %r wrote to stdout %s%s. A server's stdout carries protocol messages "
            "only: its logs and progress output belong on stderr.",
            self._server_name(),
            " and ".join(written),
            delivered,
        )

    async def __aenter__(self) -> MCPLangChainToolkit:
        await self.initialize()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.cleanup()

    def _create_langchain_tool(self, mcp_tool: Any) -> BaseTool:
        """Convert an MCP Tool definition into a LangChain StructuredTool."""

        # Build Pydantic model from JSON schema dynamically
        # (annotation, default) pairs for create_model. Annotations are nullable
        # for optional parameters, so this cannot be narrowed to ``type``.
        properties: dict[str, tuple[Any, Any]] = {}
        required = mcp_tool.inputSchema.get("required", [])
        schema_props = mcp_tool.inputSchema.get("properties", {})
        # A name no field can carry (``model_config``, ``_x``, ``class``,
        # ``a-b``) is held under an internal field name with the server's own
        # as its alias (``agents.server_names``); every other is its own.
        held_as = field_names(schema_props)

        def hold(prop_name: str, shaped: Any, default: Any) -> None:
            field = held_as[prop_name]
            if field == prop_name:
                properties[field] = (shaped, default)
            else:
                properties[field] = (shaped, Field(default, alias=prop_name))

        for prop_name, prop_schema in schema_props.items():
            if not isinstance(prop_schema, dict):
                prop_schema = {"type": "string"}
            default = prop_schema.get("default", None)
            if holds_ref(default):
                # A default that holds a ``$ref`` would be read as a reference
                # by every client that converts the schema. Left out, the
                # argument is not sent and the server applies its own default.
                default = None
            if not is_plain(prop_schema):
                # A type list, a combinator, an enum, a nested object or array,
                # a ``$ref`` or no type at all: offered the server's schema with
                # its references written out (``agents.argument_schema``).
                optional = prop_name not in required
                try:
                    shaped = argument_annotation(
                        prop_schema, mcp_tool.inputSchema, optional=optional
                    )
                except Exception as exc:  # noqa: BLE001 — one property never costs the tool
                    # Too large, too deep or not a valid schema: offered as the
                    # plain type it was before any other form was read.
                    logger.warning(
                        "MCP server '%s' tool %r property %r is offered as its plain type: "
                        "its schema is %s",
                        self._server_name(),
                        mcp_tool.name,
                        prop_name,
                        self._said(exc)
                        if isinstance(exc, UnusableSchema)
                        else f"unreadable ({type(exc).__name__})",
                    )
                    shaped = plain_type(prop_schema) | None if optional else plain_type(prop_schema)
                hold(prop_name, shaped, default if optional else ...)
                continue

            py_type = PLAIN_TYPES.get(prop_schema["type"], Any)

            if prop_name in required:
                hold(prop_name, py_type, ...)
                continue

            # An optional parameter carries the server's own declared default
            # when it has one. Substituting ``None`` for it — as this did — is
            # not the same statement: the CAPE server types every tool's
            # ``token`` as ``str`` with ``"default": ""`` and rejects a null,
            # so all 36 of its tools failed validation on the first live call.
            # The annotation stays nullable so that an agent which emits an
            # explicit ``null`` is tolerated here and dropped below, rather
            # than raising inside LangChain's own argument parsing.
            hold(prop_name, py_type | None, default)

        # A ``null`` the server's schema does not allow is dropped while the
        # model validates (``agents.null_arguments``), so the field takes its
        # declared default exactly as if the call had left it out. A ``null``
        # it admits is let through, and ``arun_tool`` does not send it.
        try:
            rules = schema_rules(mcp_tool.inputSchema, withholds_admitted_nulls=True)
        except RecursionError:
            # Nested past what can be walked: every optional field is still
            # nullable here and a top-level ``None`` is still not sent.
            logger.warning(
                "MCP server '%s' tool '%s': its schema is nested too deep to read its null "
                "rules; a null inside a nested object is sent as given",
                self._server_name(),
                mcp_tool.name,
            )
            rules = NullRules()
        args_schema = argument_model(f"{mcp_tool.name}Schema", properties, rules)

        tool_name = mcp_tool.name
        # This tool's own way of asking for less, read off the schema it
        # offered. The shortening keeps room for the sentence that names them,
        # so an answer plus its notice is still inside the limit the answer was
        # cut to.
        from maljan.agents.output_shortening import narrowing_arguments

        narrowing = narrowing_arguments(schema_props)

        async def arun_tool(**kwargs: Any) -> str:
            if not self.session:
                # Structured marker so the agent prompt can detect "no session"
                # without parsing free-form text.
                return tool_error_marker("mcp_session_inactive", tool_name)
            # LangChain fills every declared field before invoking, so an
            # argument the agent never mentioned still arrives here — as the
            # schema default when there is one, and as ``None`` when there is
            # not. Only the first is a value the caller meant; forwarding the
            # second turns "unset" into "explicitly null" and denies the server
            # the chance to apply its own default.
            # Each under the server's own name, whatever field held it.
            named = to_server_names(args_schema, kwargs)
            args = {k: v for k, v in named.items() if v is not None or k in required}
            guard = self._guard
            if guard is None:
                return await self._call(tool_name, args, narrowing)
            # Asked before waiting for a slot and again after it: a server
            # that is resting answers at once, and one that began resting
            # while this call queued is not sent the call either. The trial
            # after a cooldown is admitted once and keeps its admission.
            refused, trial = guard.admit(tool_name)
            if refused is not None:
                return str(refused)
            sent = False
            try:
                async with guard.slot():
                    if not trial:
                        refused, trial = guard.admit(tool_name)
                        if refused is not None:
                            return str(refused)
                    # From here ``_call`` owns the outcome, abandonment
                    # included, so the guard is told exactly once.
                    sent = True
                    return await self._call(tool_name, args, narrowing, trial=trial)
            except BaseException:
                if not sent:
                    # Cancelled while it queued for a slot: nothing was sent.
                    guard.abandoned(trial=trial)
                raise

        # Compress description to reduce ReAct context bloat
        raw_desc = mcp_tool.description or f"Executes {mcp_tool.name} on the MCP server."
        description = self._tag_description(mcp_tool.name, raw_desc)

        # Whether the server marks the tool read-only (MCP ``readOnlyHint``):
        # an identical call answers the same, so a revision that repeats one
        # of an earlier round is answered from its entry
        # (``tool_pinning.answers_again``).
        from maljan.agents.tool_pinning import READ_ONLY_METADATA_KEY, SERVER_HINTS_METADATA_KEY
        from maljan.core.declared_reading import hints_of_annotations

        hints = getattr(mcp_tool, "annotations", None)
        read_only = getattr(hints, "readOnlyHint", None)
        if read_only is None and isinstance(hints, Mapping):
            read_only = hints.get("readOnlyHint")
        metadata: dict[str, Any] = {READ_ONLY_METADATA_KEY: True} if read_only is True else {}
        # Every MCP hint the server gave, read here at attach time and kept on
        # each entry of the tool (``core.declared_reading.with_hints``).
        given = hints_of_annotations(hints)
        if given:
            metadata[SERVER_HINTS_METADATA_KEY] = given
        return ServerNamedTool.from_function(
            func=None,  # Not supporting sync execution since MCP client is async
            coroutine=arun_tool,
            name=mcp_tool.name,
            description=description,
            args_schema=args_schema,
            metadata=metadata or None,
        )

    async def _call(
        self,
        tool_name: str,
        args: dict[str, Any],
        narrowing: Sequence[str],
        *,
        trial: bool = False,
    ) -> str:
        """Send one call and tell the guard whether the transport carried it."""
        from maljan.providers.server_guard import transport_failure

        guard = self._guard
        settled = False
        try:
            session = self.session
            if session is None:
                return tool_error_marker("mcp_session_inactive", tool_name)
            deadline = guard.call_timeout(tool_name) if guard is not None else None
            # The client library answers a call past its deadline with its own
            # request-timeout error, which is a transport failure. Only named
            # when there is one, so an unguarded call is sent exactly as before.
            timing: dict[str, Any] = (
                {"read_timeout_seconds": timedelta(seconds=deadline)} if deadline else {}
            )
            long_running = guard is not None and guard.long_running(tool_name)
            request_id = next_request_id(session)
            note_call_began()
            try:
                result = await session.call_tool(tool_name, arguments=args, **timing)
            except asyncio.CancelledError:
                await _cancel_at_the_server(session, request_id, "the caller stopped waiting")
                # A long-running tool still at work when its caller stopped
                # waiting is not a server that failed to answer.
                if guard is not None and not settled and not long_running:
                    # The caller's own budget ran out while this call was with
                    # the server: a call the server did not answer in the time
                    # there was, counted as one rather than let go as abandoned.
                    guard.failed(
                        "the call did not finish within its caller's budget",
                        trial=trial,
                    )
                    settled = True
                raise
            except Exception as exc:
                if transport_failure(exc) is not None:
                    await _cancel_at_the_server(session, request_id, "the client gave up")
                if long_running and guard is not None and not settled:
                    # Its own deadline passed: the server was still working.
                    guard.abandoned(trial=trial)
                    settled = True
                raise
            if guard is not None:
                guard.answered()
                settled = True
            from maljan.llm.context_window import output_limit

            # One limit for the whole call: the text's guardrail, the structure
            # beside it and an error's detail are held to the same number.
            limit = output_limit(self._max_output_chars, self._context_budget)
            if result.isError:
                detail = "\n".join(
                    str(getattr(c, "text", "") or "") for c in result.content or []
                ).strip()
                # The server's words, with any credential in a URL masked.
                return await asyncio.to_thread(
                    lambda: self._held_error(
                        "tool_returned_error", tool_name, self._said_text(detail), limit
                    )
                )
            output = "\n".join(c.text for c in result.content if hasattr(c, "text"))
            # On a thread: shortening a five-megabyte answer is CPU-bound
            # and synchronous, and this is a coroutine serving an agent.
            shown = await asyncio.to_thread(self._apply_output_guardrail, output, narrowing, limit)
            # The server's own structured answer, when it gave one and it is no
            # larger than what the model could be shown, rides on the text to
            # the ledger; the text the model reads is unchanged. It is noted
            # for the call either way, so an entry that cannot keep it keeps a
            # reference to it whole (``schemas.evidence_spill``).
            content = getattr(result, "structuredContent", None)
            from maljan.llm.context_window import note_answer_structure

            note_answer_structure(content)
            if not isinstance(content, dict) or not content or limit <= 0:
                return shown
            # Parsing the text and sizing the structure are CPU-bound too.
            return await asyncio.to_thread(with_structured_content, shown, content, limit)
        except Exception as exc:
            if guard is not None and not settled:
                reason = transport_failure(exc)
                if reason is None:
                    # The server answered with an error of its own; the
                    # transport carried it, and that is all the breaker reads.
                    guard.answered()
                else:
                    guard.failed(reason, trial=trial)
                settled = True
            said = self._said(exc)
            logger.warning("MCP tool '%s' raised %s: %s", tool_name, type(exc).__name__, said)
            from maljan.llm.context_window import output_limit

            # On a thread: writing a long message as JSON is CPU-bound.
            return await asyncio.to_thread(
                self._held_error,
                "exception",
                tool_name,
                said,
                output_limit(self._max_output_chars, self._context_budget),
                type=type(exc).__name__,
            )
        finally:
            if guard is not None and not settled:
                guard.abandoned(trial=trial)

    def _tag_description(self, name: str, description: str) -> str:
        """Prefix the description with its category tag; the text itself is kept whole.

        The tag is the one the tool's declaration gives, else, for a tool
        that declares none, the one its name's first word gives.
        """
        from maljan.core.undeclared_tools import category_tag

        clean = " ".join(description.split())
        return f"[{category_tag(name, self._categories.get(name, ''))}] {clean}"

    def _apply_output_guardrail(
        self, output: str, narrowing: Sequence[str] = (), limit: int | None = None
    ) -> str:
        """Limit tool output size to prevent LLM context overflow.

        The limit is ``_max_output_chars`` when the operator set one, and
        otherwise what the served model's context window has left for one
        answer at this moment (``maljan.llm.context_window.output_limit``). It
        is read once, here, so the whole of one call's decision — the
        shortening target, the summariser, the character cut and the ledger row
        — is taken against one number.

        A limit of zero is not "cut to nothing": it is the conversation having
        no room left for a tool answer at all. The model is handed one sentence
        saying so — a deterministic fact about this conversation — and the call
        is said to be cut (``note_answer_not_shown``), so its ledger entry is
        recorded as cut rather than as a successful empty answer.

        If the output exceeds it:
          1. Call ``_output_guardrail`` (e.g. FunctionSummarizer) when available.
          2. Fall back to simple character truncation otherwise.

        Every outcome — including the pass-through — is recorded on
        ``_truncation_ledger`` when one is attached. The pass-through matters as
        much as the cut: pitfall P6 asks for truncation *frequency*, and a
        frequency needs its denominator.

        A JSON answer over the limit only because of its whitespace is handed
        over whole, written without it: no value changes, so it carries no
        notice, and the ledger counts it as ``compacted``. Only a compact form
        that still does not fit is shortened.

        A JSON object is shortened as a document: elements come off the end of
        its largest lists, then characters off the end of its largest long
        strings, until it fits, and one reserved key says what was left out
        (``maljan.agents.output_shortening``). A cut made in characters ends a
        document mid-array, which reaches the model as a prefix it cannot read
        the metadata of and the ledger as prose with no ``structured`` at all —
        so the calls that found the most were the ones the report never saw.

        This runs **before** the summariser, and for a JSON object it is the
        better of the two: the summariser answers in English prose, and prose
        is exactly what leaves the record with nothing structured in it.
        Everything that is not a JSON object — a decompilation, any plain text
        — reaches the summariser and then the character cut, which keeps back
        the room of the completeness line the recorder appends to a cut answer
        (``schemas.answer_completeness.cut_line_room``).

        ``narrowing`` names this tool's own arguments that reach what a
        shortening leaves out. The recorder appends a sentence naming them to a
        shortened answer, so the room that sentence needs is kept back here:
        the answer and its notice together are what has to fit.

        Args:
            output: Raw tool output text.
            narrowing: The tool's arguments that narrow or page its answer.
            limit: The call's limit, when the caller already read it for the
                same call (the structure beside the answer is held to it too).

        Returns:
            Potentially shortened output.
        """
        from maljan.agents.output_shortening import shorten_json_document, shorten_target
        from maljan.agents.tool_fence import cut_length, view_room
        from maljan.llm.context_window import (
            note_answer_line_room,
            note_answer_not_shown,
            note_answer_whole,
            output_limit,
        )
        from maljan.schemas.answer_completeness import cut_line_room, shortened_line_room

        chars_in = len(output)
        if limit is None:
            limit = output_limit(self._max_output_chars, self._context_budget)

        if limit <= 0:
            note_answer_whole(output)
            note_answer_not_shown(chars_in)
            said = self._no_room(chars_in)
            self._record_guardrail(chars_in, len(said), over_limit=True, no_room=True, limit=limit)
            return said

        # An answer is shown through one view (``agents.tool_fence``): a text
        # answer fenced, a JSON one with its raw breaks escaped. The answer and
        # what the view adds together are what has to fit.
        fence = view_room(output)
        if chars_in + fence <= limit:
            self._record_guardrail(chars_in, chars_in, over_limit=False, limit=limit)
            return output

        # The answer as the tool gave it, for the call's entry to keep whole
        # when what follows cuts it (``schemas.evidence_spill``).
        note_answer_whole(output)
        logger.warning(
            "Tool output exceeds limit (%d > %d chars). Applying guardrail.",
            chars_in,
            limit,
        )

        # The completeness line under a shortened document is kept back from
        # the shortening's target as its sentence is, so the answer, the
        # sentence and the line together are inside the limit; the compact
        # form is still measured against the limit itself.
        # Kept back only while the shortening still has a target left;
        # otherwise the line is charged by the recorder.
        target = shorten_target(limit, narrowing) - shortened_line_room(output, narrowing)
        line_kept_back = target >= 1
        if not line_kept_back:
            target = shorten_target(limit, narrowing)
        attempt = shorten_json_document(output, target, cap=limit)
        if attempt.shortened and line_kept_back:
            note_answer_line_room()
        if attempt.compacted:
            self._record_guardrail(
                chars_in, len(attempt.text), over_limit=True, compacted=True, limit=limit
            )
            return attempt.text
        if attempt.shortened:
            self._charge_overage(len(attempt.text), limit)
            self._record_guardrail(
                chars_in, len(attempt.text), over_limit=True, shortened=True, limit=limit
            )
            return attempt.text

        if self._output_guardrail is not None:
            try:
                summarised = self._output_guardrail(output)
            except Exception as exc:
                logger.warning("Output guardrail failed: %s — falling back to truncation.", exc)
            else:
                # The completeness line the recorder appends to a cut answer
                # (``schemas.answer_completeness``) enters the conversation too.
                self._charge_overage(
                    len(summarised) + view_room(summarised) + cut_line_room(chars_in, narrowing),
                    limit,
                )
                note_answer_line_room()
                self._record_guardrail(
                    chars_in, len(summarised), over_limit=True, summarised=True, limit=limit
                )
                return summarised

        # Fallback: simple truncation with a marker
        # The kept part is text and fenced: the fence and the escapes inside
        # the kept part, never the whole answer's, are kept back, and so is the
        # completeness line the recorder appends to it, so the answer and the
        # line together are inside the limit.
        # Kept back only while some of the answer still fits beside it; a
        # limit too small for both keeps the answer's place, as it always
        # did, and the recorder charges the line instead.
        room = cut_line_room(chars_in, narrowing)
        kept = cut_length(output, max(0, truncation_target(limit) - room))
        if kept > 0:
            note_answer_line_room()
        else:
            kept = cut_length(output, truncation_target(limit))
        result = output[:kept] + TRUNCATION_MARKER
        self._charge_overage(len(result) + view_room(result), limit)
        self._record_guardrail(
            chars_in,
            len(result),
            over_limit=True,
            hard_truncated=True,
            shortening_timed_out=attempt.timed_out,
            limit=limit,
        )
        return result

    def _held_error(self, kind: str, tool: str, detail: str, limit: int, **fields: str) -> str:
        """The failure marker for ``detail``, held to the call's output limit like any answer.

        An error's text reaches the model as an answer does, so it is held to
        the same limit (``_apply_output_guardrail``): the detail keeps its head
        and its tail with :data:`TRUNCATION_MARKER` between them, so the whole
        marker fits,
        and the decision goes on the truncation ledger. The marker's kind and
        tool are the failure itself and are always kept, so a limit too small
        for any detail keeps them with none. The marker as the server gave it
        is noted for the call's entry to keep whole (``note_answer_whole``).
        Linear in ``detail``; CPU-bound on a large one, so a coroutine runs it
        on a thread.
        """
        import json

        from maljan.llm.context_window import note_answer_whole

        whole = tool_error_marker(kind, tool, **fields, detail=detail)
        if len(whole) <= limit:
            self._record_guardrail(len(whole), len(whole), over_limit=False, limit=limit)
            return whole
        note_answer_whole(whole)
        bare = tool_error_marker(kind, tool, **fields, detail="")
        room = max(0, int(limit) - len(bare) - len(json.dumps(TRUNCATION_MARKER)[1:-1]))
        # Its head and its tail, the marker between them: what a failure says
        # first and what it says last (a traceback's own error line) are both
        # kept. Each part is the longest run whose JSON form fits its half of
        # the room; every character is written in one or more, so no more than
        # ``room`` of them is ever read, whatever the detail's length.
        head = _json_fit(detail[: room // 2], room // 2)
        left = room - _json_width(detail[:head])
        rest = detail[head:]
        tail = _json_fit(rest[-left:][::-1], left) if left > 0 else 0
        kept_tail = rest[len(rest) - tail :] if tail else ""
        held = tool_error_marker(
            kind, tool, **fields, detail=detail[:head] + TRUNCATION_MARKER + kept_tail
        )
        self._record_guardrail(
            len(whole), len(held), over_limit=True, hard_truncated=True, limit=limit
        )
        self._charge_overage(len(held), limit)
        return held

    def _charge_overage(self, kept: int, limit: int) -> str:
        """Charge what a result is longer than the cap it was measured against.

        The budget reserved ``limit`` when it granted the cap, and two branches
        can hand back more than that: the character cut appends its marker
        after cutting, and a summariser may legitimately expand a short input.
        Twenty characters a call sounds like nothing and is not — within one
        model turn, where no measurement intervenes, every granted answer leaks
        its marker, and the run's own account of what the conversation holds
        drifts from what is in it. The ledger already records the real length;
        this makes the budget agree with it.

        Returns nothing useful; it is called for the charge.
        """
        from maljan.llm.context_window import ContextBudget

        budget = getattr(self, "_context_budget", None)
        over = max(0, int(kept) - int(limit))
        if over and isinstance(budget, ContextBudget):
            budget.charge(over)
        return ""

    def _no_room(self, chars_in: int) -> str:
        """The sentence a conversation with no room left gets, said once.

        Charged to the budget, because it is text that enters the conversation
        like any answer, and the agent is marked so its tool phase ends rather
        than paying for this sentence on every remaining round.

        Withheld when it would not fit, on the same rule as the shorter line a
        later call gets: a conversation already at its budget took a constant
        few hundred characters to be told it had none, which is the one claim
        this design makes about its own text and has to hold for the long
        sentence as well as the short one. The agent is marked either way —
        the phase ends whether or not there was room to say so.
        """
        from maljan.llm.context_window import ContextBudget, no_room_sentence

        said = no_room_sentence(chars_in)
        budget = getattr(self, "_context_budget", None)
        if not isinstance(budget, ContextBudget):
            return said
        budget.note_no_room()
        if not budget.room_for(len(said)):
            return ""
        budget.charge(len(said))
        return said

    def _record_guardrail(
        self,
        chars_in: int,
        chars_kept: int,
        *,
        over_limit: bool,
        summarised: bool = False,
        hard_truncated: bool = False,
        shortened: bool = False,
        shortening_timed_out: bool = False,
        no_room: bool = False,
        compacted: bool = False,
        limit: int = 0,
    ) -> None:
        """Record one guardrail decision; no-op without a ledger, never raises."""
        from maljan.core.truncation_ledger import record_guardrail_outcome

        record_guardrail_outcome(
            getattr(self, "_truncation_ledger", None),
            chars_in=chars_in,
            chars_kept=chars_kept,
            over_limit=over_limit,
            summarised=summarised,
            hard_truncated=hard_truncated,
            shortened=shortened,
            shortening_timed_out=shortening_timed_out,
            no_room=no_room,
            compacted=compacted,
            limit=limit,
        )
