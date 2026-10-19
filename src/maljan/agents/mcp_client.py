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
from langchain_core.tools import BaseTool, StructuredTool
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import ValidationError, create_model

from maljan.core.logger import logger


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

        try:
            if self.transport in ("http", "streamable-http"):
                from mcp.client.streamable_http import streamablehttp_client

                logger.info("Connecting to MCP server over streamable-http: %s", self.http_url)
                streams = await self._exit_stack.enter_async_context(
                    streamablehttp_client(self.http_url, headers=self.http_headers)
                )
                # streamablehttp_client yields (read, write, get_session_id).
                read, write = streams[0], streams[1]
            elif self.transport == "sse":
                from mcp.client.sse import sse_client

                logger.info("Connecting to MCP server over SSE: %s", self.http_url)
                read, write = await self._exit_stack.enter_async_context(
                    sse_client(self.http_url, headers=self.http_headers)
                )
            else:
                if self.server_params is None:
                    raise ValueError("stdio transport requires server_params (command/args).")
                logger.info(
                    "Connecting to MCP server over stdio: %s %s",
                    self.server_params.command,
                    self.server_params.args,
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
            logger.error("Failed to initialize MCP client (%s): %s", type(e).__name__, e or "—")
            with suppress(BaseException):
                await self.cleanup()
            raise

    def get_tools(self) -> list[BaseTool]:
        """Return the list of LangChain tools exposed by the MCP server."""
        return self._tools

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

        for prop_name, prop_schema in schema_props.items():
            if not isinstance(prop_schema, dict):
                prop_schema = {"type": "string"}
            prop_type_str = prop_schema.get("type", "string")

            # Map simple types
            type_mapping = {
                "string": str,
                "integer": int,
                "number": float,
                "boolean": bool,
                "array": list,
                "object": dict,
            }
            py_type = type_mapping.get(prop_type_str, Any)

            if prop_name in required:
                properties[prop_name] = (py_type, ...)
                continue

            # An optional parameter carries the server's own declared default
            # when it has one. Substituting ``None`` for it — as this did — is
            # not the same statement: the CAPE server types every tool's
            # ``token`` as ``str`` with ``"default": ""`` and rejects a null,
            # so all 36 of its tools failed validation on the first live call.
            # The annotation stays nullable so that an agent which emits an
            # explicit ``null`` is tolerated here and dropped below, rather
            # than raising inside LangChain's own argument parsing.
            properties[prop_name] = (py_type | None, prop_schema.get("default", None))

        args_schema = create_model(f"{mcp_tool.name}Schema", **properties)  # type: ignore[call-overload]

        tool_name = mcp_tool.name
        # This tool's own way of asking for less, read off the schema it
        # offered. The shortening keeps room for the sentence that names them,
        # so an answer plus its notice is still inside the limit the answer was
        # cut to.
        from maljan.agents.output_shortening import narrowing_arguments

        narrowing = narrowing_arguments(properties)

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
            args = {k: v for k, v in kwargs.items() if v is not None or k in required}
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
        return StructuredTool.from_function(
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
            if result.isError:
                return tool_error_marker(
                    "tool_returned_error",
                    tool_name,
                    detail="\n".join(
                        str(getattr(c, "text", "") or "") for c in result.content or []
                    ).strip(),
                )
            output = "\n".join(c.text for c in result.content if hasattr(c, "text"))
            # On a thread: shortening a five-megabyte answer is CPU-bound
            # and synchronous, and this is a coroutine serving an agent.
            from maljan.llm.context_window import output_limit

            # One limit for the whole call: the text's guardrail and the
            # structure beside it are held to the same number.
            limit = output_limit(self._max_output_chars, self._context_budget)
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
            logger.warning("MCP tool '%s' raised %s: %s", tool_name, type(exc).__name__, exc)
            return tool_error_marker(
                "exception", tool_name, type=type(exc).__name__, detail=str(exc)
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
