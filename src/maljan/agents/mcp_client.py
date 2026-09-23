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
from collections.abc import Callable, Sequence
from contextlib import suppress
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import create_model

from maljan.core.logger import logger

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
    ):
        self.server_params = server_params
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

    async def initialize(self) -> None:
        """Initialize the connection to the MCP server and fetch available tools."""
        from contextlib import AsyncExitStack

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
                read, write = await self._exit_stack.enter_async_context(
                    stdio_client(self.server_params)
                )
            self.session = await self._exit_stack.enter_async_context(ClientSession(read, write))
            await self.session.initialize()

            # Fetch available tools
            response = await self.session.list_tools()
            for tool in response.tools:
                lc_tool = self._create_langchain_tool(tool)
                self._tools.append(lc_tool)

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
            # the one that entered it — the ordinary case here, since agents
            # enter on the shared agent loop and may be closed from elsewhere.
            if "cancel scope" in str(exc).lower():
                logger.warning("MCP cleanup cancel-scope warning (non-fatal): %s", exc)
            else:
                logger.warning("MCP cleanup failed (non-fatal): %s", exc)
        except BaseException as exc:  # noqa: BLE001 — teardown must not propagate
            logger.warning("MCP cleanup failed (%s, non-fatal): %s", type(exc).__name__, exc or "—")

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
                return f'{{"tool_error": "mcp_session_inactive", "tool": "{tool_name}"}}'
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
            try:
                async with guard.slot():
                    if not trial:
                        refused, trial = guard.admit(tool_name)
                        if refused is not None:
                            return str(refused)
                    return await self._call(tool_name, args, narrowing, trial=trial)
            except BaseException:
                # Cancelled while it queued for a slot: the trial was never sent.
                guard.abandoned(trial=trial)
                raise

        # Compress description to reduce ReAct context bloat
        raw_desc = mcp_tool.description or f"Executes {mcp_tool.name} on the MCP server."
        description = self._tag_description(mcp_tool.name, raw_desc)

        return StructuredTool.from_function(
            func=None,  # Not supporting sync execution since MCP client is async
            coroutine=arun_tool,
            name=mcp_tool.name,
            description=description,
            args_schema=args_schema,
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
                return f'{{"tool_error": "mcp_session_inactive", "tool": "{tool_name}"}}'
            result = await session.call_tool(tool_name, arguments=args)
            if guard is not None:
                guard.answered()
                settled = True
            if result.isError:
                return (
                    f'{{"tool_error": "tool_returned_error", "tool": "{tool_name}", '
                    f'"detail": {result.content!r}}}'
                )
            output = "\n".join(c.text for c in result.content if hasattr(c, "text"))
            # On a thread: shortening a five-megabyte answer is CPU-bound
            # and synchronous, and this is a coroutine serving an agent.
            return await asyncio.to_thread(self._apply_output_guardrail, output, narrowing)
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
            return (
                f'{{"tool_error": "exception", "tool": "{tool_name}", '
                f'"type": "{type(exc).__name__}", "detail": "{exc}"}}'
            )
        finally:
            if guard is not None and not settled:
                guard.abandoned(trial=trial)

    def _tag_description(self, name: str, description: str) -> str:
        """Add a category tag and truncate to keep ReAct context lean."""
        prefix = name.split("_")[0]

        category_map: dict[str, str] = {
            "analyze": "ANALYZE",
            "decompile": "ANALYZE",
            "disassemble": "ANALYZE",
            "detect": "ANALYZE",
            "find": "ANALYZE",
            "diff": "ANALYZE",
            "compare": "ANALYZE",
            "inspect": "ANALYZE",
            "emulate": "ANALYZE",
            "extract": "ANALYZE",
            "list": "LIST",
            "get": "LIST",
            "search": "LIST",
            "batch": "BATCH",
            "bulk": "BATCH",
            "run": "EXEC",
            "rename": "MODIFY",
            "create": "MODIFY",
            "delete": "MODIFY",
            "set": "MODIFY",
            "apply": "MODIFY",
            "modify": "MODIFY",
            "remove": "MODIFY",
            "move": "MODIFY",
            "clear": "MODIFY",
            "convert": "MODIFY",
            "clone": "MODIFY",
            "force": "MODIFY",
            "open": "NAV",
            "close": "NAV",
            "save": "NAV",
            "load": "NAV",
            "switch": "NAV",
            "validate": "CHECK",
            "can": "CHECK",
            "read": "READ",
            "import": "IMPORT",
            "server": "META",
        }
        cat = category_map.get(prefix, "TOOL")

        clean = " ".join(description.split())
        return f"[{cat}] {clean}"

    def _apply_output_guardrail(self, output: str, narrowing: Sequence[str] = ()) -> str:
        """Limit tool output size to prevent LLM context overflow.

        The limit is ``_max_output_chars`` when the operator set one, and
        otherwise what the served model's context window has left for one
        answer at this moment (``maljan.llm.context_window.output_limit``). It
        is read once, here, so the whole of one call's decision — the
        shortening target, the summariser, the character cut and the ledger row
        — is taken against one number.

        A limit of zero is not "cut to nothing": it is the conversation having
        no room left for a tool answer at all. The model is handed one sentence
        saying so — a deterministic fact about this conversation — and the
        whole answer stays on the evidence ledger under the call's own id.

        If the output exceeds it:
          1. Call ``_output_guardrail`` (e.g. FunctionSummarizer) when available.
          2. Fall back to simple character truncation otherwise.

        Every outcome — including the pass-through — is recorded on
        ``_truncation_ledger`` when one is attached. The pass-through matters as
        much as the cut: pitfall P6 asks for truncation *frequency*, and a
        frequency needs its denominator.

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
        — reaches the summariser and then the character cut exactly as it
        always did, byte for byte.

        ``narrowing`` names this tool's own arguments that reach what a
        shortening leaves out. The recorder appends a sentence naming them to a
        shortened answer, so the room that sentence needs is kept back here:
        the answer and its notice together are what has to fit.

        Args:
            output: Raw tool output text.
            narrowing: The tool's arguments that narrow or page its answer.

        Returns:
            Potentially shortened output.
        """
        from maljan.agents.output_shortening import shorten_json_document, shorten_target
        from maljan.llm.context_window import output_limit

        chars_in = len(output)
        limit = output_limit(self._max_output_chars, self._context_budget)

        if limit <= 0:
            said = self._no_room(chars_in)
            self._record_guardrail(chars_in, len(said), over_limit=True, no_room=True, limit=limit)
            return said

        if chars_in <= limit:
            self._record_guardrail(chars_in, chars_in, over_limit=False, limit=limit)
            return output

        logger.warning(
            "Tool output exceeds limit (%d > %d chars). Applying guardrail.",
            chars_in,
            limit,
        )

        attempt = shorten_json_document(output, shorten_target(limit, narrowing))
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
                self._charge_overage(len(summarised), limit)
                self._record_guardrail(
                    chars_in, len(summarised), over_limit=True, summarised=True, limit=limit
                )
                return summarised

        # Fallback: simple truncation with a marker
        result = output[: truncation_target(limit)] + TRUNCATION_MARKER
        self._charge_overage(len(result), limit)
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
            limit=limit,
        )
