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

from collections.abc import Callable
from contextlib import suppress
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import create_model

from maljan.core.logger import logger


class MCPLangChainToolkit:
    """Toolkit that connects to an MCP server and exposes its tools to LangChain."""

    def __init__(
        self,
        server_params: StdioServerParameters | None = None,
        output_guardrail: Callable[[str], str] | None = None,
        max_output_chars: int = 8000,
        *,
        transport: str = "stdio",
        http_url: str = "",
        http_headers: dict[str, str] | None = None,
        truncation_ledger: Any | None = None,
    ):
        self.server_params = server_params
        self.transport = (transport or "stdio").lower()
        self.http_url = http_url
        self.http_headers = http_headers or {}
        self.session: ClientSession | None = None
        self._exit_stack: Any = None
        self._tools: list[BaseTool] = []
        self._output_guardrail = output_guardrail
        self._max_output_chars = max_output_chars
        # Optional TruncationLedger (pitfall P6). Typed loosely so this module
        # keeps no core import it does not otherwise need; None disables counting.
        self._truncation_ledger = truncation_ledger

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
            try:
                result = await self.session.call_tool(tool_name, arguments=args)
                if result.isError:
                    return (
                        f'{{"tool_error": "tool_returned_error", "tool": "{tool_name}", '
                        f'"detail": {result.content!r}}}'
                    )
                output = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                return self._apply_output_guardrail(output)
            except Exception as exc:
                logger.warning("MCP tool '%s' raised %s: %s", tool_name, type(exc).__name__, exc)
                return (
                    f'{{"tool_error": "exception", "tool": "{tool_name}", '
                    f'"type": "{type(exc).__name__}", "detail": "{exc}"}}'
                )

        # Compress description to reduce ReAct context bloat
        raw_desc = mcp_tool.description or f"Executes {mcp_tool.name} on the MCP server."
        description = self._compress_description(mcp_tool.name, raw_desc)

        return StructuredTool.from_function(
            func=None,  # Not supporting sync execution since MCP client is async
            coroutine=arun_tool,
            name=mcp_tool.name,
            description=description,
            args_schema=args_schema,
        )

    def _compress_description(self, name: str, description: str) -> str:
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
        if len(clean) > 100:
            clean = clean[:97] + "..."

        return f"[{cat}] {clean}"

    def _apply_output_guardrail(self, output: str) -> str:
        """Limit tool output size to prevent LLM context overflow.

        If the output exceeds ``_max_output_chars``:
          1. Call ``_output_guardrail`` (e.g. FunctionSummarizer) when available.
          2. Fall back to simple character truncation otherwise.

        Every outcome — including the pass-through — is recorded on
        ``_truncation_ledger`` when one is attached. The pass-through matters as
        much as the cut: pitfall P6 asks for truncation *frequency*, and a
        frequency needs its denominator.

        Args:
            output: Raw tool output text.

        Returns:
            Potentially shortened output.
        """
        chars_in = len(output)

        if chars_in <= self._max_output_chars:
            self._record_guardrail(chars_in, chars_in, over_limit=False)
            return output

        logger.warning(
            "Tool output exceeds limit (%d > %d chars). Applying guardrail.",
            chars_in,
            self._max_output_chars,
        )

        if self._output_guardrail is not None:
            try:
                summarised = self._output_guardrail(output)
            except Exception as exc:
                logger.warning("Output guardrail failed: %s — falling back to truncation.", exc)
            else:
                self._record_guardrail(chars_in, len(summarised), over_limit=True, summarised=True)
                return summarised

        # Fallback: simple truncation with a marker
        result = output[: self._max_output_chars] + "\n\n[OUTPUT TRUNCATED]"
        self._record_guardrail(chars_in, len(result), over_limit=True, hard_truncated=True)
        return result

    def _record_guardrail(
        self,
        chars_in: int,
        chars_kept: int,
        *,
        over_limit: bool,
        summarised: bool = False,
        hard_truncated: bool = False,
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
        )
