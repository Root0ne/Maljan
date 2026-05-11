"""MCP Client wrapper that exposes MCP server tools as LangChain tools.

This module connects to an MCP server via stdio and converts its
tools into LangChain BaseTool objects for use with create_react_agent.
"""

from __future__ import annotations

from collections.abc import Callable
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
        server_params: StdioServerParameters,
        output_guardrail: Callable[[str], str] | None = None,
        max_output_chars: int = 8000,
    ):
        self.server_params = server_params
        self.session: ClientSession | None = None
        self._exit_stack: Any = None
        self._tools: list[BaseTool] = []
        self._output_guardrail = output_guardrail
        self._max_output_chars = max_output_chars

    async def initialize(self) -> None:
        """Initialize the connection to the MCP server and fetch available tools."""
        from contextlib import AsyncExitStack

        logger.info(
            f"Connecting to MCP server: {self.server_params.command} {self.server_params.args}"
        )
        self._exit_stack = AsyncExitStack()

        try:
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
        except Exception as e:
            logger.error(f"Failed to initialize MCP client: {e}")
            await self.cleanup()
            raise

    def get_tools(self) -> list[BaseTool]:
        """Return the list of LangChain tools exposed by the MCP server."""
        return self._tools

    async def cleanup(self) -> None:
        """Close the MCP server connection."""
        if self._exit_stack:
            try:
                await self._exit_stack.aclose()
            except RuntimeError as exc:
                # stdio_client may raise cancel-scope errors when closed
                # from a different task; this is non-fatal.
                if "cancel scope" in str(exc).lower():
                    logger.warning("MCP cleanup cancel-scope warning (non-fatal): %s", exc)
                else:
                    raise
            finally:
                self._exit_stack = None
                self.session = None

    def _create_langchain_tool(self, mcp_tool: Any) -> BaseTool:
        """Convert an MCP Tool definition into a LangChain StructuredTool."""

        # Build Pydantic model from JSON schema dynamically
        properties = {}
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

            # Default value logic
            default_val = ... if prop_name in required else None

            properties[prop_name] = (py_type, default_val)

        args_schema = create_model(f"{mcp_tool.name}Schema", **properties)  # type: ignore[call-overload]

        tool_name = mcp_tool.name

        async def arun_tool(**kwargs: Any) -> str:
            if not self.session:
                # Structured marker so the agent prompt can detect "no session"
                # without parsing free-form text.
                return f'{{"tool_error": "mcp_session_inactive", "tool": "{tool_name}"}}'
            try:
                result = await self.session.call_tool(tool_name, arguments=kwargs)
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

        Args:
            output: Raw tool output text.

        Returns:
            Potentially shortened output.
        """
        if len(output) <= self._max_output_chars:
            return output

        logger.warning(
            "Tool output exceeds limit (%d > %d chars). Applying guardrail.",
            len(output),
            self._max_output_chars,
        )

        if self._output_guardrail is not None:
            try:
                return self._output_guardrail(output)
            except Exception as exc:
                logger.warning("Output guardrail failed: %s — falling back to truncation.", exc)

        # Fallback: simple truncation with a marker
        return output[: self._max_output_chars] + "\n\n[OUTPUT TRUNCATED]"
