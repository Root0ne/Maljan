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
        self._exit_stack = None
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
            await self._exit_stack.aclose()
            self._exit_stack = None
            self.session = None

    def _create_langchain_tool(self, mcp_tool) -> BaseTool:
        """Convert an MCP Tool definition into a LangChain StructuredTool."""

        # Build Pydantic model from JSON schema dynamically
        properties = {}
        required = mcp_tool.inputSchema.get("required", [])
        schema_props = mcp_tool.inputSchema.get("properties", {})

        for prop_name, prop_schema in schema_props.items():
            if not isinstance(prop_schema, dict):
                prop_schema = {"type": "string"}
            prop_type_str = prop_schema.get("type", "string")
            prop_desc = prop_schema.get("description", "")

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

            from pydantic import Field

            properties[prop_name] = (py_type, Field(default=default_val, description=prop_desc))

        args_schema = create_model(f"{mcp_tool.name}Schema", **properties)

        # The actual function that will be executed
        async def arun_tool(**kwargs) -> str:
            if not self.session:
                return "Error: MCP session is not active."
            try:
                result = await self.session.call_tool(mcp_tool.name, arguments=kwargs)
                if result.isError:
                    return f"Error from tool: {result.content}"
                # Join content parts (usually TextContent)
                output = "\n".join([c.text for c in result.content if hasattr(c, "text")])
                return self._apply_output_guardrail(output)
            except Exception as e:
                return f"Tool execution failed: {str(e)}"

        return StructuredTool.from_function(
            func=None,  # Not supporting sync execution since MCP client is async
            coroutine=arun_tool,
            name=mcp_tool.name,
            description=mcp_tool.description or f"Executes {mcp_tool.name} on the MCP server.",
            args_schema=args_schema,
        )

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
