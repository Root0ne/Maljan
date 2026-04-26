"""MCP Client wrapper that exposes MCP server tools as LangChain tools.

This module connects to an MCP server via stdio and converts its
tools into LangChain BaseTool objects for use with create_react_agent.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool, StructuredTool
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import create_model

from maljan.core.logger import logger


class MCPLangChainToolkit:
    """Toolkit that connects to an MCP server and exposes its tools to LangChain."""

    def __init__(self, server_params: StdioServerParameters):
        self.server_params = server_params
        self.session: ClientSession | None = None
        self._exit_stack = None
        self._tools: list[BaseTool] = []

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
        required = getattr(mcp_tool.inputSchema, "required", [])
        schema_props = getattr(mcp_tool.inputSchema, "properties", {})

        for prop_name, prop_schema in schema_props.items():
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
                return "\n".join([c.text for c in result.content if hasattr(c, "text")])
            except Exception as e:
                return f"Tool execution failed: {str(e)}"

        return StructuredTool.from_function(
            func=None,  # Not supporting sync execution since MCP client is async
            coroutine=arun_tool,
            name=mcp_tool.name,
            description=mcp_tool.description or f"Executes {mcp_tool.name} on the MCP server.",
            args_schema=args_schema,
        )
