"""HTTP client for GhidraMCP Headless Server.

Converts the server's REST API (/mcp/schema) into LangChain StructuredTool
objects so that StaticAnalyst can use Ghidra analysis endpoints without
requiring a local stdio subprocess.

Usage:
    client = GhidraHTTPClient(base_url="http://localhost:8089",
                              auth_token="secret")
    await client.initialize()
    tools = client.get_tools()
"""

from __future__ import annotations

from typing import Any

import httpx
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import create_model

from maljan.core.logger import logger


class GhidraHTTPClient:
    """Client that discovers and calls GhidraMCP headless REST endpoints."""

    def __init__(
        self,
        base_url: str,
        auth_token: str = "",
        output_guardrail: Any | None = None,
        max_output_chars: int = 8000,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self._tools: list[BaseTool] = []
        self._schema: list[dict[str, Any]] = []
        self._output_guardrail = output_guardrail
        self._max_output_chars = max_output_chars

    async def initialize(self) -> None:
        """Fetch /mcp/schema and build LangChain tools."""
        headers: dict[str, str] = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self.base_url}/mcp/schema", headers=headers
            )
            resp.raise_for_status()
            schema = resp.json()

        self._schema = schema.get("tools", [])
        for tool_def in self._schema:
            lc_tool = self._create_langchain_tool(tool_def)
            self._tools.append(lc_tool)

        logger.info(
            "GhidraHTTPClient loaded %d tools from %s",
            len(self._tools),
            self.base_url,
        )

    def get_tools(self) -> list[BaseTool]:
        """Return the list of LangChain tools."""
        return self._tools

    def _create_langchain_tool(self, tool_def: dict[str, Any]) -> BaseTool:
        """Convert a GhidraMCP schema entry into a LangChain StructuredTool."""
        path: str = tool_def["path"]
        method: str = tool_def.get("method", "GET").upper()
        description: str = tool_def.get("description", f"Call {path}")
        params: list[dict[str, Any]] = tool_def.get("params", [])

        # Build Pydantic args schema
        properties: dict[str, tuple[Any, Any]] = {}
        for p in params:
            name: str = p["name"]
            ptype: str = p.get("type", "string")
            required: bool = p.get("required", False)

            type_mapping = {
                "string": str,
                "integer": int,
                "number": float,
                "boolean": bool,
                "json": str,
                "array": list,
                "object": dict,
            }
            py_type = type_mapping.get(ptype, Any)
            default_val = ... if required else None
            properties[name] = (py_type, default_val)

        args_schema = create_model(
            f"GhidraTool_{path.lstrip('/').replace('/', '_')}Schema",
            **properties,  # type: ignore[call-overload]
        )

        async def arun_tool(
            _path: str = path,
            _method: str = method,
            _params: list[dict[str, Any]] = params,
            **kwargs: Any,
        ) -> str:
            return await self._call_endpoint(_path, _method, _params, kwargs)

        # Use the last path segment as a concise name
        tool_name = path.lstrip("/").replace("/", "_")

        return StructuredTool.from_function(
            func=None,
            coroutine=arun_tool,
            name=tool_name,
            description=description,
            args_schema=args_schema,
        )

    async def _call_endpoint(
        self,
        path: str,
        method: str,
        param_defs: list[dict[str, Any]],
        kwargs: dict[str, Any],
    ) -> str:
        """Execute a single HTTP request against a GhidraMCP endpoint."""
        headers: dict[str, str] = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        url = f"{self.base_url}{path}"
        query: dict[str, Any] = {}
        body: dict[str, Any] = {}

        for pdef in param_defs:
            pname = pdef["name"]
            psource = pdef.get("source", "query")
            if pname in kwargs and kwargs[pname] is not None:
                if psource == "body":
                    body[pname] = kwargs[pname]
                else:
                    query[pname] = kwargs[pname]

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                if method == "POST":
                    headers["Content-Type"] = "application/json"
                    resp = await client.post(url, params=query, json=body, headers=headers)
                else:
                    resp = await client.get(url, params=query, headers=headers)
                resp.raise_for_status()
                output = resp.text
        except httpx.HTTPStatusError as exc:
            output = f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except httpx.RequestError as exc:
            output = f"Request error: {exc}"

        return self._apply_output_guardrail(output)

    def _apply_output_guardrail(self, output: str) -> str:
        """Limit tool output size to prevent LLM context overflow."""
        if len(output) <= self._max_output_chars:
            return output

        logger.warning(
            "Ghidra tool output exceeds limit (%d > %d chars). Applying guardrail.",
            len(output),
            self._max_output_chars,
        )

        if self._output_guardrail is not None:
            try:
                return self._output_guardrail(output)
            except Exception as exc:
                logger.warning("Output guardrail failed: %s - falling back to truncation.", exc)

        return output[: self._max_output_chars] + "\n\n[OUTPUT TRUNCATED]"
