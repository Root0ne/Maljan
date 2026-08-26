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
        truncation_ledger: Any | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self._tools: list[BaseTool] = []
        self._schema: list[dict[str, Any]] = []
        self._output_guardrail = output_guardrail
        self._max_output_chars = max_output_chars
        # Optional TruncationLedger (pitfall P6); None disables counting. This is
        # the production Ghidra transport, so this is where the numbers come from.
        self._truncation_ledger = truncation_ledger
        # Single long-lived AsyncClient — re-using the connection pool across
        # tool calls cuts TLS/TCP handshake overhead and avoids the previous
        # "new client per tool call" anti-pattern.
        self._http: httpx.AsyncClient | None = None

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=60.0, headers=self._auth_headers())
        return self._http

    async def aclose(self) -> None:
        """Close the underlying httpx client (idempotent)."""
        if self._http is not None:
            try:
                await self._http.aclose()
            finally:
                self._http = None

    async def initialize(self) -> None:
        """Fetch /mcp/schema and build LangChain tools."""
        client = await self._get_http()
        resp = await client.get(f"{self.base_url}/mcp/schema")
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

        # Phase 2: Compress tool descriptions to reduce context bloat.
        # 165 Ghidra tools were consuming ~15K-25K tokens per ReAct step.
        # We add a category tag + truncate to ~120 chars max.
        description = self._compress_description(path, description)

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

        client = await self._get_http()
        try:
            if method == "POST":
                resp = await client.post(
                    url, params=query, json=body, headers={"Content-Type": "application/json"}
                )
            else:
                resp = await client.get(url, params=query)
            resp.raise_for_status()
            output = resp.text
        except httpx.HTTPStatusError as exc:
            output = (
                f'{{"tool_error": "http_status", "status": {exc.response.status_code}, '
                f'"path": "{path}"}}'
            )
        except httpx.RequestError as exc:
            output = (
                f'{{"tool_error": "request_failed", "type": "{type(exc).__name__}", '
                f'"path": "{path}"}}'
            )

        if path == "/load_program":
            await self._activate_loaded_program(output)

        return self._apply_output_guardrail(output)

    async def _activate_loaded_program(self, load_output: str) -> None:
        """Make a freshly loaded program the *current* one.

        ``load_program`` imports the binary and reports success, but it only
        sets Ghidra's current program when nothing is current yet — the first
        load after a restart. Every later load leaves the server looking at the
        first binary of the container's lifetime, so an agent that loads its
        sample and then decompiles, lists imports or walks the call graph is
        reading a different file entirely, with no error anywhere to say so.

        Measured 2026-08-10: two samples of 241 KB and 139 KB yielded call
        graphs identical to the character until this call was added.

        Best-effort by construction. A stale current program is a wrong answer;
        an exception raised here would be a failed analysis, which is worse.
        """
        from maljan.analysis.ghidra_program import (
            SWITCH_PARAM,
            SWITCH_PATH,
            program_name_from_load,
            switch_is_confirmed,
        )

        name = program_name_from_load(load_output)
        if not name:
            return
        try:
            client = await self._get_http()
            resp = await client.post(
                f"{self.base_url}{SWITCH_PATH}",
                params={SWITCH_PARAM: name},
                json={},
                headers={"Content-Type": "application/json"},
            )
            if not switch_is_confirmed(resp.text, name):
                logger.warning(
                    "Ghidra switch_program did not confirm '%s' (%s) — subsequent tool "
                    "calls may read the previously loaded program.",
                    name,
                    resp.text[:160],
                )
        except Exception as exc:  # noqa: BLE001 — never fail an analysis over this
            logger.warning("Ghidra switch_program failed for '%s' (non-fatal): %s", name, exc)

    def _compress_description(self, path: str, description: str) -> str:
        """Add a category tag and truncate to keep ReAct context lean.

        Category prefixes help the LLM quickly identify tool families
        without reading full prose descriptions for all 165 tools.
        """
        name = path.lstrip("/").replace("/", "_")
        prefix = name.split("_")[0]

        # Map first word of tool name to a functional category
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

        # Strip existing newlines and collapse whitespace
        clean = " ".join(description.split())
        if len(clean) > 100:
            clean = clean[:97] + "..."

        return f"[{cat}] {clean}"

    def _apply_output_guardrail(self, output: str) -> str:
        """Limit tool output size to prevent LLM context overflow.

        Every outcome is recorded on ``_truncation_ledger`` when one is attached,
        including the pass-through: pitfall P6 asks for truncation *frequency*,
        and a frequency needs its denominator.
        """
        from maljan.core.truncation_ledger import record_guardrail_outcome

        chars_in = len(output)

        if chars_in <= self._max_output_chars:
            record_guardrail_outcome(
                self._truncation_ledger,
                chars_in=chars_in,
                chars_kept=chars_in,
                over_limit=False,
            )
            return output

        logger.warning(
            "Ghidra tool output exceeds limit (%d > %d chars). Applying guardrail.",
            chars_in,
            self._max_output_chars,
        )

        if self._output_guardrail is not None:
            try:
                summarised: str = self._output_guardrail(output)
            except Exception as exc:
                logger.warning("Output guardrail failed: %s - falling back to truncation.", exc)
            else:
                record_guardrail_outcome(
                    self._truncation_ledger,
                    chars_in=chars_in,
                    chars_kept=len(summarised),
                    over_limit=True,
                    summarised=True,
                )
                return summarised

        result = output[: self._max_output_chars] + "\n\n[OUTPUT TRUNCATED]"
        record_guardrail_outcome(
            self._truncation_ledger,
            chars_in=chars_in,
            chars_kept=len(result),
            over_limit=True,
            hard_truncated=True,
        )
        return result
