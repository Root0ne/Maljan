"""Unit tests for MCPLangChainToolkit._create_langchain_tool().

Validates that the MCP Tool inputSchema (a plain Python dict) is correctly
parsed into LangChain StructuredTool instances with proper parameter schemas.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.agents.mcp_client import MCPLangChainToolkit


def _make_mcp_tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
) -> MagicMock:
    """Create a mock MCP Tool object with a dict-based inputSchema."""
    tool = MagicMock()
    tool.name = name
    tool.description = description
    tool.inputSchema = input_schema
    return tool


@pytest.fixture
def toolkit() -> MCPLangChainToolkit:
    """Create a toolkit instance without connecting to any server."""
    server_params = MagicMock()
    return MCPLangChainToolkit(server_params)


# ---------------------------------------------------------------------------
# Schema parsing tests
# ---------------------------------------------------------------------------


class TestCreateLangChainToolDictSchema:
    """Tests that dict-based inputSchema is correctly parsed."""

    def test_parses_required_params(self, toolkit: MCPLangChainToolkit) -> None:
        """Required params should not have default values."""
        mcp_tool = _make_mcp_tool(
            name="submit_file",
            description="Submit a file for analysis",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the malware sample",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Analysis timeout in seconds",
                    },
                },
                "required": ["file_path"],
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)

        assert lc_tool.name == "submit_file"
        # The MCP toolkit compresses descriptions with a leading category tag
        # (e.g. "[TOOL]") so ReAct prompts stay compact — see
        # ``MCPLangChainToolkit._compress_description``.
        assert lc_tool.description.endswith("Submit a file for analysis")
        assert lc_tool.description.startswith("[")

        # Verify schema fields exist
        schema = lc_tool.args_schema
        assert schema is not None
        fields = schema.model_fields

        assert "file_path" in fields
        assert "timeout" in fields

        # file_path is required (no default)
        assert fields["file_path"].is_required()

        # timeout is optional (has default=None)
        assert not fields["timeout"].is_required()

    def test_handles_all_json_types(self, toolkit: MCPLangChainToolkit) -> None:
        """All JSON Schema types should map to correct Python types."""
        mcp_tool = _make_mcp_tool(
            name="test_types",
            description="Test type mapping",
            input_schema={
                "type": "object",
                "properties": {
                    "str_field": {"type": "string"},
                    "int_field": {"type": "integer"},
                    "float_field": {"type": "number"},
                    "bool_field": {"type": "boolean"},
                    "list_field": {"type": "array"},
                    "dict_field": {"type": "object"},
                },
                "required": [],
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)
        fields = lc_tool.args_schema.model_fields

        # All fields should be present
        assert len(fields) == 6

        # Every field here is optional, and an optional field's annotation is
        # nullable on purpose: LangChain fills unmentioned arguments before
        # invoking, and a ReAct agent may emit an explicit `null`. Both have to
        # be accepted here so the toolkit can drop them before the call rather
        # than raise — the alternative sent `token: null` to the CAPE server and
        # failed all 36 of its tools. The base type is what matters, so assert
        # that rather than the exact annotation object.
        expected = {
            "str_field": str,
            "int_field": int,
            "float_field": float,
            "bool_field": bool,
            "list_field": list,
            "dict_field": dict,
        }
        for name, base in expected.items():
            annotation = fields[name].annotation
            assert annotation == base | None, f"{name}: {annotation}"
            assert not fields[name].is_required()


class TestCreateLangChainToolEdgeCases:
    """Tests for edge cases and malformed schemas."""

    def test_empty_properties(self, toolkit: MCPLangChainToolkit) -> None:
        """Tool with no parameters should be created successfully."""
        mcp_tool = _make_mcp_tool(
            name="get_status",
            description="Get sandbox status",
            input_schema={
                "type": "object",
                "properties": {},
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)

        assert lc_tool.name == "get_status"
        assert len(lc_tool.args_schema.model_fields) == 0

    def test_missing_properties_key(self, toolkit: MCPLangChainToolkit) -> None:
        """Schema without 'properties' key should create a tool with no params."""
        mcp_tool = _make_mcp_tool(
            name="simple_tool",
            description="A simple tool",
            input_schema={"type": "object"},
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)

        assert lc_tool.name == "simple_tool"
        assert len(lc_tool.args_schema.model_fields) == 0

    def test_missing_required_key(self, toolkit: MCPLangChainToolkit) -> None:
        """Schema without 'required' key should treat all params as optional."""
        mcp_tool = _make_mcp_tool(
            name="optional_tool",
            description="All params optional",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)
        fields = lc_tool.args_schema.model_fields

        assert "query" in fields
        assert not fields["query"].is_required()

    def test_non_dict_prop_schema_handled(self, toolkit: MCPLangChainToolkit) -> None:
        """Non-dict property schemas should be treated as strings gracefully."""
        mcp_tool = _make_mcp_tool(
            name="weird_tool",
            description="Malformed schema",
            input_schema={
                "type": "object",
                "properties": {
                    "normal_param": {"type": "integer", "description": "A number"},
                    "broken_param": "not-a-dict",  # malformed
                },
                "required": [],
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)
        fields = lc_tool.args_schema.model_fields

        # Optional parameters are nullable by design — see
        # test_mcp_schema_defaults.py for why an unmentioned argument must be
        # accepted here and dropped before the call rather than rejected.
        assert "normal_param" in fields
        assert fields["normal_param"].annotation == int | None

        # broken_param should default to str
        assert "broken_param" in fields
        assert fields["broken_param"].annotation == str | None

    def test_missing_description_uses_fallback(self, toolkit: MCPLangChainToolkit) -> None:
        """Tool with None description should get a generated fallback."""
        mcp_tool = _make_mcp_tool(
            name="nodesc_tool",
            description=None,
            input_schema={"type": "object", "properties": {}},
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)

        assert "nodesc_tool" in lc_tool.description

    def test_unknown_type_maps_to_any(self, toolkit: MCPLangChainToolkit) -> None:
        """Unknown JSON Schema types should map to Any."""
        from typing import Any

        mcp_tool = _make_mcp_tool(
            name="any_tool",
            description="Unknown type test",
            input_schema={
                "type": "object",
                "properties": {
                    "custom_field": {"type": "custom_type"},
                },
                "required": [],
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)
        fields = lc_tool.args_schema.model_fields

        assert "custom_field" in fields
        assert fields["custom_field"].annotation == Any | None


class TestCreateLangChainToolCAPEv2:
    """Tests with realistic CAPEv2 MCP server tool schemas."""

    def test_submit_file_schema(self, toolkit: MCPLangChainToolkit) -> None:
        """Validates a realistic CAPEv2 submit_file tool schema."""
        mcp_tool = _make_mcp_tool(
            name="submit_file",
            description="Submit a file to the CAPEv2 sandbox for analysis.",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to submit.",
                    },
                    "package": {
                        "type": "string",
                        "description": "Analysis package (e.g. exe, dll, pdf).",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Analysis timeout in seconds.",
                    },
                    "enforce_timeout": {
                        "type": "boolean",
                        "description": "Force full timeout even if analysis finishes early.",
                    },
                    "options": {
                        "type": "object",
                        "description": "Additional analysis options as key-value pairs.",
                    },
                },
                "required": ["file_path"],
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)

        assert lc_tool.name == "submit_file"
        fields = lc_tool.args_schema.model_fields

        # file_path is required
        assert fields["file_path"].is_required()
        assert fields["file_path"].annotation is str

        # optional params
        assert not fields["package"].is_required()
        assert not fields["timeout"].is_required()
        assert not fields["enforce_timeout"].is_required()
        assert not fields["options"].is_required()

    def test_get_task_report_schema(self, toolkit: MCPLangChainToolkit) -> None:
        """Validates a realistic CAPEv2 get_task_report tool schema."""
        mcp_tool = _make_mcp_tool(
            name="get_task_report",
            description="Retrieve the analysis report for a completed task.",
            input_schema={
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "integer",
                        "description": "The task ID to retrieve the report for.",
                    },
                    "format": {
                        "type": "string",
                        "description": "Report format: 'full' or 'lean'.",
                    },
                },
                "required": ["task_id"],
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)
        fields = lc_tool.args_schema.model_fields

        assert fields["task_id"].is_required()
        assert fields["task_id"].annotation is int
        assert not fields["format"].is_required()
        assert fields["format"].annotation == str | None
        # This fixture declares no `default`, so there is nothing to inherit and
        # None is correct — the toolkit then omits the argument entirely rather
        # than sending a null. A schema that *does* declare one keeps it; that
        # is pinned in test_mcp_schema_defaults.py against the live CAPE
        # schemas, where a null `token` failed all 36 tools.
        assert fields["format"].default is None

    def test_get_cuckoo_status_no_params(self, toolkit: MCPLangChainToolkit) -> None:
        """Validates a CAPEv2 status tool with no parameters."""
        mcp_tool = _make_mcp_tool(
            name="get_cuckoo_status",
            description="Check if the CAPEv2 sandbox is online and operational.",
            input_schema={
                "type": "object",
                "properties": {},
            },
        )

        lc_tool = toolkit._create_langchain_tool(mcp_tool)

        assert lc_tool.name == "get_cuckoo_status"
        assert len(lc_tool.args_schema.model_fields) == 0


# ---------------------------------------------------------------------------
# HTTP transport (remote CAPE MCP on a separate VM)
# ---------------------------------------------------------------------------


class TestHttpTransport:
    """The toolkit must connect over streamable-http (not stdio) when
    transport='http', forwarding the URL and auth headers."""

    def test_http_transport_uses_streamablehttp_client(self, monkeypatch) -> None:
        import mcp.client.streamable_http as shm

        captured: dict[str, Any] = {}

        class _FakeStreamCtx:
            async def __aenter__(self):
                # streamablehttp_client yields (read, write, get_session_id)
                return ("read", "write", lambda: "sid")

            async def __aexit__(self, *exc: object) -> bool:
                return False

        def _fake_streamablehttp_client(url, headers=None):
            captured["url"] = url
            captured["headers"] = headers
            return _FakeStreamCtx()

        monkeypatch.setattr(shm, "streamablehttp_client", _fake_streamablehttp_client)

        fake_session = MagicMock()
        fake_session.initialize = AsyncMock()
        list_resp = MagicMock()
        list_resp.tools = []
        fake_session.list_tools = AsyncMock(return_value=list_resp)

        class _FakeSessionCtx:
            def __init__(self, read, write):
                captured["read_write"] = (read, write)

            async def __aenter__(self):
                return fake_session

            async def __aexit__(self, *exc: object) -> bool:
                return False

        monkeypatch.setattr("maljan.agents.mcp_client.ClientSession", _FakeSessionCtx)

        tk = MCPLangChainToolkit(
            transport="http",
            http_url="http://vm:9004/mcp/",
            http_headers={"Authorization": "Bearer secret"},
        )
        asyncio.run(tk.initialize())

        assert captured["url"] == "http://vm:9004/mcp/"
        assert captured["headers"] == {"Authorization": "Bearer secret"}
        assert captured["read_write"] == ("read", "write")
        assert tk.session is fake_session
        fake_session.initialize.assert_awaited_once()


class TestDynamicAnalystMcpTransportWiring:
    """``CAPE2SandboxProvider.dynamic_tools()`` picks the transport from config:
    transport='http' must build an HTTP toolkit (url + Bearer header), never
    a stdio subprocess.

    This wiring moved out of ``DynamicAnalyst._initialize_mcp_client`` and into
    the provider in the provider-layer refactor (Task 11) — the analyst now
    only asks the configured sandbox provider for tools, so there is nothing
    left in ``DynamicAnalyst`` to patch ``get_settings()`` into; these tests
    exercise ``CAPE2SandboxProvider`` directly instead.
    """

    def test_http_transport_builds_http_toolkit(self, monkeypatch) -> None:
        import maljan.agents.mcp_client as mc
        from maljan.core.config import Settings
        from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

        captured: dict[str, Any] = {}

        class _FakeToolkit:
            def __init__(
                self,
                server_params=None,
                output_guardrail=None,
                max_output_chars=8000,
                *,
                transport="stdio",
                http_url="",
                http_headers=None,
            ):
                captured["transport"] = transport
                captured["http_url"] = http_url
                captured["http_headers"] = http_headers
                captured["server_params"] = server_params

            async def initialize(self):
                return None

            def get_tools(self):
                return []

        monkeypatch.setattr(mc, "MCPLangChainToolkit", _FakeToolkit)

        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        cfg.sandbox.cape2.mcp.transport = "http"
        cfg.sandbox.cape2.mcp.url = "http://vm:9004/mcp/"
        cfg.sandbox.cape2.mcp.auth_token = "secret"
        provider = CAPE2SandboxProvider.from_settings(cfg)

        provider.dynamic_tools()

        assert captured["transport"] == "http"
        assert captured["http_url"] == "http://vm:9004/mcp/"
        assert captured["http_headers"] == {"Authorization": "Bearer secret"}
        # stdio path must NOT have been taken
        assert captured["server_params"] is None

    def test_http_transport_without_url_skips(self, monkeypatch) -> None:
        import maljan.agents.mcp_client as mc
        from maljan.core.config import Settings
        from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

        def _boom(*a, **k):
            raise AssertionError("toolkit must not be built when url is empty")

        monkeypatch.setattr(mc, "MCPLangChainToolkit", _boom)

        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        cfg.sandbox.cape2.mcp.transport = "http"
        cfg.sandbox.cape2.mcp.url = ""
        provider = CAPE2SandboxProvider.from_settings(cfg)

        # Should log a warning and return without raising, and without
        # attaching a toolkit.
        tools = provider.dynamic_tools()
        assert tools == []
        assert provider._toolkit is None
