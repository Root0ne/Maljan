"""Unit tests for MCPLangChainToolkit._create_langchain_tool().

Validates that the MCP Tool inputSchema (a plain Python dict) is correctly
parsed into LangChain StructuredTool instances with proper parameter schemas.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

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

        # Verify each field has the correct annotation
        assert fields["str_field"].annotation is str
        assert fields["int_field"].annotation is int
        assert fields["float_field"].annotation is float
        assert fields["bool_field"].annotation is bool
        assert fields["list_field"].annotation is list
        assert fields["dict_field"].annotation is dict


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

        assert "normal_param" in fields
        assert fields["normal_param"].annotation is int

        # broken_param should default to str
        assert "broken_param" in fields
        assert fields["broken_param"].annotation is str

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
        assert fields["custom_field"].annotation is Any


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
        assert fields["format"].annotation is str

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
