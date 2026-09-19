"""The schema a model is shown for a sidecar tool has no sample-path argument.

A live static analyst typed the sample's path by hand, dropped three characters
out of the sha256 in it, and then spent its whole step budget guessing
directories — ``/``, ``.``, ``samples``, ``staging``, ``carved``, ``uploads``,
``private``. Nineteen of that run's thirty-five tool calls failed. The path
correction that existed could not help: the mistyped value shares no spelling
and no basename with the real one, so nothing recognised it as the sample.

An argument the model cannot see is an argument it cannot mistype. For the
built-in sidecars, the sample's path is taken out of the schema the model binds
to and supplied by the platform; a qualified path argument — a capture, a rule
file, a member inside an archive — is a choice and stays where it is. The
delivery primitives are not tools at all and are not offered.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import create_model

from maljan.agents.tool_pinning import DELIVERY_TOOLS, names_the_sample, pin_paths

ROOT = Path(__file__).resolve().parents[3]
SIDECARS = {
    "analysis": ROOT / "services" / "analysis-mcp" / "server.py",
    "network": ROOT / "services" / "network-mcp" / "server.py",
    "knowledge": ROOT / "services" / "knowledge-mcp" / "server.py",
}

STAGED = "/srv/staging/8f2c1a/sample.bin"


def _advertised_tools(source: Path) -> list[tuple[str, list[str]]]:
    """``(tool name, parameter names)`` for every ``@mcp.tool`` in one sidecar.

    Read out of the source rather than by importing the module: a sidecar
    imports its own analysis stack, and what this is about is the signature it
    advertises, which the text carries exactly.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    found: list[tuple[str, list[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        decorated = any("mcp.tool" in ast.unparse(decorator) for decorator in node.decorator_list)
        if not decorated:
            continue
        names = [arg.arg for arg in (*node.args.posonlyargs, *node.args.args)]
        found.append((node.name, names))
    return found


def _as_langchain_tool(
    name: str, parameters: list[str], server: str, seen: dict[str, dict[str, Any]]
) -> StructuredTool:
    """One sidecar tool as the registry hands it to an agent."""

    def _run(**kwargs: Any) -> str:
        seen[name] = kwargs
        return "ok"

    schema = create_model(f"{name}Schema", **{p: (str | None, "") for p in parameters})
    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=name,
        args_schema=schema,
        infer_schema=False,
        metadata={"maljan_server": server},
    )


def _offered(
    server: str, source: Path, seen: dict[str, dict[str, Any]] | None = None
) -> list[StructuredTool]:
    calls = seen if seen is not None else {}
    tools = [
        _as_langchain_tool(name, params, server, calls)
        for name, params in _advertised_tools(source)
    ]
    return list(pin_paths(tools, default_path=STAGED, agent_name="static"))


@pytest.mark.parametrize("server", sorted(SIDECARS))
class TestWhatTheModelIsShown:
    def test_the_sidecar_advertises_tools_at_all(self, server: str) -> None:
        assert _advertised_tools(SIDECARS[server]), server

    def test_no_advertised_schema_carries_a_sample_path_parameter(self, server: str) -> None:
        offending = [
            (tool.name, field)
            for tool in _offered(server, SIDECARS[server])
            for field in (tool.args_schema.model_fields if tool.args_schema else {})
            if names_the_sample(field)
        ]

        assert not offending, (
            "These advertise the sample's own path to the model, which is the platform's "
            f"to supply: {offending}"
        )

    def test_no_delivery_primitive_is_offered(self, server: str) -> None:
        offered = {tool.name for tool in _offered(server, SIDECARS[server])}

        assert not offered & DELIVERY_TOOLS


class TestWhatThePlatformSupplies:
    def test_the_pinned_path_reaches_the_tool_anyway(self) -> None:
        seen: dict[str, dict[str, Any]] = {}
        tool = next(
            t for t in _offered("analysis", SIDECARS["analysis"], seen) if t.name == "strings"
        )

        tool.invoke({})

        assert seen["strings"]["path"] == STAGED

    def test_a_qualified_path_argument_stays_the_model_s(self) -> None:
        tool = next(t for t in _offered("network", SIDECARS["network"]) if t.name == "extract_dns")

        assert "pcap_path" in (tool.args_schema.model_fields if tool.args_schema else {})

    def test_the_sidecar_itself_still_takes_the_path(self) -> None:
        """Hidden from the model, not removed: the platform's own calls need it."""
        advertised = dict(_advertised_tools(SIDECARS["analysis"]))

        assert advertised["strings"][0] == "path"
        assert "put_sample" in advertised
