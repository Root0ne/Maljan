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
corpus, a file an earlier call in this run produced — is a choice and stays
where it is. The delivery primitives are not tools at all and are not offered.

Hiding the sample's path took a capability with it: ``carve_payloads`` writes
each embedded payload out under the staging directory and returns the paths,
and with ``path`` gone the model had nothing to pass them to. ``carved_path``
is the qualified argument that gives it back, on every tool here that reads a
file, confined to the staging base and to nothing else.
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

# The analysis tools that read a file, and therefore the ones a carved payload
# can be handed to. Written out rather than derived, so a tool added with a
# path argument and no way to reach a carved file fails this list.
READS_A_FILE = frozenset(
    {
        "identify_file",
        "hashes",
        "signing_info",
        "strings",
        "iocs_from_file",
        "pe_info",
        "elf_info",
        "macho_info",
        "apk_info",
        "carve_payloads",
        "archive_list",
        "document_info",
        "yara_scan",
        "capa",
        "floss",
        "resolve_api_hashes",
        "decode_string_blobs",
    }
)
CARVED = "carved_path"


def _advertised_tools(source: Path) -> list[tuple[str, list[str], str]]:
    """``(tool name, parameter names, description)`` for each ``@mcp.tool``.

    Read out of the source rather than by importing the module: a sidecar
    imports its own analysis stack, and what this is about is the signature it
    advertises, which the text carries exactly. The description is the
    docstring plus whatever a decorator under ``@mcp.tool()`` appends to it,
    which is how the one sentence about the carved argument is written once.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    note = _appended_note(source)
    found: list[tuple[str, list[str], str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        decorators = [ast.unparse(decorator) for decorator in node.decorator_list]
        if not any("mcp.tool" in decorator for decorator in decorators):
            continue
        names = [arg.arg for arg in (*node.args.posonlyargs, *node.args.args)]
        described = ast.get_docstring(node) or node.name
        if "reads_a_carved_file" in decorators:
            described = f"{described}\n\n{note}"
        found.append((node.name, names, described))
    return found


def _appended_note(source: Path) -> str:
    """The sentence the sidecar appends to every tool that reads a carved file."""
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "CARVED_NOTE" for target in node.targets
        ):
            return str(ast.literal_eval(node.value))
    return ""


def _as_langchain_tool(
    name: str,
    parameters: list[str],
    server: str,
    seen: dict[str, dict[str, Any]],
    description: str = "",
) -> StructuredTool:
    """One sidecar tool as the registry hands it to an agent."""

    def _run(**kwargs: Any) -> str:
        seen[name] = kwargs
        return "ok"

    schema = create_model(f"{name}Schema", **{p: (str | None, "") for p in parameters})
    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=description or name,
        args_schema=schema,
        infer_schema=False,
        metadata={"maljan_server": server},
    )


def _offered(
    server: str, source: Path, seen: dict[str, dict[str, Any]] | None = None
) -> list[StructuredTool]:
    calls = seen if seen is not None else {}
    tools = [
        _as_langchain_tool(name, params, server, calls, described)
        for name, params, described in _advertised_tools(source)
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
        advertised = {
            name: params for name, params, _doc in _advertised_tools(SIDECARS["analysis"])
        }

        assert advertised["strings"][0] == "path"
        assert "put_sample" in advertised


class TestTheQualifiedArgumentForACarvedFile:
    @staticmethod
    def _advertised() -> dict[str, list[str]]:
        return {
            tool.name: list(tool.args_schema.model_fields if tool.args_schema else {})
            for tool in _offered("analysis", SIDECARS["analysis"])
        }

    def test_every_file_reading_tool_offers_it(self) -> None:
        advertised = self._advertised()

        missing = sorted(name for name in READS_A_FILE if CARVED not in advertised.get(name, []))

        assert not missing, f"these read a file and cannot be pointed at a carved one: {missing}"

    def test_nothing_else_does(self) -> None:
        advertised = self._advertised()

        extra = sorted(
            name
            for name, fields in advertised.items()
            if CARVED in fields and name not in READS_A_FILE
        )

        assert not extra, f"these take a carved path and do not read a file: {extra}"

    def test_the_pin_leaves_it_alone(self) -> None:
        """It is qualified, so it is the model's to give and is never overwritten."""
        from maljan.agents.tool_pinning import names_the_sample

        assert names_the_sample(CARVED) is False

    def test_the_other_sidecars_do_not_offer_it(self) -> None:
        for server in ("network", "knowledge"):
            for tool in _offered(server, SIDECARS[server]):
                fields = tool.args_schema.model_fields if tool.args_schema else {}
                assert CARVED not in fields, f"{server}.{tool.name}"

    def test_the_description_says_what_it_is_for(self) -> None:
        tool = next(t for t in _offered("analysis", SIDECARS["analysis"]) if t.name == "strings")

        assert "carve_payloads" in tool.description
        assert "instead of the sample" in tool.description
